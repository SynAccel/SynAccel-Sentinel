import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.core.sentinel_core import (
    adapt_config,
    parse_iam_reports,
    parse_s3_reports,
    rollup_events_into_state,
    score_risks,
)


class SentinelCoreTests(unittest.TestCase):
    def test_reports_preserve_each_affected_resource(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report_dir = Path(temp_dir)
            iam_report = report_dir / "iam_detector_report.md"
            iam_report.write_text(
                "- [!] alice has no MFA enabled.\n"
                "- User bob has no MFA enabled.\n"
                "- [!] carol has an old access key (145 days).\n",
                encoding="utf-8",
            )
            s3_report = report_dir / "s3_detector_report.md"
            s3_report.write_text(
                "- [!] Public bucket policy detected on bucket: bucket-one\n"
                "- [!] Public Access Block not fully enabled for bucket: bucket-two\n",
                encoding="utf-8",
            )

            iam_findings = parse_iam_reports([iam_report])
            s3_findings = parse_s3_reports([s3_report])

            self.assertEqual([event["resource"] for event in iam_findings], ["alice", "bob", "carol"])
            self.assertEqual(iam_findings[0]["signal"], "IAM_NO_MFA")
            self.assertEqual(iam_findings[2]["resource"], "carol")
            self.assertEqual(iam_findings[2]["age_days"], 145)
            self.assertEqual([event["resource"] for event in s3_findings], ["bucket-one", "bucket-two"])
            self.assertEqual(s3_findings[0]["signal"], "S3_PUBLIC_POLICY")

    def test_rollup_deduplicates_resources_and_escalates_policy(self):
        events = [
            {"type": "IAM_NO_MFA", "report": "iam-one.md", "resource": "alice"},
            {"type": "IAM_NO_MFA", "report": "iam-one.md", "resource": "bob"},
            {
                "type": "S3_PUBLIC",
                "signal": "S3_PUBLIC_POLICY",
                "report": "s3-one.md",
                "resource": "bucket-one",
            },
            {
                "type": "S3_PUBLIC",
                "signal": "S3_MISSING_PUBLIC_ACCESS_BLOCK",
                "report": "s3-one.md",
                "resource": "bucket-one",
            },
            {
                "type": "S3_PUBLIC",
                "signal": "S3_PUBLIC_POLICY",
                "report": "s3-one.md",
                "resource": "bucket-two",
            },
        ]
        state = {"events": [], "counters": {}, "last_updated": ""}
        rollup_events_into_state(state, events + events)

        self.assertEqual(
            state["counters"],
            {"IAM_NO_MFA_24h": 2, "IAM_OLD_KEY_24h": 0, "S3_PUBLIC_24h": 2},
        )
        self.assertEqual(len(state["events"]), 5)

        config = {
            "policy": {
                "iam": {
                    "require_mfa": False,
                    "disable_keys_on_nomfa": False,
                    "escalation_threshold_24h": 2,
                },
                "s3": {
                    "auto_tag_only": True,
                    "auto_remediate_public": False,
                    "escalation_threshold_24h": 2,
                },
            }
        }
        config, changes = adapt_config(config, state)

        self.assertTrue(config["policy"]["iam"]["require_mfa"])
        self.assertTrue(config["policy"]["s3"]["auto_remediate_public"])
        self.assertIn("IAM: set require_mfa=True", changes)
        self.assertIn("S3: escalated to auto_remediate_public=True", changes)

    def test_weighted_scores_combine_signals_and_decay_over_time(self):
        now = datetime(2026, 10, 28, 12, tzinfo=timezone.utc)
        events = [
            {"type": "IAM_NO_MFA", "signal": "IAM_NO_MFA", "resource": "alice", "ts": now.isoformat()},
            {"type": "IAM_OLD_ACCESS_KEY", "signal": "IAM_OLD_ACCESS_KEY", "resource": "alice", "ts": now.isoformat()},
            {"type": "S3_PUBLIC", "signal": "S3_PUBLIC_POLICY", "resource": "bucket-one", "ts": now.isoformat()},
            {"type": "S3_PUBLIC", "signal": "S3_MISSING_PUBLIC_ACCESS_BLOCK", "resource": "bucket-one", "ts": now.isoformat()},
            {
                "type": "IAM_NO_MFA",
                "signal": "IAM_NO_MFA",
                "resource": "carol",
                "ts": (now - timedelta(hours=24)).isoformat(),
            },
        ]

        scores = {result["entity"]: result for result in score_risks(events, now=now)}

        self.assertEqual(scores["iam:alice"]["score"], 60)
        self.assertEqual(scores["iam:alice"]["level"], "high")
        self.assertEqual(scores["s3:bucket-one"]["score"], 100)
        self.assertEqual(scores["s3:bucket-one"]["level"], "critical")
        self.assertEqual(scores["iam:carol"]["score"], 18)
        self.assertEqual(scores["iam:carol"]["level"], "low")
        self.assertIn("human review", scores["s3:bucket-one"]["recommendation"])


if __name__ == "__main__":
    unittest.main()
