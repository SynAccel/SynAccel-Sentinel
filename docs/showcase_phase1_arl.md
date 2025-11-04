# SynAccel Sentinel – Phase-1 Adaptive Response Loop (ARL) Showcase

This document demonstrates how **SynAccel Sentinel’s Adaptive Response Loop (ARL)** learns from its own detections and automatically strengthens its defense posture.

---

##  Setup Overview

Sentinel uses two key files for its adaptive logic:

- configs/sentinel_config.json -> current auto-tuned policy
- state/sentinel_state.json -> short term memory of detections


Both start in a low-intensity “monitor-only” mode:
```json
"s3": { "auto_tag_only": true, "auto_remediate_public": false },
"iam": { "require_mfa": false, "disable_keys_on_nomfa": false }
```

## Step 1: Simulate Detector Reports

The Adaptive Core looks for key phrases inside detector markdown files located in:

```
reports/sample_output/
```

By using these quick PowerShell commands to create mock reports from the root directory:

```
# --- Create S3 findings (2 simulated triggers) ---
@'
# S3 Detector Report
Public bucket policy detected on bucket: demo-bucket-1
'@ | Out-File "reports/sample_output/s3_report_1.md" -Encoding utf8

@'
# S3 Detector Report
Public Access Block not fully enabled for bucket: demo-bucket-2
'@ | Out-File "reports/sample_output/s3_report_2.md" -Encoding utf8

# --- Create IAM findings (2 simulated triggers) ---
@'
# IAM Detector Report
User alice has no MFA enabled
'@ | Out-File "reports/sample_output/iam_report_1.md" -Encoding utf8

@'
# IAM Detector Report
User bob has no MFA enabled
'@ | Out-File "reports/sample_output/iam_report_2.md" -Encoding utf8
```

## Step 2: Run the Adaptive Core

```
python src/core/sentinel_core.py
```

Output:
```
[i] Found 4 new events from recent reports.
[✓] Core report saved: C:\Users\Nick\projects\SynAccel-Sentinel\reports\sample_output\sentinel_core_report_2025-11-03-23-55-43.md
[+] Policy escalated based on recent events:
{"iam": {"disable_keys_on_nomfa": false, "escalation_threshold_24h": 2, "require_mfa": true}, "s3": {"auto_remediate_public": true, "auto_tag_only": false, "escalation_threshold_24h": 2}}
```

## Step 3: Observe the Adaptation

| Event Type            | Detections  | Policy Change                   |
| --------------------- | ----------- | ------------------------------- |
| S3 public buckets     | ≥ 2 in 24 h | Enabled `auto_remediate_public` |
| IAM users without MFA | ≥ 2 in 24 h | Enforced `require_mfa`          |

Check the updated configuration

```
Get-Content configs\sentinel_config.json
```

Output:
```
{
  "version": 1,
  "updated_at": "2025-11-04T04:56:42.331247+00:00",
  "policy": {
    "iam": {
      "require_mfa": true,
      "disable_keys_on_nomfa": false,
      "escalation_threshold_24h": 2
    },
    "s3": {
      "auto_tag_only": false,
      "auto_remediate_public": true,
      "escalation_threshold_24h": 2
    }
  }
}
```

Review the generated core report

Open the newest file in reports/sample_output/ named:

```
sentinel_core_report_YYYY-MM-DD-HH-MM-SS.md
```
It should include:

```
## 24h Counters
- IAM_NO_MFA_24h: 2
- S3_PUBLIC_24h: 2

## Changes Applied
- S3: escalated to auto_remediate_public=True
- IAM: set require_mfa=True
```

## Step 4 — Stabilization Phase

Now remove the mock detector reports and reset Sentinel’s state:

```
Remove-Item reports/sample_output/s3_report_*.md, reports/sample_output/iam_report_*.md -Force

$stateJson = @'
{
  "events": [],
  "counters": {
    "IAM_NO_MFA_24h": 0,
    "S3_PUBLIC_24h": 0
  },
  "last_updated": ""
}
'@
[IO.File]::WriteAllText("state/sentinel_state.json", $stateJson)
```
Then rerun:

```powershell
python src/core/sentinel_core.py
```

Output:

```
[i] Found 0 new events from recent reports.
[✓] Core report saved: reports/sample_output/sentinel_core_report_2025-11-04-00-09-47.md
[-] No escalation needed.
```

## Key Takeaway:

It learns, adapts, and stabilizes. Repeated detections trigger stronger defenses; once conditions 
improve, the system is steady.

```
Detectors → Reports → Adaptive Core → Updated Config → Responders
                   ↑                               ↓
             24-Hour Rolling State Memory
```







