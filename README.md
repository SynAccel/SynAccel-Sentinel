# SynAccel-Sentinel

**SynAccel-Sentinel** is a modular, Python-based security detection framework designed to identify risks across cloud environments and network activity.

It is part of the larger **SynAccel** ecosystem and focuses on early-stage detection, analysis, and response logic for modern security threats.

---

## Current Features

### AWS Misconfiguration Detection
Located in: `/src/detectors/`

- IAM exposure detection
- Public S3 bucket detection
- Extensible detector-based design

---

### CloudTrail Anomaly Detection (Experimental)
Located in: `/src/cloudtrail_anomaly_detector/` — on `guardduty-dev` branch

- Pulls CloudTrail events using `boto3`
- Flags:
  - Unusual API call frequency
  - High-risk actions (Delete*, Put*, Attach*, etc.)
- Rule-driven via `anomaly_rules.json`
- Designed to integrate with Sentinel's core loop

---

### GuardDuty Integration (Experimental)
Located in: `/src/guardduty_integration/` — on `guardduty-dev` branch

- Connects to AWS GuardDuty
- Pulls recent findings
- Parses and normalizes alerts for Sentinel
- Awaiting live AWS testing/activation


---

## Development Flow

- Stable code remains on `main`
- Experimental modules are developed on:

guardduty-dev

- Changes are added via pull requests after testing

---

## Planned Next Steps

- Finish AWS account activation
- Enable GuardDuty + CloudTrail logging
- Live test anomaly detection modules
- Build Sentinel core execution loop
- Add logging/dashboard

---

## Goal

To create an **adaptive, AI-assisted security monitoring system** capable of detecting misconfigurations, abnormal behavior, and potential threats across cloud and network environments.














