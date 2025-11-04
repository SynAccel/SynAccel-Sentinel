# SynAccel Sentinel

**Status:** Active Development (Phase-1 Prototype)  
**Last Updated:** November 2025  

SynAccel Sentinel is an **adaptive cloud-security research framework** under active development by the **SynAccel Cyber R&D** initiative.  
The project explores how automation and feedback loops can enable **self-learning cloud defenses** that detect risks, respond intelligently, and adapt over time.

---

##  Current Focus

### Phase-1: Adaptive Response Loop (ARL)
Sentinel currently includes a working **Adaptive Response Loop**, which allows the system to learn from its own detections and automatically tighten its response policy when repeated risks occur.

**What’s implemented so far:**
- **Detectors** — Identify AWS misconfigurations (IAM and S3 modules).  
- **Responders** — Perform actions or tagging based on the live policy.  
- **Core (ARL)** — Tracks detections, updates 24-hour counters, and adjusts policy automatically.  
- **Config + State** — JSON files store Sentinel’s current policy and adaptive memory.

```
Detectors → Reports → Core (ARL) → Updated Config → Responders
↑ ↓
└────────────────────── 24h State Memory ─────────────┘

```

**Example behavior**
- Multiple public S3 buckets in 24h → `auto_remediate_public = true`  
- Repeated IAM users without MFA → `require_mfa = true`, later `disable_keys_on_nomfa = true`


**Run**
```bash
python src/core/sentinel_core.py
```

**Current Folder Structure**
```
SynAccel-Sentinel/
├── src/
│   ├── detectors/
│   │   ├── iam_exposure_detector.py
│   │   └── s3_public_access_detector.py
│   ├── responders/
│   │   ├── iam_responder.py
│   │   └── s3_responder.py
│   ├── core/
│   │   └── sentinel_core.py
│   ├── utils/
│   └── ...
├── configs/
│   └── sentinel_config.json
├── state/
│   └── sentinel_state.json
├── reports/
│   ├── sample_output/
│   └── ...
└── README.md
```

### Phase-2: Behavioral scoring and weighted risk aggregation

----Planned----













