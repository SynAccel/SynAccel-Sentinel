import os, json, glob, time    # stdlib: filesystem, JSON, file-matching patterns, timestamps
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Figure out repo root *relative to this file*:
# __file__ -> .../src/core/sentinel_core.py
# .parents[2] walks up two directories -> repo root
ROOT = Path(__file__).resolve().parents[2]

# Where to read detector reports, read/write config, and writre core reports
REPORTS_DIR = ROOT / "reports" / "sample_output"
CONFIG_PATH  = ROOT / "configs" / "sentinel_config.json"
STATE_PATH   = ROOT / "state" / "sentinel_state.json"
CORE_REPORTS_DIR = REPORTS_DIR  # reuse same folder for core report for now

# ---- helpers ---------------------------------------------------------------

def _now_iso():
    """Return current time in ISO 8601 with timezone (UTC)."""
    return datetime.now(timezone.utc).isoformat()

def _load_json(p: Path, default):
    """
    Read JSON from path `p`. If the file doesn't exist yet, return `default`.
    Also ensure the parent folder exists (so later saves won't fail).
    """
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.exists():
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    return default

def _save_json(p: Path, data):
    """Write JSON to path `p` (pretty, UTF-8) and ensure folder exists."""
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def _list_recent_reports(patterns, within_hours=24):
    """
    Given filename patterns (glob), return files in reports/ modified within N hours,
    sorted by modification time (oldest -> newest).
    """
    files = []
    cutoff = time.time() - within_hours * 3600
    for pat in patterns:
        for fp in glob.glob(str(REPORTS_DIR / pat)):
            if os.path.getmtime(fp) >= cutoff:
                files.append(fp)
    return sorted(files, key=os.path.getmtime)

# ---- parsers for our current detectors ------------------------------------

def parse_s3_reports(paths):
    """
    Open each report and look for simple substrings that indicate a finding.
    Keeping this simple/robust so it still works if the report wording changes slightly.
    """
    findings = []
    for p in paths:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            txt = f.read()
        if ("Public bucket policy detected" in txt
            or "Public Access Block not fully enabled" in txt):
            findings.append({"type": "S3_PUBLIC", "report": p})
    return findings

def parse_iam_reports(paths):
    """
    Read IAM markdown line-by-line and capture lines that say 'has no MFA enabled'.
    Each match becomes an event of type IAM_NO_MFA.
    """
    findings = []
    for p in paths:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if "has no MFA enabled" in line:
                    findings.append({"type": "IAM_NO_MFA", "report": p})
    return findings

# ---- core logic ------------------------------------------------------------

def rollup_events_into_state(state, new_events):
    """
    Merge new events into state['events'] (with timestamps) and recompute 24h counters.
    Also garbage-collect old events (>48h) to keep state small.
    """

    # De-duplicate: dont count the exact same type, report pair twice
    seen = {(e["type"], e.get("report", "")) for e in state["events"]}
    for e in new_events:
        key = (e["type"], e.get("report", ""))
        if key not in seen:
            e["ts"] = _now_iso()              # stamp with current time
            state["events"].append(e)

    # Keep only the last 48h of events (larger than our 24h counters)
    cutoff_dt = datetime.now(timezone.utc) - timedelta(hours=48)
    def _keep(e):
        try:
            return datetime.fromisoformat(e["ts"]) >= cutoff_dt
        except Exception:
            # If anything is malformed keep it than it crash; next run can clean it.
            return True
    state["events"] = [e for e in state["events"] if _keep(e)]

    # Recompute the rolling 24h counters from events
    counters = {"IAM_NO_MFA_24h": 0, "S3_PUBLIC_24h": 0}
    cutoff_24 = datetime.now(timezone.utc) - timedelta(hours=24)
    for e in state["events"]:
        try:
            ts = datetime.fromisoformat(e["ts"])
        except Exception:
            continue
        if ts >= cutoff_24:
            if e["type"] == "IAM_NO_MFA":
                counters["IAM_NO_MFA_24h"] += 1
            elif e["type"] == "S3_PUBLIC":
                counters["S3_PUBLIC_24h"] += 1

    state["counters"] = counters
    state["last_updated"] = _now_iso()
    return state

def adapt_config(config, state):
    """
    Compare counters vs thresholds and flip policy knobs if thresholds are exceeded.
    Returns the possibly-updated config and a list of human-readable 'changes'.
    """
    changed = []

    s3_th  = int(config["policy"]["s3"]["escalation_threshold_24h"])
    iam_th = int(config["policy"]["iam"]["escalation_threshold_24h"])

    # If too many S3 public issues in 24h, escalate from tag-only to auto-remediate
    if state["counters"]["S3_PUBLIC_24h"] >= s3_th:
        if not config["policy"]["s3"]["auto_remediate_public"]:
            config["policy"]["s3"]["auto_remediate_public"] = True
            config["policy"]["s3"]["auto_tag_only"] = False
            changed.append("S3: escalated to auto_remediate_public=True")

    # If too many IAM no-MFA in 24h... require MFA;
    # and if it gets *really* bad, disable keys automatically.
    if state["counters"]["IAM_NO_MFA_24h"] >= iam_th:
        if not config["policy"]["iam"]["require_mfa"]:
            config["policy"]["iam"]["require_mfa"] = True
            changed.append("IAM: set require_mfa=True")
        if (state["counters"]["IAM_NO_MFA_24h"] >= iam_th + 2
            and not config["policy"]["iam"]["disable_keys_on_nomfa"]):
            config["policy"]["iam"]["disable_keys_on_nomfa"] = True
            changed.append("IAM: set disable_keys_on_nomfa=True")

    # Stamp updated_at every time we evaluate (or you could do it only if its changed)
    config["updated_at"] = _now_iso()
    return config, changed

def save_core_report(state, config, changes):
    """
    Write a human-readable markdown report with counters, changes, and
    a JSON snapshot of current policy, into reports/sample_output/.
    """
    ts = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    path = CORE_REPORTS_DIR / f"sentinel_core_report_{ts}.md"
    CORE_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Sentinel Core (Adaptive Response Loop) Report\n\n")
        f.write(f"Generated: {ts}\n\n")
        f.write("## 24h Counters\n")
        for k, v in state["counters"].items():
            f.write(f"- {k}: {v}\n")
        f.write("\n## Changes Applied\n")
        if not changes:
            f.write("- None (no escalation)\n")
        else:
            for c in changes:
                f.write(f"- {c}\n")
        f.write("\n## Current Policy Snapshot\n")
        f.write("```json\n")
        f.write(json.dumps(config["policy"], indent=2))
        f.write("\n```\n")
    print(f"[✓] Core report saved: {path}")

def main():
    # Load current config/state or sensible defaults if files don't exist yet
    config = _load_json(CONFIG_PATH, {"version": 1, "updated_at": "", "policy": {"iam":{}, "s3":{}}})
    state  = _load_json(STATE_PATH,  {"events": [], "counters": {"IAM_NO_MFA_24h":0, "S3_PUBLIC_24h":0}, "last_updated": ""})

    # Look back 24h for files that *look like* existing detector reports
    s3_paths  = _list_recent_reports(["*s3*report*.md", "*s3*_public*detector*.md"], within_hours=24)
    iam_paths = _list_recent_reports(["iam_*report*.md"], within_hours=24)

    # Parse those files into normalized "events"
    s3_findings  = parse_s3_reports(s3_paths)
    iam_findings = parse_iam_reports(iam_paths)
    new_events = s3_findings + iam_findings

    print(f"[i] Found {len(new_events)} new events from recent reports.")

    # Update rolling memory + counters
    state = rollup_events_into_state(state, new_events)

    # Compare before/after to know if the policy actually changed
    config_before = json.dumps(config["policy"], sort_keys=True)
    config, changes = adapt_config(config, state)
    config_after  = json.dumps(config["policy"], sort_keys=True)

    # Persist state + (possibly) updated config, and write a core report
    _save_json(STATE_PATH, state)
    _save_json(CONFIG_PATH, config)
    save_core_report(state, config, changes)

    # Console feedback for you during runs
    if config_before != config_after:
        print("[+] Policy escalated based on recent events:")
        print(config_after)
    else:
        print("[-] No escalation needed.")

if __name__ == "__main__":
    main()

                
                  
                  
              
         
             
    




