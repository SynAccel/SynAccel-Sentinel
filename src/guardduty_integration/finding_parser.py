def parse_findings(findings):
    """
    Convert raw GuardDuty finding objects into a simplified alert structure.

    Input: list of findings from GuardDutyConnector.run()
    Output: list of dicts with key fields Sentinel can act on.
    """
    alerts = []

    for f in findings:
        alerts.append({
            "id": f.get("Id"),
            "type": f.get("Type"),
            "severity": f.get("Severity"),
            "resource": f.get("Resource"),
            "created_at": f.get("CreatedAt"),
            "title": f.get("Title"),
            "description": f.get("Description")
        })

    return alerts
