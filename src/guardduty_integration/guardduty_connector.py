import boto3


class GuardDutyConnector:
    """
    GuardDutyConnector
    ------------------
    - Connects to AWS GuardDuty
    - Fetches recent findings
    - Returns raw finding objects for further parsing
    """

    def __init__(self, region_name="us-east-1"):
        self.client = boto3.client("guardduty", region_name=region_name)
        self.detector_id = self._get_detector_id()

    def _get_detector_id(self):
        """
        Get the first available GuardDuty detector ID.
        """
        response = self.client.list_detectors()
        detector_ids = response.get("DetectorIds", [])

        if not detector_ids:
            raise RuntimeError("No GuardDuty detectors found in this account/region.")

        return detector_ids[0]

    def get_findings(self, max_results=50):
        """
        List and retrieve GuardDuty findings.
        """
        finding_ids_response = self.client.list_findings(
            DetectorId=self.detector_id,
            MaxResults=max_results
        )

        finding_ids = finding_ids_response.get("FindingIds", [])
        if not finding_ids:
            return []

        findings_response = self.client.get_findings(
            DetectorId=self.detector_id,
            FindingIds=finding_ids
        )

        return findings_response.get("Findings", [])

    def run(self, max_results=50):
        """
        Public entry point – fetch recent findings.
        """
        return self.get_findings(max_results=max_results)
