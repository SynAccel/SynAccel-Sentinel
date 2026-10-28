import boto3
from botocore.exceptions import ClientError
import json
from datetime import datetime, timezone
from pathlib import Path


def save_report(findings):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H-%M-%S")
    report_dir = Path(__file__).resolve().parents[2] / "reports" / "sample_output"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / f"s3_detector_report_{timestamp}.md"

    with open(report_path, "w", encoding="utf-8") as report:
        report.write("# SynAccel S3 Public Access Report\n\n")
        report.write(f"Generated: {timestamp} UTC\n\n")
        if findings:
            for finding in findings:
                report.write(f"- {finding}\n")
        else:
            report.write("No public access findings detected.\n")

    print(f"[+] Markdown report saved to: {report_path}")


def check_bucket_policy(s3, bucket_name):
    """
    Step 2: Checks the S3 bucket policy for statements that allow public access.
    """
    findings = []
    try:
        response = s3.get_bucket_policy(Bucket=bucket_name)
        policy_str = response['Policy']
        policy = json.loads(policy_str)

        for statement in policy.get('Statement', []):
            effect = statement.get('Effect')
            principal = statement.get('Principal')
            action = statement.get('Action')
            resource = statement.get('Resource')

            # Detect if the bucket policy allows public access
            if effect == "Allow" and (principal == "*" or principal == {"AWS": "*"}):
                finding = f"[!] Public bucket policy detected on bucket: {bucket_name}"
                findings.append(finding)
                print(finding)
                print(f"    Action: {action}")
                print(f"    Resource: {resource}")

    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "NoSuchBucketPolicy":
            print(f"[x] Error checking policy for {bucket_name}: {e}")
    return findings
        
def check_public_access_blocks(s3, bucket_name):
    """Checks if the buckets Public Access Block configuration
    is missing or not fully enabled

    Args:
        s3 (_type_): _description_
        bucket_name (_type_): _description_
    """
    findings = []
    try:
        pab = s3.get_public_access_block(Bucket=bucket_name)
        config = pab['PublicAccessBlockConfiguration']
        
        # If any flag is false, alert
        expected_flags = (
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        )
        if not all(config.get(flag, False) for flag in expected_flags):
            finding = f"[!] Public Access Block not fully enabled for bucket: {bucket_name}"
            findings.append(finding)
            print(finding)
            print(f"    Config: {config}")
            
    except ClientError as e:
        # Handle cases where config doesn't exist or access denied
        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
            finding = f"[!] Public Access Block not fully enabled for bucket: {bucket_name} (missing configuration)"
            findings.append(finding)
            print(finding)
        else:
            print(f"[x] Error checking Public Access Block for {bucket_name}: {e}")
    return findings


def create_aws_session(profile_name="sentinel-automation"):
    """
    Creates an authenticated AWS session using the specified IAM profile.
    This lets the detector use your sentinel-automation credentials securely.
    """
    session = boto3.Session(profile_name=profile_name)
    return session


def check_s3_public_access(session):
    """
    Checks all S3 buckets in the AWS account for public exposure
    via ACLs, policies, or missing public access blocks.
    """
    s3 = session.client('s3')
    findings = []

    try:
        response = s3.list_buckets()
        print("=== SynAccel Detector: S3 Public Access ===")

        # Loop through all buckets
        for bucket in response['Buckets']:
            bucket_name = bucket['Name']
            print(f"\n[+] Checking bucket: {bucket_name}")

            # Step 1: Check bucket ACL for public grants
            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)
                for grant in acl['Grants']:
                    grantee = grant.get('Grantee', {})
                    permission = grant.get('Permission', 'Unknown')

                    # Check if ACL allows public or any AWS-authenticated user
                    if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                        finding = f"[!] Public ACL detected on bucket: {bucket_name} | Permission: {permission}"
                        findings.append(finding)
                        print(finding)
                    elif grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers':
                        finding = f"[!] ACL open to all AWS accounts on bucket: {bucket_name} | Permission: {permission}"
                        findings.append(finding)
                        print(finding)
            except ClientError as e:
                print(f"[x] Error checking ACL for {bucket_name}: {e}")

            # Step 2: Check bucket policy exposure
            findings.extend(check_bucket_policy(s3, bucket_name))
            findings.extend(check_public_access_blocks(s3, bucket_name))

        save_report(findings)

    except ClientError as e:
        print(f"[x] AWS Error: {e}")


if __name__ == "__main__":
    session = create_aws_session()
    check_s3_public_access(session)
