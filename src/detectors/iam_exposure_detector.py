import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone
import os

def save_report(findings):
    """Saves IAM exposure findings to a MD report

    Args:
        findings (_type_): _description_
    """
    timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    report_dir = os.path.join(os.path.dirname(__file__), "../../report/sample_output")
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, f"iam_detector_report_{timestamp}.md")
    
    with open(report_path, "w") as f:
        f.write(" # SynAccel IAM Exposure Report\n\n")
        f.write(f"Generated: {timestamp}\n\n")
        if not findings:
            f.write("✓ No risky IAM users detected.\n")
        else:
            for findings in findings:
                f.write(f"- {findings}\n")
    
    print(f"[✓] Markdown report saved to: {os.path.abspath(report_path)}")
    
def create_aws_session(profile_name="sentinel-automation"):
    """Create authenticated AWS session"""
    return boto3.Session(profile_name=profile_name)

def check_iam_exposures(session):
    """Detects IAM users with:
    -No MFA enabled
    -Old access keys >90 days
    """
    
    iam = session.client("iam")
    findings = []

    try:
        users = iam.list_users()["Users"]    
        print("=== SynAccel Detector: IAM Exposure ===")
        
        for users in users:
            username = users["UserName"]
            print(f"\n[+] Checking user: {username}")
            
            # Step 1: Check MFA devices
            mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
            if not mfa_devices:
                msg = f"[!] {username} has no MFA enabled."
                print(msg)
                findings.append(msg)   
                
            # Step 2: Check access key age
            keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
            for key in keys:
                key_id = key["AccessKeyId"]
                create_date = key["CreateDate"]
                age_days = (datetime.now(timezone.utc) - create_date).days
                if age_days > 90:
                    msg = f"[!] {username} has an old access key ({age_days} days)."
                    print(msg)
                    findings.append(msg)
    except ClientError as e:
        print(f"[x] AWS Error: {e}")
        
    return findings

if __name__ == "__main__":
    session = create_aws_session()
    findings = check_iam_exposures(session)
    save_report(findings)