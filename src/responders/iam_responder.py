import boto3
from botocore.exceptions import ClientError
from datetime import datetime
import os

def save_report(user_name, result):
    """Saves responder output to a markdown report."""
    timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    report_dir = os.path.join(os.path.dirname(__file__), "../../reports/sample_output")
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, f"iam_responder_report_{timestamp}.md")

    with open(report_path, "w") as f:
        f.write("# SynAccel IAM Responder Report\n\n")
        f.write(f"Generated: {timestamp}\n\n")
        f.write(f"User: {user_name}\n\n")
        f.write(f"Result: {result}\n")

    print(f"[✓] Markdown report saved to: {os.path.abspath(report_path)}")


def create_aws_session(profile_name="sentinel-automation"):
    """Creates an authenticated AWS session."""
    session = boto3.Session(profile_name=profile_name)
    return session


def tag_user_no_mfa(user_name, session):
    """Applies a tag to an IAM user missing MFA."""
    iam = session.client("iam")
    try:
        iam.tag_user(
            UserName=user_name,
            Tags=[{"Key": "SynAccelFlagged", "Value": "NoMFA"}]
        )
        print(f"[+] Tagged user {user_name} as SynAccelFlagged:NoMFA")
        return "User tagged successfully (No MFA)"
    except ClientError as e:
        print(f"[x] Error tagging user {user_name}: {e}")
        return f"Error tagging user: {e}"


def check_and_remediate_users(session):
    """Scans users and remediates those missing MFA."""
    iam = session.client("iam")
    response = iam.list_users()

    for user in response["Users"]:
        user_name = user["UserName"]
        mfa_devices = iam.list_mfa_devices(UserName=user_name)["MFADevices"]

        if not mfa_devices:
            print(f"[!] {user_name} has no MFA — tagging user.")
            result = tag_user_no_mfa(user_name, session)
            save_report(user_name, result)
        else:
            print(f"[✓] {user_name} already has MFA.")


if __name__ == "__main__":
    session = create_aws_session()
    check_and_remediate_users(session)
