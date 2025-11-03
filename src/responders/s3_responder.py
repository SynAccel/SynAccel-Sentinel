import boto3
from botocore.exceptions import ClientError
from datetime import datetime
import os


def save_report(bucket_name, result):
    """
    Saves a markdown report summarizing responder actions.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_dir = os.path.join(os.path.dirname(__file__), "../../reports/sample_output")
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, f"s3_responder_report_{timestamp}.md")

    with open(report_path, "w") as f:
        f.write(f"# SynAccel Responder Report\n\n")
        f.write(f"Generated: {timestamp}\n\n")
        f.write(f"Bucket: {bucket_name}\n\n")
        f.write(f"Result: {result}\n")

    print(f"[✓] Markdown report saved to: {os.path.abspath(report_path)}")


def create_aws_session(profile_name="sentinel-automation"):
    """
    Creates an authenticated AWS session using the specified IAM profile.
    """
    session = boto3.Session(profile_name=profile_name)
    return session


def lock_public_bucket(bucket_name, session):
    """
    Enforces full S3 Public Access Block and tags the bucket.
    """
    s3 = session.client('s3')

    try:
        # Step 1: Block all public access
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        print(f"[+] Public Access Block applied to: {bucket_name}")

        # Step 2: Add a security tag
        s3.put_bucket_tagging(
            Bucket=bucket_name,
            Tagging={
                'TagSet': [
                    {'Key': 'SynAccelFlagged', 'Value': 'PublicAccessRemediated'}
                ]
            }
        )
        print(f"[+] Tagged {bucket_name} as SynAccelFlagged")

        # Save success report
        save_report(bucket_name, f"Public Access Block applied and tagged successfully.")

    except ClientError as e:
        error_message = f"Error remediating bucket {bucket_name}: {e}"
        print(f"[x] {error_message}")
        # Save error report
        save_report(bucket_name, error_message)


if __name__ == "__main__":
    session = create_aws_session()
    # Example test bucket (replace with your target)
    bucket_to_fix = "synaccel-site"
    lock_public_bucket(bucket_to_fix, session)


