import boto3
from botocore.exceptions import ClientError


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

    except ClientError as e:
        print(f"[x] Error remediating bucket {bucket_name}: {e}")


if __name__ == "__main__":
    session = create_aws_session()
    # Example test bucket (replace with your target)
    bucket_to_fix = "synaccel-site"
    lock_public_bucket(bucket_to_fix, session)

