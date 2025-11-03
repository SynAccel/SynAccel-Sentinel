import boto3
from botocore.exceptions import ClientError
import json


def check_bucket_policy(s3, bucket_name):
    check_public_access_blocks(s3, bucket_name)
    """
    Step 2: Checks the S3 bucket policy for statements that allow public access.
    """
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
                print(f"[!] Public bucket policy detected: {bucket_name}")
                print(f"    Action: {action}")
                print(f"    Resource: {resource}")

    except s3.exceptions.from_code('NoSuchBucketPolicy'):
        print(f"[-] No bucket policy found for {bucket_name}.")
    except ClientError as e:
        print(f"[x] Error checking policy for {bucket_name}: {e}")
        
def check_public_access_blocks(s3, bucket_name):
    """Checks if the buckets Public Access Block configuration
    is missing or not fully enabled

    Args:
        s3 (_type_): _description_
        bucket_name (_type_): _description_
    """
    try:
        pab = s3.get_public_access_block(Bucket=bucket_name)
        config = pab['PublicAccessBlockConfiguration']
        
        # If any flag is false, alert
        if not all(config.values()):
            print(f"[!] Public Access Block not fully enabled: {bucket_name}")
            print(f"    Config: {config}")
            
    except ClientError as e:
        # Handle cases where config doesn't exist or access denied
        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
            print(f"[!] Missing Public Access Block: {bucket_name}")
        else:
            print(f"[x] Error checking Public Access Block for {bucket_name}: {e}")
        
            


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
                        print(f"[!] Public ACL detected: {bucket_name} | Permission: {permission}")
                    elif grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers':
                        print(f"[!] ACL open to all AWS accounts: {bucket_name} | Permission: {permission}")
            except ClientError as e:
                print(f"[x] Error checking ACL for {bucket_name}: {e}")

            # Step 2: Check bucket policy exposure
            check_bucket_policy(s3, bucket_name)

    except ClientError as e:
        print(f"[x] AWS Error: {e}")


if __name__ == "__main__":
    session = create_aws_session()
    check_s3_public_access(session)
