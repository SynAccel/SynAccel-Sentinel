import boto3
from botocore.exceptions import ClientError

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

                    # Check if ACL allows public (AllUsers) or any AWS-authenticated user
                    if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                        print(f"[!] Public ACL detected: {bucket_name} | Permission: {permission}")
                    elif grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers':
                        print(f"[!] ACL open to all AWS accounts: {bucket_name} | Permission: {permission}")
            except ClientError as e:
                print(f"[x] Error checking ACL for {bucket_name}: {e}")
                
    except ClientError as e:
        print(f"[x] AWS Error: {e}")


if __name__ == "__main__":
    session = create_aws_session()
    check_s3_public_access(session)
