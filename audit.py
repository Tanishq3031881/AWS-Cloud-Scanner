"""
AWS Security Audit Script
-------------------------
This script scans an AWS account for two common misconfigurations:
1. S3 Buckets with "Block Public Access" disabled.
2. IAM Users with Console access but no MFA enabled.

Usage:
    python audit.py
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError


def audit_s3_buckets():
    """
    Scans all S3 buckets to check if 'Block Public Access' is enabled.
    """
    print("\nSTARTING S3 SECURITY AUDIT...")
    # start connection
    s3 = boto3.client("s3")

    try:
        response = s3.list_buckets()
        buckets = response["Buckets"]
        print(f"Found {len(buckets)} buckets to scan.")

        for bucket in buckets:
            name = bucket["Name"]
            try:
                # Check for Block Public Access settings
                pab = s3.get_public_access_block(Bucket=name)
                settings = pab["PublicAccessBlockConfiguration"]

                # there are 4 blocks in AWS, if these 2 are not on, it's risky
                if not settings["BlockPublicAcls"] or not settings["BlockPublicPolicy"]:
                    print(f"ALERT: Bucket '{name}' has weak public access settings!")
                else:
                    print(f"Bucket '{name}' is secure.")

            except ClientError as e:
                # If no configuration exists, it often means the bucket is fully public.
                if (
                    e.response["Error"]["Code"]
                    == "NoSuchPublicAccessBlockConfiguration"
                ):
                    print(
                        f"CRITICAL: Bucket '{name}' has NO Public Access Block configuration!"
                    )
                else:
                    print(f"Could not scan '{name}': {e}")

    except (ClientError, BotoCoreError) as e:
        print(f"Error listing buckets: {e}")


def audit_iam_users():
    """
    Scans all IAM users to check if they have Console Access enabled
    without Multi-Factor Authentication (MFA).
    """
    print("\nSTARTING IAM MFA AUDIT...")
    iam = boto3.client("iam")

    try:
        users = iam.list_users()["Users"]
        print(f"Found {len(users)} users to scan.")

        for user in users:
            username = user["UserName"]

            # Check if they have a login profile
            try:
                iam.get_login_profile(UserName=username)
                has_console = True
            except ClientError:
                # CLI only users are less risky for this check, they are bots
                has_console = False

            if has_console:
                # Check Multi Factor Authentication
                mfa = iam.list_mfa_devices(UserName=username)["MFADevices"]
                if not mfa:
                    print(
                        f"CRITICAL: User '{username}' has Console Access but NO MFA enabled!"
                    )
                else:
                    print(f"User '{username}' has MFA enabled.")
            else:
                print(f"User '{username}' has no console access (Skipping).")

    except (ClientError, BotoCoreError) as e:
        print(f"Error auditing IAM: {e}")


def audit_iam_password_length():
    """
    Scans IAM account password policy to check minimum password length.
    """
    print("\nSTARTING IAM PASSWORD POLICY AUDIT...")
    iam = boto3.client("iam")

    try:
        # Gets the account password policy
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        min_length = policy.get("MinimumPasswordLength", 0)

        # checks according to CIS_Amazon_Web_Services_Foundations_Benchmark
        if min_length < 14:
            print(
                f"ALERT: Minimum password length is {min_length}. Recommended is at least 14."
            )
        else:
            print(f"Password policy is secure with minimum length of {min_length}.")

    # if no password policy is set, it's a risk
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            print("No password policy found. This is a security risk!")
        else:
            print(f"Error retrieving password policy: {e}")


if __name__ == "__main__":
    audit_s3_buckets()
    audit_iam_users()
    audit_iam_password_length()
