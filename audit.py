"""
AWS Security Audit Script
-------------------------
Scans for S3 buckets with weak public access settings, IAM users without MFA,
and password policy compliance.

Usage:
    python audit.py
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


def audit_s3_buckets():
    """
    Scans all S3 buckets to check if 'Block Public Access' is enabled.
    """
    print(f"\n{Fore.CYAN}STARTING S3 SECURITY AUDIT...")
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

                # If these 2 are not on, it's risky
                if not settings["BlockPublicAcls"] or not settings["BlockPublicPolicy"]:
                    print(
                        f"{Fore.RED}ALERT: Bucket '{name}' has weak public access settings!"
                    )
                else:
                    print(f"{Fore.GREEN}OK: Bucket '{name}' is secure.")

            except ClientError as e:
                # If no configuration exists, it often means the bucket is fully public.
                if (
                    e.response["Error"]["Code"]
                    == "NoSuchPublicAccessBlockConfiguration"
                ):
                    print(
                        f"{Fore.RED}CRITICAL: Bucket '{name}' has NO Public Access Block configuration!"
                    )
                else:
                    print(f"{Fore.YELLOW}WARNING: Could not scan '{name}': {e}")

    except (ClientError, BotoCoreError) as e:
        print(f"{Fore.RED}Error listing buckets: {e}")


def audit_iam_users():
    """
    Scans all IAM users to check if they have Console Access enabled
    without Multi-Factor Authentication (MFA).
    """
    print(f"\n{Fore.CYAN}STARTING IAM MFA AUDIT...")
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
                # CLI only users are less risky for this check
                has_console = False

            if has_console:
                # Check Multi Factor Authentication
                mfa = iam.list_mfa_devices(UserName=username)["MFADevices"]
                if not mfa:
                    print(
                        f"{Fore.RED}CRITICAL: User '{username}' has Console Access but NO MFA enabled!"
                    )
                else:
                    print(f"{Fore.GREEN}OK: User '{username}' has MFA enabled.")
            else:
                print(f"{Fore.YELLOW}SKIP: User '{username}' has no console access.")

    except (ClientError, BotoCoreError) as e:
        print(f"{Fore.RED}Error auditing IAM: {e}")


def audit_password_policy():
    """
    Scans the IAM account password policy for CIS compliance (Min length 14).
    """
    print(f"\n{Fore.CYAN}STARTING PASSWORD POLICY AUDIT...")
    iam = boto3.client("iam")

    try:
        # Get the policy from AWS
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        min_length = policy.get("MinimumPasswordLength", 0)

        # CIS Benchmark recommends 14 characters
        if min_length < 14:
            print(
                f"{Fore.RED}ALERT: Password length is {min_length}. CIS recommends 14+."
            )
        else:
            print(f"{Fore.GREEN}OK: Password policy is secure (Length: {min_length}).")

    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            print(
                f"{Fore.RED}CRITICAL: No password policy exists! Users can set 1-character passwords."
            )
        else:
            print(f"{Fore.RED}Error retrieving policy: {e}")


if __name__ == "__main__":
    audit_s3_buckets()
    audit_iam_users()
    audit_password_policy()
