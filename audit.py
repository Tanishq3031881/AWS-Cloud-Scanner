"""
AWS Security Audit Script
-------------------------
Scans AWS account for common security misconfigurations based on CIS AWS Foundations Benchmark v6.0.0.

Usage:
    python audit.py
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from colorama import Fore, Style, init
import reporter

# Initialize colorama for section headers
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
                    reporter.log_finding(
                        "S3 Public Access",
                        "FAIL",
                        f"Bucket '{name}' has weak public access settings!",
                    )
                else:
                    reporter.log_finding(
                        "S3 Public Access", "OK", f"Bucket '{name}' is secure."
                    )

            except ClientError as e:
                # If no configuration exists, it often means the bucket is fully public.
                if (
                    e.response["Error"]["Code"]
                    == "NoSuchPublicAccessBlockConfiguration"
                ):
                    reporter.log_finding(
                        "S3 Public Access",
                        "CRITICAL",
                        f"Bucket '{name}' has NO Public Access Block configuration!",
                    )
                else:
                    reporter.log_finding(
                        "S3 Public Access",
                        "WARNING",
                        f"Could not scan '{name}': {e}",
                    )

    except (ClientError, BotoCoreError) as e:
        print(f"{Fore.RED}Error listing buckets: {e}")


def audit_iam_users():
    """
    Scans all IAM users for CIS compliance:
    - 2.9: MFA is enabled for all IAM users with Console Access
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
                    reporter.log_finding(
                        "IAM MFA Audit",
                        "CRITICAL",
                        f"User '{username}' has Console Access but NO MFA enabled!",
                    )
                else:
                    reporter.log_finding(
                        "IAM MFA Audit", "OK", f"User '{username}' has MFA enabled."
                    )
            else:
                reporter.log_finding(
                    "IAM MFA Audit", "INFO", f"User '{username}' has no console access."
                )

    except (ClientError, BotoCoreError) as e:
        print(f"{Fore.RED}Error auditing IAM: {e}")


def audit_password_policy():
    """
    Scans the IAM account for CIS compliance:
    - 2.7: Minimum Password Length of at least 14 characters
    - 2.8: Password Reuse Prevention of at least 24 passwords
    """
    print(f"\n{Fore.CYAN}STARTING PASSWORD POLICY AUDIT...")
    iam = boto3.client("iam")

    try:
        # Get the policy from AWS
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        min_length = policy.get("MinimumPasswordLength", 0)

        # CIS Benchmark recommends 14 characters
        if min_length < 14:
            reporter.log_finding(
                "Password Policy",
                "FAIL",
                f"Password length is {min_length}. CIS recommends 14+.",
            )
        else:
            reporter.log_finding(
                "Password Policy",
                "OK",
                f"Password policy is secure (Length: {min_length}).",
            )
        # check for password reuse
        reuse_prevention = policy.get("PasswordReusePrevention", 0)

        if reuse_prevention >= 24:
            reporter.log_finding(
                "Password Reuse",
                "OK",
                f"Prevents reusing last {reuse_prevention} passwords.",
            )
        else:
            reporter.log_finding(
                "Password Reuse",
                "FAIL",
                f"Reuse prevention is {reuse_prevention}. CIS wants 24.",
            )

    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            reporter.log_finding(
                "Password Policy",
                "CRITICAL",
                "No password policy exists! Users can set 1-character passwords.",
            )
        else:
            print(f"{Fore.RED}Error retrieving policy: {e}")


def audit_cloudtrail():
    """
    Scans CloudTrail for CIS Compliance:
    - 4.1: Enabled in all regions
    - 4.2: Log File Validation
    - 4.5: Encryption with KMS
    """
    print(f"\n{Fore.CYAN}STARTING CLOUDTRAIL AUDIT...")
    ct = boto3.client("cloudtrail")

    try:
        response = ct.describe_trails()
        trails = response["trailList"]

        if not trails:
            reporter.log_finding(
                "CloudTrail Logging", "CRITICAL", "No CloudTrail trails found!"
            )
            return

        for trail in trails:
            name = trail["Name"]
            arn = trail["TrailARN"]

            # --- Check 4.1: Logging & Multi-Region ---
            status = ct.get_trail_status(Name=arn)
            if status["IsLogging"]:
                reporter.log_finding(
                    "CloudTrail Logging", "OK", f"Trail '{name}' is logging."
                )
            else:
                reporter.log_finding(
                    "CloudTrail Logging",
                    "FAIL",
                    f"Trail '{name}' is PAUSED (CIS 4.1 Fail).",
                )

            if trail.get("IsMultiRegionTrail"):
                reporter.log_finding(
                    "CloudTrail Multi-Region", "OK", f"Trail '{name}' is Multi-Region."
                )
            else:
                reporter.log_finding(
                    "CloudTrail Multi-Region",
                    "WARNING",
                    f"Trail '{name}' is Single-Region (CIS 4.1 Fail).",
                )

            # --- Check 4.2: Log File Validation (NEW) ---
            if trail.get("LogFileValidationEnabled"):
                reporter.log_finding(
                    "CloudTrail Validation",
                    "OK",
                    f"Trail '{name}' has Log Validation enabled.",
                )
            else:
                reporter.log_finding(
                    "CloudTrail Validation",
                    "FAIL",
                    f"Trail '{name}' has NO Log Validation (CIS 4.2 Fail).",
                )

            # --- Check 4.5: Encryption (KMS) ---
            if trail.get("KmsKeyId"):
                reporter.log_finding(
                    "CloudTrail Encryption",
                    "OK",
                    f"Trail '{name}' is encrypted with KMS.",
                )
            else:
                reporter.log_finding(
                    "CloudTrail Encryption",
                    "FAIL",
                    f"Trail '{name}' is not encrypted with KMS (CIS 4.5 Fail).",
                )

    except (ClientError, BotoCoreError) as e:
        print(f"{Fore.RED}Error auditing CloudTrail: {e}")


def audit_security_hub():
    """
    Checks AWS Security Hub status for CIS Compliance:
    - 5.16: Ensure Security Hub is enabled
    """
    print(f"\n{Fore.CYAN}STARTING SECURITY HUB AUDIT (CIS Level 2)...")
    sh = boto3.client("securityhub")

    try:
        # If Security Hub is enabled, returns details
        sh.describe_hub()
        reporter.log_finding("Security Hub", "OK", "Security Hub is enabled.")

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        # Catch all the different ways AWS says "It's not on"
        if error_code in [
            "InvalidAccessException",
            "ResourceNotFoundException",
            "SubscriptionRequiredException",
        ]:
            reporter.log_finding("Security Hub", "FAIL", "Security Hub is NOT enabled.")
        else:
            print(f"{Fore.RED}Error checking Security Hub: {e}")


if __name__ == "__main__":
    audit_s3_buckets()
    audit_iam_users()
    audit_password_policy()
    audit_cloudtrail()
    audit_security_hub()
    reporter.generate_report()
