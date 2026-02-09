# AWS Cloud Security Scanner

A Python-based automated security tool that audits AWS environments for critical misconfigurations and checks it against CIS AWS Foundations Benchmark v6.0.0. Generates an automatic .csv file that reports all the checks.

## Features
### 1. Identity & Access Management (IAM)
- **MFA Audit (CIS 2.9):** Identifies console users who have not enabled Multi-Factor Authentication.
- **Password Policy (CIS 2.7 & 2.8):**
  - Verifies minimum password length is **14+ characters**.
  - Checks if **Password Reuse Prevention** is set to 24 (preventing recycling of old passwords).

### 2. Storage Security (S3)
- **Public Access Audit:** Scans all S3 buckets to ensure **"Block Public Access"** settings are strictly enabled to prevent data leaks.

### 3. Logging & Monitoring (CloudTrail)
- **Global Logging (CIS 4.1):** Ensures CloudTrail is enabled and recording events in **all regions**.
- **Log Validation (CIS 4.2):** Verifies that log file validation is enabled to prevent tampering.
- **Encryption (CIS 4.5):** Checks if logs are encrypted at rest using **KMS Customer Managed Keys (CMKs)**.

### 4. Governance
- **Security Hub (CIS 5.16):** Checks if AWS Security Hub is enabled for centralized security monitoring.

### 5. Reporting
- **Automated CSV Reports:** Generates a timestamped `.csv` file (e.g., `aws_audit_report_20260210.csv`) containing all pass/fail findings for audit documentation.
- **Console Feedback:** Provides real-time, color-coded feedback in the terminal (Green=OK, Red=FAIL).

## 🛠️ Tech Stack
- **Python 3.9+**
- **AWS Boto3 SDK** (Infrastructure as Code auditing)
- **Colorama** (Terminal UI formatting)
- **CSV Module** (Report generation)

## How to Run
1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Configure AWS credentials: `aws configure`
4. Run the scanner: `python audit.py`

## ⚠️ Disclaimer
This tool is for educational and defensive purposes only. Ensure you have authorization before scanning any AWS account.
