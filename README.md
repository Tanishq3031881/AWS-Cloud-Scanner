# AWS Cloud Security Scanner

A Python-based automated security tool that audits AWS environments for critical misconfigurations. It uses the `boto3` SDK to inspect the cloud infrastructure control plane.

## 🚀 Features
- **S3 Bucket Audit:** Scans for buckets with "Block Public Access" disabled.
- **IAM User Audit:** Identifies console users lacking Multi-Factor Authentication (MFA).
- **Security Group Audit:** Flags firewalls allowing SSH (Port 22) from the open internet (`0.0.0.0/0`).

## 🛠️ Tech Stack
- **Python 3.9+**
- **AWS Boto3 SDK**
- **AWS IAM & S3 APIs**

## 📦 How to Run
1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Configure AWS credentials: `aws configure`
4. Run the scanner: `python audit.py`

## ⚠️ Disclaimer
This tool is for educational and defensive purposes only. Ensure you have authorization before scanning any AWS account.
