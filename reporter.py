import csv
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Global list to store all findings
audit_results = []


def log_finding(check_name, status, message):
    """
    1. Prints the result to the screen with color.
    2. Appends the result to the global audit_results list.
    """
    # 1. Print to Screen
    if status == "OK":
        print(f"{Fore.GREEN}[OK] {check_name}: {message}")
    elif status == "WARNING":
        print(f"{Fore.YELLOW}[WARN] {check_name}: {message}")
    elif status == "FAIL" or status == "CRITICAL":
        print(f"{Fore.RED}[FAIL] {check_name}: {message}")
    else:
        print(f"{Fore.CYAN}[INFO] {check_name}: {message}")

    # 2. Save to List (for CSV)
    audit_results.append(
        {
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Check": check_name,
            "Status": status,
            "Message": message,
        }
    )


def generate_report():
    """
    Saves the audit_results list to a CSV file.
    """
    filename = f"aws_audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    print(f"\n{Fore.CYAN}📄 Generating Report: {filename}...")

    keys = ["Timestamp", "Check", "Status", "Message"]

    try:
        with open(filename, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(audit_results)
        print(f"{Fore.GREEN}Report saved successfully!")
    except IOError as e:
        print(f"{Fore.RED}Error saving report: {e}")
