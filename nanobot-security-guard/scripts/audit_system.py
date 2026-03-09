#!/usr/bin/env python3
import os
import subprocess
import re
from pathlib import Path

# Common malicious signatures in processes or cron jobs
MALICIOUS_SIGS = [
    r"bash\s+-i",
    r"nc\s+-e",
    r"ncat\s+-e",
    r"curl\s+.*\|\s*(bash|sh|zsh)",
    r"wget\s+.*\|\s*(bash|sh|zsh)",
    r"/dev/tcp/",
    r"ngrok\s+tcp",
]

NANOBOT_LOG_DIR = Path.home() / ".nanobot" / "logs"
SENSITIVE_FILES = ["config.json", ".env", "whatsapp-auth", "id_rsa"]

def check_running_processes():
    print("[*] 1. Checking for malicious running processes...")
    try:
        # Use ps aux to get all processes
        result = subprocess.run(["ps", "aux"], capture_output=True, text=True, check=True)
        processes = result.stdout.splitlines()
        
        found_malicious = False
        for line in processes:
            for sig in MALICIOUS_SIGS:
                if re.search(sig, line, re.IGNORECASE):
                    # Exclude the grep or Python script itself if matched
                    if "audit_system.py" not in line:
                        print(f"  [CRITICAL] Suspicious process found matching '{sig}':")
                        print(f"      {line.strip()}")
                        found_malicious = True
        if not found_malicious:
            print("  [OK] No suspicious processes detected.")
    except Exception as e:
        print(f"  [WARNING] Failed to check processes: {e}")

def check_cron_jobs():
    print("[*] 2. Checking user crontab for persistence...")
    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        if result.returncode != 0:
            print("  [OK] No crontab found for current user.")
            return

        crons = result.stdout.splitlines()
        found_malicious = False
        for line in crons:
            if line.strip().startswith("#") or not line.strip():
                continue
            for sig in MALICIOUS_SIGS:
                if re.search(sig, line, re.IGNORECASE):
                    print(f"  [CRITICAL] Suspicious cron job found matching '{sig}':")
                    print(f"      {line.strip()}")
                    found_malicious = True
        
        if not found_malicious:
            print("  [OK] No suspicious cron jobs detected.")
    except Exception as e:
        print(f"  [WARNING] Failed to check crontab: {e}")

def check_sensitive_file_reads():
    print("[*] 3. Validating sensitive file access in nanobot logs...")
    log_file = NANOBOT_LOG_DIR / "nanobot.log"
    
    if not log_file.exists():
        print(f"  [INFO] Nanobot log file not found at {log_file}. Skipping.")
        return

    try:
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        
        # Read the last 5000 lines to avoid analyzing excessively large files
        recent_lines = lines[-5000:]
        
        # Regex to simulate detecting tool usage for file reading (e.g., read_file action)
        read_tool_pattern = re.compile(r"(read_file|cat|view_file|open).*?([/\w\.-]+)", re.IGNORECASE)
        
        found_sensitive_access = False
        for line in recent_lines:
            match = read_tool_pattern.search(line)
            if match:
                target_file = match.group(2)
                for sensitive in SENSITIVE_FILES:
                    if sensitive in target_file:
                        print(f"  [CRITICAL] Sensitive file read detected in logs! Tool invoked on: {target_file}")
                        print(f"      Log entry: {line.strip()}")
                        found_sensitive_access = True
                        break # break inner loop only
                        
        if not found_sensitive_access:
            print("  [OK] No suspicious reads of sensitive files detected in recent logs.")
    except Exception as e:
        print(f"  [WARNING] Failed to parse logs: {e}")

def run_audit():
    print("="*60)
    print(" NANOBOT SECURITY AUDIT SCRIPT")
    print("="*60)
    check_running_processes()
    print("-" * 60)
    check_cron_jobs()
    print("-" * 60)
    check_sensitive_file_reads()
    print("="*60)
    print("Audit Complete.")

if __name__ == "__main__":
    run_audit()
