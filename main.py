import os
import sys
import re
import ctypes
import threading
import psutil
from datetime import datetime
from collections import defaultdict
from tkinter import filedialog
import customtkinter as ctk

# Windows Event Log handling via pywin32
try:
    import win32evtlog
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False


def is_admin():
    """Check if the current process has Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


class LocalSecAuditorApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("LocalSec Auditor - Standalone Security Inspector")
        self.geometry("850x620")
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        # Privilege Mode Check
        self.admin_status = is_admin()

        # Top Title Bar
        self.header_label = ctk.CTkLabel(
            self, 
            text="LocalSec Auditor", 
            font=ctk.CTkFont(size=22, weight="bold")
        )
        self.header_label.pack(pady=(15, 2))

        status_text = "Mode: Administrator" if self.admin_status else "Mode: Standard User (Non-Admin)"
        status_color = "#2fa572" if self.admin_status else "#e59400"
        
        self.sub_header = ctk.CTkLabel(
            self, 
            text=f"Windows Security Inspector | {status_text}", 
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=status_color
        )
        self.sub_header.pack(pady=(0, 15))

        # Action Buttons Frame
        self.btn_frame = ctk.CTkFrame(self)
        self.btn_frame.pack(fill="x", padx=20, pady=5)

        self.scan_ports_btn = ctk.CTkButton(
            self.btn_frame, 
            text="Inspect Listening Ports", 
            command=self.start_port_scan
        )
        self.scan_ports_btn.pack(side="left", padx=5, pady=10)

        self.scan_secrets_btn = ctk.CTkButton(
            self.btn_frame, 
            text="Scan Secrets in Directory", 
            command=self.start_secret_scan
        )
        self.scan_secrets_btn.pack(side="left", padx=5, pady=10)

        self.scan_logs_btn = ctk.CTkButton(
            self.btn_frame, 
            text="Scan Failed Logins (Admin)", 
            command=self.start_log_scan
        )
        self.scan_logs_btn.pack(side="left", padx=5, pady=10)

        self.clear_btn = ctk.CTkButton(
            self.btn_frame, 
            text="Clear", 
            fg_color="gray", 
            width=60,
            command=self.clear_output
        )
        self.clear_btn.pack(side="right", padx=10, pady=10)

        # Output Display Text Area
        self.output_textbox = ctk.CTkTextbox(
            self, 
            width=800, 
            height=420, 
            font=ctk.CTkFont(family="Consolas", size=12)
        )
        self.output_textbox.pack(padx=20, pady=15, fill="both", expand=True)

        self.log_message(f"[INFO] App Started in {'ADMINISTRATOR' if self.admin_status else 'STANDARD USER'} mode.")
        if not self.admin_status:
            self.log_message("[NOTE] Running as Standard User. Network Inspector & Secret Finder modules are fully enabled.\n")

    def log_message(self, text):
        """Thread-safe UI logger."""
        self.after(0, self._append_text, text)

    def _append_text(self, text):
        self.output_textbox.insert("end", text + "\n")
        self.output_textbox.see("end")

    def clear_output(self):
        self.output_textbox.delete("1.0", "end")

    def toggle_buttons(self, state):
        """Enable or disable scan buttons during processing."""
        self.after(0, lambda: self.scan_ports_btn.configure(state=state))
        self.after(0, lambda: self.scan_secrets_btn.configure(state=state))
        self.after(0, lambda: self.scan_logs_btn.configure(state=state))

    # --- THREAD WRAPPERS ---
    def start_secret_scan(self):
        # Open directory selection dialog
        selected_directory = filedialog.askdirectory(
            title="Select Directory to Scan for Secrets",
            initialdir=os.path.expanduser("~")
        )

        if not selected_directory:
            self.log_message("[INFO] Directory selection canceled.")
            return

        self.toggle_buttons("disabled")
        threading.Thread(
            target=self._scan_sensitive_files_worker, 
            args=(selected_directory,), 
            daemon=True
        ).start()

    def start_port_scan(self):
        self.toggle_buttons("disabled")
        threading.Thread(target=self._scan_network_ports_worker, daemon=True).start()

    def start_log_scan(self):
        self.toggle_buttons("disabled")
        threading.Thread(target=self._scan_brute_force_worker, daemon=True).start()

    # --- WORKER FUNCTIONS ---
    def _scan_sensitive_files_worker(self, target_dir):
        self.log_message("=" * 65)
        self.log_message(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] SCANNING DIRECTORY FOR UNPROTECTED SECRETS...")
        self.log_message(f"[+] Target Path: {target_dir}")
        self.log_message("=" * 65)

        # Ignore noisy build, virtualenv, and library subdirectories
        ignore_dirs = {
            "venv", ".venv", "env", "site-packages", "node_modules", 
            "__pycache__", ".git", "vendor", "octave-11.3.0-w64", "Orange3-3.40.0"
        }

        patterns = {
            "Plaintext Password": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]+)",
            "API Key / Token": r"(?i)(api[_\-]?key|secret|token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})",
            "Private Key Header": r"-----BEGIN (RSA|OPENSSH|PRIVATE) KEY-----"
        }

        scan_extensions = {".txt", ".json", ".env", ".ini", ".py", ".xml", ".yml", ".yaml", ".log"}
        max_file_size_bytes = 5 * 1024 * 1024  # 5 MB safety limit
        findings_count = 0

        for root, dirs, files in os.walk(target_dir):
            # Prune skipped directories in-place
            dirs[:] = [d for d in dirs if d.lower() not in ignore_dirs and not d.startswith('.')]

            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in scan_extensions:
                    file_path = os.path.join(root, file)
                    try:
                        if os.path.getsize(file_path) > max_file_size_bytes:
                            continue

                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            for threat_type, pattern in patterns.items():
                                matches = re.findall(pattern, content)
                                if matches:
                                    findings_count += 1
                                    self.log_message(f"  [ALERT - {threat_type.upper()}] File: {file_path}")
                    except Exception:
                        continue

        if findings_count == 0:
            self.log_message("\n[OK] No plaintext passwords or API keys found in the selected folder.")
        else:
            self.log_message(f"\n[WARNING] Found {findings_count} potential plaintext secrets/credentials!")

        self.toggle_buttons("normal")

    def _scan_network_ports_worker(self):
        self.log_message("=" * 65)
        self.log_message(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INSPECTING LISTENING NETWORK PORTS...")
        self.log_message("=" * 65)

        try:
            connections = psutil.net_connections(kind='inet')
            listening_ports = [conn for conn in connections if conn.status == 'LISTEN']

            self.log_message(f"{'PROTO':<6} {'LOCAL ADDRESS':<22} {'PID':<8} {'PROCESS NAME'}")
            self.log_message("-" * 65)

            for conn in listening_ports:
                protocol = "TCP" if conn.type == 1 else "UDP"
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
                pid = conn.pid or "N/A"
                
                try:
                    proc_name = psutil.Process(conn.pid).name() if conn.pid else "Unknown"
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = "System/Protected"

                self.log_message(f"{protocol:<6} {laddr:<22} {str(pid):<8} {proc_name}")

            self.log_message(f"\n[OK] Total listening services identified: {len(listening_ports)}")

        except Exception as e:
            self.log_message(f"[ERROR] Failed to fetch network connections: {e}")

        self.toggle_buttons("normal")

    def _scan_brute_force_worker(self):
        self.log_message("=" * 65)
        self.log_message(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] SCANNING SECURITY LOGS FOR BRUTE-FORCE ATTEMPTS...")
        self.log_message("=" * 65)

        if not self.admin_status:
            self.log_message("[NOTICE] Windows limits raw Security Event Log reading to Administrator accounts.")
            self.log_message("[TIP] Standard User Mode is active. Use 'Scan Secrets in Directory' or 'Inspect Listening Ports'.")
            self.toggle_buttons("normal")
            return

        if not WIN32_AVAILABLE:
            self.log_message("[ERROR] 'pywin32' library is missing.")
            self.toggle_buttons("normal")
            return

        try:
            hand = win32evtlog.OpenEventLog('localhost', 'Security')
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            failed_attempts_count = 0
            user_failure_map = defaultdict(int)

            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            while events:
                for event in events:
                    event_id = event.EventID & 0xFFFF
                    if event_id == 4625:
                        failed_attempts_count += 1
                        user_name = "Unknown User"
                        if event.StringInserts and len(event.StringInserts) > 5:
                            user_name = event.StringInserts[5]
                        user_failure_map[user_name] += 1

                events = win32evtlog.ReadEventLog(hand, flags, 0)

            win32evtlog.CloseEventLog(hand)

            if failed_attempts_count == 0:
                self.log_message("[OK] No failed logon events (Event ID 4625) recorded.")
            else:
                self.log_message(f"[WARNING] Detected {failed_attempts_count} failed login attempt(s).\n")
                for user, count in user_failure_map.items():
                    status = "[ALERT - POSSIBLE BRUTE FORCE]" if count >= 5 else "[NOTICE]"
                    self.log_message(f"  {status} Account: '{user}' | Failures: {count}")

        except Exception as e:
            self.log_message(f"[ERROR] Could not access Security Event Logs: {e}")

        self.toggle_buttons("normal")


if __name__ == "__main__":
    app = LocalSecAuditorApp()
    app.mainloop()