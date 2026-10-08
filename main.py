import os
import sys
import psutil
from datetime import datetime
from collections import defaultdict
import customtkinter as ctk

# Windows Event Log handling via pywin32
try:
    import win32evtlog
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False


class LocalSecAuditorApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("LocalSec Auditor - Standalone Security Inspector")
        self.geometry("850x600")
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        # Top Title Bar
        self.header_label = ctk.CTkLabel(
            self, 
            text="LocalSec Auditor", 
            font=ctk.CTkFont(size=22, weight="bold")
        )
        self.header_label.pack(pady=(15, 5))

        self.sub_header = ctk.CTkLabel(
            self, 
            text="Windows System Audit & Brute-Force Log Analyzer", 
            font=ctk.CTkFont(size=12)
        )
        self.sub_header.pack(pady=(0, 15))

        # Action Buttons Frame
        self.btn_frame = ctk.CTkFrame(self)
        self.btn_frame.pack(fill="x", padx=20, pady=5)

        self.scan_logs_btn = ctk.CTkButton(
            self.btn_frame, 
            text="Scan Failed Logins (Event 4625)", 
            command=self.scan_brute_force
        )
        self.scan_logs_btn.pack(side="left", padx=10, pady=10)

        self.scan_ports_btn = ctk.CTkButton(
            self.btn_frame, 
            text="Inspect Listening Ports", 
            command=self.scan_network_ports
        )
        self.scan_ports_btn.pack(side="left", padx=10, pady=10)

        self.clear_btn = ctk.CTkButton(
            self.btn_frame, 
            text="Clear Output", 
            fg_color="gray", 
            command=self.clear_output
        )
        self.clear_btn.pack(side="right", padx=10, pady=10)

        # Output Display Text Area
        self.output_textbox = ctk.CTkTextbox(
            self, 
            width=800, 
            height=430, 
            font=ctk.CTkFont(family="Consolas", size=12)
        )
        self.output_textbox.pack(padx=20, pady=15, fill="both", expand=True)

        self.log_message("[INFO] LocalSec Auditor initialized. Select a scan module above.\n")

    def log_message(self, text):
        self.output_textbox.insert("end", text + "\n")
        self.output_textbox.see("end")

    def clear_output(self):
        self.output_textbox.delete("1.0", "end")

    def scan_brute_force(self):
        self.log_message("=" * 65)
        self.log_message(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] SCANNING WINDOWS SECURITY LOGS FOR BRUTE-FORCE ATTEMPTS...")
        self.log_message("=" * 65)

        if not WIN32_AVAILABLE:
            self.log_message("[ERROR] 'pywin32' library is not available. Please run: pip install pywin32")
            return

        server = 'localhost'
        log_type = 'Security'

        try:
            hand = win32evtlog.OpenEventLog(server, log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            failed_attempts_count = 0
            user_failure_map = defaultdict(int)

            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            while events:
                for event in events:
                    # Event ID 4625 = Account Failed to Log On
                    event_id = event.EventID & 0xFFFF
                    if event_id == 4625:
                        failed_attempts_count += 1
                        time_generated = event.TimeGenerated.Format()
                        
                        # Extract account name if available in event strings
                        user_name = "Unknown User"
                        if event.StringInserts and len(event.StringInserts) > 5:
                            user_name = event.StringInserts[5]
                        
                        user_failure_map[user_name] += 1

                events = win32evtlog.ReadEventLog(hand, flags, 0)

            win32evtlog.CloseEventLog(hand)

            if failed_attempts_count == 0:
                self.log_message("[OK] No failed logon events (Event ID 4625) recorded in recent security logs.")
            else:
                self.log_message(f"[WARNING] Detected {failed_attempts_count} total failed login attempt(s).\n")
                self.log_message("Breakdown by Targeted Account:")
                for user, count in user_failure_map.items():
                    status = "[ALERT - POSSIBLE BRUTE FORCE]" if count >= 5 else "[NOTICE]"
                    self.log_message(f"  {status} Account: '{user}' | Failures: {count}")

        except Exception as e:
            self.log_message(f"[ERROR] Could not read Windows Event Logs. Run CMD as Administrator. Details: {e}")

    def scan_network_ports(self):
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
            self.log_message(f"[ERROR] Failed to fetch active network connections: {e}")


if __name__ == "__main__":
    app = LocalSecAuditorApp()
    app.mainloop()