import os
import re
import sys
import platform
from datetime import datetime
from collections import defaultdict
import psutil
import streamlit as st

# Windows Event Log handling via pywin32
try:
    import win32evtlog
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False


def is_admin():
    """Check if the current process has Administrator privileges."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# Streamlit Page Setup
st.set_page_config(
    page_title="LocalSec Auditor", 
    page_icon="🛡️", 
    layout="wide"
)

# App Header
st.title("🛡️ LocalSec Auditor - Security Inspector")

admin_status = is_admin()
mode_color = "green" if admin_status else "orange"
mode_label = "Administrator Mode" if admin_status else "Standard User Mode"

st.markdown(f"**Mode:** :{mode_color}[{mode_label}] | **OS:** {platform.system()} {platform.release()}")
st.divider()

# Navigation Tabs
tab_secrets, tab_ports, tab_logs = st.tabs([
    "🔍 Scan Secrets & Keys", 
    "🌐 Inspect Listening Ports", 
    "📋 Failed Logins (Admin)"
])

# Threat Regex Patterns
PATTERNS = {
    "Plaintext Password": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]+)",
    "API Key / Token": r"(?i)(api[_\-]?key|secret|token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})",
    "Private Key Header": r"-----BEGIN (RSA|OPENSSH|PRIVATE) KEY-----"
}

SCAN_EXTENSIONS = {".txt", ".json", ".env", ".ini", ".py", ".xml", ".yml", ".yaml", ".log"}
IGNORE_DIRS = {
    "venv", ".venv", "env", "site-packages", "node_modules", 
    "__pycache__", ".git", "vendor", "octave-11.3.0-w64", "Orange3-3.40.0"
}


# ==============================================================================
# TAB 1: SCAN SECRETS & KEYS
# ==============================================================================
with tab_secrets:
    st.header("🔍 Unprotected Secret Finder")
    st.write("Scan a specific file or an entire directory for exposed credentials and API keys.")

    scan_mode = st.radio(
        "Select Scan Input Method:",
        options=["Upload Particular File(s)", "Scan Local Path (File or Directory)"],
        horizontal=True
    )

    findings = []

    # --- OPTION A: UPLOAD SPECIFIC FILE(S) ---
    if scan_mode == "Upload Particular File(s)":
        uploaded_files = st.file_uploader(
            "Choose a particular file (or multiple files) to scan:",
            accept_multiple_files=True,
            type=["txt", "json", "env", "ini", "py", "xml", "yml", "yaml", "log"]
        )

        if st.button("Start File Scan", type="primary"):
            if not uploaded_files:
                st.warning("Please select at least one file to scan.")
            else:
                for file in uploaded_files:
                    try:
                        content = file.read().decode("utf-8", errors="ignore")
                        for threat_type, pattern in PATTERNS.items():
                            matches = re.findall(pattern, content)
                            if matches:
                                findings.append({
                                    "File": file.name,
                                    "Threat Type": threat_type,
                                    "Status": "ALERT"
                                })
                    except Exception as e:
                        st.error(f"Error reading file {file.name}: {e}")

                if findings:
                    st.error(f"⚠️ Found {len(findings)} potential plaintext secret(s)!")
                    st.dataframe(findings, use_container_width=True)
                else:
                    st.success("✅ No plaintext passwords or API keys found in the selected file(s).")

    # --- OPTION B: SCAN LOCAL PATH (SINGLE FILE OR DIRECTORY) ---
    else:
        target_path = st.text_input(
            "Enter full path to a file OR directory on host machine:",
            value=os.path.expanduser("~")
        )

        if st.button("Start Path Scan", type="primary"):
            if not os.path.exists(target_path):
                st.error(f"The path `{target_path}` does not exist.")
            else:
                # 1. Single File Target
                if os.path.isfile(target_path):
                    st.info(f"Scanning single file: `{target_path}`")
                    try:
                        with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            for threat_type, pattern in PATTERNS.items():
                                if re.search(pattern, content):
                                    findings.append({
                                        "File Path": target_path,
                                        "Threat Type": threat_type,
                                        "Status": "ALERT"
                                    })
                    except Exception as e:
                        st.error(f"Could not read file: {e}")

                # 2. Directory Target
                elif os.path.isdir(target_path):
                    st.info(f"Scanning directory tree: `{target_path}`")
                    progress_bar = st.progress(0)
                    
                    for root, dirs, files in os.walk(target_path):
                        # Skip virtual environments and noisy folders
                        dirs[:] = [d for d in dirs if d.lower() not in IGNORE_DIRS and not d.startswith('.')]

                        for file in files:
                            ext = os.path.splitext(file)[1].lower()
                            if ext in SCAN_EXTENSIONS:
                                file_path = os.path.join(root, file)
                                try:
                                    if os.path.getsize(file_path) > 5 * 1024 * 1024:
                                        continue  # Skip files > 5MB

                                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                                        content = f.read()
                                        for threat_type, pattern in PATTERNS.items():
                                            if re.search(pattern, content):
                                                findings.append({
                                                    "File Path": file_path,
                                                    "Threat Type": threat_type,
                                                    "Status": "ALERT"
                                                })
                                except Exception:
                                    continue
                    progress_bar.progress(100)

                if findings:
                    st.error(f"⚠️ Found {len(findings)} potential plaintext secret(s)!")
                    st.dataframe(findings, use_container_width=True)
                else:
                    st.success("✅ No secrets or API keys found in the specified path.")


# ==============================================================================
# TAB 2: INSPECT LISTENING PORTS
# ==============================================================================
with tab_ports:
    st.header("🌐 Active Network Listener Inspection")
    st.write("Lists local services currently listening for incoming connections.")

    if st.button("Inspect Listening Ports", type="primary"):
        try:
            connections = psutil.net_connections(kind='inet')
            listening_ports = [conn for conn in connections if conn.status == 'LISTEN']

            port_data = []
            for conn in listening_ports:
                protocol = "TCP" if conn.type == 1 else "UDP"
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
                pid = conn.pid or "N/A"

                try:
                    proc_name = psutil.Process(conn.pid).name() if conn.pid else "Unknown"
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = "System/Protected"

                port_data.append({
                    "Protocol": protocol,
                    "Local Address": laddr,
                    "PID": pid,
                    "Process Name": proc_name
                })

            if port_data:
                st.success(f"Total listening ports found: {len(port_data)}")
                st.dataframe(port_data, use_container_width=True)
            else:
                st.info("No active listening ports detected.")

        except Exception as e:
            st.error(f"Failed to fetch network connections: {e}")


# ==============================================================================
# TAB 3: FAILED LOGINS (WINDOWS LOGS)
# ==============================================================================
with tab_logs:
    st.header("📋 Failed Login Attempt Auditor")
    st.write("Parses Windows Security Event Logs for Event ID 4625 (Failed Logon).")

    if not admin_status:
        st.warning("🔒 Administrator privileges are required to access Windows Security Event Logs.")
    elif not WIN32_AVAILABLE:
        st.error("The `pywin32` package is not installed on this system.")
    else:
        if st.button("Scan Windows Event Logs", type="primary"):
            try:
                hand = win32evtlog.OpenEventLog('localhost', 'Security')
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

                failed_count = 0
                user_failures = defaultdict(int)

                events = win32evtlog.ReadEventLog(hand, flags, 0)
                while events:
                    for event in events:
                        if (event.EventID & 0xFFFF) == 4625:
                            failed_count += 1
                            uname = "Unknown"
                            if event.StringInserts and len(event.StringInserts) > 5:
                                uname = event.StringInserts[5]
                            user_failures[uname] += 1

                    events = win32evtlog.ReadEventLog(hand, flags, 0)

                win32evtlog.CloseEventLog(hand)

                if failed_count == 0:
                    st.success("✅ No failed logon events (Event ID 4625) recorded.")
                else:
                    st.error(f"⚠️ Total Failed Login Attempts Recorded: {failed_count}")
                    
                    log_summary = [
                        {
                            "Account Name": uname,
                            "Failure Count": count,
                            "Risk Flag": "HIGH (Brute Force Indicator)" if count >= 5 else "NORMAL"
                        }
                        for uname, count in user_failures.items()
                    ]
                    st.dataframe(log_summary, use_container_width=True)

            except Exception as e:
                st.error(f"Error accessing security logs: {e}")