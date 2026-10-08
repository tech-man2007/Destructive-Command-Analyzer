import os
import re
import time
import platform
from datetime import datetime, timedelta
from collections import defaultdict
import streamlit as st

# Optional Windows Event Log support
try:
    import win32evtlog
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False


def is_admin():
    """Check for Administrator privileges on Windows."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


st.set_page_config(page_title="LocalSec - Brute-Force Detector", page_icon="🚨", layout="wide")

st.title("🚨 Real-Time Brute-Force Detection Engine")
st.caption("Analyzes authentication logs to identify automated login spams, credential stuffing, and dictionary attacks.")

# System Status Bar
col_a, col_b, col_c = st.columns(3)
col_a.metric("OS Environment", platform.system())
col_b.metric("Admin Privileges", "Yes" if is_admin() else "No (Standard User)")
col_c.metric("Windows Event Log Driver", "Available" if WIN32_AVAILABLE else "Unavailable")

st.divider()

# Sidebar Control Panel for Detection Thresholds
st.sidebar.header("⚙️ Detection Thresholds")
threshold_attempts = st.sidebar.slider("Failed Attempts Limit", min_value=3, max_value=50, value=5, step=1)
time_window_minutes = st.sidebar.slider("Time Window (Minutes)", min_value=1, max_value=60, value=5, step=1)

st.sidebar.info(
    f"**Rule Trigger:** Flag as **ACTIVE BRUTE FORCE** if an account or IP receives **≥ {threshold_attempts} failed attempts** within **{time_window_minutes} minute(s)**."
)

# Tabs
tab_live_win, tab_log_file, tab_simulator = st.tabs([
    "🪟 Windows Security Event Logs",
    "📄 Custom Auth Log Scanner (Linux SSH / Web / CSV)",
    "🧪 Attack Simulator (Test the Detector)"
])

# ==============================================================================
# TAB 1: WINDOWS EVENT LOG BRUTE-FORCE DETECTOR
# ==============================================================================
with tab_live_win:
    st.header("Windows Event ID 4625 (Failed Logon) Analyzer")

    if not is_admin():
        st.warning("⚠️ Reading raw Windows Security logs requires Administrator privileges. Run your terminal as Admin or use the Log Scanner / Simulator tabs.")
    elif not WIN32_AVAILABLE:
        st.error("`pywin32` is missing. Install it using `pip install pywin32`.")
    else:
        if st.button("Run Windows Event Log Analysis", type="primary"):
            try:
                hand = win32evtlog.OpenEventLog('localhost', 'Security')
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

                user_attempts = defaultdict(list)
                total_failed_events = 0

                events = win32evtlog.ReadEventLog(hand, flags, 0)
                now = datetime.now()
                cutoff_time = now - timedelta(minutes=time_window_minutes)

                while events:
                    for event in events:
                        event_id = event.EventID & 0xFFFF
                        if event_id == 4625:  # Failed Logon
                            evt_time = event.TimeGenerated
                            if evt_time < cutoff_time:
                                continue

                            total_failed_events += 1
                            user_name = "Unknown"
                            if event.StringInserts and len(event.StringInserts) > 5:
                                user_name = event.StringInserts[5]
                            
                            user_attempts[user_name].append(evt_time)

                    events = win32evtlog.ReadEventLog(hand, flags, 0)

                win32evtlog.CloseEventLog(hand)

                # Detection Logic
                threats_found = []
                for user, timestamps in user_attempts.items():
                    count = len(timestamps)
                    is_attack = count >= threshold_attempts
                    threats_found.append({
                        "Targeted Account": user,
                        "Failures in Window": count,
                        "Time Window": f"Last {time_window_minutes} mins",
                        "Threat Status": "🚨 HIGH (BRUTE-FORCE ATTACK)" if is_attack else "⚠️ LOW (Likely Typo)"
                    })

                st.subheader("Detection Results")
                st.metric("Total Failed Logons Scanned", total_failed_events)
                
                if threats_found:
                    st.dataframe(threats_found, use_container_width=True)
                else:
                    st.success("No suspicious authentication velocity detected.")

            except Exception as e:
                st.error(f"Error accessing security logs: {e}")

# ==============================================================================
# TAB 2: CUSTOM LOG FILE BRUTE-FORCE SCANNER
# ==============================================================================
with tab_log_file:
    st.header("Upload or Specify Auth Log File")
    st.write("Parses SSH `auth.log`, web access logs, or application security logs for brute-force attacks.")

    uploaded_log = st.file_uploader("Upload an Auth Log File (.log, .txt, .csv)", type=["log", "txt", "csv"])

    if st.button("Analyze Uploaded Log File", type="primary"):
        if not uploaded_log:
            st.warning("Please upload a log file first.")
        else:
            log_lines = uploaded_log.read().decode("utf-8", errors="ignore").splitlines()
            
            # Common Brute-Force Log Patterns
            # e.g., "Failed password for root from 192.168.1.50"
            # e.g., "LOGIN_FAILED user=admin ip=10.0.0.5"
            ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
            user_pattern = r"(?:user|for)\s+([a-zA-Z0-9_\-\.]+)"

            ip_counts = defaultdict(int)
            user_counts = defaultdict(int)
            total_log_failures = 0

            for line in log_lines:
                if any(keyword in line.lower() for keyword in ["failed", "unauthorized", "invalid", "401", "error"]):
                    total_log_failures += 1
                    
                    # Extract IP
                    ip_match = re.search(ip_pattern, line)
                    if ip_match:
                        ip_counts[ip_match.group(0)] += 1

                    # Extract Username
                    user_match = re.search(user_pattern, line, re.IGNORECASE)
                    if user_match:
                        user_counts[user_match.group(1)] += 1

            st.subheader("Analysis Summary")
            c1, c2 = st.columns(2)
            c1.metric("Total Detected Failed Logins", total_log_failures)
            
            # Identify Attacking IPs
            flagged_ips = [
                {"Source IP": ip, "Failed Attempts": count, "Risk Level": "🚨 ACTIVE BRUTE-FORCE" if count >= threshold_attempts else "NOTICE"}
                for ip, count in ip_counts.items()
            ]

            # Identify Targeted Users
            flagged_users = [
                {"Target Account": u, "Targeted Count": count, "Risk Level": "🎯 HIGHLY TARGETED" if count >= threshold_attempts else "NORMAL"}
                for u, count in user_counts.items()
            ]

            if flagged_ips:
                st.write("### Suspicious IP Activity")
                st.dataframe(flagged_ips, use_container_width=True)

            if flagged_users:
                st.write("### Targeted Accounts")
                st.dataframe(flagged_users, use_container_width=True)

            if not flagged_ips and not flagged_users:
                st.success("No brute-force signatures found matching your threshold settings.")

# ==============================================================================
# TAB 3: ATTACK SIMULATOR (TEST THE DETECTOR)
# ==============================================================================
with tab_simulator:
    st.header("🧪 Brute-Force Attack Simulator")
    st.write("Simulate a dictionary/brute-force attack on a test account to see how the detection algorithm responds.")

    sim_target_user = st.text_input("Target Test Account Name:", value="admin")
    sim_attacker_ip = st.text_input("Attacker IP Address:", value="192.168.1.100")
    sim_attempt_count = st.slider("Simulated Rapid Failed Attempts:", min_value=1, max_value=30, value=12)

    if st.button("Run Attack Simulation", type="secondary"):
        st.subheader("Simulating Attack Stream...")
        progress = st.progress(0)
        
        simulated_logs = []
        base_time = datetime.now()

        for i in range(sim_attempt_count):
            event_time = base_time - timedelta(seconds=(sim_attempt_count - i) * 2)
            log_entry = f"[{event_time.strftime('%Y-%m-%d %H:%M:%S')}] AUTH_FAILURE user={sim_target_user} src_ip={sim_attacker_ip} port={40000+i} reason='Invalid Password'"
            simulated_logs.append(log_entry)
            time.sleep(0.05)
            progress.progress(int((i + 1) / sim_attempt_count * 100))

        st.code("\n".join(simulated_logs), language="log")

        # Run Evaluation Engine
        st.subheader("Detector Evaluation:")
        if sim_attempt_count >= threshold_attempts:
            st.error(
                f"🚨 **ALARM TRIGGERED: BRUTE-FORCE ATTACK DETECTED!**\n\n"
                f"- **Attacker IP:** `{sim_attacker_ip}`\n"
                f"- **Victim Account:** `{sim_target_user}`\n"
                f"- **Velocity:** {sim_attempt_count} failures in under 1 minute (Exceeds threshold of {threshold_attempts})."
            )
        else:
            st.info(
                f"🟢 **NORMAL ACTIVITY:** {sim_attempt_count} attempt(s) received. Below the threshold of {threshold_attempts} attempts."
            )