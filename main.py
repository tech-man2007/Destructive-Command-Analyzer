import os
import re
import platform
import streamlit as st

# Streamlit Page Configuration
st.set_page_config(
    page_title="CodeSec - Destructive Command Analyzer",
    page_icon="⚠️",
    layout="wide"
)

st.title("⚠️ Static Code Security & Destructive Command Analyzer")
st.write("Inspect source code and scripts for system-wiping commands, boot tampering, and malicious execution patterns.")
st.divider()

# Rule Definitions for Harmful Commands & System Threats
RULES = [
    # --- CRITICAL: System Wiping & Directory Destruction ---
    {
        "id": "CRIT-001",
        "severity": "CRITICAL",
        "category": "System Wiping",
        "description": "Attempt to recursively delete root, system directories, or Windows System32",
        "pattern": r"(?i)(rm\s+-[rf]{1,2}\s+(/|\*|/\*)|rd\s+/s\s+/q\s+[cC]:\\|del\s+/f\s+/s\s+/q\s+[cC]:\\|system32|Windows\\System32)"
    },
    {
        "id": "CRIT-002",
        "severity": "CRITICAL",
        "category": "Disk & Partition Tampering",
        "description": "Attempt to format volumes, overwrite MBR/disk headers, or manipulate boot config",
        "pattern": r"(?i)(format\s+[c-zC-Z]:|Format-Volume|dd\s+if=.*\s+of=/dev/sd|bcdedit\s+/set|bootrec\s+/(fixmbr|fixboot)|diskpart)"
    },

    # --- HIGH: Ransomware & Backup Sabotage ---
    {
        "id": "HIGH-001",
        "severity": "HIGH",
        "category": "Shadow Copy & Backup Erasure",
        "description": "Deletes volume shadow copies or disables system recovery features",
        "pattern": r"(?i)(vssadmin\s+delete\s+shadows|wbadmin\s+delete\s+catalog|Resize-Partition)"
    },
    {
        "id": "HIGH-002",
        "severity": "HIGH",
        "category": "Security Control Override",
        "description": "Disables Windows Defender, firewalls, or execution policies",
        "pattern": r"(?i)(Set-ExecutionPolicy\s+(Bypass|Unrestricted)|Set-MpPreference\s+-DisableRealtimeMonitoring|netsh\s+advfirewall\s+set\s+.*state\0*off)"
    },

    # --- HIGH: Malicious Scripting & Shell Injection ---
    {
        "id": "HIGH-003",
        "severity": "HIGH",
        "category": "Remote Code Download & Execute",
        "description": "Downloads payload from external server and immediately executes it",
        "pattern": r"(?i)(iwr|Invoke-WebRequest|curl|wget).*\|\s*(iex|Invoke-Expression|bash|sh|cmd)"
    },
    {
        "id": "HIGH-004",
        "severity": "HIGH",
        "category": "Fork Bomb / Denial of Service",
        "description": "Infinite resource exhaustion attack",
        "pattern": r"(:\(\)\{\s*:\|\:&\s*\};:|while\s*\(\s*true\s*\)\s*\{\s*fork\(\)\s*\})"
    },

    # --- MEDIUM: Unsafe System Calls & Process Spawning ---
    {
        "id": "MED-001",
        "severity": "MEDIUM",
        "category": "Unchecked System Call",
        "description": "Executes shell commands directly through application code",
        "pattern": r"(?i)(os\.system\(|subprocess\.Popen\(.*shell=True|eval\(|exec\()"
    }
]


def analyze_code_content(content: str, filename: str):
    """Parses text line-by-line and checks against risk rules."""
    findings = []
    lines = content.splitlines()

    for line_num, line_text in enumerate(lines, start=1):
        # Skip empty lines or pure standard comments
        stripped = line_text.strip()
        if not stripped:
            continue

        for rule in RULES:
            match = re.search(rule["pattern"], line_text)
            if match:
                findings.append({
                    "File": filename,
                    "Line": line_num,
                    "Severity": rule["severity"],
                    "Category": rule["category"],
                    "Detected Code": line_text.strip(),
                    "Risk Summary": rule["description"]
                })

    return findings


# Input Method Tabs
tab_upload, tab_path = st.tabs(["📄 Inspect Uploaded File(s)", "📂 Inspect Local System Path"])

# --- TAB 1: FILE UPLOAD SCANNER ---
with tab_upload:
    uploaded_files = st.file_uploader(
        "Upload source code or script files (.py, .ps1, .sh, .bat, .c, .cpp, .js):",
        accept_multiple_files=True,
        type=["py", "ps1", "sh", "bat", "cmd", "c", "cpp", "js", "txt"]
    )

    if st.button("Analyze Selected Files", type="primary"):
        if not uploaded_files:
            st.warning("Please upload at least one file.")
        else:
            all_findings = []
            for file in uploaded_files:
                try:
                    content = file.read().decode("utf-8", errors="ignore")
                    results = analyze_code_content(content, file.name)
                    all_findings.extend(results)
                except Exception as e:
                    st.error(f"Failed to process {file.name}: {e}")

            if all_findings:
                st.error(f"🚨 Detected {len(all_findings)} potential threat(s) across uploaded file(s)!")
                st.dataframe(all_findings, use_container_width=True)
            else:
                st.success("✅ Clean Code: No destructive commands or malicious execution patterns identified.")

# --- TAB 2: LOCAL PATH FILE SCANNER ---
with tab_path:
    target_file_path = st.text_input(
        "Enter path to a specific file on the machine:",
        value=""
    )

    if st.button("Scan Local File", type="primary"):
        if not target_file_path or not os.path.exists(target_file_path):
            st.error("Please enter a valid file path.")
        elif os.path.isdir(target_file_path):
            st.warning("Please enter a path to a specific file, not a folder.")
        else:
            try:
                with open(target_file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                results = analyze_code_content(content, os.path.basename(target_file_path))

                if results:
                    st.error(f"🚨 Detected {len(results)} potential threat(s) in `{target_file_path}`!")
                    st.dataframe(results, use_container_width=True)
                else:
                    st.success(f"✅ Clean Code: No harmful commands found in `{target_file_path}`.")
            except Exception as e:
                st.error(f"Could not read file: {e}")