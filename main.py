import os
import re
import streamlit as st

# Streamlit Page Configuration
st.set_page_config(
    page_title="Destructive Command Analyzer",
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
        stripped = line_text.strip()
        if not stripped:
            continue

        for rule in RULES:
            match = re.search(rule["pattern"], line_text)
            if match:
                findings.append({
                    "Source": filename,
                    "Line": line_num,
                    "Severity": rule["severity"],
                    "Category": rule["category"],
                    "Detected Code": line_text.strip(),
                    "Risk Summary": rule["description"]
                })

    return findings


# Input Method Tabs
tab_native, tab_paste = st.tabs(["📂 Browse", "📝 Paste Codes"])

# --- TAB 1: BROWSE FILES ---
with tab_native:
    st.header("📂 Select Local Files")
    st.write("Click below to open your computer's native file picker window and select files to scan.")

    uploaded_files = st.file_uploader(
        "Choose script or source code files:",
        accept_multiple_files=True,
        type=["py", "ps1", "sh", "bat", "cmd", "c", "cpp", "js", "txt"]
    )

    if st.button("Start Security Scan", type="primary"):
        if not uploaded_files:
            st.warning("Please select at least one file using the file browser above.")
        else:
            findings = []
            for file in uploaded_files:
                try:
                    content = file.read().decode("utf-8", errors="ignore")
                    results = analyze_code_content(content, file.name)
                    findings.extend(results)
                except Exception as e:
                    st.error(f"Could not read {file.name}: {e}")

            if findings:
                st.error(f"🚨 Detected {len(findings)} potential threat(s)!")
                st.dataframe(findings, use_container_width=True)
            else:
                st.success("✅ Clean Code: No destructive commands or malicious execution patterns identified.")


# --- TAB 2: PASTE CODE DIRECTLY ---
with tab_paste:
    st.header("📝 Code Vulnerability & Command Inspector")
    st.write("Paste raw code or script commands below to analyze for security risks and destructive patterns.")

    pasted_code = st.text_area(
        "Paste Code Block Here:",
        height=320,
        placeholder="Paste your Python, PowerShell, Bash, Batch, or C/C++ code here..."
    )

    if st.button("Analyze Pasted Code", type="primary"):
        if not pasted_code.strip():
            st.warning("Please paste some code into the text area before running the analysis.")
        else:
            results = analyze_code_content(pasted_code, "Pasted Code Block")

            if results:
                st.error(f"🚨 Detected {len(results)} potential threat(s) in pasted code!")
                st.dataframe(results, use_container_width=True)
            else:
                st.success("✅ Clean Code: No destructive commands or malicious execution patterns identified.")