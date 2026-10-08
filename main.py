import os
import re
import platform
import streamlit as st

# Check if GUI display environment is available for Tkinter
HAS_DISPLAY = True
try:
    import tkinter as tk
    from tkinter import filedialog
    if platform.system() != "Windows" and not os.environ.get("DISPLAY"):
        HAS_DISPLAY = False
except Exception:
    HAS_DISPLAY = False

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

IGNORE_DIRS = {
    "venv", ".venv", "env", "site-packages", "node_modules", 
    "__pycache__", ".git", "vendor", "$recycle.bin", "system volume information"
}
SUPPORTED_EXTS = {".py", ".ps1", ".sh", ".bat", ".cmd", ".c", ".cpp", ".js", ".txt"}


def select_folder_path():
    """Opens a native OS folder picker dialog over the browser window."""
    root = tk.Tk()
    root.withdraw()
    root.wm_attributes('-topmost', 1)
    folder_selected = filedialog.askdirectory(master=root, title="Select Directory to Scan")
    root.destroy()
    return folder_selected


def select_file_path():
    """Opens a native OS file picker dialog over the browser window."""
    root = tk.Tk()
    root.withdraw()
    root.wm_attributes('-topmost', 1)
    file_selected = filedialog.askopenfilename(
        master=root, 
        title="Select Script File to Scan",
        filetypes=[("Script / Source Files", "*.py;*.ps1;*.sh;*.bat;*.cmd;*.c;*.cpp;*.js;*.txt"), ("All Files", "*.*")]
    )
    root.destroy()
    return file_selected


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

# --- TAB 1: NATIVE OS FILE / FOLDER BROWSER ---
with tab_native:
    st.header("📂 Select Local File or Folder")

    if "target_path" not in st.session_state:
        st.session_state.target_path = ""

    if HAS_DISPLAY:
        st.write("Click a button below to open your computer's native file or folder browser window.")
        col_btn1, col_btn2 = st.columns([1, 1])

        if col_btn1.button("📁 Browse & Select Folder", type="secondary"):
            try:
                selected_dir = select_folder_path()
                if selected_dir:
                    st.session_state.target_path = selected_dir
            except Exception as e:
                st.error(f"Could not open folder picker: {e}")

        if col_btn2.button("📄 Browse & Select File", type="secondary"):
            try:
                selected_file = select_file_path()
                if selected_file:
                    st.session_state.target_path = selected_file
            except Exception as e:
                st.error(f"Could not open file picker: {e}")
    else:
        st.info("🌐 Running on Cloud Environment: Enter path manually or use 'Paste Codes' tab.")
        st.session_state.target_path = st.text_input(
            "Enter path to file or folder:",
            value=st.session_state.target_path or "."
        )

    st.markdown(f"**Selected Target:** `{st.session_state.target_path or 'None Selected'}`")

    if st.button("Start Security Scan", type="primary"):
        target_path = st.session_state.target_path
        if not target_path or not os.path.exists(target_path):
            st.warning("Please select or enter a valid target file/folder path first.")
        else:
            findings = []

            # 1. Single File Scan
            if os.path.isfile(target_path):
                try:
                    with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    findings = analyze_code_content(content, os.path.basename(target_path))
                except Exception as e:
                    st.error(f"Could not read file: {e}")

            # 2. Entire Directory Scan
            elif os.path.isdir(target_path):
                for root, dirs, files in os.walk(target_path):
                    dirs[:] = [d for d in dirs if d.lower() not in IGNORE_DIRS and not d.startswith('.')]

                    for file in files:
                        ext = os.path.splitext(file)[1].lower()
                        if ext in SUPPORTED_EXTS:
                            file_path = os.path.join(root, file)
                            try:
                                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                                    content = f.read()
                                results = analyze_code_content(content, os.path.relpath(file_path, target_path))
                                findings.extend(results)
                            except Exception:
                                continue

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