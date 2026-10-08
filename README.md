\# LocalSec Auditor



\*\*LocalSec Auditor\*\* is a lightweight, standalone Windows Security Inspector built using Python. Designed for local enterprise auditing without requiring cloud infrastructure or database setups.



\## Core Capabilities

\* \*\*Brute-Force Detection:\*\* Parses local Windows Security Event Logs (`.evtx`) for \*\*Event ID 4625\*\* (Failed Logon Attempts) to flag automated login attacks.

\* \*\*Network Listener Inspector:\*\* Maps active listening ports to system Process IDs (PIDs) and process names to catch unauthorized services.

\* \*\*GUI Desktop Application:\*\* Native dark-mode GUI built with `CustomTkinter`.



\## Installation \& Local Execution

```cmd

git clone \[https://github.com/your-username/LocalSec-Auditor.git](https://github.com/your-username/LocalSec-Auditor.git)

cd LocalSec-Auditor

python -m venv venv

venv\\Scripts\\activate.bat

pip install -r requirements.txt

python main.py

```

## Compiling Standalone Executable
To generate a single standalone `.exe` executable:

```cmd
pyinstaller --noconsole --onefile --name LocalSecAuditor main.py
```

The compiled binary will be generated inside the `dist\` folder as `LocalSecAuditor.exe`.

## License
MIT