# SIGMA Detection Rules

Brief reference for detection rules maintained in this repo/index.

## Rules Table:
[1. Dump LSASS.exe Memory using comsvcs.dll](#1-dump-lsassexe-memory-using-comsvcsdll)
[2. PowerShell Encoded Command](#2-powershell-encoded-command)
[3. FortiGate Malware Activity Detected](#3-FortiGate-malware-activity-detected)
---

### 1. Dump LSASS.exe Memory using comsvcs.dll
 
- **Rule Query:** [Dump LSASS.exe Memory using comsvcs.dll](Windows/Dump_LSAS_Memory_using_comsvcs.yml)
- **Status:** `Stable`
- **Log source:** `Windows, process_creation`
- **Severity:** `Critical`
- **MITRE ATT&CK:** `T1003 – OS Credential Dumping, T1003.001 – LSASS Memory`
- **Author** `Saeed Elfiky`
- **What it does:** Flags `rundll32.exe` invoking `comsvcs.dll` with the `MiniDump` export, a well-known technique for dumping LSASS process memory to extract credentials without dropping a separate tool like Mimikatz.
**Known false positives:** Highly unlikely in a standard environment.
 
---

### 2. PowerShell Encoded Command

- **Rule Query:** [PowerShell Encoded Command](Windows/Execute_base64-encoded_PowerShell.yml)
- **Status:** `Stable` 
- **Log source:** `Windows, process_creation`
- **Severity:** `High` 
- **Interval:** `Every 5m`
- **MITRE ATT&CK:** `T1059 – Command and Scripting Interpreter, T1059.001 – PowerShell` 
- **Author** `Saeed Elfiky `

- **What it does:** Flags `powershell.exe` / `pwsh.exe` executions whose command line uses an encoded/shorthand command switch (`-EncodedCommand`, `-enc`, `-e`), a common technique for hiding malicious payloads from plaintext logging.

**Known false positives:** Legitimate admin scripts using encoded PowerShell; software deployment/RMM tools that launch PowerShell this way. *(No exception list configured yet — consider adding one for common deployment tools.)*

---

### 3. FortiGate Malware Activity Detected

- **Rule Query:** [FortiGate Malware Activity Detected](Network/Fortigate_Malware_Activity_Detected.yml)
- **Status:** `Experimental`
- **Log source:** `Fortinet, firewall`
- **Severity:** `High`
- **MITRE ATT&CK:** `Impact`
- **Author** `Saeed Elfiky`

- **What it does:** Flags UTM-detected virus/malware events from FortiGate firewall logs (`fortinet.firewall.subtype: virus`), indicating the firewall's antivirus profile caught infected files or virus traffic.

**Known false positives:** Normal file transfers, legitimate downloads, software updates, cloud storage syncs, partner file exchanges, antivirus test files.