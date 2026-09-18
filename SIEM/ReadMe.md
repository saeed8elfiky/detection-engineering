# SIEM Detection Rules

Brief reference for detection rules maintained in this repo/index.
[]
---

## Rules Table:

[PowerShell Encoded Command](#powershell-encoded-command)

### PowerShell Encoded Command

- **Type:** `ES|QL` 
- **Severity:** `High` 
- **Risk Score:** `73` 
- **Interval:** `Every 5m`
- **MITRE ATT&CK:** `T1059 – Command and Scripting Interpreter, T1059.001 – PowerShell` 
- **Author**  Saeed Elfiky 

- **What it does:** Flags `powershell.exe` / `pwsh.exe` executions whose command line uses an encoded/shorthand command switch (`-EncodedCommand`, `-enc`, `-e`), a common technique for hiding malicious payloads from plaintext logging.

**Known false positives:** Legitimate admin scripts using encoded PowerShell; software deployment/RMM tools that launch PowerShell this way. *(No exception list configured yet — consider adding one for common deployment tools.)*

---
