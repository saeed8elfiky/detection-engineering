# Splunk Detection Rules

Brief reference for detection rules maintained in this repo/index.

## Rules Table:

1. [PowerShell Encoded Command](#1-powershell-encoded-command)

---

### 1. PowerShell Encoded Command

- **Type:** `SPL` 
- **Severity:** `High` 
- **Interval:** `Every 5m`
- **MITRE ATT&CK:** `T1059 – Command and Scripting Interpreter, T1059.001 – PowerShell` 
- **Author**  Saeed Elfiky 

- **What it does:** Flags `powershell.exe` / `pwsh.exe` executions whose command line uses an encoded/shorthand command switch (`-EncodedCommand`, `-enc`, `-e`), a common technique for hiding malicious payloads from plaintext logging.

```Spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*powershell.exe" OR Image="*pwsh.exe"
| regex CommandLine="(?i)(^|[[:space:]])-(EncodedCommand|enc|e)([[:space:]]|=)"
| eval alert_name="PowerShell Encoded Command"
| eval severity="high"
| eval rule_id="7c9d3e8a-5f21-4b7d-9c31-2a6e8f4d1b90"
| eval mitre_attack="T1059.001"
| table _time host user Image CommandLine ParentImage ParentCommandLine ProcessId alert_name severity rule_id mitre_attack
| sort - _time
```

----