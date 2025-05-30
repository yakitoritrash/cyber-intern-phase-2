# Hint 2: Malicious PowerShell

## Scenario Overview

Simulates execution of encoded PowerShell commands, which are commonly used by attackers to evade detection and execute payloads in memory.

## Simulation Steps

**Encode & Execute:**
```powershell
$cmd = "Start-Process calc.exe"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
powershell -enc $encoded
```

## Detection Guidance

- **Key Logs/Events:**
  - Sysmon Event ID 1: (Parent: winword.exe if from Office)
  - PowerShell Event ID 4104: Script block logging
- **SIEM Query Example:** `powershell.event_id:4104 AND message:"*encodedcommand*"`
- **What to Look For:** Encoded or obfuscated PowerShell commands, parent process anomalies (e.g., Office apps spawning PowerShell).

## Example Log Artifacts

(Paste actual log lines or reference screenshots here if available.)

## Additional Notes

Enable PowerShell logging and monitor for suspicious command-line arguments and encoded invocations.
