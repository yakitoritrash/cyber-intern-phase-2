# Hint 9: Malicious Archive

## Scenario Overview

Simulates the creation and extraction of a password-protected ZIP archive containing a malicious executable.

## Simulation Steps

**Create password-protected ZIP (Kali):**
```bash
zip -P infected malware.zip malware.exe
```
**Execute on Windows:**
```powershell
powershell -c "Expand-Archive -Path malware.zip -DestinationPath C:\temp"
```

## Detection Guidance

- **Key Logs/Events:**
  - AV detection events
  - Sysmon Event ID 1: Archive execution
- **SIEM Query Example:** `event.module:"antivirus" AND file.extension:"zip"`
- **What to Look For:** Archive extraction followed by suspicious process execution or AV alerts.

## Example Log Artifacts

(Paste actual log lines or reference screenshots here if available.)

## Additional Notes

Correlate archive extraction with subsequent alerts or suspicious processes.
