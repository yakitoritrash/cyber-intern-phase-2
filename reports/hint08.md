# Hint 8: Lateral Movement

## Scenario Overview

Simulates lateral movement by copying a file to a network share on another Windows system.

## Simulation Steps

**From one Windows VM to another:**
```powershell
copy C:\malware.exe \\TARGET_VM\C$\temp\
```

## Detection Guidance

- **Key Logs/Events:**
  - Event ID 5145: Network share access
  - Sysmon Event ID 3: Network connection
- **SIEM Query Example:** `winlog.event_id:5145 AND file.name:"malware.exe"`
- **What to Look For:** File transfer events to admin shares, abnormal SMB activity.

## Example Log Artifacts

(Paste actual log lines or reference screenshots here if available.)

## Additional Notes

Monitor for access to C$, D$, or ADMIN$ shares, especially by non-admin accounts.
