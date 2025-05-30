# Hint 3: Credential Dumping

## Scenario Overview

Simulates credential dumping attempts, such as extracting password hashes from the Windows SAM and SYSTEM registry hives.

## Simulation Steps

**Simulate Mimikatz-like Activity:**
```powershell
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save
```

## Detection Guidance

- **Key Logs/Events:**
  - Event ID 4657: Registry access
  - Sysmon Event ID 1: reg.exe execution
- **SIEM Query Example:** `event.code:4657 AND registry.key_path:"HKLM\\SAM"`
- **What to Look For:** Registry save or access operations on sensitive hives, reg.exe launched by unexpected users or outside of maintenance windows.

## Example Log Artifacts

(Paste actual log lines or reference screenshots here if available.)

## Additional Notes

Alert on any access to SAM/SYSTEM hives outside normal patch cycles or admin tasks.
