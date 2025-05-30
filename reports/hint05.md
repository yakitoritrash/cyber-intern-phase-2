# Hint 5: Privilege Escalation

## Scenario Overview

Simulates an attacker creating a new local user and adding it to the Administrators group to escalate privileges.

## Simulation Steps

**Create User & Add to Admin:**
```powershell
net user attacker P@ssw0rd! /add
net localgroup administrators attacker /add
```

## Detection Guidance

- **Key Logs/Events:**
  - Event ID 4720: User added
  - Event ID 4732: Added to admin group
- **SIEM Query Example:** `winlog.event_id:4732 AND user.name:"attacker"`
- **What to Look For:** Account creation events, new users added to administrative groups.

## Example Log Artifacts

(Paste actual log lines or reference screenshots here if available.)

## Additional Notes

Monitor for group membership changes and new account creations, especially outside standard provisioning times.
