# Hint 6: RDP Access

## Scenario Overview

Simulates remote desktop (RDP) login attempts from an attacker-controlled system, including both successful and failed logins.

## Simulation Steps

**From Kali:**
```bash
xfreerdp /v:Windows_VM_IP /u:attacker /p:P@ssw0rd!
```

## Detection Guidance

- **Key Logs/Events:**
  - Event ID 4624: Logon Type 10 (RDP)
  - Event ID 4625: Failed login
- **SIEM Query Example:** `winlog.event_id:4624 AND logon.type:10`
- **What to Look For:** RDP logins from unfamiliar IPs, excessive failed logon attempts.

## Example Log Artifacts

(Paste actual log lines or reference screenshots here if available.)

## Additional Notes

Alert on RDP access from unexpected geolocations or at unusual times.
