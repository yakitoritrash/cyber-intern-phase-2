# Hint 7: Vulnerability Scan

## Scenario Overview

Simulates network vulnerability scanning using tools like Nmap to identify open ports and services.

## Simulation Steps

**On Kali:**
```bash
nmap -sS -T4 Windows_VM_IP
```

## Detection Guidance

- **Key Logs/Events:**
  - Firewall/IDS alerts
  - Event ID 5157: Windows Filtering Platform
- **SIEM Query Example:** `event.type:"alert" AND tags:"nmap"`
- **What to Look For:** Unusual port scanning activity, IDS alerts for scan signatures.

## Example Log Artifacts

(Paste actual log lines or reference screenshots here if available.)

## Additional Notes

Tune IDS/IPS to detect high-velocity scans and bursty network activity.
