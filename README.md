# Cyber Intern Phase 2: Detection & Response Simulation

## Overview

This project documents and demonstrates a series of simulated attacker techniques and corresponding detection strategies as part of the **Cyber Intern Phase 2** program. The exercises below cover a broad range of attack tactics, from suspicious downloads and credential dumping to lateral movement and web shell execution. Each simulation is paired with tips for detection using industry-standard monitoring and logging tools.

---

## Completed Simulation Scenarios

### 1. Suspicious ZIP or RAR File Downloads
- **Simulation:** Downloaded `.zip`, `.rar`, and `.7z` files from external IPs using nonstandard User-Agents and direct download links.
- **Detection:** 
  - Analyzed Winlogbeat and Sysmon logs for file creation events.
  - Parsed proxy logs to trace external downloads and identify anomalous User-Agent strings.

### 2. Malicious PowerShell Execution
- **Simulation:** Executed encoded PowerShell commands, including those spawned from Office applications (e.g., `winword.exe` → `powershell.exe`).
- **Detection:**
  - Monitored Sysmon Event ID 1 (process creation) and 4104 (PowerShell script block logging) for suspicious execution chains and encoded commands.

### 3. Credential Dumping Tools
- **Simulation:** Ran Mimikatz and similar credential dumping tools.
- **Detection:**
  - Observed EDR/AV alerts and system logs for signs of credential access attempts.
  - Identified relevant events in Security logs (e.g., suspicious process creation, memory access patterns).

### 4. External Beaconing or C2 Communication
- **Simulation:** Generated scheduled outbound HTTP/HTTPS traffic to a custom domain to mimic beaconing.
- **Detection:**
  - Used Wireshark and Zeek for packet monitoring.
  - Reviewed Winlogbeat and firewall logs for recurring external connections and unusual patterns.

### 5. Privilege Escalation Simulation
- **Simulation:** Created a local user and added it to the Administrators group.
- **Detection:**
  - Monitored Security Event IDs 4728 and 4732 for group membership changes.
  - Compared group memberships before and after escalation.

### 6. Unauthorized Remote Desktop Access
- **Simulation:** Attempted RDP logins from different IPs within the LAN or VM environment.
- **Detection:**
  - Focused on Security Event ID 4624 (logon) with Logon Type 10 (RDP).
  - Reviewed logs for both failed and successful login attempts.

### 7. Vulnerability Scan Simulation
- **Simulation:** Performed scans with Nmap and Nessus Essentials against target hosts.
- **Detection:**
  - Checked logs for evidence of port scanning or vulnerability enumeration (e.g., IDS alerts, increased connection attempts).

### 8. Lateral Movement Simulation
- **Simulation:** Accessed shared folders on another VM and copied executables.
- **Detection:**
  - Analyzed logs for SMB access and file transfer events.
  - Assessed existing security controls to detect and prevent lateral movement.

### 9. Malicious Archive Execution
- **Simulation:** Executed files from inside password-protected archives.
- **Detection:**
  - Used Sysmon to trace process execution, file hashes, and parent-child relationships.
  - Correlated AV logs for execution of files originating from archives.

### 10. Web Shell or Reverse Shell Execution
- **Simulation:** Opened reverse shells using Netcat and PowerShell.
- **Detection:**
  - Inspected process trees for abnormal parent-child relationships.
  - Detected outbound connections on uncommon ports via network and firewall logs.

---

## Tools & Techniques Used

- **Log Collection:** Winlogbeat, Sysmon, Windows Event Viewer
- **Network Monitoring:** Wireshark, Zeek
- **Detection & Response:** EDR/AV solutions, Firewall logs, Proxy log parsers
- **Attack Simulation:** PowerShell, Mimikatz, Nmap, Nessus, Netcat

---

## Lessons Learned

- Effective log collection and correlation are critical for early detection of attacker behavior.
- Monitoring for specific Event IDs and network patterns provides valuable indicators of compromise.
- Simulated attacks help test and improve detection rules, raising awareness of attack lifecycle stages.

---

## References

- [Sysmon Documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Winlogbeat Documentation](https://www.elastic.co/guide/en/beats/winlogbeat/current/index.html)
- [Mitre ATT&CK Framework](https://attack.mitre.org/)

---
