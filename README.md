# claude-public

## secure-check.ps1
First-boot compromise audit + hardening for a used Windows 10/11 PC.

Run in an **elevated** PowerShell:

```powershell
[Net.ServicePointManager]::SecurityProtocol='Tls12'; iwr https://raw.githubusercontent.com/rogueinkamp/claude-public/main/secure-check.ps1 -OutFile $env:TEMP\sc.ps1; powershell -ep bypass -f $env:TEMP\sc.ps1 -Harden -Debloat
```

Switches: `-Harden` (apply security settings), `-Debloat` (telemetry/ads/junk apps off; idempotent, never touches activation/Update/Defender/Store), `-FullScan`, `-OfflineScan` (reboots), `-NoScan`.
Report lands on the Public Desktop as `SecurityAudit_<date>`.
