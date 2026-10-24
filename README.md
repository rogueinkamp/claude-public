# claude-public

## secure-check.ps1
First-boot compromise audit + hardening for a used Windows 10/11 PC.

Run in an **elevated** PowerShell:

```powershell
[Net.ServicePointManager]::SecurityProtocol='Tls12'; iwr https://raw.githubusercontent.com/rogueinkamp/claude-public/main/secure-check.ps1 -OutFile $env:TEMP\sc.ps1; powershell -ep bypass -f $env:TEMP\sc.ps1 -Harden -Debloat
```

Switches: `-Harden` (apply security settings), `-Debloat` (telemetry/ads/junk apps off; idempotent, never touches activation/Update/Defender/Store), `-FullScan`, `-OfflineScan` (reboots), `-NoScan`.
Report lands on the Public Desktop as `SecurityAudit_<date>`.

## Driver downloads (ThinkStation S30 build)

Install drivers **after** running `secure-check.ps1` and finishing Windows Update. Only download from these official sites.

| Part | Where to get it |
|---|---|
| XFX Radeon RX 580 8GB (RX-580P8DFD6) | [AMD RX 580 drivers](https://www.amd.com/en/support/downloads/drivers.html/graphics/radeon-600-500-400/radeon-rx-500-series/radeon-rx-580.html) — pick Windows 10 64-bit, AMD Software: Adrenalin Edition |
| Chipset, BIOS, Intel NIC, etc. | [Lenovo PC Support](https://pcsupport.lenovo.com) — search "ThinkStation S30" |

Tip: in the AMD installer choose **Driver Only** or **Minimal** if you don't want the full Adrenalin overlay/telemetry.
