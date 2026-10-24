<#
  secure-check.ps1  -  First-boot compromise audit + hardening for a used Windows 10/11 PC
  Run from an ELEVATED PowerShell (right-click Start > Windows PowerShell (Admin)).

    Audit only (changes nothing except Defender signature update + quick scan):
      .\secure-check.ps1
    Audit, then harden settings:
      .\secure-check.ps1 -Harden
    Strip telemetry, ads and preinstalled junk (safe to re-run; only changes what isn't already set):
      .\secure-check.ps1 -Harden -Debloat
    Options:
      -Debloat      Telemetry/ads/suggestions off, bloat apps removed. Uses only Microsoft's own
                    documented settings - never touches activation, Windows Update, Defender,
                    the Store, or blocks Microsoft servers (that's what breaks activation/updates).
      -FullScan     Defender full scan instead of quick scan (slow)
      -OfflineScan  Queue a Defender Offline (boot-time rootkit) scan - REBOOTS the PC
      -NoScan       Skip the Defender scan

  Report folder lands on the Public Desktop: SecurityAudit_<date>
  NOTE: no script can prove a machine is clean (firmware/rootkits). If you see any HIGH
  findings you can't explain, wipe and reinstall from official Microsoft media.
#>
[CmdletBinding()]
param(
  [switch]$Harden,
  [switch]$Debloat,
  [switch]$FullScan,
  [switch]$OfflineScan,
  [switch]$NoScan
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

$wid = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$wid).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Run this from an ELEVATED PowerShell (Run as administrator)." -ForegroundColor Red
  return
}

$ReportDir = Join-Path $env:PUBLIC ("Desktop\SecurityAudit_" + (Get-Date -Format 'yyyyMMdd_HHmm'))
New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
Start-Transcript -Path (Join-Path $ReportDir 'transcript.txt') | Out-Null

# ---------------------------------------------------------------- helpers
$Flags = New-Object System.Collections.Generic.List[object]
function Flag([string]$Severity, [string]$Area, [string]$Detail) {
  $Flags.Add([pscustomobject]@{ Severity = $Severity; Area = $Area; Detail = $Detail })
  $color = @{ HIGH = 'Red'; MED = 'Yellow'; LOW = 'Cyan' }[$Severity]
  Write-Host ("  [{0}] {1}: {2}" -f $Severity, $Area, $Detail) -ForegroundColor $color
}
function Info([string]$t) { Write-Host "  $t" }
function Section([string]$t) { Write-Host "`n=== $t ===" -ForegroundColor Green }
function Save([string]$name, $obj) {
  $obj | Format-Table -AutoSize -Wrap | Out-String -Width 400 |
    Out-File -FilePath (Join-Path $ReportDir "$name.txt") -Encoding utf8
}

$SigCache = @{}
function Get-Sig([string]$Path) {
  if (-not $Path) { return 'NoPath' }
  if ($SigCache.ContainsKey($Path)) { return $SigCache[$Path] }
  if (-not (Test-Path -LiteralPath $Path)) { $SigCache[$Path] = 'Missing'; return 'Missing' }
  $s = Get-AuthenticodeSignature -LiteralPath $Path
  if ($s.Status -eq 'Valid') {
    $r = 'Valid:' + ($s.SignerCertificate.Subject -replace '^CN="?([^,"]+)"?.*$', '$1')
  } else { $r = [string]$s.Status }
  $SigCache[$Path] = $r
  return $r
}

function Get-ExePath([string]$cmd) {
  if (-not $cmd) { return $null }
  $c = [Environment]::ExpandEnvironmentVariables($cmd).Trim()
  $c = $c -replace '^\\\?\?\\', '' -replace '^\\SystemRoot', $env:SystemRoot
  if ($c -match '^"([^"]+)"') { $p = $Matches[1] }
  elseif ($c -match '^(.+?\.(exe|dll|sys|bat|cmd|ps1|vbs|js|scr|com|hta))\b') { $p = $Matches[1] }
  else { $p = ($c -split '\s+')[0] }
  if ($p -match '^(?i)system32\\') { $p = Join-Path $env:SystemRoot $p }
  if ($p -and -not [IO.Path]::IsPathRooted($p)) {
    $g = Get-Command $p -CommandType Application | Select-Object -First 1
    if ($g) { $p = $g.Source }
  }
  return $p
}

$UserWritable = '(?i)\\(AppData|Temp|ProgramData|Users\\Public|Downloads|Recycle)'
$SusCmd = '(?i)(\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|frombase64string|downloadstring|downloadfile|invoke-webrequest|\biex\b|invoke-expression|mshta(\.exe)?\s|regsvr32.+(/i:|scrobj)|rundll32.+(javascript|http)|certutil.+(-urlcache|-decode)|bitsadmin.+/transfer|\\(appdata|temp|users\\public)\\[^"]+\.(vbs|vbe|js|jse|wsf|hta|ps1|bat|cmd))'

function Judge([string]$Area, [string]$Label, [string]$Cmd) {
  if ($Cmd -match $SusCmd) { Flag 'HIGH' $Area "$Label -> suspicious command: $Cmd"; return }
  $path = Get-ExePath $Cmd
  $sig  = Get-Sig $path
  if ($sig -like 'Valid:*') { return }
  if ($path -match $UserWritable) { $sev = 'HIGH' } else { $sev = 'MED' }
  Flag $sev $Area "$Label -> $path [$sig]"
}

$RemoteTools = '(?i)anydesk|teamviewer|screenconnect|connectwise|rustdesk|ultravnc|tightvnc|tigervnc|realvnc|winvnc|vnc server|splashtop|logmein|gotoassist|goto resolve|atera|ninjarmm|ninjaone|kaseya|n-able|dameware|remote utilities|rutserv|rfusclient|radmin|ammyy|supremo|meshagent|mesh agent|zoho assist|tactical ?rmm|action1|syncro|netsupport|client32|chrome remote desktop|remoting_host|nomachine|dwservice|dwagent|getscreen|simplehelp|bomgar|beyondtrust|aeroadmin|hoptodesk|parsec'
$Miners = '(?i)xmrig|nicehash|phoenixminer|nbminer|t-rex|lolminer|gminer|teamredminer|nanominer|ethminer|cpuminer'

# ---------------------------------------------------------------- 1. system
Section 'System'
$os  = Get-CimInstance Win32_OperatingSystem
$cv  = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$cs  = Get-CimInstance Win32_ComputerSystem
Info "OS: $($os.Caption) $($cv.DisplayVersion) build $($os.BuildNumber).$($cv.UBR)"
Info "Installed: $($os.InstallDate)   Last boot: $($os.LastBootUpTime)"
Info "Registered owner: $($cv.RegisteredOwner)  Org: $($cv.RegisteredOrganization)"
if ([int]$os.BuildNumber -lt 22000) {
  Flag 'MED' 'OS' 'Windows 10: check Settings > Windows Update for Extended Security Updates (ESU) enrollment / status, or move to Windows 11/Linux'
}
$hf = Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($hf) {
  Info "Newest hotfix: $($hf.HotFixID) on $($hf.InstalledOn)"
  if ($hf.InstalledOn -lt (Get-Date).AddDays(-60)) { Flag 'MED' 'Updates' "No updates installed since $($hf.InstalledOn.ToShortDateString()) - run Windows Update before logging in to anything" }
}
try { $sb = Confirm-SecureBootUEFI; Info "Secure Boot: $sb" } catch { Info 'Secure Boot: not supported / legacy BIOS' }

if ($cs.PartOfDomain) { Flag 'HIGH' 'Management' "PC is joined to domain '$($cs.Domain)' - someone else can push software/policy to it" }
$dsreg = dsregcmd /status 2>$null | Out-String
if ($dsreg -match 'AzureAdJoined\s*:\s*YES') { Flag 'HIGH' 'Management' 'PC is Azure AD / Entra joined to an organization' }
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' | ForEach-Object {
  $e = Get-ItemProperty $_.PSPath
  if ($e.UPN -or $e.ProviderID) { Flag 'HIGH' 'Management' "MDM enrollment found: $($e.ProviderID) $($e.UPN)" }
}
$policyRoots = 'HKLM:\SOFTWARE\Policies\Google\Chrome','HKLM:\SOFTWARE\Policies\Microsoft\Edge','HKLM:\SOFTWARE\Policies\BraveSoftware\Brave','HKLM:\SOFTWARE\Policies\Mozilla\Firefox','HKCU:\SOFTWARE\Policies\Google\Chrome','HKCU:\SOFTWARE\Policies\Microsoft\Edge','HKCU:\SOFTWARE\Policies\BraveSoftware\Brave'
foreach ($r in $policyRoots) {
  if (Test-Path $r) {
    $force = Get-ItemProperty "$r\ExtensionInstallForcelist"
    if ($force) { $force.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { Flag 'HIGH' 'Browser' "Force-installed extension policy ($r): $($_.Value)" } }
    else { Flag 'MED' 'Browser' "Browser policy key exists: $r (review - pre-seeded browser policies are a common hijack)" }
  }
}

# ---------------------------------------------------------------- 2. accounts
Section 'Local accounts'
$users = Get-LocalUser
Save 'users' ($users | Select-Object Name, Enabled, LastLogon, PasswordLastSet, Description)
foreach ($u in ($users | Where-Object Enabled)) { Info "enabled user: $($u.Name)  last logon: $($u.LastLogon)" }
$admins = Get-LocalGroupMember -SID 'S-1-5-32-544'
if (-not $admins) { $admins = net localgroup administrators | Select-Object -Skip 6 | Where-Object { $_ -and $_ -notmatch 'command completed' } }
Save 'admins' $admins
foreach ($a in $admins) {
  $n = if ($a.Name) { $a.Name } else { [string]$a }
  Info "administrator: $n"
  if ($n -notmatch ("\\(" + [regex]::Escape($env:USERNAME) + "|Administrator)$") -and $n -ne $env:USERNAME) {
    Flag 'MED' 'Accounts' "Extra admin account: $n - delete it unless you created it"
  }
}
if ($users | Where-Object { $_.Name -eq 'Guest' -and $_.Enabled }) { Flag 'HIGH' 'Accounts' 'Guest account is enabled' }
if ($users | Where-Object { $_.SID -like '*-500' -and $_.Enabled }) { Flag 'MED' 'Accounts' 'Built-in Administrator account is enabled' }
$wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if ($wl.AutoAdminLogon -eq '1') { Flag 'MED' 'Accounts' "Auto-logon is on for '$($wl.DefaultUserName)'" }
if ($wl.DefaultPassword) { Flag 'HIGH' 'Accounts' 'A plaintext auto-logon password is stored in the registry' }

# ---------------------------------------------------------------- 3. defender
Section 'Microsoft Defender'
$mp   = Get-MpComputerStatus
$pref = Get-MpPreference
$pol  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
if (-not $mp) { Flag 'HIGH' 'Defender' 'Defender is not responding - disabled, removed, or replaced' }
else {
  Info "RealTime=$($mp.RealTimeProtectionEnabled)  AV=$($mp.AntivirusEnabled)  Tamper=$($mp.IsTamperProtected)  SigAge=$($mp.AntivirusSignatureAge)d"
  if (-not $mp.RealTimeProtectionEnabled) { Flag 'HIGH' 'Defender' 'Real-time protection is OFF' }
  if (-not $mp.IsTamperProtected) { Flag 'MED' 'Defender' 'Tamper Protection is OFF - turn on in Windows Security > Virus & threat protection > Manage settings' }
}
foreach ($k in 'ExclusionPath','ExclusionProcess','ExclusionExtension','ExclusionIpAddress') {
  foreach ($v in @($pref.$k)) { if ($v -and $v -notmatch 'N/A') { Flag 'HIGH' 'Defender' "$k exclusion: $v (malware loves adding these)" } }
}
if ((Get-ItemProperty $pol).DisableAntiSpyware -eq 1) { Flag 'HIGH' 'Defender' 'Group policy disables Defender' }
if ((Get-ItemProperty "$pol\Real-Time Protection").DisableRealtimeMonitoring -eq 1) { Flag 'HIGH' 'Defender' 'Group policy disables real-time protection' }
foreach ($t in @(Get-MpThreatDetection)) {
  if ($t) { Flag 'MED' 'Defender' "Past detection: $((Get-MpThreat -ThreatID $t.ThreatID).ThreatName) at $($t.InitialDetectionTime) -> $($t.Resources -join '; ')" }
}
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object { Info "AV registered: $($_.displayName)" }

# ---------------------------------------------------------------- 4. installed software
Section 'Installed programs'
$apps = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' |
        Where-Object DisplayName | Sort-Object DisplayName -Unique |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
Save 'installed_programs' $apps
foreach ($a in $apps) {
  Info "$($a.DisplayName)  [$($a.Publisher)]"
  if ($a.DisplayName -match $RemoteTools) { Flag 'HIGH' 'RemoteAccess' "Remote-access software installed: $($a.DisplayName) - uninstall unless YOU installed it" }
  if ($a.DisplayName -match $Miners)      { Flag 'HIGH' 'Miner' "Crypto miner installed: $($a.DisplayName)" }
}

# ---------------------------------------------------------------- 5. processes
Section 'Running processes'
$procs = Get-CimInstance Win32_Process
Save 'processes' ($procs | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine)
foreach ($p in $procs) {
  if ($p.ProcessId -eq $PID) { continue }
  if ($p.Name -match $RemoteTools -or $p.ExecutablePath -match $RemoteTools) { Flag 'HIGH' 'RemoteAccess' "Remote-access process running: $($p.Name) $($p.ExecutablePath)" }
  if ($p.Name -match $Miners -or $p.CommandLine -match '(?i)stratum\+tcp|--donate-level') { Flag 'HIGH' 'Miner' "Miner-like process: $($p.Name) $($p.CommandLine)" }
  if ($p.CommandLine -match $SusCmd) { Flag 'HIGH' 'Process' "Suspicious command line: PID $($p.ProcessId) $($p.CommandLine)" }
  if ($p.ExecutablePath) {
    $sig = Get-Sig $p.ExecutablePath
    if ($sig -notlike 'Valid:*') {
      if ($p.ExecutablePath -match $UserWritable) { $sev = 'HIGH' } else { $sev = 'MED' }
      Flag $sev 'Process' "Unsigned: $($p.Name) PID $($p.ProcessId) $($p.ExecutablePath) [$sig]"
    }
  }
}

# ---------------------------------------------------------------- 6. autostart
Section 'Autostart entries (Run keys, Startup folders)'
$runSub = @('SOFTWARE\Microsoft\Windows\CurrentVersion\Run','SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
            'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run')
$hives = @('HKLM:') + (Get-ChildItem 'Registry::HKEY_USERS' | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } | ForEach-Object { "Registry::HKEY_USERS\$($_.PSChildName)" })
$autoRows = @()
foreach ($h in $hives) {
  foreach ($s in $runSub) {
    $k = "$h\$s"
    $props = Get-ItemProperty -Path $k
    if (-not $props) { continue }
    $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
      $autoRows += [pscustomobject]@{ Key = $k; Name = $_.Name; Command = $_.Value }
      Info "$($_.Name) = $($_.Value)"
      Judge 'Autorun' $_.Name ([string]$_.Value)
    }
  }
}
$startupDirs = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp") +
  (Get-ChildItem 'C:\Users' -Directory -Force | ForEach-Object { "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" })
$shell = New-Object -ComObject WScript.Shell
foreach ($d in $startupDirs) {
  Get-ChildItem -LiteralPath $d -File -Force | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object {
    $target = $_.FullName
    if ($_.Extension -eq '.lnk') { $l = $shell.CreateShortcut($_.FullName); $target = ("`"$($l.TargetPath)`" $($l.Arguments)").Trim() }
    $autoRows += [pscustomobject]@{ Key = $d; Name = $_.Name; Command = $target }
    Info "Startup folder: $($_.Name) -> $target"
    Judge 'StartupFolder' $_.Name $target
  }
}
Save 'autoruns' $autoRows

# ---------------------------------------------------------------- 7. scheduled tasks
Section 'Scheduled tasks'
$taskRows = @()
foreach ($t in (Get-ScheduledTask | Where-Object State -ne 'Disabled')) {
  $isMs = $t.TaskPath -like '\Microsoft\*'
  foreach ($a in $t.Actions) {
    if (-not $a.Execute) { continue }   # COM handler actions
    $cmd = ("$($a.Execute) $($a.Arguments)").Trim()
    $taskRows += [pscustomobject]@{ Task = "$($t.TaskPath)$($t.TaskName)"; Command = $cmd }
    if ($isMs) {
      $tExe = Get-ExePath $cmd
      $tSig = Get-Sig $tExe
      if ($cmd -match $SusCmd -or ($tExe -match $UserWritable -and $tSig -notmatch '^Valid:.*Microsoft')) { Flag 'HIGH' 'SchedTask' "Suspicious task hiding under \Microsoft: $($t.TaskPath)$($t.TaskName) -> $cmd [$tSig]" }
    } else {
      Info "$($t.TaskPath)$($t.TaskName) -> $cmd"
      Judge 'SchedTask' "$($t.TaskPath)$($t.TaskName)" $cmd
    }
  }
}
Save 'scheduled_tasks' $taskRows

# ---------------------------------------------------------------- 8. services & drivers
Section 'Services and drivers'
$svcRows = @()
foreach ($s in (Get-CimInstance Win32_Service)) {
  if (-not $s.PathName) { continue }
  $path = Get-ExePath $s.PathName
  $sig  = Get-Sig $path
  $dll  = $null
  if ($path -match '(?i)\\svchost\.exe$') {
    $dll = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)\Parameters").ServiceDll
    if ($dll) { $dll = [Environment]::ExpandEnvironmentVariables($dll); $sig = Get-Sig $dll; $path = $dll }
  }
  $svcRows += [pscustomobject]@{ Name = $s.Name; State = $s.State; Start = $s.StartMode; Binary = $path; Signer = $sig }
  if ($s.Name -match $RemoteTools -or $s.DisplayName -match $RemoteTools) { Flag 'HIGH' 'RemoteAccess' "Remote-access service: $($s.DisplayName) ($($s.State))" }
  if ($s.PathName -match $SusCmd) { Flag 'HIGH' 'Service' "$($s.Name) suspicious command: $($s.PathName)"; continue }
  if ($sig -notlike 'Valid:*') {
    if ($path -match $UserWritable) { $sev = 'HIGH' } else { $sev = 'MED' }
    Flag $sev 'Service' "$($s.Name) [$($s.State)] -> $path [$sig]"
  } elseif ($sig -notmatch 'Microsoft') {
    Info "3rd-party service: $($s.Name) [$($s.State)] signed by $($sig.Substring(6))"
  }
}
Save 'services' $svcRows
foreach ($d in (Get-CimInstance Win32_SystemDriver | Where-Object State -eq 'Running')) {
  $path = Get-ExePath $d.PathName
  $sig  = Get-Sig $path
  if ($sig -notlike 'Valid:*') { Flag 'HIGH' 'Driver' "Running driver not validly signed: $($d.Name) -> $path [$sig]" }
  elseif ($sig -notmatch 'Microsoft') { Info "3rd-party driver: $($d.Name) signed by $($sig.Substring(6))" }
}

# ---------------------------------------------------------------- 9. persistence / hijack points
Section 'Hijack and credential-theft persistence points'
foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon','HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon') {
  $w = Get-ItemProperty $k
  if ($w.Shell -and $w.Shell -ne 'explorer.exe') { Flag 'HIGH' 'Winlogon' "$k Shell = $($w.Shell)" }
  if ($w.Userinit -and $w.Userinit.TrimEnd(',').Trim() -notmatch '^(?i)C:\\Windows\\system32\\userinit\.exe$') { Flag 'HIGH' 'Winlogon' "$k Userinit = $($w.Userinit)" }
}
foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
  $v = (Get-ItemProperty $k).AppInit_DLLs
  if ($v) { Flag 'HIGH' 'AppInit' "AppInit_DLLs = $v" }
}
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' | ForEach-Object {
  $dbg = (Get-ItemProperty $_.PSPath).Debugger
  if ($dbg) { Flag 'HIGH' 'IFEO' "$($_.PSChildName) hijacked by debugger: $dbg" }
}
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit' | ForEach-Object {
  $m = (Get-ItemProperty $_.PSPath).MonitorProcess
  if ($m) { Flag 'HIGH' 'SilentExit' "$($_.PSChildName) -> $m" }
}
$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
foreach ($p in @($lsa.'Authentication Packages')) { if ($p -and $p -ne 'msv1_0') { Flag 'HIGH' 'LSA' "Unknown authentication package: $p" } }
foreach ($p in @($lsa.'Notification Packages'))   { if ($p -and $p -notin @('scecli','rassfm')) { Flag 'HIGH' 'LSA' "Password filter DLL (grabs every password change): $p" } }
$okSsp = @('""','kerberos','msv1_0','schannel','wdigest','tspkg','pku2u','cloudap','livessp')
foreach ($p in @($lsa.'Security Packages') + @((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig').'Security Packages')) {
  if ($p -and $p -notin $okSsp) { Flag 'HIGH' 'LSA' "Unknown security package (SSP): $p" }
}
if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest').UseLogonCredential -eq 1) {
  Flag 'HIGH' 'LSA' 'WDigest UseLogonCredential=1 (keeps plaintext passwords in memory for stealers)'
}
$cmdHash = (Get-FileHash "$env:windir\System32\cmd.exe").Hash
$psHash  = (Get-FileHash "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe").Hash
foreach ($f in 'sethc','utilman','osk','magnify','narrator','displayswitch','atbroker') {
  $p = "$env:windir\System32\$f.exe"
  if (Test-Path $p) {
    $h = (Get-FileHash $p).Hash
    if ($h -eq $cmdHash -or $h -eq $psHash -or (Get-Sig $p) -notlike 'Valid:*') { Flag 'HIGH' 'Backdoor' "$f.exe has been replaced (login-screen backdoor)" }
  }
}
$wmiC = Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer
foreach ($c in $wmiC) {
  if ($c.Name -ne 'SCM Event Log Consumer') { Flag 'HIGH' 'WMI' "WMI persistence consumer '$($c.Name)': $($c.CommandLineTemplate)$($c.ScriptText)" }
}
$profs = @("$env:windir\System32\WindowsPowerShell\v1.0\profile.ps1", "$env:windir\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1")
Get-ChildItem 'C:\Users' -Directory -Force | ForEach-Object {
  $profs += "$($_.FullName)\Documents\WindowsPowerShell\profile.ps1"
  $profs += "$($_.FullName)\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
}
foreach ($p in $profs) { if (Test-Path $p) { Flag 'MED' 'PSProfile' "PowerShell profile exists (runs on every PS start): $p" } }

# ---------------------------------------------------------------- 10. network
Section 'Network'
$pn = @{}; Get-Process | ForEach-Object { $pn[$_.Id] = $_.ProcessName }
$listen = Get-NetTCPConnection -State Listen | Sort-Object LocalPort -Unique |
  Select-Object LocalAddress, LocalPort, OwningProcess, @{ n = 'Process'; e = { $pn[[int]$_.OwningProcess] } }
Save 'listening_ports' $listen
foreach ($l in $listen) {
  Info ("listening {0}:{1}  {2}" -f $l.LocalAddress, $l.LocalPort, $l.Process)
  if ($l.LocalPort -in 5900,5901,5902,5938,4899,7070,6568,21115,21116,21118) { Flag 'HIGH' 'Network' "Remote-control port $($l.LocalPort) listening ($($l.Process))" }
  if ($l.LocalPort -eq 3389) { Flag 'MED' 'Network' 'RDP port 3389 is listening' }
  if ($l.LocalPort -in 5985,5986) { Flag 'MED' 'Network' "WinRM port $($l.LocalPort) is listening" }
}
$est = Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1$|0\.0\.0\.0)' } |
  Select-Object RemoteAddress, RemotePort, OwningProcess, @{ n = 'Process'; e = { $pn[[int]$_.OwningProcess] } }
Save 'established_connections' $est
foreach ($e in $est) { Info ("outbound {0}:{1}  {2}" -f $e.RemoteAddress, $e.RemotePort, $e.Process) }

$hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$hostLines = Get-Content $hostsFile | Where-Object { $_ -match '^\s*[^#\s]' }
foreach ($h in $hostLines) { Flag 'MED' 'Hosts' "Active hosts-file entry: $h" }

$inet = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
if ($inet.ProxyEnable -eq 1) { Flag 'HIGH' 'Proxy' "System proxy enabled: $($inet.ProxyServer)" }
if ($inet.AutoConfigURL)     { Flag 'HIGH' 'Proxy' "Proxy auto-config (PAC) URL: $($inet.AutoConfigURL)" }
$wh = netsh winhttp show proxy | Out-String
if ($wh -notmatch 'Direct access') { Flag 'HIGH' 'Proxy' "WinHTTP proxy is set: $($wh.Trim())" }

$knownDns = '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|1\.1\.1\.1$|1\.0\.0\.1$|8\.8\.8\.8$|8\.8\.4\.4$|9\.9\.9\.9$|149\.112\.112\.112$|208\.67\.22[02]\.22[02]$|94\.140\.1[45]\.1[45]$|76\.76\.(2|10)\.0$)'
foreach ($d in (Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object ServerAddresses)) {
  Info "DNS on $($d.InterfaceAlias): $($d.ServerAddresses -join ', ')"
  foreach ($ip in $d.ServerAddresses) { if ($ip -notmatch $knownDns) { Flag 'LOW' 'DNS' "DNS server $ip on $($d.InterfaceAlias) - fine if it's your ISP's, suspicious if not" } }
}
Get-NetAdapter | ForEach-Object { Info "adapter: $($_.Name) - $($_.InterfaceDescription) [$($_.Status)]" }
foreach ($fp in Get-NetFirewallProfile) { if (-not $fp.Enabled) { Flag 'HIGH' 'Firewall' "$($fp.Name) firewall profile is OFF" } }
Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | ForEach-Object {
  $app = ($_ | Get-NetFirewallApplicationFilter).Program
  if ($app -and $app -match $UserWritable) { Flag 'MED' 'Firewall' "Inbound allow rule for user-writable program: $($_.DisplayName) -> $app" }
}

# ---------------------------------------------------------------- 11. remote access / misc settings
Section 'Remote access and system settings'
if ((Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections -eq 0) { Flag 'MED' 'RDP' 'Remote Desktop is ENABLED' }
if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance').fAllowToGetHelp -eq 1) { Flag 'LOW' 'RemoteAssist' 'Remote Assistance is enabled' }
if ((Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State -eq 'Enabled') { Flag 'MED' 'SMBv1' 'SMBv1 is enabled' }
foreach ($n in 'RemoteRegistry','WinRM','sshd') { if ((Get-Service $n).Status -eq 'Running') { Flag 'LOW' 'Service' "$n is running" } }
$uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
if ($uac.EnableLUA -ne 1) { Flag 'HIGH' 'UAC' 'UAC is disabled' }
elseif ($uac.ConsentPromptBehaviorAdmin -eq 0) { Flag 'HIGH' 'UAC' 'UAC set to never notify' }
$wu = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
if ($wu.WUServer) { Flag 'HIGH' 'Updates' "Windows Update redirected to $($wu.WUServer)" }
if ((Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU').NoAutoUpdate -eq 1) { Flag 'MED' 'Updates' 'Automatic updates disabled by policy' }
if ((Get-Service wuauserv).StartType -eq 'Disabled') { Flag 'HIGH' 'Updates' 'Windows Update service is disabled' }

# ---------------------------------------------------------------- 12. root certificates
Section 'Trusted root certificates'
$sst = Join-Path $env:TEMP 'wu_roots.sst'
certutil -generateSSTFromWU $sst 2>$null | Out-Null
if (Test-Path $sst) {
  $wuRoots = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
  $wuRoots.Import($sst)
  $known = @{}; foreach ($c in $wuRoots) { $known[$c.Thumbprint] = 1 }
  $roots = Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\Root | Sort-Object Thumbprint -Unique
  Save 'root_certs' ($roots | Select-Object Thumbprint, Subject, NotBefore, NotAfter)
  foreach ($r in $roots) {
    if (-not $known[$r.Thumbprint] -and $r.Subject -notmatch '(?i)Microsoft|Thawte Timestamping|NO LIABILITY ACCEPTED') {
      Flag 'HIGH' 'RootCert' "Root CA not in Microsoft's trusted list (can intercept HTTPS): $($r.Subject) [$($r.Thumbprint)]"
    }
  }
  Remove-Item $sst -Force
} else { Flag 'LOW' 'RootCert' "Couldn't download Microsoft's root list to compare - see root_certs.txt" }

# ---------------------------------------------------------------- 13. loose executables in user-writable dirs
Section 'Unsigned executables in user-writable folders'
$scanRoots = @("$env:SystemRoot\Temp", "$env:PUBLIC", "$env:ProgramData") + (Get-ChildItem 'C:\Users' -Directory -Force | ForEach-Object { "$($_.FullName)\AppData", "$($_.FullName)\Downloads" })
$skip = '(?i)\\(Microsoft\\Windows Defender|Package Cache|WindowsApps|Microsoft\\Windows\\WER|Microsoft\\Edge|Microsoft\\EdgeUpdate|Microsoft\\OneDrive)\\'
$found = 0
foreach ($root in $scanRoots) {
  Get-ChildItem -LiteralPath $root -Recurse -Force -File |
    Where-Object { $_.Extension -match '(?i)^\.(exe|dll|scr|com|ps1|vbs|vbe|js|jse|hta|bat|cmd)$' -and
                   $_.FullName -notmatch $skip -and $_.FullName -notmatch '\\SecurityAudit_\d' -and $_.Length -gt 0 } | ForEach-Object {
      if ($found -ge 60) { return }
      if ($_.Extension -match '(?i)\.(exe|dll|scr|com)$') {
        $sig = Get-Sig $_.FullName
        if ($sig -notlike 'Valid:*') { Flag 'MED' 'LooseFile' "$($_.FullName) [$sig]"; $found++ }
      } elseif ($_.FullName -match '(?i)\\(Temp|AppData\\Roaming|Users\\Public)\\') {
        Flag 'LOW' 'LooseScript' $_.FullName; $found++
      }
    }
}
if ($found -ge 60) { Info '(stopped listing after 60 files)' }

# ---------------------------------------------------------------- 14. defender scan
if (-not $NoScan) {
  Section 'Defender scan'
  Info 'Updating signatures...'
  Update-MpSignature
  if ($FullScan) { Info 'Full scan (this takes a while)...'; Start-MpScan -ScanType FullScan }
  else { Info 'Quick scan...'; Start-MpScan -ScanType QuickScan }
  foreach ($t in @(Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddHours(-2) })) {
    if ($t) { Flag 'HIGH' 'Defender' "Scan found: $((Get-MpThreat -ThreatID $t.ThreatID).ThreatName) -> $($t.Resources -join '; ')" }
  }
}

# ---------------------------------------------------------------- 15. harden
if ($Harden) {
  Section 'HARDENING'
  Remove-ItemProperty $pol -Name DisableAntiSpyware, DisableAntiVirus
  Remove-ItemProperty "$pol\Real-Time Protection" -Name DisableRealtimeMonitoring, DisableBehaviorMonitoring, DisableOnAccessProtection, DisableScanOnRealtimeEnable
  foreach ($v in @($pref.ExclusionPath))      { if ($v -and $v -notmatch 'N/A') { Remove-MpPreference -ExclusionPath $v; Info "Removed exclusion path $v" } }
  foreach ($v in @($pref.ExclusionProcess))   { if ($v -and $v -notmatch 'N/A') { Remove-MpPreference -ExclusionProcess $v; Info "Removed exclusion process $v" } }
  foreach ($v in @($pref.ExclusionExtension)) { if ($v -and $v -notmatch 'N/A') { Remove-MpPreference -ExclusionExtension $v; Info "Removed exclusion ext $v" } }
  foreach ($v in @($pref.ExclusionIpAddress)) { if ($v -and $v -notmatch 'N/A') { Remove-MpPreference -ExclusionIpAddress $v; Info "Removed exclusion IP $v" } }
  Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false `
                   -DisableScriptScanning $false -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples `
                   -PUAProtection Enabled -CloudBlockLevel High -CloudExtendedTimeout 50 -EnableNetworkProtection Enabled
  Info 'Defender: real-time, cloud, PUA blocking, network protection ON'

  # Attack Surface Reduction rules (credential theft + common malware persistence)
  $asrOn = @('9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2',  # block credential stealing from LSASS
             '56a863a9-875e-4185-98a7-b882c64b5ce5',  # block vulnerable signed drivers
             'e6db77e5-3df2-4cf1-b95a-636979351e5b',  # block WMI event-subscription persistence
             'd3e037e1-3eb8-44c8-a917-57927947596d',  # block JS/VBS launching downloaded executables
             'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4',  # block untrusted/unsigned processes from USB
             'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550',  # block executable content from email/webmail
             'd4f940ab-401b-4efc-aadc-ad5f3c50688a')  # block Office apps creating child processes
  Add-MpPreference -AttackSurfaceReductionRules_Ids $asrOn -AttackSurfaceReductionRules_Actions ($asrOn | ForEach-Object { 'Enabled' })
  Add-MpPreference -AttackSurfaceReductionRules_Ids '5beb7efe-fd9a-4556-801d-275e5ffc04cc' -AttackSurfaceReductionRules_Actions AuditMode  # obfuscated scripts (audit only)
  Info 'ASR rules enabled (LSASS theft, vulnerable drivers, WMI persistence, script droppers, USB, email, Office)'

  Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
  Info 'Firewall ON for all profiles, inbound default = block'

  Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1
  Disable-NetFirewallRule -DisplayGroup 'Remote Desktop'
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name fAllowToGetHelp -Value 0
  foreach ($n in 'RemoteRegistry','WinRM') { Stop-Service $n -Force; Set-Service $n -StartupType Disabled }
  Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null
  Info 'RDP, Remote Assistance, Remote Registry, WinRM, SMBv1 OFF'

  $sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
  Set-ItemProperty $sys -Name EnableLUA -Value 1
  if ((Get-ItemProperty $sys).ConsentPromptBehaviorAdmin -in 0,3,4) { Set-ItemProperty $sys -Name ConsentPromptBehaviorAdmin -Value 5 }
  Set-ItemProperty $sys -Name PromptOnSecureDesktop -Value 1
  Info 'UAC on (secure desktop)'

  Disable-LocalUser -Name Guest
  New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Force | Out-Null
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0 -Type DWord
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1 -Type DWord
  Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword
  Info 'Guest off, WDigest off, LSASS protection (RunAsPPL) on - takes effect after reboot'

  $exp = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
  New-Item $exp -Force | Out-Null
  Set-ItemProperty $exp -Name NoDriveTypeAutoRun -Value 255 -Type DWord
  Set-ItemProperty $exp -Name NoAutorun -Value 1 -Type DWord
  Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name HideFileExt -Value 0
  Info 'AutoRun off, file extensions visible (spots invoice.pdf.exe tricks)'

  if ($hostLines) {
    Copy-Item $hostsFile "$ReportDir\hosts.bak" -Force
    Set-Content $hostsFile "# Copyright (c) 1993-2009 Microsoft Corp.`r`n# Reset by secure-check.ps1 - original saved in report folder" -Encoding ascii
    Info 'Hosts file reset (backup in report folder)'
  }
  $is = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
  Set-ItemProperty $is -Name ProxyEnable -Value 0
  Remove-ItemProperty $is -Name AutoConfigURL
  netsh winhttp reset proxy | Out-Null
  Clear-DnsClientCache
  Info 'Proxy settings reset, DNS cache flushed'

  Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name WUServer, WUStatusServer
  Set-Service wuauserv -StartupType Manual
  Start-Service wuauserv
  Start-Process UsoClient.exe -ArgumentList 'StartScan' -WindowStyle Hidden
  Info 'Windows Update scan kicked off - check Settings > Windows Update'

  Write-Host "`n  Not automated (do by hand): Tamper Protection ON in Windows Security; uninstall any remote-access tools flagged above." -ForegroundColor Yellow
}

# ---------------------------------------------------------------- 16. debloat (idempotent)
if ($Debloat) {
  Section 'DEBLOAT (telemetry, ads, preinstalled junk)'
  $script:Changed = 0; $script:Already = 0
  function Set-RegValue([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord') {
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    $cur = (Get-ItemProperty -Path $Path -Name $Name).$Name
    if ($null -ne $cur -and "$cur" -eq "$Value") { $script:Already++; return }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    $script:Changed++
    Info "[+] $($Path -replace '^Registry::HKEY_USERS\\','HKU\')\$Name = $Value"
  }

  # --- machine-wide policies (documented Group Policy registry values)
  $dc = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
  Set-RegValue $dc 'AllowTelemetry' 0                 # Pro treats 0 as "Required" - the lowest Microsoft supports
  Set-RegValue $dc 'DoNotShowFeedbackNotifications' 1
  Set-RegValue $dc 'LimitDiagnosticLogCollection' 1
  Set-RegValue $dc 'AllowDeviceNameInTelemetry' 0
  Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' 'DisabledByGroupPolicy' 1
  $ws = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
  Set-RegValue $ws 'AllowCortana' 0
  Set-RegValue $ws 'DisableWebSearch' 1
  Set-RegValue $ws 'ConnectedSearchUseWeb' 0
  $sy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
  Set-RegValue $sy 'EnableActivityFeed' 0
  Set-RegValue $sy 'PublishUserActivities' 0
  Set-RegValue $sy 'UploadUserActivities' 0
  Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsConsumerFeatures' 1
  Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableSoftLanding' 1
  Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds' 'EnableFeeds' 0      # taskbar News & Interests
  Set-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'HideSCAMeetNow' 1
  Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization' 'AllowInputPersonalization' 0
  Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' 'DODownloadMode' 1  # share updates on LAN only, not the internet

  # --- per-user settings: you, plus the Default profile so new accounts (kids) start clean
  $userRoots = @('HKCU:')
  $defLoaded = $false
  if (-not (Test-Path 'Registry::HKEY_USERS\SC_Default')) {
    reg load 'HKU\SC_Default' "$env:SystemDrive\Users\Default\NTUSER.DAT" 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { $defLoaded = $true }
  }
  if (Test-Path 'Registry::HKEY_USERS\SC_Default') { $userRoots += 'Registry::HKEY_USERS\SC_Default' }
  foreach ($u in $userRoots) {
    $cdm = "$u\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    foreach ($n in 'ContentDeliveryAllowed','OemPreInstalledAppsEnabled','PreInstalledAppsEnabled','PreInstalledAppsEverEnabled',
                   'SilentInstalledAppsEnabled','SoftLandingEnabled','SystemPaneSuggestionsEnabled','RotatingLockScreenOverlayEnabled',
                   'SubscribedContent-310093Enabled','SubscribedContent-338387Enabled','SubscribedContent-338388Enabled',
                   'SubscribedContent-338389Enabled','SubscribedContent-338393Enabled','SubscribedContent-353694Enabled',
                   'SubscribedContent-353696Enabled','SubscribedContent-353698Enabled') { Set-RegValue $cdm $n 0 }
    Set-RegValue "$u\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" 'Enabled' 0
    Set-RegValue "$u\Software\Microsoft\Windows\CurrentVersion\Privacy" 'TailoredExperiencesWithDiagnosticDataEnabled' 0
    Set-RegValue "$u\Software\Policies\Microsoft\Windows\CloudContent" 'DisableTailoredExperiencesWithDiagnosticData' 1
    Set-RegValue "$u\Software\Microsoft\Windows\CurrentVersion\Search" 'BingSearchEnabled' 0
    Set-RegValue "$u\Software\Microsoft\Windows\CurrentVersion\Search" 'CortanaConsent' 0
    Set-RegValue "$u\Software\Policies\Microsoft\Windows\Explorer" 'DisableSearchBoxSuggestions' 1
    Set-RegValue "$u\Software\Microsoft\Siuf\Rules" 'NumberOfSIUFInPeriod' 0
    Set-RegValue "$u\Software\Microsoft\InputPersonalization" 'RestrictImplicitTextCollection' 1
    Set-RegValue "$u\Software\Microsoft\InputPersonalization" 'RestrictImplicitInkCollection' 1
    Set-RegValue "$u\Software\Microsoft\InputPersonalization\TrainedDataStore" 'HarvestContacts' 0
    Set-RegValue "$u\Software\Microsoft\Personalization\Settings" 'AcceptedPrivacyPolicy' 0
    Set-RegValue "$u\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" 'Start_TrackProgs' 0
    Set-RegValue "$u\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" 'ShowSyncProviderNotifications' 0
    Set-RegValue "$u\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" 'ScoobeSystemSettingEnabled' 0   # "finish setting up your device" nags
  }
  if ($defLoaded) { [gc]::Collect(); [gc]::WaitForPendingFinalizers(); reg unload 'HKU\SC_Default' 2>$null | Out-Null }

  # --- telemetry services
  foreach ($n in 'DiagTrack','dmwappushservice') {
    $s = Get-Service $n
    if ($s -and $s.StartType -ne 'Disabled') {
      Stop-Service $n -Force; Set-Service $n -StartupType Disabled
      $script:Changed++; Info "[+] Service $n disabled"
    } elseif ($s) { $script:Already++ }
  }

  # --- telemetry scheduled tasks
  $teleTasks = '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator',
               '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip',
               '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser',
               '\Microsoft\Windows\Application Experience\ProgramDataUpdater',
               '\Microsoft\Windows\Autochk\Proxy',
               '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector',
               '\Microsoft\Windows\Feedback\Siuf\DmClient',
               '\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload'
  foreach ($full in $teleTasks) {
    $leaf = $full.Split('\')[-1]
    $tp   = $full.Substring(0, $full.Length - $leaf.Length)
    $t = Get-ScheduledTask -TaskPath $tp -TaskName $leaf
    if ($t -and $t.State -ne 'Disabled') { $t | Disable-ScheduledTask | Out-Null; $script:Changed++; Info "[+] Task disabled: $full" }
    elseif ($t) { $script:Already++ }
  }

  # --- preinstalled junk apps (keeps Store, Xbox/Game Bar, Photos, Calculator, media players, Edge)
  $bloat = 'Microsoft.BingNews','Microsoft.BingWeather','Microsoft.GetHelp','Microsoft.Getstarted',
           'Microsoft.Microsoft3DViewer','Microsoft.MicrosoftOfficeHub','Microsoft.MicrosoftSolitaireCollection',
           'Microsoft.MixedReality.Portal','Microsoft.Office.OneNote','Microsoft.OneConnect','Microsoft.People',
           'Microsoft.Print3D','Microsoft.SkypeApp','Microsoft.Wallet','Microsoft.WindowsFeedbackHub',
           'Microsoft.WindowsMaps','Microsoft.Messaging','Microsoft.YourPhone','Microsoft.549981C3F5F10',
           'Microsoft.Todos','Microsoft.PowerAutomateDesktop','MicrosoftTeams','Clipchamp.Clipchamp',
           '*king.com*','*CandyCrush*','*BubbleWitch*','*Spotify*','*Disney*','*TikTok*','*Facebook*',
           '*Twitter*','*Netflix*','*Hulu*','*Dolby*','*HiddenCity*','*MarchofEmpires*','*FarmVille*','*Duolingo*'
  foreach ($b in $bloat) {
    foreach ($p in @(Get-AppxPackage -AllUsers -Name $b)) {
      if ($p) { Remove-AppxPackage -Package $p.PackageFullName -AllUsers; $script:Changed++; Info "[+] Removed app: $($p.Name)" }
    }
    foreach ($p in @(Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $b)) {
      if ($p) { Remove-AppxProvisionedPackage -Online -PackageName $p.PackageName | Out-Null; $script:Changed++; Info "[+] Unprovisioned: $($p.DisplayName)" }
    }
  }

  Write-Host ("  Debloat: {0} changed, {1} already set." -f $script:Changed, $script:Already) -ForegroundColor Green
  Write-Host '  Left alone on purpose: activation, Windows Update, Defender + SmartScreen, Store, Xbox, Edge, OneDrive.' -ForegroundColor DarkGray
  Write-Host '  Big updates can re-enable some of this - just re-run with -Debloat.' -ForegroundColor DarkGray
}

# ---------------------------------------------------------------- summary
Section 'SUMMARY'
$Flags | Export-Csv (Join-Path $ReportDir 'findings.csv') -NoTypeInformation
$hi = @($Flags | Where-Object Severity -eq 'HIGH').Count
$md = @($Flags | Where-Object Severity -eq 'MED').Count
$lo = @($Flags | Where-Object Severity -eq 'LOW').Count
Write-Host ("  HIGH: {0}   MED: {1}   LOW: {2}" -f $hi, $md, $lo)
if ($hi -gt 0) {
  Write-Host "`n  HIGH findings present. Do NOT sign in to anything until each is explained." -ForegroundColor Red
  Write-Host "  If you can't explain them: wipe and reinstall Windows from official Microsoft media." -ForegroundColor Red
  $Flags | Where-Object Severity -eq 'HIGH' | ForEach-Object { Write-Host "   - $($_.Area): $($_.Detail)" -ForegroundColor Red }
} elseif ($md -gt 0) {
  Write-Host "`n  No HIGH findings. Review the MED items above, then you're reasonably clear." -ForegroundColor Yellow
} else {
  Write-Host "`n  Clean on every check this script runs." -ForegroundColor Green
}
Write-Host "  Full report: $ReportDir"
if ($Harden -or $Debloat) { Write-Host '  Reboot to finish applying changes.' -ForegroundColor Yellow }

Stop-Transcript | Out-Null

if ($OfflineScan) {
  $ans = Read-Host "`nDefender Offline scan reboots NOW and scans before Windows loads (~15 min). Type YES to start"
  if ($ans -eq 'YES') { Start-MpWDOScan }
}
