<#
.SYNOPSIS
    Preventive Maintenance - Read-Only System Health Report Generator

.DESCRIPTION
    Safely audits a Windows PC and produces an HTML report. This script is
    100% READ-ONLY:
        - No files are deleted
        - No settings are changed
        - No updates/apps are installed
        - No reboot is triggered
    It only inspects the system and writes a report to disk.

    Designed to be safe to run on ANY Windows machine (desktop or laptop,
    SSD or HDD, domain-joined or standalone, single or multi-user), with
    detection logic so checks that don't apply are skipped and clearly
    labeled "N/A" instead of throwing errors or giving misleading results.

.NOTES
    - Run in PowerShell 5.1+ (Windows 10/11).
    - Administrator rights are NOT required, but a few checks (SMART
      status, some security-center queries) return more detail when run
      elevated. The script auto-detects this and labels results either way.
    - No parameter needed. Just run it.

.OUTPUT
    An HTML report saved to the current user's Desktop, named:
    PM-Report_<ComputerName>_<yyyyMMdd_HHmmss>.html
#>

# ============================================================
#  SETUP
# ============================================================

$ErrorActionPreference = 'SilentlyContinue'   # never let one bad check kill the script
$ProgressPreference    = 'SilentlyContinue'   # keep console clean

$startTime   = Get-Date
$computer    = $env:COMPUTERNAME
$reportName  = "PM-Report_${computer}_$($startTime.ToString('yyyyMMdd_HHmmss')).html"
$desktopPath = [Environment]::GetFolderPath('Desktop')
$reportPath  = Join-Path $desktopPath $reportName

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Collect all findings into this ordered list of sections.
# Each section = @{ Title = "..."; Rows = @(...) ; Note = "optional caveat" }
$Sections = New-Object System.Collections.Generic.List[object]

function New-Section {
    param($Title, $Rows, $Note = $null)
    $Sections.Add([PSCustomObject]@{ Title = $Title; Rows = $Rows; Note = $Note })
}

Write-Host "Preventive Maintenance Report - starting checks on $computer ..." -ForegroundColor Cyan
Write-Host ("Running as Administrator: {0}" -f $isAdmin) -ForegroundColor DarkGray

# ============================================================
#  1. SYSTEM OVERVIEW
# ============================================================
Write-Host "[1/12] System overview..."

$os        = Get-CimInstance Win32_OperatingSystem
$cs        = Get-CimInstance Win32_ComputerSystem
$bios      = Get-CimInstance Win32_BIOS
$uptime    = (Get-Date) - $os.LastBootUpTime

# Chassis type -> determine desktop vs laptop (for battery check later)
$chassisTypes = (Get-CimInstance Win32_SystemEnclosure).ChassisTypes
$laptopChassisCodes = @(8,9,10,11,12,14,18,21,30,31,32)
$isLaptop = $false
foreach ($c in $chassisTypes) { if ($laptopChassisCodes -contains $c) { $isLaptop = $true } }

# Domain-joined? (matters because GPO can silently override local settings)
$isDomainJoined = $cs.PartOfDomain

# MAC address(es) - only active/physical adapters, skip virtual/disabled ones
$macAddresses = Get-CimInstance Win32_NetworkAdapter | Where-Object {
    $_.PhysicalAdapter -eq $true -and $_.MACAddress -and $_.NetEnabled -eq $true
} | ForEach-Object { "$($_.MACAddress) ($($_.NetConnectionID))" }

$macValue = if ($macAddresses) { $macAddresses -join "; " } else { "No active physical adapter found" }

$sysRows = @(
    [PSCustomObject]@{ Item = "Computer Name";      Value = $computer }
    [PSCustomObject]@{ Item = "Manufacturer/Model";  Value = "$($cs.Manufacturer) $($cs.Model)" }
    [PSCustomObject]@{ Item = "MAC Address(es)"; Value = $macValue }
    [PSCustomObject]@{ Item = "Chassis Type";        Value = if ($isLaptop) { "Laptop" } else { "Desktop / Other (non-laptop)" } }
    [PSCustomObject]@{ Item = "OS";                  Value = "$($os.Caption) (Build $($os.BuildNumber)), $($os.OSArchitecture)" }
    [PSCustomObject]@{ Item = "BIOS/UEFI Version";   Value = $bios.SMBIOSBIOSVersion }
    [PSCustomObject]@{ Item = "Last Boot Time";      Value = $os.LastBootUpTime }
    [PSCustomObject]@{ Item = "System Uptime";       Value = "{0}d {1}h {2}m" -f $uptime.Days,$uptime.Hours,$uptime.Minutes }
    [PSCustomObject]@{ Item = "Domain Joined";       Value = if ($isDomainJoined) { "Yes ($($cs.Domain)) - some settings may be enforced by Group Policy" } else { "No (standalone/workgroup)" } }
    [PSCustomObject]@{ Item = "Script Run As Admin"; Value = $isAdmin }
)
New-Section -Title "1. System Overview" -Rows $sysRows

# ============================================================
#  2. CPU & MEMORY (current snapshot - fast, no monitoring loop)
# ============================================================
Write-Host "[2/12] CPU and memory snapshot..."

$cpu       = Get-CimInstance Win32_Processor | Select-Object -First 1
$cpuLoad   = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
$totalRAM  = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
$freeRAM   = [math]::Round($os.FreePhysicalMemory / 1MB, 2)   # FreePhysicalMemory is in KB
$usedRAMPct = [math]::Round((($totalRAM - $freeRAM) / $totalRAM) * 100, 1)

# CPU temperature: not exposed on most consumer boards without OEM/vendor
# tools or elevated WMI namespaces. Try the standard thermal zone; skip
# quietly if unavailable rather than guessing.
$cpuTempC = $null
try {
    $temp = Get-CimInstance -Namespace "root/wmi" -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop
    if ($temp) {
        $cpuTempC = [math]::Round((($temp[0].CurrentTemperature) / 10 - 273.15), 1)
    }
} catch { $cpuTempC = $null }

$cpuRows = @(
    [PSCustomObject]@{ Item = "CPU";                Value = $cpu.Name }
    [PSCustomObject]@{ Item = "Current CPU Load";   Value = "$cpuLoad %" }
    [PSCustomObject]@{ Item = "Total RAM";          Value = "$totalRAM GB" }
    [PSCustomObject]@{ Item = "RAM In Use";         Value = "$usedRAMPct %" }
    [PSCustomObject]@{ Item = "CPU Temperature";    Value = if ($cpuTempC) { "$cpuTempC C" } else { "Not accessible on this hardware/OEM (requires vendor tool - not an error)" } }
)
New-Section -Title "2. CPU & Memory" -Rows $cpuRows -Note "CPU load is a point-in-time snapshot, not a sustained average."

# ============================================================
#  3. DISK INVENTORY - ALL FIXED VOLUMES, NOT JUST C:
# ============================================================
Write-Host "[3/12] Disk inventory (all drives, SSD/HDD auto-detected)..."

$diskRows = @()
$defragNote = @()

$physicalDisks = Get-PhysicalDisk
$volumes = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter }

foreach ($vol in $volumes) {
    $letter = $vol.DriveLetter
    $sizeGB = [math]::Round($vol.Size / 1GB, 1)
    $freeGB = [math]::Round($vol.SizeRemaining / 1GB, 1)
    $freePct = if ($vol.Size -gt 0) { [math]::Round(($vol.SizeRemaining / $vol.Size) * 100, 1) } else { 0 }

    # Try to map this volume back to a physical disk to get media type (SSD/HDD)
    $mediaType = "Unknown"
    try {
        $partition = Get-Partition -DriveLetter $letter -ErrorAction Stop
        $physDisk  = Get-PhysicalDisk -DeviceNumber $partition.DiskNumber -ErrorAction Stop
        $mediaType = $physDisk.MediaType
        if (-not $mediaType -or $mediaType -eq 'Unspecified') { $mediaType = "Unknown (could not confirm SSD/HDD)" }
    } catch { $mediaType = "Unknown (e.g. removable/virtual/RAID volume)" }

    # Low space flag is PERCENTAGE-based (fair for both a 128GB SSD and 2TB HDD)
    $spaceFlag = if ($freePct -lt 10) { "LOW SPACE" } elseif ($freePct -lt 20) { "Getting full" } else { "OK" }

    $diskRows += [PSCustomObject]@{ Item = "Drive $letter`:"; Value = "$freeGB GB free of $sizeGB GB ($freePct% free) - $spaceFlag - Media: $mediaType" }

    if ($mediaType -like "SSD*") {
        $defragNote += "Drive $letter`: is SSD - defrag skipped (would reduce SSD lifespan, not needed)."
    } elseif ($mediaType -like "HDD*") {
        $defragNote += "Drive $letter`: is HDD - defrag analysis recommended periodically (not run automatically by this script)."
    } else {
        $defragNote += "Drive $letter`: media type could not be confirmed - defrag left to manual judgment."
    }
}
New-Section -Title "3. Disk Space & Media Type (all fixed drives)" -Rows $diskRows -Note ($defragNote -join " ")

# ============================================================
#  4. DISK HEALTH (SMART) - per physical disk, skip gracefully if unsupported
# ============================================================
Write-Host "[4/12] Disk health (SMART, where supported)..."

$smartRows = @()
foreach ($pd in $physicalDisks) {
    $status = $pd.HealthStatus
    $smartRows += [PSCustomObject]@{ Item = "$($pd.FriendlyName) ($($pd.MediaType))"; Value = "Health: $status | Bus: $($pd.BusType)" }
}
if ($smartRows.Count -eq 0) {
    $smartRows += [PSCustomObject]@{ Item = "SMART Data"; Value = "Not available on this system (common on some USB/RAID-controlled drives)" }
}
New-Section -Title "4. Disk Health (SMART Status)" -Rows $smartRows -Note "External/USB or RAID-controlled drives may not expose SMART data - this is normal, not a failure."

# ============================================================
#  5. BATTERY (laptops only)
# ============================================================
Write-Host "[5/12] Battery check (if applicable)..."

if ($isLaptop) {
    $battery = Get-CimInstance Win32_Battery
    if ($battery) {
        $battRows = @(
            [PSCustomObject]@{ Item = "Battery Status";        Value = $battery.Status }
            [PSCustomObject]@{ Item = "Estimated Charge";      Value = "$($battery.EstimatedChargeRemaining)%" }
        )
    } else {
        $battRows = @([PSCustomObject]@{ Item = "Battery"; Value = "Laptop chassis detected, but no battery info reported (may be removed/desktop-replacement unit)" })
    }
} else {
    $battRows = @([PSCustomObject]@{ Item = "Battery"; Value = "N/A - desktop/non-laptop chassis detected" })
}
New-Section -Title "5. Battery Health" -Rows $battRows

# ============================================================
#  6. SECURITY: ANTIVIRUS + FIREWALL
# ============================================================
Write-Host "[6/12] Security status (AV + firewall)..."

$secRows = @()
try {
    $avProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop
    if ($avProducts) {
        foreach ($av in $avProducts) {
            # productState decode is unreliable across vendors; report name + raw enabled bit only
            $secRows += [PSCustomObject]@{ Item = "Antivirus Product"; Value = $av.displayName }
        }
    } else {
        $secRows += [PSCustomObject]@{ Item = "Antivirus Product"; Value = "None detected via Security Center (may still be present but unregistered)" }
    }
} catch {
    $secRows += [PSCustomObject]@{ Item = "Antivirus Product"; Value = "Could not query Security Center (some SKUs restrict this API)" }
}

try {
    $fw = Get-NetFirewallProfile -ErrorAction Stop
    foreach ($profile in $fw) {
        $secRows += [PSCustomObject]@{ Item = "Firewall ($($profile.Name) profile)"; Value = if ($profile.Enabled) { "Enabled" } else { "DISABLED" } }
    }
} catch {
    $secRows += [PSCustomObject]@{ Item = "Firewall"; Value = "Could not query firewall status" }
}
New-Section -Title "6. Security (Antivirus & Firewall)" -Rows $secRows -Note "This is a status check only - no scan is run (a full AV scan is intentionally excluded to avoid long delays)."

# ============================================================
#  7. WINDOWS UPDATE - CHECK ONLY, NEVER INSTALL, NEVER REBOOT
# ============================================================
Write-Host "[7/12] Checking for available Windows updates (metadata only, no install)..."

$wuRows = @()
try {
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    $searchResult = $updateSearcher.Search("IsInstalled=0 and IsHidden=0")
    $pendingCount = $searchResult.Updates.Count
    if ($pendingCount -gt 0) {
        $titles = @()
        for ($i = 0; $i -lt [Math]::Min($pendingCount, 5); $i++) { $titles += $searchResult.Updates.Item($i).Title }
        $wuRows += [PSCustomObject]@{ Item = "Pending Updates"; Value = "$pendingCount update(s) available" }
        $wuRows += [PSCustomObject]@{ Item = "Examples (up to 5)"; Value = ($titles -join "; ") }
    } else {
        $wuRows += [PSCustomObject]@{ Item = "Pending Updates"; Value = "None - system is up to date" }
    }
} catch {
    $wuRows += [PSCustomObject]@{ Item = "Pending Updates"; Value = "Could not check (no internet, or update service disabled/managed by IT policy)" }
}
New-Section -Title "7. Windows Update Status" -Rows $wuRows -Note "Check only - nothing is downloaded, installed, or rebooted by this script."

# ============================================================
#  8. STARTUP PROGRAMS (list only - not modified)
# ============================================================
Write-Host "[8/12] Startup programs (listing only, nothing disabled)..."

$startupItems = Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User
$startRows = @()
if ($startupItems) {
    foreach ($item in $startupItems) {
        $startRows += [PSCustomObject]@{ Item = $item.Name; Value = "$($item.Command)  [User: $($item.User)]" }
    }
} else {
    $startRows += [PSCustomObject]@{ Item = "Startup Items"; Value = "None found" }
}
New-Section -Title "8. Startup Programs (informational - review with user before disabling anything)" -Rows $startRows -Note "Some items (OEM utilities, docking station/driver helpers) look 'unnecessary' but are needed - do not mass-disable without checking with the user."

# ============================================================
#  9. TEMP FILE SIZE - ALL USER PROFILES, SIZE ONLY, NOTHING DELETED
# ============================================================
Write-Host "[9/12] Estimating reclaimable temp file space (all user profiles, read-only)..."

$tempRows = @()
$userProfiles = Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special -and (Test-Path $_.LocalPath) }

foreach ($profile in $userProfiles) {
    $userTemp = Join-Path $profile.LocalPath "AppData\Local\Temp"
    if (Test-Path $userTemp) {
        $sizeMB = [math]::Round(((Get-ChildItem $userTemp -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB), 1)
        $profileName = Split-Path $profile.LocalPath -Leaf
        $tempRows += [PSCustomObject]@{ Item = "User: $profileName"; Value = "~$sizeMB MB in Temp folder (not deleted - review with user first)" }
    }
}
$winTemp = "$env:WINDIR\Temp"
if (Test-Path $winTemp) {
    $winTempMB = [math]::Round(((Get-ChildItem $winTemp -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB), 1)
    $tempRows += [PSCustomObject]@{ Item = "System-wide (Windows\Temp)"; Value = "~$winTempMB MB" }
}
if ($tempRows.Count -eq 0) { $tempRows += [PSCustomObject]@{ Item = "Temp Files"; Value = "Could not enumerate user profiles" } }
New-Section -Title "9. Temp File Space (all users - reporting only, nothing deleted)" -Rows $tempRows

# ============================================================
#  10. RECENT SYSTEM ERRORS/WARNINGS (COUNT ONLY - fast, not a full dump)
# ============================================================
Write-Host "[10/12] Scanning recent event log for errors/warnings (last 48 hours, summary only)..."

$evtRows = @()
try {
    $since = (Get-Date).AddHours(-48)
    $sysErrors = Get-WinEvent -FilterHashtable @{ LogName='System'; Level=2,3; StartTime=$since } -MaxEvents 200 -ErrorAction Stop
    $errCount  = ($sysErrors | Where-Object { $_.Level -eq 2 }).Count
    $warnCount = ($sysErrors | Where-Object { $_.Level -eq 3 }).Count
    $evtRows += [PSCustomObject]@{ Item = "System Log - Errors (last 48h)"; Value = $errCount }
    $evtRows += [PSCustomObject]@{ Item = "System Log - Warnings (last 48h)"; Value = $warnCount }

    if ($errCount -gt 0) {
        $topErr = $sysErrors | Where-Object { $_.Level -eq 2 } | Select-Object -First 3
        foreach ($e in $topErr) {
            $shortMsg = ($e.Message -split "`n")[0]
            $evtRows += [PSCustomObject]@{ Item = "  Sample Error ($($e.TimeCreated))"; Value = $shortMsg }
        }
    }
} catch {
    $evtRows += [PSCustomObject]@{ Item = "Event Log"; Value = "Could not read System log (may require Administrator rights)" }
}
New-Section -Title "10. Recent Event Log Summary (last 48 hours)" -Rows $evtRows -Note "Summary counts only - capped at 200 events - to keep the script fast."

# ============================================================
#  11. NETWORK CONNECTIVITY + INTERNET SPEED TEST
# ============================================================
Write-Host "[11/12] Network connectivity and internet speed test (this step takes ~15-30 seconds)..."

$netRows = @()

$pingResult = Test-Connection -ComputerName "8.8.8.8" -Count 2 -ErrorAction SilentlyContinue
if ($pingResult) {
    $avgLatency = ($pingResult | Measure-Object -Property ResponseTime -Average).Average
    $netRows += [PSCustomObject]@{ Item = "Internet Connectivity"; Value = "Connected (avg latency: $([math]::Round($avgLatency,0)) ms)" }
} else {
    $netRows += [PSCustomObject]@{ Item = "Internet Connectivity"; Value = "No response - offline or ICMP blocked by network" }
}

# Speed test strategy:
#   1) Use speedtest-cli / Ookla CLI if already installed (fast, accurate).
#   2) Otherwise fall back to a timed download of a known-size test file.
#      This fallback is approximate (single-threaded, single-server) but
#      gives a usable ballpark without installing anything new.
$speedTestRan = $false

$speedtestExe = Get-Command "speedtest.exe" -ErrorAction SilentlyContinue
if (-not $speedtestExe) { $speedtestExe = Get-Command "speedtest-cli.exe" -ErrorAction SilentlyContinue }

if ($speedtestExe -and $pingResult) {
    try {
        $raw = & $speedtestExe.Source --format=json 2>$null
        $json = $raw | ConvertFrom-Json
        if ($json.download) {
            $dlMbps = [math]::Round($json.download.bandwidth * 8 / 1MB, 1)
            $ulMbps = [math]::Round($json.upload.bandwidth * 8 / 1MB, 1)
            $netRows += [PSCustomObject]@{ Item = "Internet Speed Test (Ookla CLI)"; Value = "Download: $dlMbps Mbps | Upload: $ulMbps Mbps | Server: $($json.server.name)" }
            $speedTestRan = $true
        }
    } catch { $speedTestRan = $false }
}

if (-not $speedTestRan -and $pingResult) {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

    $cfDownloadUrl = "https://speed.cloudflare.com/__down?bytes=25000000"
    $cfMetaUrl     = "https://speed.cloudflare.com/meta"

    try {
        $cfMeta = $null
        try { $cfMeta = Invoke-RestMethod -Uri $cfMetaUrl -TimeoutSec 10 -ErrorAction Stop } catch { $cfMeta = $null }

        $tmpFile = Join-Path $env:TEMP "pm_speedtest_tmp.bin"
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        Invoke-WebRequest -Uri $cfDownloadUrl -OutFile $tmpFile -TimeoutSec 30 -ErrorAction Stop
        $sw.Stop()

        $fileSizeMB = (Get-Item $tmpFile).Length / 1MB
        $seconds = [math]::Max($sw.Elapsed.TotalSeconds, 0.1)
        $mbps = [math]::Round(($fileSizeMB * 8) / $seconds, 1)
        Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue

        $serverInfo = if ($cfMeta -and $cfMeta.colo) { " | Cloudflare edge: $($cfMeta.colo)" } else { "" }
        $netRows += [PSCustomObject]@{ Item = "Internet Speed Test (Cloudflare)"; Value = "~$mbps Mbps download (approximate, single connection)$serverInfo" }
        $speedTestRan = $true
    } catch {
        $netRows += [PSCustomObject]@{ Item = "Internet Speed Test"; Value = "Could not run - $($_.Exception.Message)" }
    }
} elseif (-not $pingResult) {
    $netRows += [PSCustomObject]@{ Item = "Internet Speed Test"; Value = "Skipped - no internet connectivity detected" }
}

New-Section -Title "11. Network & Internet Speed" -Rows $netRows -Note "Fallback speed test is a single-threaded approximation, not a lab-accurate measurement - result can vary with current network load."

# ============================================================
#  12. BROWSER EXTENSIONS (basic count per profile - informational)
# ============================================================
Write-Host "[12/12] Browser extension inventory (Chrome/Edge, count only)..."

$extRows = @()
foreach ($profile in $userProfiles) {
    foreach ($browserInfo in @(
        @{ Name = "Chrome"; Path = "AppData\Local\Google\Chrome\User Data\Default\Extensions" },
        @{ Name = "Edge";   Path = "AppData\Local\Microsoft\Edge\User Data\Default\Extensions" }
    )) {
        $extPath = Join-Path $profile.LocalPath $browserInfo.Path
        if (Test-Path $extPath) {
            $count = (Get-ChildItem $extPath -Directory -ErrorAction SilentlyContinue).Count
            $userName = Split-Path $profile.LocalPath -Leaf
            $extRows += [PSCustomObject]@{ Item = "$($browserInfo.Name) - User: $userName"; Value = "$count extension(s) installed" }
        }
    }
}
if ($extRows.Count -eq 0) { $extRows += [PSCustomObject]@{ Item = "Browser Extensions"; Value = "No Chrome/Edge profiles found, or browsers not installed" } }
New-Section -Title "12. Browser Extensions (count only - review manually for anything suspicious)" -Rows $extRows -Note "Count only, by design - identifying malicious extensions reliably needs a security tool, not a PM script."

# ============================================================
#  BUILD HTML REPORT
# ============================================================
Write-Host "`nAll checks complete. Generating report..." -ForegroundColor Cyan

$endTime = Get-Date
$duration = [math]::Round(($endTime - $startTime).TotalSeconds, 1)

$htmlSections = ""
foreach ($section in $Sections) {
    $rowsHtml = ""
    foreach ($row in $section.Rows) {
        $rowsHtml += "<tr><td class='item'>$($row.Item)</td><td class='value'>$($row.Value)</td></tr>`n"
    }
    $noteHtml = if ($section.Note) { "<p class='note'>Note: $($section.Note)</p>" } else { "" }
    $htmlSections += @"
<div class="section">
  <h2>$($section.Title)</h2>
  <table>$rowsHtml</table>
  $noteHtml
</div>
"@
}

$html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>PM Report - $computer</title>
<style>
  body { font-family: Segoe UI, Arial, sans-serif; background:#f4f6f8; color:#1a1a1a; margin:0; padding:0; }
  header { background:#1f3a5f; color:#fff; padding:24px 32px; }
  header h1 { margin:0; font-size:22px; }
  header p { margin:4px 0 0; font-size:13px; color:#cfd8e3; }
  .container { max-width: 900px; margin: 24px auto; padding: 0 16px; }
  .section { background:#fff; border-radius:8px; padding:18px 22px; margin-bottom:18px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
  .section h2 { font-size:16px; margin-top:0; color:#1f3a5f; border-bottom:1px solid #e5e9ee; padding-bottom:8px; }
  table { width:100%; border-collapse: collapse; font-size: 13px; }
  td { padding:6px 4px; vertical-align: top; border-bottom: 1px solid #f0f2f4; }
  td.item { width: 35%; font-weight:600; color:#33475b; }
  td.value { color:#1a1a1a; word-break: break-word; }
  .note { font-size:12px; color:#7a8794; font-style: italic; margin: 10px 0 0; }
  footer { text-align:center; font-size:12px; color:#8a97a5; padding: 20px; }
</style>
</head>
<body>
<header>
  <h1>Preventive Maintenance Report</h1>
  <p>$computer &nbsp;|&nbsp; Generated: $($endTime.ToString('yyyy-MM-dd HH:mm:ss')) &nbsp;|&nbsp; Scan duration: $duration sec &nbsp;|&nbsp; Read-only scan - no changes were made to this system</p>
</header>
<div class="container">
$htmlSections
</div>
<footer>Automated PM report - all checks are read-only. Any recommended actions should be confirmed with the user before applying.</footer>
</body>
</html>
"@

$html | Out-File -FilePath $reportPath -Encoding UTF8

Write-Host "`nReport saved to: $reportPath" -ForegroundColor Green
Write-Host "Total time: $duration seconds. No files were deleted, no settings changed, no reboot performed." -ForegroundColor Green

# Optionally open the report automatically
Invoke-Item $reportPath