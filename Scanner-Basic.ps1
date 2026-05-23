Clear-Host
$ErrorActionPreference = "SilentlyContinue"

Write-Host "========================================" -ForegroundColor Magenta
Write-Host "     ADVANCED FORENSIC SS TOOL          " -ForegroundColor Magenta
Write-Host "          Create by dnbbs               " -ForegroundColor Magenta
Write-Host " https://discord.gg/w3rcWj8BPs          " -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host ""

Write-Host "[*] SYSTEM INFORMATION" -ForegroundColor Cyan
$os = Get-CimInstance Win32_OperatingSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -ExpandProperty Name
$boot = $os.LastBootUpTime
$uptime = (Get-Date) - $boot

Write-Host (" OS Version : {0} {1}" -f $os.Caption, $os.Version) -ForegroundColor White
Write-Host (" Processor  : {0}" -f $cpu) -ForegroundColor White
Write-Host (" User       : {0}" -f $env:USERNAME) -ForegroundColor White
Write-Host (" Last Boot  : {0}" -f $boot) -ForegroundColor White
Write-Host (" Uptime     : {0}d, {1}h, {2}m" -f $uptime.Days, $uptime.Hours, $uptime.Minutes) -ForegroundColor White

Write-Host "`n[*] STORAGE & DRIVES (DETAILED)" -ForegroundColor Cyan

Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -in 2,3 } | ForEach-Object {
    $free = [math]::Round($_.FreeSpace / 1GB, 2)
    $total = [math]::Round($_.Size / 1GB, 2)

    $type = if ($_.DriveType -eq 2) { "REMOVABLE" } else { "LOCAL" }

    Write-Host (" Drive {0} [{1}] - {2} ({3}) | Free: {4}GB / {5}GB" -f $_.DeviceID, $type, $_.VolumeName, $_.FileSystem, $free, $total) -ForegroundColor White
}

Write-Host "`n[*] USB FORENSIC HISTORY" -ForegroundColor Cyan

$usbPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"

if (Test-Path $usbPath) {

    $usbDevices = Get-ChildItem $usbPath | Get-ChildItem
    $usbList = @()

    foreach ($dev in $usbDevices) {

        $props = Get-ItemProperty $dev.PSPath -ErrorAction SilentlyContinue

        $friendly = $props.FriendlyName
        if (-not $friendly) { $friendly = $dev.PSChildName }

        $regKey = Get-Item $dev.PSPath
        $lastWrite = $regKey.LastWriteTime

        $serial = $dev.PSChildName

        $usbList += [PSCustomObject]@{
            Name       = $friendly
            Serial     = $serial
            LastSeen   = $lastWrite
        }
    }

    if ($usbList.Count -gt 0) {

        $usbList = $usbList | Sort-Object LastSeen -Descending

        foreach ($usb in $usbList | Select-Object -First 10) {

            Write-Host " [USB DEVICE]" -ForegroundColor Yellow
            Write-Host ("    Name    : {0}" -f $usb.Name)
            Write-Host ("    Serial  : {0}" -f $usb.Serial)
            Write-Host ("    LastUse : {0}" -f $usb.LastSeen)
        }

    } else {
        Write-Host " No USB history found." -ForegroundColor DarkGray
    }

} else {
    Write-Host " USB registry not accessible." -ForegroundColor DarkGray
}

Write-Host "`n[*] USB LAST REMOVAL EVENTS" -ForegroundColor Cyan

$usbEvents = Get-WinEvent -FilterHashtable @{
    LogName = "System"
    ID = 2100,2102
} -MaxEvents 20 -ErrorAction SilentlyContinue

if ($usbEvents) {

    foreach ($evt in $usbEvents) {

        $msg = $evt.Message.ToLower()

        if ($msg -match "usb" -or $msg -match "disk") {

            Write-Host " [USB REMOVAL DETECTED]" -ForegroundColor Red
            Write-Host ("    Time : {0}" -f $evt.TimeCreated)
            Write-Host ("    Info : {0}" -f $evt.Message.Substring(0,150)) -ForegroundColor Gray
        }
    }

} else {
    Write-Host " No recent USB removal events found." -ForegroundColor Green
}

Write-Host "`n[*] RECENT USB CONNECTION" -ForegroundColor Cyan

$connectEvents = Get-WinEvent -FilterHashtable @{
    LogName = "System"
    ID = 2003
} -MaxEvents 20 -ErrorAction SilentlyContinue

if ($connectEvents) {

    foreach ($evt in $connectEvents) {

        if ($evt.Message -match "USB") {

            Write-Host " [USB CONNECTED]" -ForegroundColor Green
            Write-Host ("    Time : {0}" -f $evt.TimeCreated)
            Write-Host ("    Info : {0}" -f $evt.Message.Substring(0,150)) -ForegroundColor Gray
        }
    }

} else {
    Write-Host " No recent USB connection events." -ForegroundColor DarkGray
}

Write-Host "`n[*] DELETED EVENT LOGS" -ForegroundColor Cyan
$logclear = Get-WinEvent -FilterHashtable @{LogName = @("System", "Security"); ID = @(104, 1102) } -MaxEvents 5
if ($logclear) {
    foreach ($log in $logclear) {
        Write-Host (" [!] LOG CLEARED - {0} at {1}" -f $log.LogName, $log.TimeCreated) -ForegroundColor Red
    }
}
else {
    Write-Host " No recent log clears detected." -ForegroundColor Green
}

Write-Host "`n[*] SERVICES STATUS" -ForegroundColor Cyan
$services = "SysMain", "PcaSvc", "DPS", "EventLog", "Schedule", "bam", "DusmSvc", "Appinfo", "DcomLaunch", "PlugPlay", "wsearch", "wuauserv", "windefend"

foreach ($s in $services) {
    $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
    if ($svc) {
        $color = if ($svc.Status -eq "Running") { "Green" } else { "Red" }
        Write-Host (" {0,-15} : {1}" -f $s, $svc.Status) -ForegroundColor $color
    }
    else {
        Write-Host (" {0,-15} : Not Found (SUSPICIOUS)" -f $s) -ForegroundColor DarkGray
    }
}

Write-Host "`n[*] SYSMON CHECK" -ForegroundColor Cyan

$svc = Get-Service -Name "Sysmon64", "Sysmon" -ErrorAction SilentlyContinue

if ($svc) {
    Write-Host "[SYSMON INSTALLED]" -ForegroundColor Green
    
    foreach ($s in $svc) {
        Write-Host (" -> Service: {0} | Status: {1}" -f $s.Name, $s.Status)
    }

    $regPaths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon64",
        "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon"
    )

    $sysPath = $null

    foreach ($reg in $regPaths) {
        $path = (Get-ItemProperty $reg -ErrorAction SilentlyContinue).ImagePath
        if ($path) {
            $sysPath = $path -replace '"', '' -replace ' -.*', ''
            break
        }
    }

    if ($sysPath -and (Test-Path $sysPath)) {
        Write-Host (" -> Path: {0}" -f $sysPath) -ForegroundColor Yellow

        $version = (Get-Item $sysPath).VersionInfo.FileVersion
        Write-Host (" -> Version: {0}" -f $version) -ForegroundColor Cyan

        if ($version -match "^15") {
            Write-Host " -> STATUS: UPDATED ✅" -ForegroundColor Green
        }
        elseif ($version -match "^13|^14") {
            Write-Host " -> STATUS: OK (not latest) ⚠️" -ForegroundColor Yellow
        }
        else {
            Write-Host " -> STATUS: OUTDATED ❌" -ForegroundColor Red
        }

    }
    else {
        Write-Host " -> Could not find executable path" -ForegroundColor DarkGray
    }

}
else {
    Write-Host "[SYSMON NOT INSTALLED]" -ForegroundColor Red
}

Write-Host "`n[*] RECYCLE BIN ANALYSIS" -ForegroundColor Cyan

$shell = New-Object -ComObject Shell.Application
$bin = $shell.Namespace(0xA)

$susKeywords = @("cheat","inject","spoofer","aim","hack","bypass","mod","dump","dll","loader")

if ($bin -and $bin.Items().Count -gt 0) {

    Write-Host (" Total Items: {0}" -f $bin.Items().Count) -ForegroundColor Yellow

    $binItems = @()

    foreach ($item in $bin.Items()) {

        $delDate = $item.ExtendedProperty("System.Recycle.DateDeleted")
        $origPath = $item.ExtendedProperty("System.ItemFolderPathDisplay")
        $sizeMB = [math]::Round($item.Size / 1MB, 2)

        $nameLower = $item.Name.ToLower()

        $minutesAgo = 0
        if ($delDate) {
            $minutesAgo = [math]::Round(((Get-Date) - $delDate).TotalMinutes,1)
        }

        $risk = "LOW"
        $color = "Green"
        $reason = ""

        if ($nameLower -match "\.exe|\.dll|\.bat|\.ps1") {
            $risk = "MEDIUM"
            $color = "Yellow"
            $reason = "Executable deleted"
        }

        foreach ($k in $susKeywords) {
            if ($nameLower -match $k) {
                $risk = "HIGH"
                $color = "Red"
                $reason = "Keyword match: $k"
                break
            }
        }

        if ($sizeMB -gt 50 -and $risk -ne "HIGH") {
            $risk = "MEDIUM"
            $color = "Yellow"
            $reason = "Large file"
        }

        if ($minutesAgo -lt 30 -and $minutesAgo -gt 0) {
            $risk = "HIGH"
            $color = "Red"
            $reason = "Recently deleted"
        }

        $binItems += [PSCustomObject]@{
            Name     = $item.Name
            Size     = $sizeMB
            Deleted  = $delDate
            Minutes  = $minutesAgo
            Path     = $origPath
            Risk     = $risk
            Reason   = $reason
            Color    = $color
        }
    }

    $binItems = $binItems | Sort-Object Deleted -Descending

    foreach ($item in $binItems | Select-Object -First 20) {

        Write-Host (" [{0}] {1} ({2} MB)" -f $item.Risk, $item.Name, $item.Size) -ForegroundColor $item.Color

        Write-Host ("    Deleted : {0} ({1} min ago)" -f $item.Deleted, $item.Minutes)

        if ($item.Reason) {
            Write-Host ("    Reason  : {0}" -f $item.Reason) -ForegroundColor DarkGray
        }

        Write-Host ("    Origin  : {0}" -f $item.Path) -ForegroundColor DarkGray
    }

}
else {
    Write-Host " Recycle Bin is Empty" -ForegroundColor Green
}

Write-Host "`n[*] BAM EXECUTION (BOOT -> NOW)" -ForegroundColor Cyan

$bamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
$validExt = @(".exe", ".dll", ".tmp")

$bootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

Write-Host " System Boot Time: $bootTime`n" -ForegroundColor DarkGray

$windowsOnly = @(
    "c:\windows\system32\",
    "c:\windows\syswow64\",
    "c:\windows\"
)

function Convert-DevicePath {
    param ($path)

    if ($path -match "\\device\\harddiskvolume\d+") {
        return $path -replace "\\device\\harddiskvolume\d+", "C:"
    }

    return $path
}

$results = @()

Get-ChildItem $bamPath | ForEach-Object {

    $bamItems = Get-ItemProperty $_.PSPath

    $bamItems.PSObject.Properties | Where-Object {
        $_.Name -like "*\*"
    } | ForEach-Object {

        $path = $_.Name.ToLower()
        $ext = [System.IO.Path]::GetExtension($path)

        if (-not ($validExt -contains $ext)) { return }

        try {
            $bytes = [byte[]]$_.Value
            $fileTime = [BitConverter]::ToInt64($bytes, 0)
            $date = [DateTime]::FromFileTimeUtc($fileTime).ToLocalTime()
        } catch { return }

        if ($date.Year -lt 2000 -or $date.Year -gt (Get-Date).Year + 1) { return }
        if ($date -lt $bootTime) { return }

        $realPath = Convert-DevicePath $path
        $sigStatus = "Unknown"

        if (Test-Path $realPath) {
            try {
                $sigStatus = (Get-AuthenticodeSignature $realPath).Status
            } catch {}
        }

        $realLower = $realPath.ToLower()

        $skip = $false
        foreach ($w in $windowsOnly) {
            if ($realLower.StartsWith($w) -and $sigStatus -eq "Valid") {
                $skip = $true
                break
            }
        }

        if ($skip) { return }

        $results += [PSCustomObject]@{
            Date = $date
            Path = $realPath
            Signature = $sigStatus
        }
    }
}

$results = $results | Sort-Object Date -Descending

foreach ($item in $results) {

    if ($item.Signature -eq "Valid") {
        Write-Host ("[{0}] [SIGNED]   {1}" -f $item.Date, $item.Path) -ForegroundColor Green
    }
    else {
        Write-Host ("[{0}] [UNSIGNED: {1}] {2}" -f $item.Date, $item.Signature, $item.Path) -ForegroundColor Red
    }
}

Write-Host "`n[*] RECENT FILES ACCESSED" -ForegroundColor Cyan
$recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
if (Test-Path $recentPath) {
    $susRecent = Get-ChildItem $recentPath -Include *.exe.lnk, *.dll.lnk, *.bat.lnk, *.zip.lnk, *.rar.lnk -Recurse -File | Sort-Object LastWriteTime -Descending | Select-Object -First 10
    foreach ($lnk in $susRecent) {
        Write-Host (" [RECENT] {0} (Accessed: {1})" -f $lnk.Name.Replace(".lnk", ""), $lnk.LastWriteTime) -ForegroundColor Yellow
    }
}

Write-Host "`n[*] VERIFY SETTINGS STATUS" -ForegroundColor Cyan

$settings = @(
@{ Name = "CMD"; Path = "HKCU:\Software\Policies\Microsoft\Windows\System"; Key = "DisableCMD"; Warning = "Disabled"; Safe = "Available" },
@{ Name = "PowerShell Logging"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Key = "EnableScriptBlockLogging"; Warning = "Disabled"; Safe = "Enabled" },
@{ Name = "Activities Cache"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Key = "EnableActivityFeed"; Warning = "Disabled"; Safe = "Enabled" }
)

foreach ($s in $settings) {
$status = Get-ItemProperty -Path $s.Path -Name $s.Key -ErrorAction SilentlyContinue
Write-Host "$($s.Name): " -NoNewLine
if ($status -and $status.$($s.Key) -eq 0) {
Write-Host "$($s.Warning)" -ForegroundColor Red
} else {
Write-Host "$($s.Safe)" -ForegroundColor Green
}
}

Write-Host "Check complete."

Write-Host "`n[*] PREFETCH (CLEAN | POST HD-PLAYER)" -ForegroundColor Cyan

$pfPath = "C:\Windows\Prefetch"

$hdProc = Get-Process | Where-Object {
    $_.ProcessName -like "*hd-player*"
} | Select-Object -First 1

if (-not $hdProc) {
    Write-Host " HD-Player not running." -ForegroundColor Red
    return
}

$hdTime = $hdProc.StartTime
Write-Host " HD-Player Start: $hdTime`n" -ForegroundColor DarkGray

$windowsBinaries = @(
    "svchost","dllhost","conhost","cmd","powershell","explorer",
    "taskhostw","searchapp","searchprotocolhost","sihost","dwm",
    "runtimebroker","backgroundtaskhost","audiodg","winlogon",
    "csrss","ctfmon","consent","smartscreen","wmiprvse",
    "dataexchangehost","notepad","msedgewebview2","msedge",
    "werfault","softlandingtask","bstksvc"
)

$pfFiles = Get-ChildItem "$pfPath\*.pf" -ErrorAction SilentlyContinue
$pfList = @()

foreach ($pf in $pfFiles) {

    $nameClean = $pf.Name.Split("-")[0].ToLower().Replace(".exe", "")
    $lastRun = $pf.LastWriteTime

    if ($lastRun -lt $hdTime) {
        continue
    }

    if ($nameClean -in $windowsBinaries) {
        continue
    }

    if ($nameClean -match "^ms|^win|^runtime|^search") {
        continue
    }

    try {
        $bytes = [System.IO.File]::ReadAllBytes($pf.FullName)
        $runCount = [BitConverter]::ToInt32($bytes, 0x90)
    }
    catch {
        $runCount = 0
    }

    if ($runCount -gt 20) {
        continue
    }

    $timeDiff = (Get-Date) - $lastRun

    $risk = "LOW"
    $color = "Green"

    if ($timeDiff.TotalMinutes -lt 30) {
        $risk = "RECENT"
        $color = "Red"
    }
    elseif ($timeDiff.TotalHours -lt 2) {
        $risk = "VERY RECENT"
        $color = "Yellow"
    }

    $pfList += [PSCustomObject]@{
        Name    = $nameClean
        Runs    = $runCount
        LastRun = $lastRun
        Risk    = $risk
        Color   = $color
    }
}

$pfList = $pfList | Sort-Object LastRun -Descending | Select-Object -First 20

if ($pfList.Count -gt 0) {
    foreach ($item in $pfList) {
        Write-Host (" {0,-20} | Runs: {1,-5} | Last: {2} | {3}" -f `
            $item.Name.ToUpper(),
            $item.Runs,
            $item.LastRun.ToString("HH:mm:ss"),
            $item.Risk
        ) -ForegroundColor $item.Color
    }
}
else {
    Write-Host " No relevant prefetch entries found." -ForegroundColor Green
}

Write-Host "`n[*] EMULATOR / MEMORY ANALYSIS" -ForegroundColor Cyan

$emuList = "hd-player","bluestacks","msiplayer","memu","nox","smartgaga","ld9boxheadless"

$trustedPaths = @(
    "c:\program files\bluestacks_msi5\qt6quicktemplates2.dll",
    "c:\program files\bluestacks_msi5\qtquick\templates\qtquicktemplates2plugin.dll",
    "c:\program files\bluestacks_msi5\opengl32.dll",
    "*\windows\system32\comctl32.dll"
)

Get-Process | Where-Object { $emuList -contains $_.Name.ToLower() } | ForEach-Object {

    Write-Host "`n[EMULATOR DETECTED] $($_.Name) PID: $($_.Id)" -ForegroundColor Yellow

    try {
        $modules = $_.Modules
        $seen = @{}

        foreach ($mod in $modules) {

            $modPath = $mod.FileName.ToLower()
            $modName = $mod.ModuleName

            if ($trustedPaths | Where-Object { $modPath -like "$_*" }) {
                continue
            }

            if ($modPath -match "appdata|temp|users") {
                Write-Host " [SUSPICIOUS DLL PATH] $modName -> $modPath" -ForegroundColor Red
            }

            if ($seen.ContainsKey($modName) -and $modName -notmatch "system32") {
                Write-Host " [DUPLICATE MODULE] $modName" -ForegroundColor Yellow
            }

            $seen[$modName] = $true
        }

        Write-Host " -> Memory scan complete" -ForegroundColor Green
    }
    catch {
        Write-Host " [!] Cannot read modules (run as admin)" -ForegroundColor DarkGray
    }
}

Write-Host "`n[*] ADB ANALYSIS" -ForegroundColor Cyan

$adb = Get-CimInstance Win32_Process | Where-Object { $_.Name -like "*adb.exe*" }

if ($adb) {
    foreach ($a in $adb) {
        $cmd = $a.CommandLine.ToLower()

        if ($cmd -match "shell|push|pull|connect|tcpip") {
            Write-Host " [ADB ACTIVE CONTROL]" -ForegroundColor Red
            Write-Host " -> $($a.CommandLine)"
        }
        else {
            Write-Host " [ADB PASSIVE]" -ForegroundColor Yellow
        }
    }
}
else {
    Write-Host " No ADB activity detected." -ForegroundColor Green
}

Write-Host "`n========================================" -ForegroundColor Magenta
Write-Host "         DNS CORRELATION                  " -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta

$highRiskDomains = @(
    "keyauth", "webhook", "pastebin",
    "ngrok", "duckdns", "no-ip",
    "iplogger", "grabify",
    "discord.com/api/webhooks",
    "api.telegram.org"
)

$mediumRiskDomains = @(
    "auth", "panel", "loader", "inject",
    "spoof", "bypass"
)

$ignoreDomains = @(
    "microsoft", "windows", "google",
    "cloudflare", "amazonaws", "akamaiedge"
)

Write-Host "`n[*] SYSMON DNS CORRELATION" -ForegroundColor Cyan

$sysmonEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" `
    -FilterXPath "*[System[(EventID=22)]]" `
    -MaxEvents 100 -ErrorAction SilentlyContinue

$sysmonHits = 0

if ($sysmonEvents) {

    foreach ($evt in $sysmonEvents) {

        $xml = [xml]$evt.ToXml()

        $query = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "QueryName" }).'#text'
        $image = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "Image" }).'#text'
        $pid = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "ProcessId" }).'#text'

        if (-not $query) { continue }

        $q = $query.ToLower()

        if ($ignoreDomains | Where-Object { $q -match $_ }) { continue }

        foreach ($d in $highRiskDomains) {
            if ($q -match $d) {

                Write-Host "`n [!!!] HIGH RISK DNS ( SYSMON )" -ForegroundColor Red
                Write-Host ("    Domain : {0}" -f $query) -ForegroundColor Yellow
                Write-Host ("    Process: {0}" -f $image) -ForegroundColor White
                Write-Host ("    PID    : {0}" -f $pid) -ForegroundColor Gray
                Write-Host ("    Time   : {0}" -f $evt.TimeCreated) -ForegroundColor DarkGray

                $running = Get-Process -Id $pid -ErrorAction SilentlyContinue
                if ($running) {
                    Write-Host "    [!!!] PROCESS STILL ACTIVE" -ForegroundColor Red
                }

                $sysmonHits++
                break
            }
        }

        foreach ($d in $mediumRiskDomains) {
            if ($q -match $d) {

                Write-Host "`n [!] MEDIUM DNS" -ForegroundColor Yellow
                Write-Host ("    Domain : {0}" -f $query)
                Write-Host ("    Process: {0}" -f $image)
                Write-Host ("    PID    : {0}" -f $pid)

                $sysmonHits++
                break
            }
        }
    }

}
else {
    Write-Host "DNS logs not found." -ForegroundColor DarkGray
}

Write-Host "`n[*] DNS CACHE ANALYSIS" -ForegroundColor Cyan

$dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
$dnsHits = 0

if ($dnsCache) {

    $entries = $dnsCache | Select-Object -ExpandProperty Entry -Unique

    foreach ($entry in $entries) {

        $e = $entry.ToLower()

        if ($ignoreDomains | Where-Object { $e -match $_ }) { continue }

        foreach ($d in $highRiskDomains) {
            if ($e -match $d) {

                Write-Host (" [!!!] HIGH RISK DNS: {0}" -f $entry) -ForegroundColor Red
                $dnsHits++
                break
            }
        }

        foreach ($d in $mediumRiskDomains) {
            if ($e -match $d -and $e.Length -gt 12) {

                Write-Host (" [!] Suspicious DNS: {0}" -f $entry) -ForegroundColor Yellow
                $dnsHits++
                break
            }
        }
    }

}
else {
    Write-Host " Could not read DNS cache." -ForegroundColor DarkGray
}

Write-Host "`n[*] FINAL CORRELATION RESULT" -ForegroundColor Cyan

if ($sysmonHits -ge 2) {
    Write-Host " HIGH RISK (Confirmed external communication)" -ForegroundColor Red
}
elseif ($dnsHits -ge 3) {
    Write-Host " MEDIUM RISK (Suspicious DNS activity)" -ForegroundColor Yellow
}
else {
    Write-Host " LOW / CLEAN" -ForegroundColor Green
}

function Log-Message {
    param (
        [string]$Message,
        [string]$Color = "White",
        [string]$Level = "INFO"
    )
    Write-Host "[$Level] $Message" -ForegroundColor $Color
}

function Scan-EcstasyCheat {

    Log-Message "Executing: Ecstasy EFI & Network Scan" -Color Cyan
    Log-Message "==================================================" -Color Cyan

if (-not (
    (New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
)) {
    Log-Message "FEHLER: Bitte starte PowerShell als Administrator!" -Color Red -Level "ERROR"
    return
}

    Log-Message "Scanning System (PID 4) connections..." -Color Gray
    
    try {
        $detectedNet = $false

        $connections = Get-NetTCPConnection -OwningProcess 4 -ErrorAction SilentlyContinue

        foreach ($conn in $connections) {
            $remoteIP = $conn.RemoteAddress

            if ($remoteIP -like "85.10.*") {
                $octets = $remoteIP.Split('.')
                
                if ($octets.Count -eq 4) {
                    $thirdOctet = [int]$octets[2]

                    if ($thirdOctet -ge 192 -and $thirdOctet -le 207) {
                        Log-Message "CRITICAL: Ecstasy Webcontrol Connection found!" -Color Red -Level "CRITICAL"
                        Write-Host "    └── Remote IP: $remoteIP" -ForegroundColor Red
                        Write-Host "    └── Process: System (PID 4) - EFI/Kernel Level" -ForegroundColor Red
                        $detectedNet = $true
                    }
                }
            }
        }

        if (-not $detectedNet) {
            Log-Message "✅ No suspicious Kernel network connections found." -Color Green
        }

    } catch {
        Log-Message "Error scanning network: $_" -Color Red -Level "ERROR"
    }

}

Write-Host ""
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "     ADVANCED HD-PLAYER MEMORY FORENSICS"
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host ""

Add-Type @"
using System;
using System.Runtime.InteropServices;

public class Win32
{
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(
        UInt32 access,
        bool inherit,
        UInt32 pid
    );

    [DllImport("kernel32.dll")]
    public static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        int dwSize,
        out int lpNumberOfBytesRead
    );

    [DllImport("kernel32.dll")]
    public static extern int VirtualQueryEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION lpBuffer,
        uint dwLength
    );

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("ntdll.dll")]
    public static extern uint NtQueryInformationThread(
        IntPtr ThreadHandle,
        int ThreadInformationClass,
        out IntPtr ThreadInformation,
        int ThreadInformationLength,
        IntPtr ReturnLength
    );

    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenThread(
        UInt32 dwDesiredAccess,
        bool bInheritHandle,
        UInt32 dwThreadId
    );

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }
}
"@

$PROCESS_ALL_ACCESS = 0x1F0FFF
$THREAD_QUERY_INFORMATION = 0x0040

$MEM_COMMIT  = 0x1000
$MEM_PRIVATE = 0x20000
$MEM_IMAGE   = 0x1000000

$PAGE_EXECUTE_READWRITE = 0x40
$PAGE_EXECUTE_READ      = 0x20
$PAGE_EXECUTE           = 0x10

$HD = Get-Process HD-Player -ErrorAction SilentlyContinue

if (!$HD)
{
    Write-Host "[HD-PLAYER NAO ENCONTRADO]" -ForegroundColor Red
    exit
}

Write-Host "[PROCESSO DETECTADO]" -ForegroundColor Green
Write-Host "PID: $($HD.Id)"
Write-Host ""

$Handle = [Win32]::OpenProcess(
    $PROCESS_ALL_ACCESS,
    $false,
    $HD.Id
)

if ($Handle -eq [IntPtr]::Zero)
{
    Write-Host "[FALHA OPENPROCESS]" -ForegroundColor Red
    exit
}

Write-Host "[ENUMERANDO MEMORIA...]" -ForegroundColor Cyan
Write-Host ""

$Address = [IntPtr]::Zero
$Regions = @()

while ($true)
{
    $MBI = New-Object Win32+MEMORY_BASIC_INFORMATION

    $Result = [Win32]::VirtualQueryEx(
        $Handle,
        $Address,
        [ref]$MBI,
        [System.Runtime.InteropServices.Marshal]::SizeOf($MBI)
    )

    if ($Result -eq 0)
    {
        break
    }

    $Executable =
        $MBI.Protect -eq $PAGE_EXECUTE_READWRITE -or
        $MBI.Protect -eq $PAGE_EXECUTE_READ -or
        $MBI.Protect -eq $PAGE_EXECUTE

    if (
        $MBI.State -eq $MEM_COMMIT -and
        $Executable
    )
    {
        $Regions += $MBI
    }

    $Address = [IntPtr](
        $MBI.BaseAddress.ToInt64() +
        $MBI.RegionSize.ToInt64()
    )
}

Write-Host "[ENUMERANDO THREADS...]" -ForegroundColor Cyan
Write-Host ""

$Findings = @()

foreach ($Thread in $HD.Threads)
{
    try
    {
        $ThreadHandle = [Win32]::OpenThread(
            $THREAD_QUERY_INFORMATION,
            $false,
            $Thread.Id
        )

        if ($ThreadHandle -eq [IntPtr]::Zero)
        {
            continue
        }

        $StartAddress = [IntPtr]::Zero

        [Win32]::NtQueryInformationThread(
            $ThreadHandle,
            9,
            [ref]$StartAddress,
            [IntPtr]::Size,
            [IntPtr]::Zero
        ) | Out-Null

        foreach ($Region in $Regions)
        {
            $Base = $Region.BaseAddress.ToInt64()
            $End  = $Base + $Region.RegionSize.ToInt64()

            $Addr = $StartAddress.ToInt64()

            if ($Addr -ge $Base -and $Addr -le $End)
            {
                $Reasons = @()

                if ($Region.Type -eq $MEM_PRIVATE)
                {
                    $Reasons += "Thread em MEM_PRIVATE"
                }

                if ($Region.Protect -eq $PAGE_EXECUTE_READWRITE)
                {
                    $Reasons += "RWX"
                }

                $Buffer = New-Object byte[] 4096
                $Read = 0

                [Win32]::ReadProcessMemory(
                    $Handle,
                    $Region.BaseAddress,
                    $Buffer,
                    $Buffer.Length,
                    [ref]$Read
                ) | Out-Null

                if (
                    $Buffer[0] -eq 0x4D -and
                    $Buffer[1] -eq 0x5A
                )
                {
                    $Reasons += "PE Header em memoria"
                }

                $Nops = ($Buffer | Where-Object { $_ -eq 0x90 }).Count

                if ($Nops -gt 100)
                {
                    $Reasons += "NOP sled"
                }

                $INT3 = ($Buffer | Where-Object { $_ -eq 0xCC }).Count

                if ($INT3 -gt 100)
                {
                    $Reasons += "INT3 padding"
                }

                $freq = @{}

                foreach ($b in $Buffer)
                {
                    if ($freq.ContainsKey($b))
                    {
                        $freq[$b]++
                    }
                    else
                    {
                        $freq[$b] = 1
                    }
                }

                $entropy = 0

                foreach ($f in $freq.Values)
                {
                    $p = $f / $Buffer.Length
                    $entropy -= $p * [Math]::Log($p,2)
                }

                if ($entropy -gt 6.8)
                {
                    $Reasons += "Alta entropia"
                }

                if (
                    $Region.Type -eq $MEM_PRIVATE -and
                    $Buffer[0] -eq 0x4D -and
                    $Buffer[1] -eq 0x5A
                )
                {
                    $Reasons += "Possivel Manual Map"
                }

                if ($Reasons.Count -gt 0)
                {
                    $Findings += [PSCustomObject]@{
                        ThreadID = $Thread.Id
                        Address  = ('0x{0:X}' -f $Addr)
                        Base     = ('0x{0:X}' -f $Base)
                        SizeKB   = [math]::Round(
                            $Region.RegionSize.ToInt64()/1KB,
                            2
                        )
                        Reasons  = ($Reasons -join " | ")
                    }
                }
            }
        }

        [Win32]::CloseHandle($ThreadHandle) | Out-Null
    }
    catch {}
}

Write-Host ""
Write-Host "===================================================="

if ($Findings.Count -gt 0)
{
    Write-Host ""
    Write-Host "[MEMORY ANOMALIES DETECTADAS]" -ForegroundColor Red
    Write-Host ""

    foreach ($F in $Findings)
    {
        Write-Host "----------------------------------------------------" -ForegroundColor DarkRed
        Write-Host "ThreadID : $($F.ThreadID)" -ForegroundColor Yellow
        Write-Host "Address  : $($F.Address)"
        Write-Host "Base     : $($F.Base)"
        Write-Host "SizeKB   : $($F.SizeKB)"
        Write-Host "Motivos  : $($F.Reasons)" -ForegroundColor Cyan
        Write-Host "----------------------------------------------------" -ForegroundColor DarkRed
        Write-Host ""
    }
}
else
{
    Write-Host ""
    Write-Host "[NENHUMA ANOMALIA ENCONTRADA]" -ForegroundColor Green
}

Write-Host ""
Write-Host "===================================================="

[Win32]::CloseHandle($Handle) | Out-Null
Scan-EcstasyCheat