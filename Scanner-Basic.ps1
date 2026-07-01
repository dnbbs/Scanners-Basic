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


Write-Host "`n[*] EMULATOR / MEMORY ANALYSIS" -ForegroundColor Cyan

$emuList = "hd-player","bluestacks","msiplayer","memu","nox","smartgaga","ld9boxheadless"

$trustedPaths = @(
    "c:\program files\bluestacks_msi5\qt6quicktemplates2.dll",
    "c:\program files\bluestacks_msi5\qt5quicktemplates2.dll",
    "qtquicktemplates2plugin.dll -> c:\program files\bluestacks_msi5\qtquick\templates.2\qtquicktemplates2plugin.dll",
    "c:\program files\bluestacks_msi5\qtquick\templates\qtquicktemplates2plugin.dll",
    "c:\program files\bluestacks_msi5\opengl32.dll",
    "c:\program files\bluestacks_msi5\qtquick\templates.2\qtquicktemplates2plugin.dll",
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
    "spoof", "bypass", "aimbot", "chams", "silent", "aim head", "hs alto", "hs peito", "antena"
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

# =========================
# UNSIGNED EXE FROM REGISTRY
# =========================

$Results = @()

$RegistryPaths = @(
"HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched",
"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView"
)

foreach($RegistryPath in $RegistryPaths)
{
    if(!(Test-Path $RegistryPath)) { continue }

    try
    {
        $Key = Get-ItemProperty $RegistryPath

        foreach($Property in $Key.PSObject.Properties)
        {
            if($Property.Name -like "PS*") { continue }

            $Path = $Property.Name

            # só .exe
            if($Path -notlike "*.exe") { continue }

            if(!(Test-Path $Path)) { continue }

            try
            {
                $Item = Get-Item $Path -ErrorAction Stop

                $Sig = Get-AuthenticodeSignature $Path

                # SOMENTE NÃO ASSINADOS
                if($Sig.Status -eq "Valid") { continue }

                $ExecTime = (Get-Item $RegistryPath).LastWriteTime

                $Results += [PSCustomObject]@{
                    FileName   = $Item.Name
                    FullPath   = $Item.FullName
                    Signature  = $Sig.Status
                    Registry   = Split-Path $RegistryPath -Leaf
                    LastSeen   = $ExecTime
                }
            }
            catch {}
        }
    }
    catch {}
}

# =========================
# OUTPUT
# =========================

Write-Host ""
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host " UNSIGNED EXECUTABLES ONLY" -ForegroundColor Cyan
Write-Host " (REGISTRY TRACE)" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

if($Results.Count -eq 0)
{
    Write-Host "[+] Nenhum executável não assinado encontrado." -ForegroundColor Green
}
else
{
    $Results |
    Sort-Object LastSeen -Descending |
    Format-Table FileName,Signature,LastSeen,Registry -AutoSize

    Write-Host ""
    Write-Host "Detalhes completos:" -ForegroundColor Yellow
    Write-Host ""

    $Results |
    Select-Object FileName,FullPath,Signature,LastSeen |
    Format-List
}

Write-Host "`n[*] SYSMON HOOK CHECK" -ForegroundColor Cyan

$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

try {

    $events = Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-Sysmon/Operational"
        Id      = 1
        StartTime = $boot
    } | Sort-Object TimeCreated

    if ($events.Count -lt 2) {
        Write-Host " Sysmon possui poucos eventos para an�lise." -ForegroundColor Yellow
    }
    else {

        $maxGap = 10
        $bootWindow = 5

        $suspect = $false

        for ($i = 1; $i -lt $events.Count; $i++) {

            $prev = $events[$i-1].TimeCreated
            $curr = $events[$i].TimeCreated

            $gap = ($curr - $prev).TotalSeconds

            $sinceBoot = ($prev - $boot).TotalMinutes

            if ($sinceBoot -le $bootWindow -and $gap -gt $maxGap) {

                Write-Host ""
                Write-Host "[!] POSSIBLE SYSMON INTERRUPTION" -ForegroundColor Red
                Write-Host (" Previous Event : {0}" -f $prev)
                Write-Host (" Next Event     : {0}" -f $curr)
                Write-Host (" Gap            : {0:N1} seconds" -f $gap)

                $suspect = $true
            }
        }

        if (-not $suspect) {
            Write-Host " No abnormal Sysmon gaps detected." -ForegroundColor Green
        }

    }

}
catch {
    Write-Host " Sysmon log not found or Sysmon is not installed." -ForegroundColor DarkGray
}

Write-Host "`n[*] UNSIGNED MODULES (SYSMON ID 7 AFTER BOOT)" -ForegroundColor Cyan

$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

$IgnoredExtensions = @(
    ".exe",
    ".sys",
    ".json",
    ".log",
    ".ldb",
    ".evtx",
    ".xml",
    ".pf",
    ".pdb",
    ".ps1",
    ".wal",
    ".txt"
)

# Whitelist
$Whitelist = @(

    # Microsoft Edge
    "*\Microsoft\Edge\User Data\Well Known Domains\*\well_known_domains.dll",
    "*\Microsoft\Edge\User Data\Domain Actions\*\domain_actions.dll",

    # Discord
    "*\Discord\app-*\profapi.dll",

    # Temp
    "*\AppData\Local\Temp\*",

    # Native Images (.NET)
    "*\Windows\assembly\NativeImages_v4.0.30319_64\*\System.Management.Automation.ni.dll"
)

try {

    $events = Get-WinEvent -FilterHashtable @{
        LogName   = "Microsoft-Windows-Sysmon/Operational"
        Id        = 7
        StartTime = $boot
    } -ErrorAction Stop

    $seen = @{}

    foreach ($evt in $events) {

        $xml = [xml]$evt.ToXml()

        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) {
            $data[$d.Name] = $d.'#text'
        }

        $path = $data["ImageLoaded"]

        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        if (!(Test-Path $path)) { continue }

        $ext = [IO.Path]::GetExtension($path).ToLower()

        if ($IgnoredExtensions -contains $ext) { continue }

        # Whitelist
        $Skip = $false
        foreach ($w in $Whitelist) {
            if ($path -like $w) {
                $Skip = $true
                break
            }
        }
        if ($Skip) { continue }

        if ($seen.ContainsKey($path.ToLower())) { continue }
        $seen[$path.ToLower()] = $true

        $signed = $data["Signed"]
        $status = $data["SignatureStatus"]

        if ($signed -ne "true") {

            Write-Host ""
            Write-Host "[!] UNSIGNED MODULE DETECTED" -ForegroundColor Red
            Write-Host "Time      : $($evt.TimeCreated)"
            Write-Host "Path      : $path"
            Write-Host "Extension : $ext"
            Write-Host "Signed    : $signed"
            Write-Host "Status    : $status"

        }

    }

    if ($seen.Count -eq 0) {
        Write-Host "No modules found." -ForegroundColor Green
    }

}
catch {

    Write-Host "Sysmon Event ID 7 not found or Sysmon is not installed." -ForegroundColor Yellow

}

Write-Host "`n[ID 1] Suspicious Processes" -ForegroundColor Cyan

try {

    # Hor�rio do boot atual
    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

    # Whitelist
    $Whitelist = @(

        # Microsoft Edge
        "*\msedge.exe",
        "*\C:\Program Files\WindowsApps\Microsoft.MicrosoftOfficeHub_19.2606.58031.0_x64__8wekyb3d8bbwe\",
        "*\Microsoft\Edge\Application\msedge.exe",
        "*C:\Program Files\WindowsApps\Microsoft.MicrosoftOfficeHub_19.2606.58031.0_x64__8wekyb3d8bbwe\m365copilot_autostarter.exe",

        # Discord
        "*\Discord\app-*\Discord.exe",
        "*\Discord\app-*\modules\*",

        # AMD
        "*\Windows\System32\atieah64.exe",

        # Steam
        "*\Program Files (x86)\Steam\*",

        # Windows Temp
        "*\AppData\Local\Temp\*",

        # Gaming Services
        "*\Program Files\WindowsApps\Microsoft.GamingServices_*\GamingServicesUI\*",

        # Medal
        "*\AppData\Local\Medal\recorder-*\*"
    )

    $events = Get-WinEvent -FilterHashtable @{
        LogName   = "Microsoft-Windows-Sysmon/Operational"
        Id        = 1
        StartTime = $boot
    }

    foreach ($evt in $events) {

        $xml = [xml]$evt.ToXml()

        $Data = @{}
        foreach ($d in $xml.Event.EventData.Data) {
            $Data[$d.Name] = $d.'#text'
        }

        $image = $Data["Image"]

        if ([string]::IsNullOrWhiteSpace($image)) { continue }
        if (!(Test-Path $image)) { continue }

        # Whitelist
        $Skip = $false
        foreach ($w in $Whitelist) {
            if ($image -like $w) {
                $Skip = $true
                break
            }
        }
        if ($Skip) { continue }

        $Company     = $Data["Company"]
        $Description = $Data["Description"]
        $Product     = $Data["Product"]

        # Exibe somente quando TODOS os metadados estiverem ausentes
        $MissingCompany     = [string]::IsNullOrWhiteSpace($Company)     -or $Company -eq "-"
        $MissingDescription = [string]::IsNullOrWhiteSpace($Description) -or $Description -eq "-"
        $MissingProduct     = [string]::IsNullOrWhiteSpace($Product)     -or $Product -eq "-"

        if ($MissingCompany -and $MissingDescription -and $MissingProduct) {

            Write-Host ""
            Write-Host "[!] Suspicious Process" -ForegroundColor Yellow
            Write-Host "Time         : $($evt.TimeCreated)"
            Write-Host "Image        : $image"
            Write-Host "Company      : $Company"
            Write-Host "Description  : $Description"
            Write-Host "Product      : $Product"
            Write-Host "CommandLine  : $($Data["CommandLine"])"
        }
    }

}
catch {
    Write-Host "Failed to read Sysmon Event ID 1." -ForegroundColor Red
}