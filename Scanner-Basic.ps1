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
            Write-Host " -> STATUS: UPDATED ‚úÖ" -ForegroundColor Green
        }
        elseif ($version -match "^13|^14") {
            Write-Host " -> STATUS: OK (not latest) ‚ö†Ô∏è" -ForegroundColor Yellow
        }
        else {
            Write-Host " -> STATUS: OUTDATED ‚ùå" -ForegroundColor Red
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

            # s√≥ .exe
            if($Path -notlike "*.exe") { continue }

            if(!(Test-Path $Path)) { continue }

            try
            {
                $Item = Get-Item $Path -ErrorAction Stop

                $Sig = Get-AuthenticodeSignature $Path

                # SOMENTE N√ÉO ASSINADOS
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
    Write-Host "[+] Nenhum execut√°vel n√£o assinado encontrado." -ForegroundColor Green
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


Write-Host "`n[*] UNSIGNED MODULES (SYSMON ID 7 AFTER BOOT)" -ForegroundColor Cyan

$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

$IgnoredExtensions = @(
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

        $Exists = Test-Path $path
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

            if (-not $Exists) {
                Write-Host "Exists    : NO (FILE DELETED)" -ForegroundColor Magenta
            }
            else {
                Write-Host "Exists    : YES"
            }

            Write-Host "Extension : $ext"
            Write-Host "Signed    : $signed"
            Write-Host "Status    : $status"

}

}   # fecha foreach

if ($seen.Count -eq 0) {
    Write-Host "No modules found." -ForegroundColor Green
}

}   # fecha try

catch {
    Write-Host "Sysmon Event ID 7 not found or Sysmon is not installed." -ForegroundColor Yellow
}

Write-Host "`n[ID 1] Suspicious Processes" -ForegroundColor Cyan

try {

    # Hor·rio do boot atual
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

        # Verifica se o arquivo ainda existe (n„o descarta o evento)
        $Exists = Test-Path $image

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

            if (-not $Exists) {
                Write-Host "Exists       : NO (FILE DELETED)" -ForegroundColor Magenta
            }
            else {
                Write-Host "Exists       : YES"
            }

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

Write-Host "`n[ID 10] Suspicious Process Access" -ForegroundColor Cyan

try {

    $BootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

    $SuspiciousAccess = @(
        "0x143A",
        "0x1F0FFF",
        "0x1F3FFF",
        "0x001F0FFF"
    )

    $Whitelist = @(
        "chrome.exe",
        "discord.exe",
        "spotify.exe",
        "medal.exe"
    )

    # Primeira inst‚ncia do AnyDesk
    $AnyDesk = Get-Process -Name "AnyDesk" -ErrorAction SilentlyContinue |
        Sort-Object StartTime |
        Select-Object -First 1

    if (-not $AnyDesk) {
        Write-Host "AnyDesk n„o est· aberto." -ForegroundColor Yellow
        return
    }

    $AnyDeskStart = $AnyDesk.StartTime

    Write-Host "AnyDesk iniciado em: $($AnyDeskStart.ToString('dd/MM/yyyy HH:mm:ss'))" -ForegroundColor Green

    $Events = Get-WinEvent -FilterHashtable @{
        LogName   = "Microsoft-Windows-Sysmon/Operational"
        Id        = 10
        StartTime = $BootTime
    }

    foreach ($Evt in $Events) {

        # Apenas eventos ANTES do AnyDesk abrir
        if ($Evt.TimeCreated -ge $AnyDeskStart) {
            continue
        }

        $Xml = [xml]$Evt.ToXml()

        $Data = @{}
        foreach ($Item in $Xml.Event.EventData.Data) {
            $Data[$Item.Name] = $Item.'#text'
        }

        if ($Data["GrantedAccess"] -notin $SuspiciousAccess) {
            continue
        }

        $SourceExe = [System.IO.Path]::GetFileName($Data["SourceImage"]).ToLower()

        if ($SourceExe -in $Whitelist) {
            continue
        }

        Write-Host ""
        Write-Host "[!] Suspicious Process Access" -ForegroundColor Yellow
        Write-Host "Time           : $($Evt.TimeCreated)"
        Write-Host "Source Process : $($Data["SourceImage"])"
        Write-Host "Target Process : $($Data["TargetImage"])"
        Write-Host "Source PID     : $($Data["SourceProcessId"])"
        Write-Host "Target PID     : $($Data["TargetProcessId"])"
        Write-Host "GrantedAccess  : $($Data["GrantedAccess"])"

        if ($Data["CallTrace"]) {
            Write-Host "CallTrace      : $($Data["CallTrace"])"
        }
    }

}
catch {
    Write-Host "Erro ao ler os eventos do Sysmon: $_" -ForegroundColor Red
}

#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Audita logs de boot e arquivos EFI para detectar anomalias (bootkit/cheat via .efi).
.DESCRIPTION
    Verifica Secure Boot, entradas BCD, eventos Kernel-Boot/Code Integrity
    e inventaria .efi na particao ESP com assinatura digital e hash SHA256.
#>

param(
    [int]$Dias = 30
)

$ErrorActionPreference = 'SilentlyContinue'
$start = (Get-Date).AddDays(-$Dias)
$alertas = [System.Collections.Generic.List[string]]::new()
$ok = [System.Collections.Generic.List[string]]::new()

function Add-Alerta([string]$msg) { $alertas.Add("[!] $msg") }
function Add-Ok([string]$msg)     { $ok.Add("[OK] $msg") }

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " AUDITORIA DE BOOT / EFI - $(Get-Date)" -ForegroundColor Cyan
Write-Host " Periodo analisado: ultimos $Dias dias" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# --- 1. Secure Boot ---
Write-Host "[1] Secure Boot" -ForegroundColor Yellow
try {
    $sb = Confirm-SecureBootUEFI
    if ($sb) { Add-Ok "Secure Boot ATIVADO" }
    else     { Add-Alerta "Secure Boot DESATIVADO - comum em cheats EFI/bootkit" }
} catch {
    Add-Alerta "Nao foi possivel verificar Secure Boot: $($_.Exception.Message)"
}

$ci = Get-ComputerInfo -Property BiosFirmwareType, SecureBootState -ErrorAction SilentlyContinue
if ($ci.BiosFirmwareType -ne 'Uefi') {
    Add-Alerta "Sistema nao e UEFI (tipo: $($ci.BiosFirmwareType))"
} else {
    Add-Ok "Firmware UEFI detectado"
}

# --- 2. BCD / entradas de firmware ---
Write-Host "[2] Entradas BCD (bootloader)" -ForegroundColor Yellow
$bcdFirmware = bcdedit /enum firmware 2>&1 | Out-String
$bcdBoot     = bcdedit /enum {bootmgr} 2>&1 | Out-String
$bcdCurrent  = bcdedit /enum {current} 2>&1 | Out-String

if ($bcdFirmware -match 'Acesso negado|denied') {
    Add-Alerta "bcdedit sem permissao - execute como Administrador"
} else {
    $fwCount = ([regex]::Matches($bcdFirmware, 'identifier')).Count
    if ($fwCount -gt 5) {
        Add-Alerta "Muitas entradas de firmware no BCD ($fwCount) - verificar entradas suspeitas"
    } else {
        Add-Ok "Entradas de firmware BCD: $fwCount"
    }

    if ($bcdFirmware -match '(?i)usb|removable|custom|hack|cheat|loader') {
        Add-Alerta "BCD firmware contem entrada com nome suspeito"
    }

    # {current} aponta para winload.efi (normal). bootmgfw.efi fica em {bootmgr}.
    if ($bcdBoot -match 'bootmgfw\.efi') {
        Add-Ok "Boot Manager usa bootmgfw.efi padrao"
    } elseif ($bcdFirmware -match 'bootmgfw\.efi') {
        Add-Ok "bootmgfw.efi encontrado nas entradas de firmware"
    } else {
        Add-Alerta "bootmgfw.efi NAO encontrado no BCD - verificar manualmente com: bcdedit /enum {bootmgr}"
    }

    if ($bcdCurrent -match 'winload\.efi') {
        Add-Ok "Carregador do Windows (winload.efi) padrao"
    }
}

# --- 3. Eventos Kernel-Boot ---
Write-Host "[3] Logs Kernel-Boot" -ForegroundColor Yellow
$kernelBoot = Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    ProviderName = 'Microsoft-Windows-Kernel-Boot'
    StartTime = $start
} -ErrorAction SilentlyContinue

if ($kernelBoot) {
    $bootTypes = $kernelBoot | Where-Object Id -eq 27 | ForEach-Object {
        if ($_.Message -match '0x([0-9A-Fa-f]+)') { $matches[1] }
    } | Sort-Object -Unique

    $recoveryBoots = $kernelBoot | Where-Object { $_.Id -eq 27 -and $_.Message -match '0x1\b' }
    $normalBoots   = $kernelBoot | Where-Object { $_.Id -eq 27 -and $_.Message -match '0x0\b' }

    if ($normalBoots) { Add-Ok "Tipo de boot 0x0 (normal) - $($normalBoots.Count) vez(es)" }

    if ($recoveryBoots) {
        $datas = ($recoveryBoots | ForEach-Object { $_.TimeCreated.ToString('dd/MM/yyyy HH:mm') }) -join ', '
        Add-Alerta "Boot recovery (0x1) em: $datas - geralmente Windows Update/reparo, nao cheat EFI"
    }

    $bootOptions = $kernelBoot | Where-Object Id -eq 18
    foreach ($ev in $bootOptions) {
        if ($ev.Message -match '0x([0-9A-Fa-f]+)') {
            $count = [Convert]::ToInt32($matches[1], 16)
            if ($count -gt 1) {
                Add-Alerta "Boot com $count opcoes de inicializacao (esperado: 1) em $($ev.TimeCreated)"
            }
        }
    }
    if (-not ($bootOptions | Where-Object { $_.Message -notmatch '0x1\b' })) {
        Add-Ok "Sempre 1 opcao de boot (sem menu alternativo)"
    }

    $waitEvents = $kernelBoot | Where-Object Id -eq 32
    foreach ($ev in $waitEvents) {
        if ($ev.Message -match '(\d+)\s*ms' -and [int]$matches[1] -gt 5000) {
            Add-Alerta "Bootmgr esperou $($matches[1])ms por entrada do usuario em $($ev.TimeCreated) - possivel selecao manual de boot"
        }
    }

    $vbsDisabled = $kernelBoot | Where-Object { $_.Id -eq 153 -and $_.Message -match 'disabled' }
    if ($vbsDisabled) {
        Add-Alerta "VBS (Virtualization Based Security) desativado - facilita bypass de anti-cheat"
    }
} else {
    Add-Alerta "Nenhum evento Kernel-Boot encontrado no periodo"
}

# --- 4. Code Integrity (assinatura de drivers/EFI) ---
Write-Host "[4] Code Integrity" -ForegroundColor Yellow
$ciEvents = Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-CodeIntegrity/Operational'
    StartTime = $start
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Id -in 3033, 3034, 3076, 3077, 3081, 3082, 3090, 3091
}

$efiCi = $ciEvents | Where-Object { $_.Message -match '\.efi' }
if ($efiCi) {
    foreach ($ev in $efiCi | Select-Object -First 10) {
        Add-Alerta "Code Integrity bloqueou/rejeitou .efi: $($ev.TimeCreated) (ID $($ev.Id))"
    }
} else {
    Add-Ok "Nenhuma violacao de Code Integrity envolvendo .efi no periodo"
}

$unsignedDrivers = $ciEvents | Where-Object { $_.Id -eq 3033 }
if ($unsignedDrivers.Count -gt 0) {
    Add-Alerta "$($unsignedDrivers.Count) evento(s) de driver sem assinatura Microsoft (ID 3033) - revisar manualmente"
}

# --- 5. Desligamentos anomalos (pode indicar boot externo/USB) ---
Write-Host "[5] Desligamentos inesperados" -ForegroundColor Yellow
$crashBoot = Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    StartTime = $start
} -ErrorAction SilentlyContinue | Where-Object { $_.Id -in 41, 6008 }

if ($crashBoot) {
    Add-Alerta "$($crashBoot.Count) desligamento(s) inesperado(s)/crash no periodo (IDs 41/6008) - nao prova cheat, mas vale investigar"
} else {
    Add-Ok "Sem desligamentos inesperados no periodo"
}

# --- 6. Inventario EFI na ESP ---
Write-Host "[6] Arquivos .efi na particao ESP" -ForegroundColor Yellow
$espPath = $null
$espLetter = $null

# Metodo 1: mountvol X: /S (sintaxe correta para ESP)
$usedLetters = (Get-Volume -ErrorAction SilentlyContinue).DriveLetter
foreach ($c in [char[]]([int][char]'E'..[int][char]'Z')) {
    if ($c -notin $usedLetters) {
        $tryLetter = "$c`:"
        $out = mountvol $tryLetter /S 2>&1 | Out-String
        Start-Sleep -Seconds 1
        if (Test-Path $tryLetter) {
            $espLetter = $tryLetter
            $espPath = $tryLetter
            break
        }
    }
}

# Metodo 2: montar pelo GUID do volume (fallback)
if (-not $espPath) {
    $espVol = (mountvol 2>&1 | Out-String) -split "`n" |
        Where-Object { $_ -match 'SEM PONTOS' } |
        Select-Object -First 1
    if ($espVol -and $espVol -match '(\\\\\?\\Volume\{[^}]+\})') {
        $espMount = Join-Path $env:TEMP "ESP_Audit_$(Get-Random)"
        New-Item -ItemType Directory -Force -Path $espMount | Out-Null
        mountvol $espMount $matches[1] 2>&1 | Out-Null
        Start-Sleep -Seconds 1
        if (Test-Path (Join-Path $espMount 'EFI')) { $espPath = $espMount }
    }
}

$efiFiles = if ($espPath) {
    Get-ChildItem -Path $espPath -Recurse -Filter '*.efi' -ErrorAction SilentlyContinue
} else { $null }

if (-not $efiFiles) {
    Add-Alerta "Nao foi possivel listar .efi na ESP - tente manualmente: mountvol Z: /S"
} else {
    Add-Ok "Encontrados $($efiFiles.Count) arquivo(s) .efi na ESP"

    $suspeitos = @()
    $padroesLegitimos = @(
        'bootmgfw.efi', 'bootmgr.efi', 'memtest.efi', 'cdboot.efi', 'cdboot_noprompt.efi',
        'boot.efi', 'grubx64.efi', 'mmx64.efi', 'fbx64.efi', 'shim.efi', 'shimx64.efi',
        'PreLoader.efi', 'HashTool.efi', 'MokManager.efi', 'fwupd.efi', 'Fallback.efi'
    )

    $padroesSuspeitos = @(
        'loader', 'inject', 'cheat', 'hack', 'bypass', 'spoof', 'bootkit',
        'kdmapper', 'efi_guard', 'hyperv', 'vulnerable', 'capcom'
    )

    Write-Host "`n  --- Inventario EFI ---" -ForegroundColor DarkGray
    foreach ($f in $efiFiles) {
        $rel = $f.FullName.Replace($espPath, '').TrimStart('\','/')
        $sig = Get-AuthenticodeSignature $f.FullName
        $hash = (Get-FileHash $f.FullName -Algorithm SHA256).Hash
        $nome = $f.Name.ToLower()

        $flag = ''
        if ($padroesSuspeitos | Where-Object { $nome -match $_ }) {
            $flag = 'SUSPEITO-NOME'
            $suspeitos += $rel
        }
        elseif ($sig.Status -ne 'Valid' -and $sig.Status -ne 'UnknownError') {
            if ($nome -notin $padroesLegitimos -and $rel -notmatch '\\EFI\\Microsoft\\') {
                $flag = 'NAO-ASSINADO'
                $suspeitos += $rel
            }
        }
        elseif ($f.Name -match '\.(bak|old|orig|backup)$|bootmgfw\.efi\.') {
            $flag = 'BACKUP-SUSPEITO'
            $suspeitos += $rel
        }

        $statusSig = $sig.Status
        Write-Host ("  {0,-55} {1,12} {2,12} {3}" -f $rel, $f.Length, $statusSig, $flag)

        if ($rel -match 'bootmgfw\.efi$') {
            if ($sig.Status -eq 'Valid') {
                Add-Ok "bootmgfw.efi assinado corretamente (SHA256: $($hash.Substring(0,16))...)"
            } else {
                Add-Alerta "bootmgfw.efi NAO tem assinatura valida! Status: $statusSig"
            }
        }
    }

    $foraPadrao = $efiFiles | Where-Object {
        $rel = $_.FullName.Replace($espPath, '')
        $rel -notmatch '\\EFI\\(Microsoft|Boot|Lenovo|Dell|HP|ASUS|Acer|Gigabyte|American Megatrends|Insyde)' -and
        $_.Name -notin @('BOOTX64.EFI', 'BOOTIA32.EFI')
    }
    if ($foraPadrao) {
        foreach ($f in $foraPadrao) {
            Add-Alerta "EFI fora de pastas padrao: $($f.FullName.Replace($espPath,''))"
        }
    }

    if ($suspeitos.Count -eq 0) {
        Add-Ok "Nenhum .efi com nome/assinatura suspeita"
    } else {
        foreach ($s in $suspeitos) { Add-Alerta "EFI suspeito: $s" }
    }
}

if ($espLetter) { mountvol $espLetter /D 2>&1 | Out-Null }
elseif ($espPath -and $espPath -notmatch '^[A-Z]:\\?$') {
    mountvol $espPath /D 2>&1 | Out-Null
    Remove-Item -Path $espPath -Force -Recurse -ErrorAction SilentlyContinue
}

# --- Resumo ---
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " RESUMO" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`nVerificacoes OK ($($ok.Count)):" -ForegroundColor Green
$ok | ForEach-Object { Write-Host "  $_" -ForegroundColor Green }

Write-Host "`nAlertas ($($alertas.Count)):" -ForegroundColor $(if ($alertas.Count -gt 0) { 'Red' } else { 'Green' })
if ($alertas.Count -eq 0) {
    Write-Host "  Nenhum alerta - boot parece normal no periodo analisado" -ForegroundColor Green
} else {
    $alertas | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
}

Write-Host "`n--- Interpretacao rapida ---" -ForegroundColor DarkYellow
Write-Host "  Boot tipo 0x0 + 1 opcao + Secure Boot ON + bootmgfw assinado = NORMAL"
Write-Host "  Secure Boot OFF + .efi nao assinado + multiplas opcoes boot = SUSPEITO"
Write-Host "  Cheats EFI costumam: desativar Secure Boot, trocar bootmgfw.efi, ou adicionar .efi custom na ESP"
Write-Host ""

# --- 4.1 Code Integrity (ID 3033) ---
Write-Host "Code Integrity - ID 3033" -ForegroundColor Yellow

$Whitelist = @(
    "discord",
    "ocean"
)

$ci3033 = Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-CodeIntegrity/Operational"
    Id      = 3033
} -ErrorAction SilentlyContinue

if ($ci3033) {

    foreach ($event in $ci3033) {

        $msg = $event.Message.ToLower()

        if ($Whitelist | Where-Object { $msg -match $_ }) {
            continue
        }

        Write-Host ""
        Write-Host "[!] Code Integrity 3033" -ForegroundColor Yellow
        Write-Host "Time : $($event.TimeCreated)"
        Write-Host "ID   : $($event.Id)"
        Write-Host "Mensagem:"
        Write-Host $event.Message
        Write-Host "------------------------------------------------------------"

    }

}
else {
    Write-Host "Nenhum evento 3033 encontrado." -ForegroundColor Green
}