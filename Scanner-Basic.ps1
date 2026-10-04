#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$LolDriversPath,
    [string[]]$ExtraScanPath,
    [string]$IocFile,
    [string]$WhitelistFile,
    [switch]$NoExternalBase,
    [switch]$NoBeep,
    [switch]$IncludeMedium,
    [switch]$IncludeLow,
    [switch]$ShowReport,
    [switch]$Json,
    [switch]$NoColor,
    [switch]$ImportOnly,
    [switch]$NoProgress,
    [switch]$Progress,
    [switch]$NoPause
)


Clear-Host


$ErrorActionPreference = "SilentlyContinue"

$Banner = @"
 ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗       ██████╗  █████╗ ███████╗██╗ ██████╗
██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗      ██╔══██╗██╔══██╗██╔════╝██║██╔════╝
███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝█████╗██████╔╝███████║███████╗██║██║     
╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗╚════╝██╔══██╗██╔══██║╚════██║██║██║     
███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║      ██████╔╝██║  ██║███████║██║╚██████╗
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝ ╚═════╝

╔══════════════════════════════════════════════════════════════╗
║                    CREATE BY DNBBS                           ║
║        Discord: https://discord.gg/qdsG44Jz88               ║
╚══════════════════════════════════════════════════════════════╝
"@

Write-Host ""
Write-Host ""

foreach ($Line in $Banner -split "`n") {
    Write-Host $Line -ForegroundColor Cyan
    Start-Sleep -Milliseconds 80
}

$install = Read-Host "`n[*] Antes de tudo, deseja instalar as tools que o dnbbs usa? ( tool do Technical ) S/N"

if ($install -match "^[Ss]$") {

    $path = "C:\ss"
    $downloads = Join-Path $env:USERPROFILE "Downloads"

    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }

    Write-Host "`n[*] Instalando Technical Utilities..." -ForegroundColor Cyan

    Invoke-WebRequest `
        -Uri "https://github.com/techlinn/Screenshare-Collector/releases/download/tech/Technical.Utilities.exe" `
        -OutFile "$downloads\Technical.Utilities.exe"

    Write-Host "[+] Technical Utilities.exe foi baixado para a pasta Downloads!" -ForegroundColor Cyan

    Invoke-WebRequest `
        -Uri "https://github.com/ruivosss/ss-tools/releases/download/realease/NXUtilities.exe" `
        -OutFile "$path\NxUtilities.exe"

    Invoke-WebRequest `
        -Uri "https://github.com/Orbdiff/PrefetchView/releases/download/v1.6.8/pv++.exe" `
        -OutFile "$path\pv++.exe"

    Write-Host "[+] Tools instaladas em C:\ss" -ForegroundColor Cyan

    Start-Sleep -Seconds 5

} elseif ($install -match "^[Nn]$") {

} else {

    Write-Host "[!] Responda apenas S ou N." -ForegroundColor Red
    exit
}

Clear-Host

$ErrorActionPreference = "SilentlyContinue"

$Banner = @"
 ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗       ██████╗  █████╗ ███████╗██╗ ██████╗
██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗      ██╔══██╗██╔══██╗██╔════╝██║██╔════╝
███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝█████╗██████╔╝███████║███████╗██║██║     
╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗╚════╝██╔══██╗██╔══██║╚════██║██║██║     
███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║      ██████╔╝██║  ██║███████║██║╚██████╗
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝ ╚═════╝

╔══════════════════════════════════════════════════════════════╗
║                    CREATE BY DNBBS                           ║
║        Discord: https://discord.gg/qdsG44Jz88               ║
╚══════════════════════════════════════════════════════════════╝
"@

Write-Host ""
Write-Host ""

foreach ($Line in $Banner -split "`n") {
    Write-Host $Line -ForegroundColor Cyan
    Start-Sleep -Milliseconds 80
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

$services = @(
    "PcaSvc",
    "DiagTrack",
    "DPS",
    "SysMain",
    "EventLog",
    "WinDefend",
    "DusmSvc"
)

$result = foreach ($name in $services) {

    $svc = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue

    if ($svc) {
        $startTime = "N/A"

        if ($svc.ProcessId -ne 0) {
            try {
                $startTime = (Get-Process -Id $svc.ProcessId -ErrorAction Stop).StartTime
            }
            catch {
                $startTime = "N/A"
            }
        }

        [PSCustomObject]@{
            Servico       = $svc.Name
            Status        = $svc.State
            Inicializacao = $svc.StartMode
            PID           = $svc.ProcessId
            Inicio        = $startTime
        }
    }
    else {
        [PSCustomObject]@{
            Servico       = $name
            Status        = "NOT FOUND"
            Inicializacao = "-"
            PID           = "-"
            Inicio        = "-"
        }
    }
}

$bamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam"
$bam = Get-Item $bamPath -ErrorAction SilentlyContinue

if ($bam) {
    $bamStatus = "Running"
}
else {
    $bamStatus = "Stopped"
}

$result += [PSCustomObject]@{
    Servico       = "bam"
    Status        = $bamStatus
    Inicializacao = "Registry"
    PID           = "-"
    Inicio        = "-"
}

Write-Host ("{0,-15} {1,-12} {2,-15} {3,-8} {4}" -f `
    "Servico", "Status", "Inicializacao", "PID", "Inicio") -ForegroundColor Cyan

Write-Host ("-" * 75) -ForegroundColor Cyan

foreach ($item in $result) {

    switch ($item.Status.ToUpper()) {
        "RUNNING" {
            $color = "Green"
        }
        "STOPPED" {
            $color = "Red"
        }
        "NOT FOUND" {
            $color = "Yellow"
        }
        default {
            $color = "Gray"
        }
    }

    Write-Host ("{0,-15} {1,-12} {2,-15} {3,-8} {4}" -f `
        $item.Servico,
        $item.Status,
        $item.Inicializacao,
        $item.PID,
        $item.Inicio) -ForegroundColor $color
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
            Write-Host " -> STATUS: UPDATED" -ForegroundColor Green
        }
        elseif ($version -match "^13|^14") {
            Write-Host " -> STATUS: OK (not latest)" -ForegroundColor Yellow
        }
        else {
            Write-Host " -> STATUS: OUTDATED" -ForegroundColor Red
        }
    }
    else {
        Write-Host " -> Could not find executable path" -ForegroundColor DarkGray
    }

    $kellerPath = "C:\Users\$env:USERNAME\AppData\Roaming\Sysmon\Keller.xml"

    if (Test-Path $kellerPath) {
        $kellerDate = (Get-Item $kellerPath).LastWriteTime

        Write-Host (' -> Date: "{0}"' -f $kellerDate) -ForegroundColor Cyan
    }
    else {
        Write-Host ' -> Date: "Keller.xml NOT FOUND"' -ForegroundColor DarkGray
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

Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;

public static class NativeDevicePath {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    public static extern uint QueryDosDevice(
        string lpDeviceName,
        StringBuilder lpTargetPath,
        int ucchMax
    );
}
"@

$deviceMap = @{}

foreach ($drive in Get-CimInstance Win32_LogicalDisk | Where-Object {
    $_.DriveType -eq 3 -and $_.DeviceID
}) {
    $buffer = New-Object System.Text.StringBuilder 1024

    $length = [NativeDevicePath]::QueryDosDevice(
        $drive.DeviceID,
        $buffer,
        $buffer.Capacity
    )

    if ($length -gt 0) {
        $devicePath = $buffer.ToString().ToLower()

        if ($devicePath -match "^\\device\\harddiskvolume\d+") {
            $deviceMap[$matches[0]] = $drive.DeviceID
        }
    }
}

function Convert-DevicePath {
    param ($path)

    $lowerPath = $path.ToLower()

    foreach ($device in $deviceMap.Keys) {
        if ($lowerPath.StartsWith($device)) {
            return $deviceMap[$device] + $path.Substring($device.Length)
        }
    }

    if ($lowerPath -match "^\\\\\?\\([a-z]):\\") {
        return $path -replace "^\\\\\?\\([a-z]):", '$1:'
    }

    return $path
}

$results = foreach ($userKey in Get-ChildItem $bamPath) {

    $bamItems = Get-ItemProperty $userKey.PSPath
    $sid = $userKey.PSChildName

    foreach ($property in $bamItems.PSObject.Properties) {

        if ($property.Name -notlike "*\*") {
            continue
        }

        $path = $property.Name
        $lowerPath = $path.ToLower()
        $ext = [System.IO.Path]::GetExtension($lowerPath)

        if ($validExt -notcontains $ext) {
            continue
        }

        if ($property.Value -isnot [byte[]] -or $property.Value.Length -lt 8) {
            continue
        }

        try {
            $fileTime = [BitConverter]::ToInt64(
                [byte[]]$property.Value,
                0
            )

            $date = [DateTime]::FromFileTimeUtc($fileTime).ToLocalTime()
        }
        catch {
            continue
        }

        if ($date.Year -lt 2000 -or $date.Year -gt ((Get-Date).Year + 1)) {
            continue
        }

        if ($date -lt $bootTime) {
            continue
        }

        $realPath = Convert-DevicePath $path
        $realLower = $realPath.ToLower()

        $skip = $false

        foreach ($w in $windowsOnly) {
            if ($realLower.StartsWith($w)) {
                $skip = $true
                break
            }
        }

        if ($skip) {
            continue
        }

        $exists = Test-Path -LiteralPath $realPath -PathType Leaf
        $sigStatus = "FileNotFound"

        if ($exists) {
            try {
                $sigStatus = (
                    Get-AuthenticodeSignature -LiteralPath $realPath
                ).Status.ToString()
            }
            catch {
                $sigStatus = "UnknownError"
            }
        }

        [PSCustomObject]@{
            Date      = $date
            Path      = $realPath
            Signature = $sigStatus
            SID       = $sid
            Exists    = $exists
        }
    }
}

$results = $results | Sort-Object Date -Descending

foreach ($item in $results) {

    if ($item.Signature -eq "Valid") {
        Write-Host (
            "[{0}] [SIGNED]   {1}" -f
            $item.Date,
            $item.Path
        ) -ForegroundColor Green
    }
    else {
        Write-Host (
            "[{0}] [UNSIGNED: {1}] {2}" -f
            $item.Date,
            $item.Signature,
            $item.Path
        ) -ForegroundColor Red
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

Write-Host ""
Write-Host "========================================" -ForegroundColor Magenta
Write-Host "          DNS CORRELATION               " -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host ""

$HighRiskDomains = @(
    "keyauth.com",
    "keyauth.win",
    "keyauth.cc",

    "ngrok.io",
    "ngrok-free.app",

    "duckdns.org",
    "no-ip.org",
    "no-ip.com",
    "ddns.net",
    "dynu.net",
    "dynv6.net",
    "hopto.org",
    "zapto.org",

    "webhook",
    "discord.com/api/webhooks",

    "grabify.link",
    "iplogger.org",
    "iplogger.com",

    "api.telegram.org",
    "pastebin.com"
)

$MediumRiskKeywords = @(
    "loader",
    "inject",
    "spoof",
    "bypass",
    "aimbot",
    "chams",
    "silentaim",
    "silent-aim",
    "aim-head",
    "aimhead",
    "hsalto",
    "hspeito",
    "antena"
)

$IgnoreDomains = @(
    "microsoft.com",
    "windows.com",
    "windowsupdate.com",

    "google.com",
    "googleapis.com",
    "gstatic.com",

    "cloudflare.com",

    "amazonaws.com",

    "akamai.net",
    "akamaiedge.net",

    "steamcontent.com",
    "steampowered.com"
)

function Test-DomainMatch {

    param(
        [string]$Domain,
        [string]$Pattern
    )

    $Domain = $Domain.ToLower().TrimEnd(".")
    $Pattern = $Pattern.ToLower().TrimEnd(".")

    return (
        $Domain -eq $Pattern -or
        $Domain.EndsWith("." + $Pattern)
    )
}

function Test-IgnoreDomain {

    param(
        [string]$Domain
    )

    foreach ($Ignore in $IgnoreDomains) {

        if (Test-DomainMatch `
            -Domain $Domain `
            -Pattern $Ignore) {

            return $true
        }
    }

    return $false
}

function Get-DNSRisk {

    param(
        [string]$Domain
    )

    $Domain = $Domain.ToLower()

    foreach ($High in $HighRiskDomains) {

        if (Test-DomainMatch `
            -Domain $Domain `
            -Pattern $High) {

            return "HIGH"
        }
    }

    foreach ($Keyword in $MediumRiskKeywords) {

        $Regex = "(^|[.\-_])$([regex]::Escape($Keyword))([.\-_]|$)"

        if ($Domain -match $Regex) {
            return "MEDIUM"
        }
    }

    return $null
}

Write-Host "[*] Obtendo horario de inicializacao..." -ForegroundColor Cyan

try {

    $OS = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop

    $BootTime = $OS.LastBootUpTime
    $ScanTime = Get-Date

    Write-Host ""
    Write-Host ("[+] Boot : {0}" -f $BootTime) -ForegroundColor Green
    Write-Host ("[+] Scan : {0}" -f $ScanTime) -ForegroundColor Green
    Write-Host ""

}
catch {

    Write-Host "[!] Nao foi possivel obter o horario de boot." `
        -ForegroundColor Red

    return
}

Write-Host "[*] Procurando eventos DNS desde o boot..." `
    -ForegroundColor Cyan

$SysmonResults = @()
$SysmonDNSAvailable = $true

try {

    $FilterHash = @{
        LogName   = "Microsoft-Windows-Sysmon/Operational"
        Id        = 22
        StartTime = $BootTime
        EndTime   = $ScanTime
    }

    $SysmonEvents = @(Get-WinEvent `
        -FilterHashtable $FilterHash `
        -ErrorAction Stop)

}
catch {

    $SysmonDNSAvailable = $false
    $SysmonEvents = @()

    Write-Host ""
    Write-Host "[!] Nao foi possivel ler o log do Sysmon." `
        -ForegroundColor Red

    Write-Host ""
    Write-Host "Possiveis motivos:" -ForegroundColor Yellow
    Write-Host " -> Sysmon nao instalado"
    Write-Host " -> Event ID 22 nao habilitado"
    Write-Host " -> Log sem eventos desde o boot"
    Write-Host " -> Permissao insuficiente"
    Write-Host ""
    Write-Host "[*] Correlacao DNS ignorada. Continuando..." `
        -ForegroundColor Yellow
    Write-Host ""
}

if ($SysmonDNSAvailable) {

    Write-Host ("[+] Eventos DNS encontrados: {0}" -f $SysmonEvents.Count) `
        -ForegroundColor Green

    Write-Host ""

    foreach ($Event in $SysmonEvents) {

        try {

            $XML = [xml]$Event.ToXml()

            $Query = (
                $XML.Event.EventData.Data |
                Where-Object {
                    $_.Name -eq "QueryName"
                }
            ).'#text'

            $Image = (
                $XML.Event.EventData.Data |
                Where-Object {
                    $_.Name -eq "Image"
                }
            ).'#text'

            $PIDText = (
                $XML.Event.EventData.Data |
                Where-Object {
                    $_.Name -eq "ProcessId"
                }
            ).'#text'

            $QueryStatus = (
                $XML.Event.EventData.Data |
                Where-Object {
                    $_.Name -eq "QueryStatus"
                }
            ).'#text'

            if (-not $Query) {
                continue
            }

            $Query = $Query.Trim().TrimEnd(".")
            $LowerQuery = $Query.ToLower()

            if (Test-IgnoreDomain -Domain $LowerQuery) {
                continue
            }

            $IsIP = $false

            if ($LowerQuery -match '^\d{1,3}(\.\d{1,3}){3}$') {
                $IsIP = $true
            }

            $Risk = Get-DNSRisk -Domain $LowerQuery

            if (-not $Risk -and -not $IsIP) {
                continue
            }

            $PID = 0

            if ($PIDText -match '^\d+$') {
                $PID = [int]$PIDText
            }

            $ProcessName = "Unknown"
            $ProcessPath = $null
            $CommandLine = $null
            $ParentPID = $null
            $ProcessActive = $false

            if ($PID -gt 0) {

                try {

                    $Process = Get-CimInstance `
                        Win32_Process `
                        -Filter "ProcessId=$PID" `
                        -ErrorAction Stop

                    if ($Process) {

                        $ProcessActive = $true

                        $ProcessName = $Process.Name
                        $ProcessPath = $Process.ExecutablePath
                        $CommandLine = $Process.CommandLine
                        $ParentPID = $Process.ParentProcessId
                    }

                }
                catch {}
            }

            $SysmonResults += [PSCustomObject]@{

                Risk = if ($IsIP) {
                    "MEDIUM"
                }
                else {
                    $Risk
                }

                Domain      = $Query
                Process     = $ProcessName
                PID         = $PID
                Active      = $ProcessActive
                ParentPID   = $ParentPID
                Path        = $ProcessPath
                CommandLine = $CommandLine
                Time        = $Event.TimeCreated
                QueryStatus = $QueryStatus
            }
        }
        catch {
            continue
        }
    }

    $SysmonResults = @(
        $SysmonResults |
        Sort-Object Time -Descending |
        Group-Object Domain, PID |
        ForEach-Object {
            $_.Group | Select-Object -First 1
        }
    )

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Magenta
    Write-Host "             RESULTADOS                 " -ForegroundColor Magenta
    Write-Host "========================================" -ForegroundColor Magenta
    Write-Host ""

    if ($SysmonResults.Count -eq 0) {

        Write-Host "[+] Nenhum DNS suspeito encontrado desde o boot." `
            -ForegroundColor Green
    }
    else {

        $High = @(
            $SysmonResults |
            Where-Object {
                $_.Risk -eq "HIGH"
            }
        )

        $Medium = @(
            $SysmonResults |
            Where-Object {
                $_.Risk -eq "MEDIUM"
            }
        )

        $Active = @(
            $SysmonResults |
            Where-Object {
                $_.Active -eq $true
            }
        )

        Write-Host ("[!] HIGH          : {0}" -f $High.Count) `
            -ForegroundColor Red

        Write-Host ("[!] MEDIUM        : {0}" -f $Medium.Count) `
            -ForegroundColor Yellow

        Write-Host ("[!] PROCESS ACTIVE: {0}" -f $Active.Count) `
            -ForegroundColor Red

        foreach ($Item in $SysmonResults) {

            if ($Item.Risk -eq "HIGH") {

                Write-Host ""
                Write-Host "[!!!] HIGH RISK DNS" `
                    -ForegroundColor Red
            }
            else {

                Write-Host ""
                Write-Host "[!] MEDIUM DNS" `
                    -ForegroundColor Yellow
            }

            Write-Host ("    Domain   : {0}" -f $Item.Domain) `
                -ForegroundColor White

            Write-Host ("    Process  : {0}" -f $Item.Process) `
                -ForegroundColor White

            Write-Host ("    PID      : {0}" -f $Item.PID) `
                -ForegroundColor Gray

            if ($Item.Active) {

                Write-Host "    Active   : TRUE" `
                    -ForegroundColor Red
            }
            else {

                Write-Host "    Active   : FALSE" `
                    -ForegroundColor DarkGray
            }

            Write-Host ("    Time     : {0}" -f $Item.Time) `
                -ForegroundColor DarkGray

            if ($Item.Path) {

                Write-Host ("    Path     : {0}" -f $Item.Path) `
                    -ForegroundColor DarkCyan
            }

            if ($Item.ParentPID) {

                Write-Host ("    ParentPID: {0}" -f $Item.ParentPID) `
                    -ForegroundColor DarkGray
            }

            if ($Item.CommandLine) {

                Write-Host ("    CmdLine  : {0}" -f $Item.CommandLine) `
                    -ForegroundColor DarkGray
            }

            if ($Item.QueryStatus) {

                Write-Host ("    Status   : {0}" -f $Item.QueryStatus) `
                    -ForegroundColor DarkGray
            }

            if ($Item.Active) {

                Write-Host ""
                Write-Host "    [!!!] PROCESS STILL ACTIVE" `
                    -ForegroundColor Red
            }
        }

        Write-Host ""
        Write-Host "========================================" `
            -ForegroundColor Magenta

        Write-Host "       PROCESSOS ATIVOS RELACIONADOS    " `
            -ForegroundColor Magenta

        Write-Host "========================================" `
            -ForegroundColor Magenta

        Write-Host ""

        if ($Active.Count -gt 0) {

            $Active |
                Sort-Object Process, PID |
                Format-Table `
                    Risk,
                    Process,
                    PID,
                    Domain,
                    Time `
                    -AutoSize
        }
        else {

            Write-Host "[+] Nenhum processo suspeito continua ativo." `
                -ForegroundColor Green
        }
    }
}
else {

    Write-Host "========================================" `
        -ForegroundColor Magenta

    Write-Host "          DNS CORRELATION SKIPPED       " `
        -ForegroundColor Yellow

    Write-Host "========================================" `
        -ForegroundColor Magenta

    Write-Host ""
    Write-Host "[!] Event ID 22 indisponivel." -ForegroundColor Yellow
    Write-Host "[*] Nenhuma conclusao DNS foi feita." -ForegroundColor DarkGray
    Write-Host ""
}

Write-Host ""
Write-Host "========================================" `
    -ForegroundColor Magenta

Write-Host " DNS SCAN FINALIZADO" `
    -ForegroundColor Green

Write-Host (" Boot : {0}" -f $BootTime) `
    -ForegroundColor DarkGray

Write-Host (" Scan : {0}" -f $ScanTime) `
    -ForegroundColor DarkGray

Write-Host "========================================" `
    -ForegroundColor Magenta

Write-Host ""

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

$Results = @()

Write-Host "`n[*] KERNEL DRIVER SIGNATURE SCANNER" -ForegroundColor Cyan

$system32 = [Environment]::GetFolderPath("System")
$tempDir = Join-Path $system32 "SigcheckScanner"
$zipPath = Join-Path $tempDir "Sigcheck.zip"
$sigcheckDir = Join-Path $tempDir "Sigcheck"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {

    Write-Host "[!] Execute o PowerShell como administrador." -ForegroundColor Red
    return
}

if (Test-Path $tempDir) {
    Remove-Item `
        -LiteralPath $tempDir `
        -Recurse `
        -Force `
        -ErrorAction SilentlyContinue
}

New-Item `
    -ItemType Directory `
    -Path $tempDir `
    -Force `
    -ErrorAction Stop | Out-Null

try {

    $webClient = New-Object System.Net.WebClient

    $webClient.DownloadFile(
        "https://download.sysinternals.com/files/Sigcheck.zip",
        $zipPath
    )

    $webClient.Dispose()

    if (-not (Test-Path -LiteralPath $zipPath)) {
        throw "O arquivo Sigcheck.zip não foi criado."
    }

    $zipSize = (Get-Item -LiteralPath $zipPath).Length

    if ($zipSize -lt 10000) {
        throw "O download do Sigcheck.zip parece inválido."
    }

    New-Item `
        -ItemType Directory `
        -Path $sigcheckDir `
        -Force `
        -ErrorAction Stop | Out-Null

    Expand-Archive `
        -LiteralPath $zipPath `
        -DestinationPath $sigcheckDir `
        -Force `
        -ErrorAction Stop
}
catch {

    Write-Host "`n[!] Falha ao preparar a ferramenta de verificação." -ForegroundColor Red
    Write-Host "[!] Erro: $($_.Exception.Message)" -ForegroundColor Yellow

    Remove-Item `
        -LiteralPath $tempDir `
        -Recurse `
        -Force `
        -ErrorAction SilentlyContinue

    return
}

$sigcheck = Get-ChildItem `
    -Path $sigcheckDir `
    -Filter "sigcheck.exe" `
    -File `
    -Recurse `
    -ErrorAction SilentlyContinue |
    Select-Object -First 1

if ($null -eq $sigcheck) {

    Write-Host "[!] sigcheck.exe não encontrado." -ForegroundColor Red

    Remove-Item `
        -LiteralPath $tempDir `
        -Recurse `
        -Force `
        -ErrorAction SilentlyContinue

    return
}

$checked = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)

$drivers = @()

$whitelistFolders = @(
    "C:\Windows\WinSxS\*.sys",
    "C:\Windows\WinSxS\Backup\*.sys",
    "C:\Windows\System32\drivers\wd\*.sys",
    "C:\Windows\servicing\LCU\*.sys",
    "C:\Windows\System32\DriverStore\FileRepository\*.sys",
    "C:\ProgramData\Microsoft\NetFramework\BreadcrumbStore\*.sys"
)

$whitelistPaths = @(
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\SystemCache\Diagnostics\PerformanceTraces\SRBMiner-Multi-3-6-9\WinRing0x64.sys",
    "C:\swapfile.sys",
    "C:\pagefile.sys",
    "C:\hiberfil.sys",
    "C:\Windows\SysmonDrv.sys",
    "C:\Windows\System32\drivers\ClipSp.sys",
    "C:\Windows\System32\drivers\dumpfve.sys",
    "C:\Windows\System32\drivers\fvevol.sys",
    "C:\Windows\System32\drivers\csc.sys",
    "C:\Windows\System32\drivers\mrxdav.sys",
    "C:\Windows\System32\drivers\hvsocket.sys",
    "C:\Windows\System32\drivers\vmbkmcl.sys",
    "C:\Windows\System32\drivers\winhv.sys",
    "C:\Windows\System32\drivers\udfs.sys",
    "C:\Windows\System32\drivers\rdpdr.sys",
    "C:\Windows\System32\drivers\rdpvideominiport.sys",
    "C:\Windows\System32\drivers\rmcast.sys",
    "C:\Windows\System32\drivers\bridge.sys",
    "C:\Windows\System32\drivers\winhvr.sys",
    "C:\Windows\System32\drivers\hvservice.sys",
    "C:\Windows\System32\drivers\tdx.sys",
    "C:\Windows\SysWOW64\drivers\afunix.sys",
    "C:\Windows\SysWOW64\win32kfull.sys",
    "C:\Windows\SysWOW64\win32k.sys",
    "C:\Windows\System32\drivers\usb8023.sys",
    "C:\Windows\System32\drivers\RNDISMP.sys",
    "C:\Windows\System32\drivers\raspppoe.sys",
    "C:\Windows\System32\drivers\rasl2tp.sys",
    "C:\Windows\System32\drivers\ndiswan.sys",
    "C:\Windows\System32\drivers\agilevpn.sys",
    "C:\Windows\System32\drivers\ipfltdrv.sys",
    "C:\Windows\System32\drivers\rasacd.sys",
    "C:\Windows\System32\drivers\afunix.sys",
    "C:\Windows\System32\drivers\netbt.sys",
    "C:\Windows\System32\drivers\tcpipreg.sys",
    "C:\Windows\System32\drivers\dam.sys",
    "C:\Windows\System32\drivers\WUDFPf.sys",
    "C:\Windows\System32\drivers\WUDFRd.sys",
    "C:\Windows\System32\drivers\ahcache.sys",
    "C:\Windows\System32\drivers\luafv.sys",
    "C:\Windows\System32\drivers\ksthunk.sys",
    "C:\Windows\System32\drivers\mskssrv.sys",
    "C:\Windows\System32\drivers\ks.sys",
    "C:\Windows\System32\drivers\scfilter.sys",
    "C:\Windows\System32\drivers\Dmpusbstor.sys",
    "C:\Windows\System32\drivers\Dumpstorport.sys",
    "C:\Windows\System32\drivers\Diskdump.sys",
    "C:\Windows\System32\drivers\srv2.sys",
    "C:\Windows\System32\drivers\srvnet.sys",
    "C:\Windows\System32\drivers\mrxsmb.sys",
    "C:\Windows\System32\drivers\mrxsmb20.sys",
    "C:\Windows\System32\drivers\rdbss.sys",
    "C:\Windows\System32\drivers\mup.sys",
    "C:\Windows\System32\drivers\dfsc.sys",
    "C:\Windows\System32\drivers\tm.sys",
    "C:\Windows\System32\drivers\clfs.sys",
    "C:\Windows\System32\drivers\crashdmp.sys",
    "C:\Windows\System32\drivers\FWPKCLNT.SYS",
    "C:\Windows\System32\drivers\tcpip.sys",
    "C:\Windows\System32\drivers\NetAdapterCx.sys",
    "C:\Windows\System32\drivers\afd.sys",
    "C:\Windows\System32\drivers\msrpc.sys",
    "C:\Windows\System32\drivers\netio.sys",
    "C:\Windows\System32\drivers\ndis.sys",
    "C:\Windows\System32\drivers\ksecdd.sys",
    "C:\Windows\System32\drivers\Wdf01000.sys",
    "C:\Windows\System32\drivers\partmgr.sys",
    "C:\Windows\System32\drivers\ntfs.sys",
    "C:\Windows\System32\drivers\npfs.sys",
    "C:\Windows\System32\drivers\fltMgr.sys",
    "C:\Windows\System32\drivers\Classpnp.sys",
    "C:\Windows\System32\drivers\werkernel.sys",
    "C:\Windows\System32\drivers\ksecpkg.sys",
    "C:\Windows\System32\drivers\cng.sys",
    "C:\Windows\System32\drivers\http.sys",
    "C:\Windows\System32\drivers\cldflt.sys",
    "C:\Windows\System32\drivers\refsv1.sys",
    "C:\Windows\System32\drivers\refs.sys",
    "C:\Windows\System32\drivers\Dumpata.sys",
    "C:\Windows\System32\drivers\applockerfltr.sys",
    "C:\Windows\System32\drivers\appid.sys",
    "C:\Windows\System32\drivers\storqosflt.sys",
    "C:\Windows\System32\drivers\WindowsTrustedRT.sys",
    "C:\Windows\System32\drivers\ipnat.sys",
    "C:\Windows\System32\drivers\wcifs.sys",
    "C:\Windows\System32\drivers\bindflt.sys",
    "C:\Windows\System32\drivers\cimfs.sys",
    "C:\Windows\System32\win32kfull.sys",
    "C:\Windows\System32\win32k.sys",
    "C:\Windows\System32\win32kns.sys",
    "C:\Windows\System32\drivers\wfplwfs.sys",
    "C:\Windows\System32\drivers\CEA.sys",
    "C:\Windows\System32\win32kbase.sys",
    "C:\Windows\System32\drivers\msgpioclx.sys",
    "C:\Windows\System32\drivers\dxgmms2.sys",
    "C:\Windows\System32\drivers\dxgmms1.sys",
    "C:\Windows\System32\drivers\dxgkrnl.sys",
    "C:\Windows\System32\drivers\WdiWiFi.sys",
    "C:\Windows\System32\drivers\nwifi.sys",
    "C:\Windows\System32\drivers\tbs.sys",
    "C:\Windows\System32\drivers\PEAuth.sys",
    "C:\Windows\System32\drivers\pdc.sys",
    "C:\Windows\System32\drivers\storport.sys",
    "C:\Windows\System32\drivers\cmimcext.sys",
    "C:\Windows\System32\drivers\Acx01000.sys",
    "C:\Windows\System32\drivers\UCPD.sys",
    "C:\Windows\System32\drivers\winnat.sys",
    "C:\Windows\System32\drivers\fastfat.sys",
    "C:\Windows\System32\drivers\exfat.sys",
    "C:\Windows\System32\drivers\KNetPwrDepBroker.sys",
    "C:\Windows\System32\drivers\MbbCx.sys",
    "C:\Windows\System32\drivers\mssecwfp.sys",
    "C:\Windows\System32\drivers\mssecflt.sys",
    "C:\Windows\System32\drivers\msseccore.sys",
    "C:\Windows\System32\drivers\tsusbhub.sys",
    "C:\Windows\System32\drivers\vpci.sys",
    "C:\Windows\System32\drivers\netvsc.sys",
    "C:\Windows\System32\drivers\vmbus.sys",
    "C:\Windows\System32\drivers\Vid.sys",
    "C:\Windows\System32\drivers\tpm.sys",
    "C:\Windows\System32\drivers\dumpsd.sys",
    "C:\Windows\System32\drivers\sdbus.sys",
    "C:\Windows\System32\drivers\USBXHCI.SYS",
    "C:\Windows\System32\drivers\USBSTOR.SYS",
    "C:\Windows\System32\drivers\usbd.sys",
    "C:\Windows\System32\drivers\usbuhci.sys",
    "C:\Windows\System32\drivers\usbehci.sys",
    "C:\Windows\System32\drivers\usbhub.sys",
    "C:\Windows\System32\drivers\usbport.sys",
    "C:\Windows\System32\drivers\usbohci.sys",
    "C:\Windows\System32\drivers\USBHUB3.SYS",
    "C:\Windows\System32\drivers\usbccgp.sys",
    "C:\Windows\System32\drivers\hidi2c.sys",
    "C:\Windows\System32\drivers\rfcomm.sys",
    "C:\Windows\System32\drivers\BTHUSB.SYS",
    "C:\Windows\System32\drivers\bthport.sys",
    "C:\Windows\System32\drivers\BthMini.SYS",
    "C:\Windows\System32\drivers\bthenum.sys",
    "C:\Windows\System32\drivers\vhdmp.sys",
    "C:\Windows\System32\drivers\uaspstor.sys",
    "C:\Windows\System32\drivers\storufs.sys",
    "C:\Windows\System32\drivers\stornvme.sys",
    "C:\Windows\System32\drivers\pmem.sys",
    "C:\Windows\System32\drivers\pci.sys",
    "C:\Windows\System32\drivers\IPMIDrv.sys",
    "C:\Windows\System32\drivers\spacedump.sys",
    "C:\Windows\System32\drivers\spaceport.sys",
    "C:\Windows\System32\drivers\disk.sys",
    "C:\Windows\System32\drivers\amdppm.sys",
    "C:\Windows\System32\drivers\amdk8.sys",
    "C:\Windows\System32\drivers\intelppm.sys",
    "C:\Windows\System32\drivers\processr.sys",
    "C:\Windows\System32\drivers\cdrom.sys",
    "C:\Windows\System32\drivers\acpi.sys",
    "C:\Windows\System32\drivers\TsUsbGD.sys",
    "C:\Windows\System32\drivers\intelpep.sys",
    "C:\Windows\System32\drivers\usbprint.sys",
    "C:\Windows\System32\drivers\monitor.sys",
    "C:\Windows\System32\drivers\portcls.sys",
    "C:\Windows\System32\drivers\drmkaud.sys",
    "C:\Windows\System32\drivers\drmk.sys",
    "C:\Windows\System32\drivers\USBAUDIO.sys",
    "C:\Windows\System32\drivers\hdaudbus.sys",
    "C:\Windows\System32\drivers\xinputhid.sys",
    "C:\Windows\System32\drivers\devauthe.sys",
    "C:\Windows\System32\drivers\xboxgip.sys",
    "C:\Windows\System32\drivers\BtaMPM.sys",
    "C:\Windows\System32\drivers\Microsoft.Bluetooth.AvrcpTransport.sys",
    "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.4-0\Drivers\ksld.sys",
    "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.4-0\Drivers\WdNisDrv.sys",
    "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.4-0\Drivers\WdFilter.sys",
    "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.4-0\Drivers\WdDevFlt.sys",
    "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.4-0\Drivers\WdBoot.sys",
    "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.4-0\Drivers\WdAiNisDrv.sys",
    "C:\tmpgfile.sys",
    "C:\Program Files\Riot Vanguard\vgk.sys",
    "C:\Program Files (x86)\Common Files\Steam\drivers\Windows10\x64\steamxbox.sys",
    "C:\Program Files (x86)\Common Files\Steam\drivers\Windows10\x86\steamxbox.sys",
    "C:\Windows\System32\drivers\fxvad.sys",
    "C:\Program Files\FxSound LLC\FxSound\Drivers\win7\x86\fxvad.sys",
    "C:\Program Files\FxSound LLC\FxSound\Drivers\win7\x64\fxvad.sys",
    "C:\Program Files\FxSound LLC\FxSound\Drivers\win10\x86\fxvad.sys",
    "C:\Program Files\FxSound LLC\FxSound\Drivers\win10\x64\fxvad.sys",
    "C:\Windows\System32\AMDRyzenMasterDriver.sys",
    "C:\Windows\System32\drivers\amdxe.sys",
    "C:\Windows\System32\drivers\kbldfltr.sys",
    "C:\Windows\System32\drivers\UevAgentDriver.sys",
    "C:\Windows\System32\drivers\AppvVfs.sys",
    "C:\Windows\System32\drivers\AppvVemgr.sys",
    "C:\Windows\System32\drivers\AppVStrm.sys",
    "C:\Windows\System32\drivers\modem.sys",
    "C:\Windows\System32\drivers\PktMon.sys",
    "C:\Windows\System32\drivers\EhStorClass.sys",
    "C:\Windows\System32\drivers\cdfs.sys",
    "C:\Windows\System32\drivers\volsnap.sys",
    "C:\Windows\System32\drivers\rassstp.sys",
    "C:\Windows\System32\drivers\raspptp.sys",
    "C:\Windows\System32\drivers\wanarp.sys",
    "C:\Windows\System32\drivers\ndproxy.sys",
    "C:\Windows\System32\drivers\ndistapi.sys",
    "C:\Windows\System32\drivers\NdisImPlatform.sys",
    "C:\Windows\System32\drivers\tunnel.sys",
    "C:\Windows\System32\drivers\scsiport.sys",
    "C:\Windows\System32\drivers\nsiproxy.sys",
    "C:\Windows\System32\drivers\WdfLdr.sys",
    "C:\Windows\System32\drivers\hwpolicy.sys",
    "C:\Windows\System32\drivers\msquic.sys",
    "C:\Windows\System32\drivers\pcw.sys",
    "C:\Windows\System32\drivers\wimmount.sys",
    "C:\Windows\System32\drivers\wof.sys",
    "C:\Windows\System32\drivers\dumpsdport.sys",
    "C:\Windows\System32\drivers\ufx01000.sys",
    "C:\Windows\System32\drivers\UcmUcsiCx.sys",
    "C:\Windows\System32\drivers\UcmCx.sys",
    "C:\Windows\System32\drivers\SpbCx.sys",
    "C:\Windows\System32\drivers\HidSpiCx.sys",
    "C:\Windows\System32\drivers\IndirectKmd.sys",
    "C:\Windows\System32\drivers\condrv.sys",
    "C:\Windows\System32\drivers\wcnfs.sys",
    "C:\Windows\System32\drivers\pacer.sys",
    "C:\Windows\System32\drivers\watchdog.sys",
    "C:\Windows\System32\drivers\vwififlt.sys",
    "C:\Windows\System32\drivers\bowser.sys",
    "C:\Windows\System32\drivers\fsdepends.sys",
    "C:\Windows\System32\drivers\sdport.sys",
    "C:\Windows\System32\drivers\mmcss.sys",
    "C:\Windows\System32\drivers\iorate.sys",
    "C:\Windows\System32\drivers\Synth3dVsc.sys",
    "C:\Windows\System32\drivers\RfxVmt.sys",
    "C:\Windows\System32\drivers\hvcrash.sys",
    "C:\Windows\System32\drivers\vmstorfl.sys",
    "C:\Windows\System32\drivers\storvsc.sys",
    "C:\Windows\System32\drivers\HyperVideo.sys",
    "C:\Windows\System32\drivers\sdstor.sys",
    "C:\Windows\System32\drivers\ufxsynopsys.sys",
    "C:\Windows\System32\drivers\hidspi.sys",
    "C:\Windows\System32\drivers\hidparse.sys",
    "C:\Windows\System32\drivers\hidclass.sys",
    "C:\Windows\System32\drivers\hidusb.sys",
    "C:\Windows\System32\drivers\Microsoft.Bluetooth.Legacy.LEEnumerator.sys",
    "C:\Windows\System32\drivers\hidbth.sys",
    "C:\Windows\System32\drivers\usbser.sys",
    "C:\Windows\System32\drivers\scmbus.sys",
    "C:\Windows\System32\drivers\storahci.sys",
    "C:\Windows\System32\drivers\pciidex.sys",
    "C:\Windows\System32\drivers\intelide.sys",
    "C:\Windows\System32\drivers\pciide.sys",
    "C:\Windows\System32\drivers\ataport.sys",
    "C:\Windows\System32\drivers\atapi.sys",
    "C:\Windows\System32\drivers\msisadrv.sys",
    "C:\Windows\System32\drivers\isapnp.sys",
    "C:\Windows\System32\drivers\msiscsi.sys",
    "C:\Windows\System32\drivers\volmgr.sys",
    "C:\Windows\System32\drivers\sbp2port.sys",
    "C:\Windows\System32\drivers\IntelTA.sys",
    "C:\Windows\System32\drivers\HdAudio.sys",
    "C:\Program Files\BlueStacks_msi5\BstkDrv_msi5.sys",
    "C:\Windows\System32\drivers\amdfendrmgr.sys",
    "C:\Windows\System32\AMD\amdfendr\amdfendrmgr.sys",
    "C:\Windows\System32\drivers\amdfendr.sys",
    "C:\Windows\System32\AMD\amdfendr\amdfendr.sys",
    "C:\Program Files (x86)\Common Files\Steam\drivers\Windows8.1\x86\SteamStreamingSpeakers.sys",
    "C:\Program Files (x86)\Common Files\Steam\drivers\Windows8.1\x64\SteamStreamingSpeakers.sys",
    "C:\Program Files (x86)\Common Files\Steam\drivers\Windows10\x86\SteamStreamingSpeakers.sys",
    "C:\Program Files (x86)\Common Files\Steam\drivers\Windows10\x64\SteamStreamingSpeakers.sys",
    "C:\Program Files (x86)\Common Files\Steam\drivers\Windows8.1\x86\SteamStreamingMicrophone.sys",
    "C:\Program Files (x86)\Common Files\Steam\drivers\Windows8.1\x64\SteamStreamingMicrophone.sys",
    "C:\Program Files (x86)\Common Files\Steam\drivers\Windows10\x86\SteamStreamingMicrophone.sys",
    "C:\Program Files (x86)\Common Files\Steam\drivers\Windows10\x64\SteamStreamingMicrophone.sys",
    "C:\Windows\System32\drivers\smbdirect.sys",
    "C:\Windows\System32\drivers\WpdUpFltr.sys",
    "C:\Windows\System32\drivers\SpatialGraphFilter.sys",
    "C:\Windows\System32\drivers\rdyboost.sys",
    "C:\Windows\System32\drivers\rootmdm.sys",
    "C:\Windows\System32\drivers\NDKPing.sys",
    "C:\Windows\System32\drivers\ndiscap.sys",
    "C:\Windows\System32\drivers\volmgrx.sys",
    "C:\Windows\System32\drivers\spaceparser.sys",
    "C:\Windows\System32\drivers\Ndu.sys",
    "C:\Windows\System32\drivers\smclib.sys",
    "C:\Windows\System32\drivers\asyncmac.sys",
    "C:\Windows\System32\drivers\qwavedrv.sys",
    "C:\Windows\System32\drivers\mslldp.sys",
    "C:\Windows\System32\drivers\NdisVirtualBus.sys",
    "C:\Windows\System32\drivers\netbios.sys",
    "C:\Windows\System32\drivers\tape.sys",
    "C:\Windows\System32\drivers\stream.sys",
    "C:\Windows\System32\drivers\mcd.sys",
    "C:\Windows\System32\drivers\beep.sys",
    "C:\Windows\System32\drivers\ntosext.sys",
    "C:\Windows\System32\drivers\mstee.sys",
    "C:\Windows\System32\drivers\mspqm.sys",
    "C:\Windows\System32\drivers\mspclock.sys",
    "C:\Windows\System32\drivers\rspndr.sys",
    "C:\Windows\System32\drivers\lltdio.sys",
    "C:\Windows\System32\drivers\videoprt.sys",
    "C:\Windows\System32\drivers\SleepStudyHelper.sys",
    "C:\Windows\System32\drivers\tdi.sys",
    "C:\Windows\System32\drivers\WppRecorder.sys",
    "C:\Windows\System32\drivers\wmilib.sys",
    "C:\Windows\System32\drivers\null.sys",
    "C:\Windows\System32\drivers\msfs.sys",
    "C:\Windows\System32\drivers\mountmgr.sys",
    "C:\Windows\System32\drivers\VerifierExt.sys",
    "C:\Windows\System32\drivers\fs_rec.sys",
    "C:\Windows\System32\drivers\ndisuio.sys",
    "C:\Windows\System32\drivers\fileinfo.sys",
    "C:\Windows\System32\drivers\filetrace.sys",
    "C:\Windows\System32\drivers\USBCAMD2.sys",
    "C:\Windows\System32\drivers\ws2ifsl.sys",
    "C:\Windows\System32\drivers\bam.sys",
    "C:\Windows\System32\drivers\WdmCompanionFilter.sys",
    "C:\Windows\System32\drivers\cnghwassist.sys",
    "C:\Windows\System32\drivers\urscx01000.sys",
    "C:\Windows\System32\drivers\UsbPmApi.sys",
    "C:\Windows\System32\drivers\UcmTcpciCx.sys",
    "C:\Windows\System32\drivers\SerCx2.sys",
    "C:\Windows\System32\drivers\SerCx.sys",
    "C:\Windows\System32\drivers\portcfg.sys",
    "C:\Windows\System32\drivers\mshidkmdf.sys",
    "C:\Windows\System32\drivers\mshwnclx.sys",
    "C:\Windows\System32\drivers\mpsdrv.sys",
    "C:\Windows\System32\drivers\ProcLaunchMon.sys",
    "C:\Windows\System32\drivers\mshidumdf.sys",
    "C:\Windows\System32\drivers\WdNisDrv.sys",
    "C:\Windows\ELAMBKUP\WdBoot.sys",
    "C:\Windows\System32\drivers\WdFilter.sys",
    "C:\Windows\System32\drivers\WdBoot.sys",
    "C:\Windows\System32\drivers\vwifimp.sys",
    "C:\Windows\System32\drivers\vwifibus.sys",
    "C:\Windows\System32\drivers\Udecx.sys",
    "C:\Windows\System32\drivers\Ucx01000.sys",
    "C:\Windows\System32\drivers\acpiex.sys",
    "C:\Windows\System32\drivers\TsUsbFlt.sys",
    "C:\Windows\System32\drivers\ramdisk.sys",
    "C:\Windows\System32\drivers\filecrypt.sys",
    "C:\Windows\System32\drivers\rteth.sys",
    "C:\Windows\System32\drivers\ipt.sys",
    "C:\Windows\System32\drivers\gpuenergydrv.sys",
    "C:\Windows\System32\drivers\vms3cap.sys",
    "C:\Windows\System32\drivers\vmgid.sys",
    "C:\Windows\System32\drivers\vmgencounter.sys",
    "C:\Windows\System32\drivers\VMBusHID.sys",
    "C:\Windows\System32\drivers\hyperkbd.sys",
    "C:\Windows\System32\drivers\dmvsc.sys",
    "C:\Windows\System32\drivers\rdpbus.sys",
    "C:\Windows\System32\drivers\terminpt.sys",
    "C:\Windows\System32\drivers\WindowsTrustedRTProxy.sys",
    "C:\Windows\System32\drivers\npsvctrig.sys",
    "C:\Windows\System32\drivers\msgpiowin32.sys",
    "C:\Windows\System32\drivers\kdnic.sys",
    "C:\Windows\System32\drivers\winusb.sys",
    "C:\Windows\System32\drivers\UcmUcsiAcpiClient.sys",
    "C:\Windows\System32\drivers\kbdhid.sys",
    "C:\Windows\System32\drivers\kbdclass.sys",
    "C:\Windows\System32\drivers\i8042prt.sys",
    "C:\Windows\System32\drivers\hidinterrupt.sys",
    "C:\Windows\System32\drivers\buttonconverter.sys",
    "C:\Windows\System32\drivers\umpass.sys",
    "C:\Windows\System32\drivers\sermouse.sys",
    "C:\Windows\System32\drivers\mouhid.sys",
    "C:\Windows\System32\drivers\mouclass.sys",
    "C:\Windows\System32\drivers\wmiacpi.sys",
    "C:\Windows\System32\drivers\vdrvroot.sys",
    "C:\Windows\System32\drivers\bttflt.sys",
    "C:\Windows\System32\drivers\rt640x64.sys",
    "C:\Windows\System32\drivers\nvdimm.sys",
    "C:\Windows\System32\drivers\serial.sys",
    "C:\Windows\System32\drivers\serenum.sys",
    "C:\Windows\System32\drivers\parport.sys",
    "C:\Windows\System32\drivers\mssmbios.sys",
    "C:\Windows\System32\drivers\mausbip.sys",
    "C:\Windows\System32\drivers\mausbhost.sys",
    "C:\Windows\System32\drivers\vhf.sys",
    "C:\Windows\System32\drivers\sfloppy.sys",
    "C:\Windows\System32\drivers\iaStorV.sys",
    "C:\Windows\System32\drivers\iaStorAVC.sys",
    "C:\Windows\System32\drivers\hidbatt.sys",
    "C:\Windows\System32\drivers\flpydisk.sys",
    "C:\Windows\System32\drivers\fdc.sys",
    "C:\Windows\System32\drivers\CmBatt.sys",
    "C:\Windows\System32\drivers\battc.sys",
    "C:\Windows\System32\drivers\acpitime.sys",
    "C:\Windows\System32\drivers\acpipagr.sys",
    "C:\Windows\System32\drivers\winverbs.sys",
    "C:\Windows\System32\drivers\winmad.sys",
    "C:\Windows\System32\drivers\ndfltr.sys",
    "C:\Windows\System32\drivers\mlx4_bus.sys",
    "C:\Windows\System32\drivers\ibbus.sys",
    "C:\Windows\System32\drivers\errdev.sys",
    "C:\Windows\System32\drivers\cht4vx64.sys",
    "C:\Windows\System32\drivers\cht4vfx.sys",
    "C:\Windows\System32\drivers\VSTXRAID.SYS",
    "C:\Windows\System32\drivers\vsmraid.sys",
    "C:\Windows\System32\drivers\cht4sx64.sys",
    "C:\Windows\System32\drivers\cht4dx64.sys",
    "C:\Windows\System32\drivers\stexstor.sys",
    "C:\Windows\System32\drivers\SmartSAMD.sys",
    "C:\Windows\System32\drivers\sisraid4.sys",
    "C:\Windows\System32\drivers\sisraid2.sys",
    "C:\Windows\System32\drivers\percsas3i.sys",
    "C:\Windows\System32\drivers\percsas2i.sys",
    "C:\Windows\System32\drivers\nvstor.sys",
    "C:\Windows\System32\drivers\nvraid.sys",
    "C:\Windows\System32\drivers\mvumis.sys",
    "C:\Windows\System32\drivers\megasr.sys",
    "C:\Windows\System32\drivers\megasas35i.sys",
    "C:\Windows\System32\drivers\MegaSas2i.sys",
    "C:\Windows\System32\drivers\megasas.sys",
    "C:\Windows\System32\drivers\lsi_sss.sys",
    "C:\Windows\System32\drivers\lsi_sas3i.sys",
    "C:\Windows\System32\drivers\lsi_sas2i.sys",
    "C:\Windows\System32\drivers\lsi_sas.sys",
    "C:\Windows\System32\drivers\ItSas35i.sys",
    "C:\Windows\System32\drivers\HpSAMD.sys",
    "C:\Windows\System32\drivers\wacompen.sys",
    "C:\Windows\System32\drivers\MTConfig.sys",
    "C:\Windows\System32\drivers\arcsas.sys",
    "C:\Windows\System32\drivers\amdxata.sys",
    "C:\Windows\System32\drivers\amdsbs.sys",
    "C:\Windows\System32\drivers\amdsata.sys",
    "C:\Windows\System32\drivers\adp80xx.sys",
    "C:\Windows\System32\drivers\3ware.sys",
    "C:\Windows\System32\drivers\1394ohci.sys",
    "C:\Windows\System32\drivers\volume.sys",
    "C:\Windows\System32\drivers\AcpiDev.sys",
    "C:\Windows\System32\drivers\evbda.sys",
    "C:\Windows\System32\drivers\SDFRd.sys",
    "C:\Windows\System32\drivers\rhproxy.sys",
    "C:\Windows\System32\drivers\pnpmem.sys",
    "C:\Windows\System32\drivers\iaLPSSi_GPIO.sys",
    "C:\Windows\System32\drivers\bxvbda.sys",
    "C:\Windows\System32\drivers\acpipmi.sys",
    "C:\Windows\System32\drivers\usbcir.sys",
    "C:\Windows\System32\drivers\usbaudio2.sys",
    "C:\Windows\System32\drivers\iaLPSSi_I2C.sys",
    "C:\Windows\System32\drivers\hidir.sys",
    "C:\Windows\System32\drivers\EhStorTcgDrv.sys",
    "C:\Windows\System32\drivers\circlass.sys",
    "C:\Windows\System32\drivers\bthmodem.sys",
    "C:\Windows\System32\drivers\pcmcia.sys",
    "C:\Windows\System32\drivers\CAD.sys",
    "C:\Windows\System32\drivers\intelpmax.sys",
    "C:\Windows\System32\drivers\iai2c.sys",
    "C:\Windows\System32\drivers\iaLPSS2i_I2C.sys",
    "C:\Windows\System32\drivers\iaLPSS2i_I2C_GLK.sys",
    "C:\Windows\System32\drivers\iaLPSS2i_I2C_CNL.sys",
    "C:\Windows\System32\drivers\iaLPSS2i_I2C_BXT_P.sys",
    "C:\Windows\System32\drivers\iaLPSS2i_GPIO2_GLK.sys",
    "C:\Windows\System32\drivers\iaLPSS2i_GPIO2_CNL.sys",
    "C:\Windows\System32\drivers\iaLPSS2i_GPIO2_BXT_P.sys",
    "C:\Windows\System32\drivers\iaLPSS2i_GPIO2.sys",
    "C:\Windows\System32\drivers\iagpio.sys",
    "C:\Windows\System32\drivers\bcmfn2.sys",
    "C:\Windows\System32\drivers\amdi2c.sys",
    "C:\Windows\System32\drivers\BthHfEnum.sys",
    "C:\Windows\System32\drivers\BthA2dp.sys",
    "C:\Windows\System32\drivers\amdgpio2.sys",
    "C:\Windows\System32\drivers\amdgpio3.sys"
)

function Test-WhitelistedDriver {
    param(
        [string]$Path
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)

    foreach ($whitelistFolder in $whitelistFolders) {

        # A entrada e "C:\pasta\*.sys", mas a comparacao usa o prefixo da
        # pasta: o -Filter "*.sys" da varredura aceita nomes que nao terminam
        # em .sys (ex.: ..._null.sys_e821cef0 e ..._Win32.SystemEvents) e o
        # -like com sufixo ".sys" nao casa esses nomes.
        $star = $whitelistFolder.IndexOf('*')
        $folder = $whitelistFolder

        if ($star -ge 0) {
            $folder = $whitelistFolder.Substring(0, $star)
        }

        if (-not $folder.EndsWith('\')) {
            $folder += '\'
        }

        if ($fullPath.StartsWith(
            $folder,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            return $true
        }
    }

    foreach ($whitelistPath in $whitelistPaths) {
        if ($fullPath.Equals(
            $whitelistPath,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            return $true
        }
    }

    return $false
}

Write-Host "`n[*] Localizando arquivos *.sys..." -ForegroundColor Gray

$drives = Get-CimInstance Win32_LogicalDisk `
    -Filter "DriveType = 3" `
    -ErrorAction SilentlyContinue

foreach ($drive in $drives) {

    Write-Host "[*] Procurando em $($drive.DeviceID)..." -ForegroundColor DarkGray

    try {

        Get-ChildItem `
            -LiteralPath "$($drive.DeviceID)\" `
            -Filter "*.sys" `
            -File `
            -Recurse `
            -Force `
            -ErrorAction SilentlyContinue |
        ForEach-Object {

            if ($checked.Add($_.FullName)) {

                if (-not (Test-WhitelistedDriver -Path $_.FullName)) {
                    $drivers += $_.FullName
                }
            }
        }
    }
    catch {
    }
}

Write-Host "`n[*] Drivers encontrados: $($drivers.Count)" -ForegroundColor Gray
Write-Host "[*] Iniciando verificação de assinatura..." -ForegroundColor Gray

$unsignedDrivers = @()
$invalidDrivers = @()
$invalidReasons = @{}
$checkedCount = 0

foreach ($driver in $drivers) {

    $checkedCount++

    $percent = ($checkedCount / [Math]::Max($drivers.Count,1)) * 100

    Write-Progress `
        -Activity "Verificando assinaturas" `
        -Status "$checkedCount / $($drivers.Count)" `
        -PercentComplete $percent

    $process = $null

    try {

        $startInfo = New-Object System.Diagnostics.ProcessStartInfo

        $startInfo.FileName = $sigcheck.FullName
        $startInfo.Arguments = "-accepteula -nobanner -i -h `"$driver`""
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true

        # O Sigcheck grava UTF-16LE quando a saida e redirecionada.
        # Sem isso a leitura volta cheia de NUL e nenhum teste de status pega nada.
        $startInfo.StandardOutputEncoding = [System.Text.Encoding]::Unicode

        $process = [System.Diagnostics.Process]::Start($startInfo)

        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()

        $process.WaitForExit()

        $output = $stdoutTask.GetAwaiter().GetResult()
        $null = $stderrTask.GetAwaiter().GetResult()

        if ([string]::IsNullOrWhiteSpace($output)) {
            continue
        }

        # O estado da assinatura vem no campo "Verified:" do bloco do arquivo.
        $verifiedMatch = [regex]::Match(
            $output,
            '(?m)^\s*Verified:\s*(?<status>\S.*?)\s*$'
        )

        if (-not $verifiedMatch.Success) {

            # arquivo removido entre a coleta e a verificacao
            if ($output -match '(?m)^\s*No matching files were found\.') {
                continue
            }

            $invalidDrivers += $driver
            $invalidReasons[$driver] = "<ausente>"

            continue
        }

        $verified = $verifiedMatch.Groups['status'].Value

        if ($verified -match '(?i)unsigned|not signed|no signature') {

            $unsignedDrivers += $driver

            continue
        }

        if ($verified -notmatch '(?i)^signed') {

            $invalidDrivers += $driver
            $invalidReasons[$driver] = $verified
        }
    }
    catch {
    }
    finally {

        if ($null -ne $process) {
            $process.Dispose()
        }
    }
}

Write-Progress `
    -Activity "Verificando assinaturas" `
    -Completed

Write-Host "`n========================================" -ForegroundColor DarkGray
Write-Host "[*] SIGNATURE SCAN FINISHED" -ForegroundColor Gray
Write-Host "========================================" -ForegroundColor DarkGray

Write-Host "`n[*] Drivers analisados: $checkedCount" -ForegroundColor Gray
Write-Host "[!] Não assinados: $($unsignedDrivers.Count)" -ForegroundColor Red
Write-Host "[!] Assinatura com problema: $($invalidDrivers.Count)" -ForegroundColor Yellow

if ($unsignedDrivers.Count -gt 0) {

    Write-Host "`n[!] UNSIGNED DRIVERS FOUND" -ForegroundColor Red

    foreach ($driver in $unsignedDrivers) {
        Write-Host "    $driver" -ForegroundColor Red
    }

}
elseif ($invalidDrivers.Count -gt 0) {

    Write-Host "`n[!] SIGNATURE PROBLEMS FOUND" -ForegroundColor Red

    foreach ($driver in $invalidDrivers) {
        Write-Host "    $driver" -ForegroundColor Yellow
        Write-Host "      Verified: $($invalidReasons[$driver])" -ForegroundColor DarkGray
    }

}
else {

    Write-Host "`n[+] Nenhum problema de assinatura encontrado." -ForegroundColor Green
}

Remove-Item `
    -LiteralPath $tempDir `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# Varredura 7045 - listas proprias desta secao.
# Usa nomes diferentes de $whitelistPaths / $whitelistFolders para nao
# sobrescrever as listas usadas por Test-WhitelistedDriver.
# ---------------------------------------------------------------------------

$serviceWhitelistFolders = @(
    "$env:SystemRoot\System32\"
    "$env:SystemRoot\WinSxS\"
    "$env:SystemRoot\servicing\"
    "$env:SystemRoot\Inf\"
    "$env:ProgramData\Microsoft\"
    "${env:ProgramFiles}\Common Files\BattlEye\"
    "${env:ProgramFiles(x86)}\Common Files\BattlEye\"
    "${env:ProgramFiles}\EasyAntiCheat\"
    "${env:ProgramFiles(x86)}\EasyAntiCheat\"
    "${env:ProgramFiles}\EasyAntiCheat_EOS\"
    "${env:ProgramFiles(x86)}\EasyAntiCheat_EOS\"
    "${env:ProgramFiles}\MSI Afterburner\"
    "${env:ProgramFiles(x86)}\MSI Afterburner\"
)

$serviceWhitelistPaths = @(
    "C:\Users\danie\AppData\Local\Temp\pme1DDA.tmp"
)

function Resolve-ServiceImagePath {
    param(
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $Path
    }

    $resolved = $Path.Trim().Trim('"')

    foreach ($prefix in @('\??\', '\\?\')) {
        if ($resolved.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            $resolved = $resolved.Substring($prefix.Length)
        }
    }

    $systemRoot = [string]$env:SystemRoot

    if ([string]::IsNullOrWhiteSpace($systemRoot)) {
        $systemRoot = "C:\Windows"
    }

    # O 7045 grava caminhos como \SystemRoot\System32\... em vez de C:\Windows\...
    if ($resolved.StartsWith('\SystemRoot\', [System.StringComparison]::OrdinalIgnoreCase)) {
        $resolved = $systemRoot + $resolved.Substring('\SystemRoot'.Length)
    }
    elseif ($resolved.StartsWith('\Windows\', [System.StringComparison]::OrdinalIgnoreCase)) {
        $resolved = $systemRoot + $resolved.Substring('\Windows'.Length)
    }
    elseif ($resolved -match '(?i)^\\device\\harddiskvolume\d+') {
        $resolved = Convert-DevicePath $resolved
    }

    return $resolved
}

function Test-TrustedServicePath {
    param(
        [string]$Path
    )

    foreach ($whitelistFolder in $serviceWhitelistFolders) {

        if ([string]::IsNullOrWhiteSpace($whitelistFolder)) {
            continue
        }

        $folder = $whitelistFolder

        if (-not $folder.EndsWith('\')) {
            $folder += '\'
        }

        if ($Path.StartsWith($folder, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Test-WhitelistedPath {
    param(
        [string]$Path
    )

    foreach ($whitelistPath in $serviceWhitelistPaths) {
        if ($Path.Equals($whitelistPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Get-ServiceFileSignature {
    param(
        [string]$Path
    )

    $result = [PSCustomObject]@{
        Exists    = $false
        Status    = "FileNotFound"
        Publisher = $null
    }

    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {

            $result.Exists = $true

            $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $result.Status = $signature.Status.ToString()

            if ($signature.SignerCertificate -and
                $signature.SignerCertificate.Subject -match 'CN=([^,]+)') {
                $result.Publisher = $matches[1].Trim()
            }
        }
    }
    catch {
        $result.Status = "UnknownError"
    }

    return $result
}

$findings = @()
$allowed = @()

Write-Host "`n[*] KDMAPPER SCANNER ( SYSTEM 7045 )" -ForegroundColor Cyan

$events = @(Get-WinEvent `
    -FilterHashtable @{
        LogName = "System"
        Id = 7045
    } `
    -ErrorAction SilentlyContinue)

# Agrupa os eventos por arquivo: o 7045 repete o mesmo driver a cada
# reinstalacao/abertura de jogo, gerando dezenas de blocos identicos.
$serviceFiles = @{}

foreach ($event in $events) {

    $message = $event.Message

    if ([string]::IsNullOrWhiteSpace($message)) {
        continue
    }

    $serviceName = $null
    $serviceFile = $null
    $serviceType = $null

    if ($message -match '(?im)^\s*Nome do Serviço:\s*(.+?)\s*$') {
        $serviceName = $matches[1].Trim()
    }

    if ($message -match '(?im)^\s*Nome do Arquivo de Serviço:\s*(.+?)\s*$') {
        $serviceFile = $matches[1].Trim()
    }

    if ($message -match '(?im)^\s*Tipo de Serviço:\s*(.+?)\s*$') {
        $serviceType = $matches[1].Trim()
    }

    if (
        [string]::IsNullOrWhiteSpace($serviceName) -and
        [string]::IsNullOrWhiteSpace($serviceFile) -and
        [string]::IsNullOrWhiteSpace($serviceType)
    ) {
        continue
    }

    if ([string]::IsNullOrWhiteSpace($serviceFile)) {
        continue
    }

    if ($serviceFile -notmatch '(?i)\.(sys|tmp)\s*$') {
        continue
    }

    $resolvedPath = Resolve-ServiceImagePath -Path $serviceFile
    $key = $resolvedPath.ToLowerInvariant()

    if (-not $serviceFiles.ContainsKey($key)) {

        $serviceFiles[$key] = [PSCustomObject]@{
            Path        = $resolvedPath
            RawPath     = $serviceFile
            ServiceName = $serviceName
            ServiceType = $serviceType
            Events      = 0
            FirstSeen   = $event.TimeCreated
            LastSeen    = $event.TimeCreated
        }
    }

    $entry = $serviceFiles[$key]
    $entry.Events++

    if ($event.TimeCreated -lt $entry.FirstSeen) {
        $entry.FirstSeen = $event.TimeCreated
    }

    if ($event.TimeCreated -gt $entry.LastSeen) {
        $entry.LastSeen = $event.TimeCreated
    }
}

$uniqueEntries = @($serviceFiles.Values | Sort-Object -Property LastSeen -Descending)

foreach ($entry in $uniqueEntries) {

    $signature = Get-ServiceFileSignature -Path $entry.Path

    $firstDate = $entry.FirstSeen.ToString("dd/MM/yyyy HH:mm:ss")
    $lastDate = $entry.LastSeen.ToString("dd/MM/yyyy HH:mm:ss")

    $date = if ($entry.Events -gt 1) {
        "$firstDate ate $lastDate ($($entry.Events)x)"
    }
    else {
        $lastDate
    }

    $allowedReason = $null

    if (Test-WhitelistedPath -Path $entry.Path) {

        $allowedReason = "whitelist da ferramenta"
    }
    elseif ($signature.Exists -and $signature.Status -eq "Valid") {

        $allowedReason = if ($signature.Publisher) {
            "assinatura valida - $($signature.Publisher)"
        }
        else {
            "assinatura valida"
        }
    }
    elseif ((-not $signature.Exists) -and (Test-TrustedServicePath -Path $entry.Path)) {

        # Pasta do Windows/fornecedor conhecido: o evento e antigo e o arquivo
        # saiu do disco por atualizacao, nao por remocao suspeita.
        $allowedReason = "pasta confiavel - arquivo removido/atualizado"
    }

    if ($allowedReason) {

        $allowed += [PSCustomObject]@{
            Date        = $date
            ServiceName = $entry.ServiceName
            ServiceFile = $entry.RawPath
            ServiceType = $entry.ServiceType
            Reason      = $allowedReason
        }

        continue
    }

    $details = if (-not $signature.Exists) {
        "arquivo nao encontrado no disco (indice de driver apagado apos o mapeamento)"
    }
    elseif ($signature.Publisher) {
        "assinatura $($signature.Status) - $($signature.Publisher)"
    }
    else {
        "assinatura $($signature.Status)"
    }

    $findings += [PSCustomObject]@{
        Date        = $date
        ServiceName = $entry.ServiceName
        ServiceFile = $entry.RawPath
        ServiceType = $entry.ServiceType
        Details     = $details
    }

    Write-Host "`n[!] ARQUIVO DETECTADO" -ForegroundColor Red
    Write-Host "    Data: $date" -ForegroundColor Yellow
    Write-Host "    Nome do Serviço: $($entry.ServiceName)" -ForegroundColor Yellow
    Write-Host "    Nome do Arquivo de Serviço: $($entry.RawPath)" -ForegroundColor Yellow
    Write-Host "    Tipo de Serviço: $($entry.ServiceType)" -ForegroundColor Yellow
    Write-Host "    Motivo: $details" -ForegroundColor Yellow
}

Write-Host "`n[*] Eventos 7045 analisados: $($events.Count)" -ForegroundColor Cyan
Write-Host "[*] Arquivos .SYS/.TMP unicos: $($uniqueEntries.Count)" -ForegroundColor Cyan

if ($allowed.Count -gt 0) {

    Write-Host "`n[+] PERMITIDOS (assinatura valida ou pasta confiavel): $($allowed.Count)" -ForegroundColor Green

    foreach ($item in $allowed) {
        Write-Host "    [+] $($item.ServiceName) - $($item.ServiceFile)" -ForegroundColor DarkGray
        Write-Host "        $($item.Date) | $($item.Reason)" -ForegroundColor DarkGray
    }
}

if ($findings.Count -eq 0) {
    Write-Host "`n[+] Nenhum .SYS ou .TMP suspeito encontrado." -ForegroundColor Green
}
else {
    Write-Host "`n[!] INDICADORES ENCONTRADOS: $($findings.Count)" -ForegroundColor Red
}

#Requires -Version 5.1

$script:ByovdScriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace([string]$script:ByovdScriptRoot)) {
    $script:ByovdScriptRoot = (Get-Location).Path
}

$script:ByovdConfig = @{
    BaseLolDriversPath   = $null

    ExtraScanPaths       = @((Join-Path $env:TEMP 'byovd_bypass'))

    ScanRegistry         = $true
    ScanCim              = $true
    ScanServices         = $true
    ScanRecursive        = $true

    ScanSystem32Drivers  = $true
    ScanSystem32Root     = $true
    ScanWindowsTemp      = $true
    ScanSysWow64         = $false

    Whitelist            = @(
    )

    StrongValueMaxDrivers = 3
    WeakValueMaxDrivers   = 10
    MinWeakMetaFields     = 2

    MaxFileBytes          = 268435456
    MaxImportSymbols      = 8192
    MaxImportDescriptors  = 512
    MaxEvidenceCache      = 4096

    ShowProgress          = $false
    ProgressEvery         = 25
}

if ($LolDriversPath)   { $script:ByovdConfig.BaseLolDriversPath = $LolDriversPath }
if ($ExtraScanPath)    { $script:ByovdConfig.ExtraScanPaths     = @($ExtraScanPath) }

$script:ByovdDotSourced = ($MyInvocation.InvocationName -eq '.' -or
                           ($MyInvocation.Line -is [string] -and $MyInvocation.Line -match '^\s*\.'))

$script:ByovdProgressMode = 'host'
$script:ByovdLogNoColor   = $false

function Write-ByovdLog {
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Message = '',
        [string]$Color = 'Gray'
    )
    $mode = [string]$script:ByovdProgressMode
    if ([string]::IsNullOrWhiteSpace($mode)) { $mode = 'host' }
    if ($mode -eq 'none') { return }

    $ts = try { (Get-Date).ToString('HH:mm:ss') } catch { '' }
    $line = if ($ts) { '[{0}] {1}' -f $ts, $Message } else { $Message }

    if ($mode -eq 'stderr') {
        try { [Console]::Error.WriteLine($line) } catch { }
        return
    }
    if ($script:ByovdLogNoColor) {
        try { Write-Host $line } catch { }
        return
    }
    try { Write-Host $line -ForegroundColor $Color }
    catch { Write-Host $line }
}

function Test-ByovdStandaloneLaunch {
    [CmdletBinding()]
    param()
    try {
        $cli = [Environment]::GetCommandLineArgs()
        if (-not $cli) { return $false }
        $path = [string]$PSCommandPath
        for ($i = 0; $i -lt $cli.Count; $i++) {
            $a = [string]$cli[$i]
            if ($a -imatch '^-F(ile)?(:.*)?$') { return $true }
            if ($path -and $a -and ($a -ieq $path)) { return $true }
        }
    }
    catch { }
    return $false
}

function Wait-ByovdKey {
    [CmdletBinding()]
    param([string]$Message = 'Pressione ENTER para fechar...')
    try { if ([Console]::IsOutputRedirected) { return } } catch { }
    $hostName = ''
    try { $hostName = [string]$Host.Name } catch { }
    if ($hostName -match 'ISE') { return }
    try { Write-Host '' } catch { }
    try { Write-Host $Message -ForegroundColor DarkCyan } catch { }
    try { $null = Read-Host } catch { }
}

function ConvertTo-ByovdHexString {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return '' }
    return [System.BitConverter]::ToString($Bytes).Replace('-', '').ToLowerInvariant()
}

function Get-ByovdField {
    [CmdletBinding()]
    param(
        $Object,
        [Parameter(Mandatory)][string[]]$Names,
        $Default = $null
    )
    if ($null -eq $Object) { return $Default }
    foreach ($n in $Names) {
        if ($Object -is [System.Collections.IDictionary]) {
            $found = $false
            if ($null -ne $Object.PSObject.Methods['ContainsKey']) {
                $found = $Object.ContainsKey($n)
            }
            elseif ($null -ne $Object.PSObject.Methods['Contains']) {
                $found = $Object.Contains($n)
            }
            if ($found) {
                $v = $Object[$n]
                if ($null -ne $v) { return $v }
            }
        }
        else {
            $p = $Object.PSObject.Properties[$n]
            if ($p -and $null -ne $p.Value) { return $p.Value }
        }
    }
    return $Default
}

function Get-ByovdStringList {
    [CmdletBinding()]
    param($Value)
    if ($null -eq $Value) { return @() }
    $out = New-Object System.Collections.Generic.List[string]
    if ($Value -is [string]) {
        $t = $Value.Trim()
        if ($t) { $out.Add($t) }
        return $out.ToArray()
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        foreach ($item in $Value) {
            if ($null -eq $item) { continue }
            $t = ([string]$item).Trim()
            if ($t) { $out.Add($t) }
        }
    }
    else {
        $t = ([string]$Value).Trim()
        if ($t) { $out.Add($t) }
    }
    return $out.ToArray()
}

function Get-ByovdText {
    [CmdletBinding()]
    param(
        $Object,
        [Parameter(Mandatory)][string[]]$Names,
        [string]$Default = ''
    )
    $v = $null
    try { $v = Get-ByovdField -Object $Object -Names $Names -Default $null } catch { return $Default }
    if ($null -eq $v) { return $Default }
    if ($v -is [string]) { return $v }
    if ($v -is [System.Collections.IEnumerable]) {
        $parts = @(Get-ByovdStringList $v)
        if ($parts.Count -eq 0) { return $Default }
        return [string]::Join(' ', $parts)
    }
    $s = [string]$v
    if ($null -eq $s) { return $Default }
    return $s
}

function ConvertTo-ByovdNormalizedText {
    [CmdletBinding()]
    param(
        $Value,
        [string]$Field = ''
    )
    if ($null -eq $Value) { return '' }
    $s = ([string]$Value).Trim()
    if (-not $s) { return '' }
    if ($s.Length -ge 2) {
        $a = $s[0]; $b = $s[$s.Length - 1]
        if (($a -eq '"' -and $b -eq '"') -or ($a -eq "'" -and $b -eq "'")) {
            $s = $s.Substring(1, $s.Length - 2).Trim()
        }
    }
    $s = $s.ToLowerInvariant()
    $s = $s -replace '\s+', ' '
    if ($Field -eq 'fileversion' -or $Field -eq 'productversion') {
        $s = $s -replace '[\s,]+', '.'
        $s = $s -replace '\.{2,}', '.'
        $s = $s.Trim('.')
    }
    return $s
}

function Test-LolDriversRoot {
    [CmdletBinding()]
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $null }

    $full = $null
    try { $full = (Resolve-Path -LiteralPath $Path).Path } catch { return $null }

    $json = Join-Path $full 'loldrivers.io\content\api\drivers.json'
    $hashes = Join-Path $full 'detections\hashes'

    $jsonOk = Test-Path -LiteralPath $json -PathType Leaf
    if (-not $jsonOk) { return $null }

    [pscustomobject]@{
        Root       = $full
        JsonPath   = $json
        HashesPath = if (Test-Path -LiteralPath $hashes -PathType Container) { $hashes } else { $null }
    }
}

function Find-LolDriversBase {
    [CmdletBinding()]
    param([string]$Path)

    $seeds = New-Object System.Collections.Generic.List[string]
    if ($Path) { $seeds.Add($Path) }
    if ($script:ByovdConfig.BaseLolDriversPath) { $seeds.Add([string]$script:ByovdConfig.BaseLolDriversPath) }
    if ($script:ByovdScriptRoot) { $seeds.Add([string]$script:ByovdScriptRoot) }
    try { $seeds.Add((Get-Location).Path) } catch { }

    $ordered = @($seeds | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') } | Select-Object -Unique)

    foreach ($seed in $ordered) {
        $hit = Test-LolDriversRoot $seed
        if ($hit) { return $hit }
        $cur = $seed
        for ($i = 0; $i -lt 5; $i++) {
            $parent = Split-Path -Parent $cur
            if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cur) { break }
            $cur = $parent
            $hit = Test-LolDriversRoot $cur
            if ($hit) { return $hit }
        }
    }

    foreach ($seed in $ordered) {
        if (-not (Test-Path -LiteralPath $seed -PathType Container)) { continue }
        foreach ($dir in @(Get-ChildItem -LiteralPath $seed -Directory -ErrorAction SilentlyContinue)) {
            $hit = Test-LolDriversRoot $dir.FullName
            if ($hit) { return $hit }
        }
    }

    foreach ($seed in $ordered) {
        if (-not (Test-Path -LiteralPath $seed -PathType Container)) { continue }
        $found = @(Get-ChildItem -LiteralPath $seed -Directory -Recurse -Depth 4 -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -like 'LOLDrivers*' -or $_.Name -eq 'loldrivers.io' } |
                   ForEach-Object { Test-LolDriversRoot $_.FullName } |
                   Where-Object { $_ } |
                   Select-Object -First 1)
        if ($found.Count -gt 0) { return $found[0] }
    }

    return $null
}

$script:ByovdEmbeddedPayload = @'
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
Ltes/MCwzDV5PjDbtDBWQWEW9AqMcLZl8J7a5IyE0YqiIseXjwul021hqi2WZovDUxVTeeIgBLozW+BJz2hVmeRX2LeY/Er3r0SJsY1xIKaSHUwI+NxFFqdU
oIthMMocZSr8ydW6Ujqsn2XFpPpxEKeiqlpIJzfyoOGd4wo6dEQq05Jwj1gv/Sxp4gQBMy9FJlT0vkTaY0sw3+IkTcK9gGowid2skRNp8MXyoKSITAxecrSK
0AJb0BzPJGVYUOxBSWqpwKXJ0jSQFJRJnViQt51JNn8xbA1IK1eBnzfwNuiNgXVcyOfdtRxVZhaSJ/ogpzB+C6SGULaCUFei4RZonM2JgrfMMPgTEAW7IMeD
CHIjHF1JSFiE9FGBIyhwszIoqQKSUuv+qkBug1tpYYIIttW7OVURlXJO/BGorfcki9yUMhN58Bahni1xigUkoKcTySgvPymqDOcJKhM4xO9bCs9fYRfEUoy5
0q4HuKOghPLCTQU6wQRINRUy42huFnkRmpt6Mx5jQ6nEa0J7HbyNapFJB+crtMTQsJb8aUxhuO6anWF9q8RNZDigrkMmg0QKkF+1n5lJ29FX1BofYHEAKy0q
4eWEp7+iFzzBxNIKokHZAFN4KclLuGZrWE5zyS26ogqDNaF0M3lZsfkvsiKi9fFBn3y82zabuzgdvo9KkQuXSvGYsXUW1dS8uvtxfbgDP2ygYyZx+mbzgm6u
0rt1fXm8W6tyYPtliQo0vyl9uLTgeYmmCFS0M4h0jZlDUiHt0bXt2vNSZ+W3OUKnZQonOExnpCuC3F/GJN1Olrcx59FSV31c1luT2qfn5zWmYEyRZzLvPtSb
Znlozi/HTqcMtMlwC7mlLlAyZOrKwxiv4JNzYFhXXhzyNbmpwZ28KItrf4LHc1iAVBrRPecoFTa0oma3u29rLGYw5CN8vGD6p7EknYWa0oZj6viTzSNrk6E6
Cd5sAcMlzPYxQV/lQYb8sMjfXm63z5OU9K5b66MTjUY3acygGm6wOW51ubrl7nh4fDp2h+m9Zn0M5zKYs7XpxtvbQkXG6SOPznX+nAvA35eF0xTTrpjGpUfG
V7kh5IM5nBY5t9LthTenyxIzKWNyWkyvhsVsjgeshuAk77H4a9ufMY27ruOs07+ZbHXsqW12rEma7g+3HJSLw/hE7OkJ84O6h41scUf3AKStw+jmVMCfzx0M
p+6ltlPNyTr70m+3p25PRRUnvz5v3fw8i1v7eMBPnrgbrYvbc9PonKJOerMv9d6lYiy+QPfVuxru5XBXF19eLj+ZTwb9wx/8ydf/9udff/onv/7tn339dz93
T3750l//p7/++tOf//Bv/9Wvfvl3PvIP/7df/Zd/88Pf//23f/hfvv78r7/+l7/9+vv/ByzK0yn27Y/+K0h/9fe/hIv8+g//5ut//dNvf/vLb7/8mbP9vPj2
x3/x7ae//fUvf+/r7/zc3Wxc/PqPfvHtz/74cJg8rpNB8Nd/8y8ndRr/H4J/nJ0GIwgA
'@

function ConvertFrom-ByovdBase64Gzip {
    [CmdletBinding()]
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }

    $sb = New-Object System.Text.StringBuilder
    foreach ($line in ($Text -split "`r`n|`n")) {
        $t = $line.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        [void]$sb.Append($t)
    }
    if ($sb.Length -eq 0) { return '' }

    $raw = $null
    try   { $raw = [Convert]::FromBase64String($sb.ToString()) }
    catch { return '' }
    if ($null -eq $raw -or $raw.Length -eq 0) { return '' }

    $ms = $null; $gz = $null; $out = $null
    try {
        $ms  = [System.IO.MemoryStream]::new($raw)
        $gz  = [System.IO.Compression.GZipStream]::new($ms, [System.IO.Compression.CompressionMode]::Decompress)
        $out = [System.IO.MemoryStream]::new()
        $buf = New-Object byte[] 65536
        $n = 0
        while (($n = $gz.Read($buf, 0, $buf.Length)) -gt 0) { [void]$out.Write($buf, 0, $n) }
        return [System.Text.Encoding]::UTF8.GetString($out.ToArray())
    }
    catch { return '' }
    finally {
        if ($gz)  { try { $gz.Close()  } catch { } }
        if ($out) { try { $out.Close() } catch { } }
        if ($ms)  { try { $ms.Close()  } catch { } }
    }
}

function ConvertTo-ByovdGzipBase64 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $ms = [System.IO.MemoryStream]::new()
    $gz = [System.IO.Compression.GZipStream]::new($ms, [System.IO.Compression.CompressionMode]::Compress, $true)
    $gz.Write($bytes, 0, $bytes.Length)
    $gz.Close()
    $packed = $ms.ToArray()
    $ms.Close()
    return [Convert]::ToBase64String($packed)
}

function New-ByovdDatabase {
    [CmdletBinding()]
    param()

    return ([pscustomobject]@{
        Drivers      = New-Object System.Collections.Generic.List[object]
        Idx          = @{}
        Sha256       = @{}
        Md5          = @{}
        Sha1         = @{}
        Authentihash = @{}
        Imphash      = @{}
        Meta         = @{}
        Names        = @{}
        Source       = @()
        PayloadText  = 0
        SampleCount  = 0
        PayloadSamples = 0
    })
}

function Add-ByovdIndexRef {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.Hashtable]$Table,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Key,
        [Parameter(Mandatory)][int]$Driver
    )
    if ($Key -eq '') { return }
    $cur = $Table[$Key]
    if ($null -eq $cur) { $Table[$Key] = [int[]]@($Driver); return }
    foreach ($i in $cur) { if ($i -eq $Driver) { return } }
    $Table[$Key] = [int[]]($cur + $Driver)
}

function Add-ByovdDriverRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Database,
        [string]$Id = '',
        [string]$Name = '',
        [string]$Category = '',
        [string[]]$Tags = @(),
        [string]$Mitre = '',
        [bool]$Hvci = $false,
        [string]$Source = ''
    )

    $key = ([string]$Id).Trim().ToLowerInvariant()
    if ($key -ne '' -and $Database.Idx.ContainsKey($key)) {
        $i = [int]$Database.Idx[$key]
        $rec = $Database.Drivers[$i]
        if (-not $rec.Name     -and $Name)     { $rec.Name     = $Name }
        if (-not $rec.Category -and $Category) { $rec.Category = $Category }
        if ((-not $rec.Tags -or $rec.Tags.Count -eq 0) -and $Tags) { $rec.Tags = @($Tags) }
        if (-not $rec.Mitre    -and $Mitre)    { $rec.Mitre    = $Mitre }
        if ($Hvci) { $rec.Hvci = $true }
        if ($Source -and ($rec.Source -notcontains $Source)) { $rec.Source = @($rec.Source + $Source) }
        return $i
    }

    $i = $Database.Drivers.Count
    $Database.Drivers.Add([pscustomobject]@{
        Id       = [string]$Id
        Name     = [string]$Name
        Category = [string]$Category
        Tags     = @($Tags)
        Mitre    = [string]$Mitre
        Hvci     = [bool]$Hvci
        Source   = @($Source)
        Base     = $false
    }) | Out-Null
    if ($key -ne '') { $Database.Idx[$key] = $i }
    return $i
}

$script:ByovdMetaFieldMap = [ordered]@{
    'company'          = @('Company', 'CompanyName')
    'description'      = @('Description', 'FileDescription')
    'product'          = @('Product', 'ProductName')
    'copyright'        = @('Copyright', 'LegalCopyright')
    'fileversion'      = @('FileVersion')
    'productversion'   = @('ProductVersion')
    'originalfilename' = @('OriginalFilename')
    'internalname'     = @('InternalName')
}

function Get-ByovdMetaKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Field,
        $Value
    )
    $v = ConvertTo-ByovdNormalizedText -Value $Value -Field $Field
    if (-not $v) { return '' }
    if ($v.Length -gt 255) { $v = $v.Substring(0, 255) }
    return ($Field + [char]1 + $v)
}

function Add-ByovdMetaValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Database,
        [Parameter(Mandatory)][string]$Field,
        $Value,
        [Parameter(Mandatory)][int]$Driver
    )
    $key = Get-ByovdMetaKey -Field $Field -Value $Value
    if ($key) { Add-ByovdIndexRef -Table $Database.Meta -Key $key -Driver $Driver }
}

function Add-ByovdNameValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Database,
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][int]$Driver
    )
    $raw = ([string]$Value).Trim() -replace '\\', '/'
    if (-not $raw) { return }
    $base = $raw.Split('/')[-1]
    $n = ConvertTo-ByovdNormalizedText -Value $base
    if ($n) { Add-ByovdIndexRef -Table $Database.Names -Key $n -Driver $Driver }
}

function Read-ByovdJsonRoot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }

    $loaded = $false
    foreach ($asm in [System.AppDomain]::CurrentDomain.GetAssemblies()) {
        try { if ($asm.GetName().Name -eq 'System.Web.Extensions') { $loaded = $true; break } } catch { }
    }
    if (-not $loaded) {
        try { Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop; $loaded = $true } catch { }
    }
    if (-not $loaded) { return $null }

    try { $text = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8) } catch { return $null }
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    try {
        $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $ser.MaxJsonLength  = [int]::MaxValue
        $ser.RecursionLimit = 2000
        $root = $ser.DeserializeObject($text)
        return ,$root
    } catch { return $null }
}

function Get-ByovdDisplayTitles {
    [CmdletBinding()]
    param([string]$MdDir)

    $map = @{}
    if ([string]::IsNullOrWhiteSpace($MdDir)) { return $map }
    if (-not (Test-Path -LiteralPath $MdDir -PathType Container)) { return $map }
    foreach ($f in @(Get-ChildItem -LiteralPath $MdDir -Filter '*.md' -File -ErrorAction SilentlyContinue)) {
        try { $head = @(Get-Content -LiteralPath $f.FullName -TotalCount 8 -ErrorAction Stop) } catch { continue }
        foreach ($l in $head) {
            if ($l -match '^\s*displayTitle\s*=\s*"([^"]*)"') {
                $map[$f.BaseName.ToLowerInvariant()] = $Matches[1]
                break
            }
        }
    }
    return $map
}

function Get-ByovdHvciHashes {
    [CmdletBinding()]
    param([string]$HashesDir)

    $set = @{}
    if ([string]::IsNullOrWhiteSpace($HashesDir)) { return $set }
    if (-not (Test-Path -LiteralPath $HashesDir -PathType Container)) { return $set }
    foreach ($n in @('LoadsDespiteHVCI.samples_vulnerable.sha256',
                     'LoadsDespiteHVCI.samples_malicious.sha256')) {
        $p = Join-Path $HashesDir $n
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { continue }
        foreach ($line in @(Get-Content -LiteralPath $p -ErrorAction SilentlyContinue)) {
            $t = ([string]$line).Trim().ToLowerInvariant()
            if ($t -match '^[0-9a-f]{64}$') { $set[$t] = $true }
        }
    }
    return $set
}

function Add-ByovdSampleToDb {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Database,
        [Parameter(Mandatory)]$Sample,
        [Parameter(Mandatory)][int]$Driver,
        [hashtable]$HvciHashes = $null
    )

    if ($null -eq $Sample) { return $false }
    $added = $false
    $isDict = ($Sample -is [System.Collections.IDictionary])

    $sha256 = (Get-ByovdText -Object $Sample -Names @('SHA256')).Trim().ToLowerInvariant()
    $sha1   = (Get-ByovdText -Object $Sample -Names @('SHA1')).Trim().ToLowerInvariant()
    $md5    = (Get-ByovdText -Object $Sample -Names @('MD5')).Trim().ToLowerInvariant()

    if ($sha256 -match '^[0-9a-f]{64}$') {
        Add-ByovdIndexRef -Table $Database.Sha256 -Key $sha256 -Driver $Driver
        $added = $true
        if ($HvciHashes -and $HvciHashes.ContainsKey($sha256)) { $Database.Drivers[$Driver].Hvci = $true }
    }
    else {
        if ($md5  -match '^[0-9a-f]{32}$') { Add-ByovdIndexRef -Table $Database.Md5  -Key $md5  -Driver $Driver; $added = $true }
        if ($sha1 -match '^[0-9a-f]{40}$') { Add-ByovdIndexRef -Table $Database.Sha1 -Key $sha1 -Driver $Driver; $added = $true }
    }

    $ah = $null
    if ($isDict -and $Sample.ContainsKey('Authentihash')) { $ah = $Sample['Authentihash'] }
    elseif (-not $isDict) { $ah = Get-ByovdField -Object $Sample -Names @('Authentihash') }
    $ahSha = Get-ByovdText -Object $ah -Names @('SHA256')
    if (-not $ahSha -and ($ah -is [string])) { $ahSha = $ah }
    $ahSha = $ahSha.Trim().ToLowerInvariant()
    if ($ahSha -match '^[0-9a-f]{64}$') {
        Add-ByovdIndexRef -Table $Database.Authentihash -Key $ahSha -Driver $Driver
        $added = $true
    }

    $imp = (Get-ByovdText -Object $Sample -Names @('Imphash')).Trim().ToLowerInvariant()
    if ($imp -match '^[0-9a-f]{32}$') {
        Add-ByovdIndexRef -Table $Database.Imphash -Key $imp -Driver $Driver
        $added = $true
    }

    foreach ($field in $script:ByovdMetaFieldMap.Keys) {
        foreach ($srcName in $script:ByovdMetaFieldMap[$field]) {
            $raw = Get-ByovdText -Object $Sample -Names @($srcName)
            if (-not $raw) { continue }
            $key = Get-ByovdMetaKey -Field $field -Value $raw
            if ($key) { Add-ByovdIndexRef -Table $Database.Meta -Key $key -Driver $Driver; $added = $true }
        }
    }

    $rawName = Get-ByovdText -Object $Sample -Names @('OriginalFilename')
    if (-not $rawName) { $rawName = Get-ByovdText -Object $Sample -Names @('Filename') }
    if ($rawName) { Add-ByovdNameValue -Database $Database -Value $rawName -Driver $Driver; $added = $true }

    if ($added) { $Database.SampleCount++ }
    return $added
}

function Import-ByovdJsonBase {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Database,
        [Parameter(Mandatory)][string]$JsonPath,
        [string]$HashesPath = ''
    )

    $root = Read-ByovdJsonRoot -Path $JsonPath
    if ($null -eq $root) { return 0 }

    $list = New-Object System.Collections.Generic.List[object]
    if ($root -is [System.Collections.IDictionary]) { [void]$list.Add($root) }
    else { foreach ($o in $root) { if ($null -ne $o) { [void]$list.Add($o) } } }
    if ($list.Count -eq 0) { return 0 }

    $jsonDir = Split-Path -Parent $JsonPath
    $contentDir = Split-Path -Parent $jsonDir
    $mdDir = Join-Path $contentDir 'drivers'
    $titles = Get-ByovdDisplayTitles -MdDir $mdDir

    $hvci = Get-ByovdHvciHashes -HashesDir $HashesPath

    $newSamples = 0
    foreach ($drv in $list) {
        $id       = Get-ByovdText -Object $drv -Names @('Id')
        $category = Get-ByovdText -Object $drv -Names @('Category')
        $mitre    = Get-ByovdText -Object $drv -Names @('MitreID')
        $tags     = @(Get-ByovdStringList (Get-ByovdField -Object $drv -Names @('Tags')))
        $name = ''
        if ($id) {
            $lk = $id.ToLowerInvariant()
            if ($titles.ContainsKey($lk)) { $name = [string]$titles[$lk] }
        }

        $idx = Add-ByovdDriverRecord -Database $Database -Id $id -Name $name -Category $category `
                -Tags $tags -Mitre $mitre -Hvci $false -Source 'json'

        $samples = $null
        if ($drv -is [System.Collections.IDictionary]) {
            if ($drv.ContainsKey('KnownVulnerableSamples')) { $samples = $drv['KnownVulnerableSamples'] }
        }
        else {
            $prop = $drv.PSObject.Properties['KnownVulnerableSamples']
            if ($prop) { $samples = $prop.Value }
        }
        if ($null -eq $samples) { continue }

        if ($samples -is [string])        { $samples = @(, $samples) }
        elseif ($samples -is [System.Collections.IDictionary]) { $samples = @(, $samples) }

        foreach ($s in $samples) {
            if ($null -eq $s) { continue }
            if (Add-ByovdSampleToDb -Database $Database -Sample $s -Driver $idx -HvciHashes $hvci) { $newSamples++ }
        }
    }

    if ($newSamples -gt 0 -and ($Database.Source -notcontains 'json')) { $Database.Source += 'json' }
    return $newSamples
}

function Import-ByovdEmbeddedBase {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Database,
        [AllowEmptyString()][string]$Text = ''
    )

    $plain = ConvertFrom-ByovdBase64Gzip -Text $Text
    if ([string]::IsNullOrWhiteSpace($plain)) { return 0 }
    $Database.PayloadText = $plain.Length

    $rows = 0
    foreach ($line in ($plain -split "`r`n|`n")) {
        if (-not $line) { continue }
        $f = $line -split "`t", 8
        if ($f.Count -lt 2) { continue }
        $type = $f[0]

        if ($type -eq 'D') {
            if ($f.Count -lt 8) { continue }
            $tags = @()
            if ($f[5]) { $tags = @($f[5] -split ',' | Where-Object { $_ }) }
            [void](Add-ByovdDriverRecord -Database $Database -Id $f[2] -Name $f[3] -Category $f[4] `
                    -Tags $tags -Mitre $f[6] -Hvci:($f[7] -eq '1') -Source 'embedded')
            $rows++
            continue
        }
        if ($type -eq 'V') { continue }
        if ($type -eq 'C') { $Database.PayloadSamples = [int]$f[1]; continue }
        if ($f.Count -lt 3) { continue }

        $targets = $null
        switch ($type) {
            'H' { $targets = $Database.Sha256 }
            'M' { $targets = $Database.Md5 }
            'S' { $targets = $Database.Sha1 }
            'A' { $targets = $Database.Authentihash }
            'I' { $targets = $Database.Imphash }
            'N' { $targets = $Database.Names }
            'P' { $targets = $null }
        }

        if ($type -eq 'P') {
            if ($f.Count -lt 4) { continue }
            $key = $f[1] + [char]1 + $f[2]
            $idxList = $f[3]
        }
        elseif ($targets -is [System.Collections.Hashtable]) {
            $key = $f[1]
            $idxList = $f[2]
        }
        else { continue }

        foreach ($i in ($idxList -split ',')) {
            if ($i -notmatch '^\d+$') { continue }
            $di = [int]$i
            if ($type -eq 'P') { Add-ByovdIndexRef -Table $Database.Meta -Key $key -Driver $di }
            else               { Add-ByovdIndexRef -Table $targets -Key $key -Driver $di }
        }
        $rows++
    }

    if ($rows -gt 0 -and ($Database.Source -notcontains 'embedded')) { $Database.Source += 'embedded' }
    return $rows
}

function Get-ByovdDatabaseStats {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Database)

    return ([pscustomobject]@{
        Drivers        = $Database.Drivers.Count
        Samples        = [Math]::Max([int]$Database.SampleCount, [int]$Database.PayloadSamples)
        Sha256         = $Database.Sha256.Count
        Md5            = $Database.Md5.Count
        Sha1           = $Database.Sha1.Count
        Authentihashes = $Database.Authentihash.Count
        Imphashes      = $Database.Imphash.Count
        MetaKeys       = $Database.Meta.Count
        Names          = $Database.Names.Count
        PayloadChars   = $Database.PayloadText
        Sources        = (@($Database.Source) -join '+')
    })
}

function Write-ByovdIndexLines {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Text.StringBuilder]$Builder,
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][System.Collections.Hashtable]$Table
    )
    foreach ($key in @($Table.Keys | Sort-Object)) {
        $idx = (@($Table[$key]) | Sort-Object) -join ','
        $k = ([string]$key).Replace("`t", ' ').Replace("`r", '').Replace("`n", ' ')
        [void]$Builder.Append($Type + "`t" + $k + "`t" + $idx + "`n")
    }
}

function Export-ByovdEmbeddedPayload {
    [CmdletBinding()]
    param([string]$Path)

    $base = Find-LolDriversBase -Path $Path
    if (-not $base -or -not $base.JsonPath) {
        throw 'Base LOLDrivers com drivers.json nao encontrada (passe -LolDriversPath).'
    }

    $tmp = New-ByovdDatabase
    $ok = Import-ByovdJsonBase -Database $tmp -JsonPath $base.JsonPath -HashesPath $(if ($base.HashesPath) { $base.HashesPath } else { '' })
    if (-not $ok -or $ok -eq 0) { throw "Nenhum sample indexado a partir de '$($base.JsonPath)'." }

    $hvci = Get-ByovdHvciHashes -HashesDir $(if ($base.HashesPath) { $base.HashesPath } else { '' })
    if ($hvci.Count -gt 0) {
        foreach ($hashKey in @($tmp.Sha256.Keys)) {
            if (-not $hvci.ContainsKey($hashKey)) { continue }
            foreach ($i in $tmp.Sha256[$hashKey]) { $tmp.Drivers[$i].Hvci = $true }
        }
    }

    $b = New-Object System.Text.StringBuilder
    [void]$b.Append("V`t1`n")
    [void]$b.Append('C' + "`t" + [int]$tmp.SampleCount + "`n")

    for ($i = 0; $i -lt $tmp.Drivers.Count; $i++) {
        $d = $tmp.Drivers[$i]
        $tags = @($d.Tags | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ }) -join ','
        $parts = @('D', $i, $d.Id, $d.Name, $d.Category, $tags, $d.Mitre, $(if ($d.Hvci) { '1' } else { '0' }))
        for ($k = 0; $k -lt $parts.Count; $k++) {
            $parts[$k] = ([string]$parts[$k]).Replace("`t", ' ').Replace("`r", '').Replace("`n", ' ')
        }
        [void]$b.Append(($parts -join "`t") + "`n")
    }

    Write-ByovdIndexLines -Builder $b -Type 'H' -Table $tmp.Sha256
    Write-ByovdIndexLines -Builder $b -Type 'M' -Table $tmp.Md5
    Write-ByovdIndexLines -Builder $b -Type 'S' -Table $tmp.Sha1
    Write-ByovdIndexLines -Builder $b -Type 'A' -Table $tmp.Authentihash
    Write-ByovdIndexLines -Builder $b -Type 'I' -Table $tmp.Imphash
    Write-ByovdIndexLines -Builder $b -Type 'N' -Table $tmp.Names

    $sep = [char]1
    foreach ($key in @($tmp.Meta.Keys | Sort-Object)) {
        $p = ([string]$key).IndexOf($sep)
        if ($p -lt 0) { continue }
        $field = ([string]$key).Substring(0, $p)
        $value = ([string]$key).Substring($p + 1)
        $value = $value.Replace("`t", ' ').Replace("`r", '').Replace("`n", ' ')
        $idx = (@($tmp.Meta[$key]) | Sort-Object) -join ','
        [void]$b.Append('P' + "`t" + $field + "`t" + $value + "`t" + $idx + "`n")
    }

    return $b.ToString()
}

function Get-ByovdU16 {
    [CmdletBinding()]
    param([byte[]]$Bytes, [int]$Offset)
    if ($null -eq $Bytes -or $Offset -lt 0 -or ($Offset + 2) -gt $Bytes.Length) { return [uint16]0 }
    return [BitConverter]::ToUInt16($Bytes, $Offset)
}
function Get-ByovdU32 {
    [CmdletBinding()]
    param([byte[]]$Bytes, [int]$Offset)
    if ($null -eq $Bytes -or $Offset -lt 0 -or ($Offset + 4) -gt $Bytes.Length) { return [uint32]0 }
    return [BitConverter]::ToUInt32($Bytes, $Offset)
}
function Get-ByovdU64 {
    [CmdletBinding()]
    param([byte[]]$Bytes, [int]$Offset)
    if ($null -eq $Bytes -or $Offset -lt 0 -or ($Offset + 8) -gt $Bytes.Length) { return [uint64]0 }
    return [BitConverter]::ToUInt64($Bytes, $Offset)
}
function Get-ByovdI32 {
    [CmdletBinding()]
    param([byte[]]$Bytes, [int]$Offset)
    if ($null -eq $Bytes -or $Offset -lt 0 -or ($Offset + 4) -gt $Bytes.Length) { return [int]0 }
    return [BitConverter]::ToInt32($Bytes, $Offset)
}
function Get-ByovdAsciiZ {
    [CmdletBinding()]
    param([byte[]]$Bytes, [int]$Offset, [int]$Max = 260)
    if ($null -eq $Bytes -or $Offset -lt 0 -or $Offset -ge $Bytes.Length) { return '' }
    $sb = New-Object System.Text.StringBuilder
    $i = $Offset
    $end = [Math]::Min($Bytes.Length, $Offset + $Max)
    while ($i -lt $end -and $Bytes[$i] -ne 0) { [void]$sb.Append([char]$Bytes[$i]); $i++ }
    return $sb.ToString()
}
function ConvertTo-ByovdHex {
    [CmdletBinding()]
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return '' }
    return ([BitConverter]::ToString($Bytes)).Replace('-', '').ToLowerInvariant()
}

function Get-ByovdFileHashes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$ChunkSize = 1048576
    )
    $out = @{ SHA256 = ''; SHA1 = ''; MD5 = ''; Length = [int64]0; Error = '' }
    $sha = $null; $sha1 = $null; $md5 = $null; $fs = $null
    try {
        $sha  = [System.Security.Cryptography.SHA256]::Create()
        $sha1 = [System.Security.Cryptography.SHA1]::Create()
        $md5  = [System.Security.Cryptography.MD5]::Create()
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open,
                                     [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $out.Length = $fs.Length
        $buf = New-Object byte[] $ChunkSize
        $n = 0
        while (($n = $fs.Read($buf, 0, $buf.Length)) -gt 0) {
            [void]$sha.TransformBlock($buf, 0, $n, $null, 0)
            [void]$sha1.TransformBlock($buf, 0, $n, $null, 0)
            [void]$md5.TransformBlock($buf, 0, $n, $null, 0)
        }
        [void]$sha.TransformFinalBlock($buf, 0, 0)
        [void]$sha1.TransformFinalBlock($buf, 0, 0)
        [void]$md5.TransformFinalBlock($buf, 0, 0)
        $out.SHA256 = ConvertTo-ByovdHex $sha.Hash
        $out.SHA1   = ConvertTo-ByovdHex $sha1.Hash
        $out.MD5    = ConvertTo-ByovdHex $md5.Hash
    }
    catch { $out.Error = $_.Exception.Message }
    finally {
        if ($fs) { try { $fs.Close() } catch { } }
        if ($sha)  { try { $sha.Dispose() } catch { } }
        if ($sha1) { try { $sha1.Dispose() } catch { } }
        if ($md5)  { try { $md5.Dispose() } catch { } }
    }
    return $out
}

function Get-ByovdAuthentihash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][int]$ChecksumOffset,
        [Parameter(Mandatory)][int]$SecurityDdOffset,
        [int]$CertOffset = 0,
        [int]$CertSize = 0
    )
    $len = $Bytes.Length
    if ($ChecksumOffset -lt 0 -or $SecurityDdOffset -lt 8) { return '' }
    if (($ChecksumOffset + 4) -gt $SecurityDdOffset) { return '' }
    if (($SecurityDdOffset + 8) -gt $len) { return '' }

    $hasCert = ($CertOffset -gt 0 -and $CertSize -gt 0 -and
                ([int64]$CertOffset + [int64]$CertSize) -le [int64]$len -and
                $CertOffset -ge ($SecurityDdOffset + 8))

    $ms = [System.IO.MemoryStream]::new()
    try {
        if ($ChecksumOffset -gt 0) { [void]$ms.Write($Bytes, 0, $ChecksumOffset) }
        $a = $ChecksumOffset + 4
        $mid = $SecurityDdOffset - $a
        if ($mid -gt 0) { [void]$ms.Write($Bytes, $a, $mid) }
        $c = $SecurityDdOffset + 8
        if ($hasCert) {
            $end = [int]$CertOffset
            if ($end -gt $c) { [void]$ms.Write($Bytes, $c, $end - $c) }
            $tail = [int]$CertOffset + [int]$CertSize
            if ($tail -lt $len) { [void]$ms.Write($Bytes, $tail, $len - $tail) }
        }
        else {
            if ($c -lt $len) { [void]$ms.Write($Bytes, $c, $len - $c) }
        }
        $data = $ms.ToArray()
    }
    finally { try { $ms.Close() } catch { } }

    $sha = $null
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        return (ConvertTo-ByovdHex $sha.ComputeHash($data))
    }
    catch { return '' }
    finally { if ($sha) { try { $sha.Dispose() } catch { } } }
}

function Get-ByovdPeSections {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][int]$SectionTable,
        [Parameter(Mandatory)][int]$Count
    )
    $list = New-Object System.Collections.Generic.List[object]
    for ($s = 0; $s -lt $Count; $s++) {
        $b = $SectionTable + $s * 40
        if (($b + 40) -gt $Bytes.Length) { break }
        $list.Add([pscustomobject]@{
            VirtSize = [uint32](Get-ByovdU32 $Bytes ($b + 8))
            VirtAddr = [uint32](Get-ByovdU32 $Bytes ($b + 12))
            RawSize  = [uint32](Get-ByovdU32 $Bytes ($b + 16))
            RawPtr   = [uint32](Get-ByovdU32 $Bytes ($b + 20))
        }) | Out-Null
    }
    return ,$list
}

function Get-ByovdImphash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][int]$ImportRva,
        [Parameter(Mandatory)][int]$SectionTable,
        [Parameter(Mandatory)][int]$SectionCount,
        [Parameter(Mandatory)][bool]$IsPe32Plus,
        [int]$MaxDescriptors = 512,
        [int]$MaxThunks = 4096
    )
    $len = $Bytes.Length
    $sections = Get-ByovdPeSections -Bytes $Bytes -SectionTable $SectionTable -Count $SectionCount

    $rvaToOff = {
        param([uint32]$Rva)
        foreach ($sec in $sections) {
            $vs = [Math]::Max([uint32]$sec.VirtSize, [uint32]$sec.RawSize)
            if ($Rva -ge $sec.VirtAddr -and $Rva -lt ($sec.VirtAddr + $vs)) {
                return [int]([int]$Rva - [int]$sec.VirtAddr + [int]$sec.RawPtr)
            }
        }
        return -1
    }

    $importOff = & $rvaToOff $ImportRva
    if ($importOff -lt 0) { return '' }

    $thunkSize = if ($IsPe32Plus) { 8 } else { 4 }
    $ordMask   = if ($IsPe32Plus) { ([uint64][int64]::MaxValue + [uint64]1) } else { [uint64]0x80000000 }

    $funcs = New-Object System.Collections.Generic.List[string]
    $off = $importOff
    $desc = 0
    while (($off + 20) -le $len -and $desc -lt $MaxDescriptors) {
        $oft     = Get-ByovdU32 $Bytes ($off + 0)
        $nameRva = Get-ByovdU32 $Bytes ($off + 12)
        $ft      = Get-ByovdU32 $Bytes ($off + 16)
        if ($oft -eq 0 -and $nameRva -eq 0 -and $ft -eq 0) { break }
        $desc++
        $nameOff = & $rvaToOff $nameRva
        $dll = ''
        if ($nameOff -ge 0) { $dll = (Get-ByovdAsciiZ -Bytes $Bytes -Offset $nameOff).ToLowerInvariant() }
        if (-not $dll) { $off += 20; continue }

        $thunkRva = if ($oft -ne 0) { $oft } else { $ft }
        $to = & $rvaToOff $thunkRva
        if ($to -lt 0) { $off += 20; continue }

        $n = 0
        while (($to + $thunkSize) -le $len -and $n -lt $MaxThunks) {
            $v = if ($thunkSize -eq 4) { [uint64](Get-ByovdU32 $Bytes $to) } else { Get-ByovdU64 $Bytes $to }
            if ($v -eq [uint64]0) { break }
            if (($v -band $ordMask) -eq 0) {
                $ibn = & $rvaToOff ([uint32]$v)
                if ($ibn -ge 0) {
                    $fn = (Get-ByovdAsciiZ -Bytes $Bytes -Offset ($ibn + 2)).ToLowerInvariant()
                    if ($fn) { $funcs.Add(('{0}.{1}' -f $dll, $fn)) | Out-Null }
                }
            }
            $to += $thunkSize
            $n++
        }
        $off += 20
    }

    if ($funcs.Count -eq 0) { return '' }
    $joined = [string]::Join(',', $funcs)
    $md5 = $null
    try {
        $md5 = [System.Security.Cryptography.MD5]::Create()
        return (ConvertTo-ByovdHex $md5.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($joined)))
    }
    catch { return '' }
    finally { if ($md5) { try { $md5.Dispose() } catch { } } }
}

function Get-ByovdPeInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MaxBytes = 16777216
    )

    $r = [pscustomobject]@{
        IsPe         = $false
        Machine      = ''
        TimeStampUtc = $null
        Sections     = 0
        Imphash      = ''
        Authentihash = ''
        ImportDlls   = 0
        HasCert      = $false
        Error        = ''
    }

    $len = [int64]0
    try { $len = (New-Object System.IO.FileInfo($Path)).Length } catch { $r.Error = 'sem acesso'; return $r }
    if ($len -lt 64)        { $r.Error = 'pequeno demais'; return $r }
    if ($len -gt $MaxBytes) { $r.Error = 'grande demais para analise PE'; return $r }

    $b = $null
    try { $b = [System.IO.File]::ReadAllBytes($Path) } catch { $r.Error = 'falha de leitura'; return $r }
    if ($b.Length -lt 64) { $r.Error = 'pequeno demais'; return $r }
    if ($b[0] -ne 0x4D -or $b[1] -ne 0x5A) { $r.Error = 'nao e MZ'; return $r }

    $pe = Get-ByovdI32 $b 0x3C
    if ($pe -lt 0 -or ($pe + 24) -gt $b.Length) { $r.Error = 'e_lfanew invalido'; return $r }
    if ($b[$pe] -ne 0x50 -or $b[$pe+1] -ne 0x45 -or $b[$pe+2] -ne 0 -or $b[$pe+3] -ne 0) {
        $r.Error = 'assinatura PE invalida'; return $r
    }

    $numSections  = [int](Get-ByovdU16 $b ($pe + 6))
    $timeStamp    = Get-ByovdU32 $b ($pe + 8)
    $sizeOfOptHdr = [int](Get-ByovdU16 $b ($pe + 20))
    $opt = $pe + 24
    if (($opt + $sizeOfOptHdr) -gt $b.Length) { $r.Error = 'cabecalho opcional truncado'; return $r }

    $magic = Get-ByovdU16 $b $opt
    $isPlus = ($magic -eq 0x20B)
    if ($magic -ne 0x10B -and $magic -ne 0x20B) { $r.Error = 'magic invalido'; return $r }

    $r.IsPe         = $true
    $r.Sections     = $numSections
    $r.Machine      = switch (Get-ByovdU16 $b ($pe + 4)) {
                          0x8664 { 'AMD64' }
                          0x014C { 'I386' }
                          0xAA64 { 'ARM64' }
                          0x01C4 { 'ARMNT' }
                          default { '0x{0:x}' -f (Get-ByovdU16 $b ($pe + 4)) }
                      }
    try {
        $epoch = [DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
        $r.TimeStampUtc = $epoch.AddSeconds([double]$timeStamp)
    } catch { $r.TimeStampUtc = $null }

    $checksumOffset = $opt + 64
    $ddBase         = if ($isPlus) { $opt + 112 } else { $opt + 96 }
    if (($ddBase + 40) -gt $b.Length) { return $r }

    $importRva   = [int](Get-ByovdU32 $b ($ddBase + 8))
    $certOffset  = [int](Get-ByovdU32 $b ($ddBase + 32))
    $certSize    = [int](Get-ByovdU32 $b ($ddBase + 36))
    $r.HasCert   = ($certOffset -gt 0 -and $certSize -gt 0)
    $sectionTable = $opt + $sizeOfOptHdr

    if ($importRva -gt 0) {
        $r.Imphash = Get-ByovdImphash -Bytes $b -ImportRva $importRva `
                       -SectionTable $sectionTable -SectionCount $numSections -IsPe32Plus $isPlus
        $secs = Get-ByovdPeSections -Bytes $b -SectionTable $sectionTable -Count $numSections
        $ioff = -1
        foreach ($sec in $secs) {
            $vs = [Math]::Max([uint32]$sec.VirtSize, [uint32]$sec.RawSize)
            if ($importRva -ge $sec.VirtAddr -and $importRva -lt ($sec.VirtAddr + $vs)) {
                $ioff = [int]($importRva - $sec.VirtAddr + $sec.RawPtr); break
            }
        }
        if ($ioff -ge 0) {
            $d = 0
            while (($ioff + 20) -le $b.Length -and $d -lt 512) {
                $a = Get-ByovdU32 $b ($ioff + 0); $c = Get-ByovdU32 $b ($ioff + 12); $f = Get-ByovdU32 $b ($ioff + 16)
                if ($a -eq 0 -and $c -eq 0 -and $f -eq 0) { break }
                $d++; $ioff += 20
            }
            $r.ImportDlls = $d
        }
    }

    $r.Authentihash = Get-ByovdAuthentihash -Bytes $b -ChecksumOffset $checksumOffset `
                         -SecurityDdOffset ($ddBase + 32) -CertOffset $certOffset -CertSize $certSize
    return $r
}

function Get-ByovdVersionInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $empty = @{
        Company = ''; Description = ''; Product = ''; Copyright = ''
        FileVersion = ''; ProductVersion = ''; OriginalFilename = ''; InternalName = ''
    }
    try {
        $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
    } catch { return $empty }

    return @{
        Company          = ([string]$vi.CompanyName).Trim()
        Description      = ([string]$vi.FileDescription).Trim()
        Product          = ([string]$vi.ProductName).Trim()
        Copyright        = ([string]$vi.LegalCopyright).Trim()
        FileVersion      = ([string]$vi.FileVersion).Trim()
        ProductVersion   = ([string]$vi.ProductVersion).Trim()
        OriginalFilename = ([string]$vi.OriginalFilename).Trim()
        InternalName     = ([string]$vi.InternalName).Trim()
    }
}

function Get-ByovdSignatureInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $r = [pscustomobject]@{
        Status  = 'Desconhecido'
        Subject = ''
        Issuer  = ''
        Valid   = $false
        Microsoft = $false
        Error   = ''
    }
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $r.Status  = [string]$sig.Status
        $r.Valid   = ($sig.Status -eq [System.Management.Automation.SignatureStatus]::Valid)
        if ($sig.SignerCertificate) {
            $r.Subject = [string]$sig.SignerCertificate.Subject
            $r.Issuer  = [string]$sig.SignerCertificate.Issuer
        }
        if ($r.Valid -and $r.Subject -match '(?i)Microsoft\s+Windows' ) { $r.Microsoft = $true }
        if ($r.Valid -and $r.Issuer -match '(?i)Microsoft\s+Windows')  { $r.Microsoft = $true }
    }
    catch { $r.Error = $_.Exception.Message }
    return $r
}

$script:ByovdEvidenceCache = @{}

function Reset-ByovdEvidenceCache {
    [CmdletBinding()]
    param()
    $script:ByovdEvidenceCache = @{}
}

function Get-ByovdFileEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MaxHashBytes = 268435456,
        [int]$MaxPeBytes   = 16777216
    )

    $key = $Path.ToLowerInvariant()
    if ($script:ByovdEvidenceCache.ContainsKey($key)) { return $script:ByovdEvidenceCache[$key] }

    $ev = [pscustomobject]@{
        Path            = $Path
        FileName        = ''
        FileNameNoExt   = ''
        Length          = [int64]0
        SHA256          = ''
        SHA1            = ''
        MD5             = ''
        Imphash         = ''
        Authentihash    = ''
        IsPe            = $false
        Machine         = ''
        Sections        = 0
        TimeStampUtc    = $null
        ImportDlls      = 0
        HasCert         = $false
        Company         = ''
        Description     = ''
        Product         = ''
        Copyright       = ''
        FileVersion     = ''
        ProductVersion  = ''
        OriginalFilename= ''
        InternalName    = ''
        SigStatus       = ''
        SigSubject      = ''
        SigIssuer       = ''
        SigValid        = $false
        SigMicrosoft    = $false
        Error           = ''
        Readable        = $false
    }

    $ev.FileName      = [System.IO.Path]::GetFileName($Path)
    $ev.FileNameNoExt = [System.IO.Path]::GetFileNameWithoutExtension($Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        $ev.Error = 'arquivo nao encontrado'
        $script:ByovdEvidenceCache[$key] = $ev
        return $ev
    }

    try { $ev.Length = (New-Object System.IO.FileInfo($Path)).Length } catch { $ev.Error = 'sem acesso' }
    if ($ev.Length -gt $MaxHashBytes) {
        $ev.Error = 'arquivo grande demais'
        $script:ByovdEvidenceCache[$key] = $ev
        return $ev
    }

    $hashes = Get-ByovdFileHashes -Path $Path
    if ($hashes.Error) { $ev.Error = $hashes.Error }
    else {
        $ev.Readable = $true
        $ev.SHA256   = [string]$hashes.SHA256
        $ev.SHA1     = [string]$hashes.SHA1
        $ev.MD5      = [string]$hashes.MD5
        $ev.Length   = [int64]$hashes.Length
    }

    if ($ev.Readable -and $ev.Length -le $MaxPeBytes) {
        $pe = Get-ByovdPeInfo -Path $Path -MaxBytes $MaxPeBytes
        $ev.IsPe         = $pe.IsPe
        $ev.Machine      = [string]$pe.Machine
        $ev.Sections     = [int]$pe.Sections
        $ev.TimeStampUtc = $pe.TimeStampUtc
        $ev.Imphash      = [string]$pe.Imphash
        $ev.Authentihash = [string]$pe.Authentihash
        $ev.ImportDlls   = [int]$pe.ImportDlls
        $ev.HasCert      = [bool]$pe.HasCert
        if (-not $pe.IsPe -and -not $ev.Error) { $ev.Error = $pe.Error }

        $vi = Get-ByovdVersionInfo -Path $Path
        $ev.Company          = [string]$vi.Company
        $ev.Description      = [string]$vi.Description
        $ev.Product          = [string]$vi.Product
        $ev.Copyright        = [string]$vi.Copyright
        $ev.FileVersion      = [string]$vi.FileVersion
        $ev.ProductVersion   = [string]$vi.ProductVersion
        $ev.OriginalFilename = [string]$vi.OriginalFilename
        $ev.InternalName     = [string]$vi.InternalName
    }

    $sig = Get-ByovdSignatureInfo -Path $Path
    $ev.SigStatus   = [string]$sig.Status
    $ev.SigSubject  = [string]$sig.Subject
    $ev.SigIssuer   = [string]$sig.Issuer
    $ev.SigValid    = [bool]$sig.Valid
    $ev.SigMicrosoft= [bool]$sig.Microsoft

    $script:ByovdEvidenceCache[$key] = $ev
    return $ev
}

function Resolve-ByovdDriverPath {
    [CmdletBinding()]
    param([string]$ImagePath, [string]$ServiceName = '')

    $p = ([string]$ImagePath).Trim()
    if (-not $p) {
        if ($ServiceName) {
            $guess = Join-Path (Join-Path $env:SystemRoot 'System32\drivers') ($ServiceName + '.sys')
            if (Test-Path -LiteralPath $guess -PathType Leaf) { return $guess }
        }
        return ''
    }

    if ($p.Length -ge 2 -and $p[0] -eq '"' -and $p[$p.Length-1] -eq '"') {
        $p = $p.Substring(1, $p.Length - 2).Trim()
    }
    if ($p.StartsWith('\??\')) { $p = $p.Substring(4) }

    if ($p.StartsWith('\')) {
        if ($p -match '^(?i)\\SystemRoot\\(.+)$') {
            $p = Join-Path $env:SystemRoot $Matches[1]
        }
        elseif ($p -match '^(?i)\\??\\(.+)$') {
            $p = $Matches[1]
        }
        else {
            return ''
        }
    }

    $p = [Environment]::ExpandEnvironmentVariables($p)

    if (-not (Test-Path -LiteralPath $p)) {
        $m = [regex]::Match($p, '^(?:"([^"]+)"|(\S+\.sys))', 'IgnoreCase')
        if ($m.Success) {
            $cand = if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[2].Value }
            if ($cand) { $p = $cand }
        }
    }

    if (-not [System.IO.Path]::IsPathRooted($p)) {
        $join = if ($p -match '(?i)^system32\\') { $env:SystemRoot } else { $env:SystemRoot }
        $p = Join-Path $join $p
    }

    try { return (Resolve-Path -LiteralPath $p -ErrorAction Stop).Path } catch { return $p }
}

function Get-ByovdStartModeName {
    [CmdletBinding()]
    param($Value)
    switch ([string]$Value) {
        '0'     { return 'Boot' }
        '1'     { return 'System' }
        '2'     { return 'Automatic' }
        '3'     { return 'Manual' }
        '4'     { return 'Disabled' }
        'Boot'      { return 'Boot' }
        'System'    { return 'System' }
        'Auto'      { return 'Automatic' }
        'Automatic' { return 'Automatic' }
        'Demand'    { return 'Manual' }
        'Manual'    { return 'Manual' }
        'Disabled'  { return 'Disabled' }
        default     { return ([string]$Value) }
    }
}

function Get-ByovdDriverInventory {
    [CmdletBinding()]
    param(
        [string[]]$ExtraPaths = @(),
        $Config = $null
    )
    if ($null -eq $Config) { $Config = $script:ByovdConfig }

    $rows  = New-Object System.Collections.Generic.List[object]
    $bySvc = @{}

    $makeRow = {
        param($svc, $disp, $raw, $state, $started, $mode, $src)
        [pscustomobject]@{
            ServiceName = [string]$svc
            DisplayName = [string]$disp
            PathRaw     = [string]$raw
            Path        = ''
            State       = [string]$state
            Started     = [bool]$started
            StartMode   = [string]$mode
            Source      = [string]$src
        }
    }

    if ($Config.ScanRegistry) {
        try {
            $rk = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Services')
            if ($rk) {
                foreach ($n in $rk.GetSubKeyNames()) {
                    $sk = $null
                    try { $sk = $rk.OpenSubKey($n) } catch { continue }
                    if (-not $sk) { continue }
                    $type = 0
                    try { $v = $sk.GetValue('Type'); if ($null -ne $v) { $type = [int]$v } } catch { }
                    if ($type -ne 1 -and $type -ne 2 -and $type -ne 8) { $sk.Close(); continue }
                    $img = ''; $start = ''; $disp = ''
                    try { $v = $sk.GetValue('ImagePath'); if ($v) { $img = [string]$v } } catch { }
                    try { $v = $sk.GetValue('Start'); if ($null -ne $v) { $start = [string]$v } } catch { }
                    try { $v = $sk.GetValue('DisplayName'); if ($v) { $disp = [string]$v } } catch { }
                    $sk.Close()
                    if (-not $img) { continue }
                    $row = & $makeRow $n $disp $img '' $false (Get-ByovdStartModeName $start) 'registro'
                    $rows.Add($row) | Out-Null
                    $bySvc[$n.ToLowerInvariant()] = $row
                }
                $rk.Close()
            }
        }
        catch { }
    }
    Write-ByovdLog -Color 'DarkGray' -Message ('      registro HKLM\SYSTEM\CurrentControlSet\Services: {0} servico(s) de driver' -f $rows.Count)

    if ($Config.ScanCim) {
        try {
            foreach ($d in @(Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction SilentlyContinue)) {
                if ($null -eq $d) { continue }
                $name = [string]$d.Name
                if (-not $name) { continue }
                $key = $name.ToLowerInvariant()
                if ($bySvc.ContainsKey($key)) {
                    $row = $bySvc[$key]
                    if ($d.State)     { $row.State = [string]$d.State }
                    if ($null -ne $d.Started) { $row.Started = [bool]$d.Started }
                    if ($d.StartMode) { $row.StartMode = Get-ByovdStartModeName $d.StartMode }
                    if ($d.PathName -and -not $row.PathRaw) { $row.PathRaw = [string]$d.PathName }
                    if ($row.Source -notcontains 'cim') { $row.Source = @($row.Source) + @('cim') }
                }
                elseif ($d.PathName) {
                    $row = & $makeRow $name $(if ($d.DisplayName) { $d.DisplayName } else { $name }) `
                            $d.PathName $(if ($d.State) { $d.State } else { '' }) `
                            $(if ($null -ne $d.Started) { [bool]$d.Started } else { $false }) `
                            (Get-ByovdStartModeName $d.StartMode) 'cim'
                    $rows.Add($row) | Out-Null
                    $bySvc[$key] = $row
                }
            }
        }
        catch { }
    }
    Write-ByovdLog -Color 'DarkGray' -Message ('      CIM Win32_SystemDriver: estado/modo atualizados - {0} item(s) no total' -f $rows.Count)

    if ($Config.ScanServices) {
        try {
            foreach ($s in @(Get-Service -ErrorAction SilentlyContinue)) {
                if ($null -eq $s) { continue }
                $key = ([string]$s.Name).ToLowerInvariant()
                if (-not $bySvc.ContainsKey($key)) { continue }
                $row = $bySvc[$key]
                $row.State = [string]$s.Status
                $row.Started = ($s.Status -eq 'Running')
                if ($row.Source -notcontains 'service') { $row.Source = @($row.Source) + @('service') }
            }
        }
        catch { }
    }

    foreach ($row in $rows) {
        $row.Path = Resolve-ByovdDriverPath -ImagePath $row.PathRaw -ServiceName $row.ServiceName
        if ($row.State) { $row.Started = ($row.State -eq 'Running') }
        if (-not $row.Started -and $row.StartMode -in @('Boot', 'System', 'Automatic')) {
        }
    }

    $scanDirs = New-Object System.Collections.Generic.List[string]
    if ($Config.ScanSystem32Drivers) { $scanDirs.Add((Join-Path $env:SystemRoot 'System32\drivers')) | Out-Null }
    if ($Config.ScanSystem32Root)    { $scanDirs.Add((Join-Path $env:SystemRoot 'System32'))           | Out-Null }
    if ($Config.ScanWindowsTemp)     { $scanDirs.Add((Join-Path $env:SystemRoot 'Temp'))              | Out-Null }
    if ($Config.ScanSysWow64)        { $scanDirs.Add((Join-Path $env:SystemRoot 'SysWOW64'))          | Out-Null }
    foreach ($x in @($ExtraPaths)) {
        if ($x) { $scanDirs.Add($x) | Out-Null }
    }
    foreach ($x in @($Config.ExtraScanPaths)) {
        if ($x) { $scanDirs.Add($x) | Out-Null }
    }

    $covered = @{}
    foreach ($row in $rows) {
        if ($row.Path) { $covered[$row.Path.ToLowerInvariant()] = $true }
    }

    foreach ($dir in $scanDirs) {
        if (-not $dir) { continue }
        if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
        Write-ByovdLog -Color 'DarkGray' -Message ('      varredura de arquivos *.sys em: {0}' -f $dir)
        $depth = if ($Config.ScanSystem32Root -and $dir -eq (Join-Path $env:SystemRoot 'System32')) { 0 } else { 4 }
        $files = $null
        try {
            $files = Get-ChildItem -LiteralPath $dir -Filter '*.sys' -File -Recurse:([bool]$Config.ScanRecursive) `
                       -Depth $depth -ErrorAction SilentlyContinue
        }
        catch {
            try { $files = Get-ChildItem -LiteralPath $dir -Filter '*.sys' -File -ErrorAction SilentlyContinue } catch { }
        }
        $added = 0
        foreach ($f in @($files)) {
            if ($null -eq $f) { continue }
            $full = $f.FullName
            $k = $full.ToLowerInvariant()
            if ($covered.ContainsKey($k)) { continue }
            $covered[$k] = $true
            $row = & $makeRow '' $f.BaseName $full '' $false '' 'filesystem'
            $row.Path = $full
            $rows.Add($row) | Out-Null
            $added++
        }
        Write-ByovdLog -Color 'DarkGray' -Message ('         {0} arquivo(s) novo(s) - {1} item(s) no total' -f $added, $rows.Count)
    }

    return $rows.ToArray()
}

function New-ByovdWhitelist {
    [CmdletBinding()]
    param()
    return @{
        Hashes        = New-Object System.Collections.Generic.List[string]
        Authentihashes= New-Object System.Collections.Generic.List[string]
        Imphashes     = New-Object System.Collections.Generic.List[string]
        Names         = New-Object System.Collections.Generic.List[string]
        Paths         = New-Object System.Collections.Generic.List[string]
        Companies     = New-Object System.Collections.Generic.List[string]
        Publishers    = New-Object System.Collections.Generic.List[string]
        Services      = New-Object System.Collections.Generic.List[string]
        SuppressValidMicrosoftSigned = $false
    }
}

function Add-ByovdWhitelistEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Whitelist,
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Value
    )
    $v = $Value.Trim()
    if (-not $v) { return }
    switch ($Type.ToLowerInvariant()) {
        'hash'           { [void]$Whitelist.Hashes.Add($v.ToLowerInvariant()) }
        'sha256'         { [void]$Whitelist.Hashes.Add($v.ToLowerInvariant()) }
        'sha1'           { [void]$Whitelist.Hashes.Add($v.ToLowerInvariant()) }
        'md5'            { [void]$Whitelist.Hashes.Add($v.ToLowerInvariant()) }
        'authentihash'   { [void]$Whitelist.Authentihashes.Add($v.ToLowerInvariant()) }
        'imphash'        { [void]$Whitelist.Imphashes.Add($v.ToLowerInvariant()) }
        'name'           { [void]$Whitelist.Names.Add($v) }
        'path'           { [void]$Whitelist.Paths.Add($v) }
        'company'        { [void]$Whitelist.Companies.Add($v) }
        'publisher'      { [void]$Whitelist.Publishers.Add($v) }
        'service'        { [void]$Whitelist.Services.Add($v) }
        'ms'             { $Whitelist.SuppressValidMicrosoftSigned = $true }
        default          { [void]$Whitelist.Hashes.Add($v.ToLowerInvariant()) }
    }
}

function ConvertFrom-ByovdListLines {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$Lines = @(),
        [switch]$InferBare
    )

    $out = New-ByovdWhitelist
    foreach ($raw in @($Lines)) {
        if ($null -eq $raw) { continue }
        $line = ([string]$raw).Trim()
        if (-not $line -or $line.StartsWith('#') -or $line.StartsWith(';')) { continue }

        $type = ''
        $value = $line
        $c = $line.IndexOf(':')
        if ($c -gt 0 -and $c -lt 24) {
            $maybe = $line.Substring(0, $c).ToLowerInvariant()
            if ($maybe -in @('hash','sha256','sha1','md5','authentihash','imphash',
                             'name','path','company','publisher','service','ms','ioc')) {
                $type = $maybe
                $value = $line.Substring($c + 1).Trim()
            }
        }
        if (-not $value) { continue }

        if (-not $type) {
            if ($value -match '^[0-9a-fA-F]{64}$')     { $type = 'sha256' }
            elseif ($value -match '^[0-9a-fA-F]{40}$') { $type = 'sha1' }
            elseif ($value -match '^[0-9a-fA-F]{32}$') { $type = 'md5'; Add-ByovdWhitelistEntry -Whitelist $out -Type 'imphash' -Value $value }
            elseif ($InferBare)                        { $type = 'name' }
            else                                       { continue }
        }
        if ($type -eq 'ioc') { $type = 'hash' }
        Add-ByovdWhitelistEntry -Whitelist $out -Type $type -Value $value
    }
    return $out
}

function Import-ByovdListFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$InferBare
    )

    $lines = @()
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        try { $lines = @(Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue) } catch { $lines = @() }
    }
    $out = ConvertFrom-ByovdListLines -Lines $lines -InferBare:$InferBare
    $out | Add-Member -NotePropertyName 'File' -NotePropertyValue ([string]$Path) -Force
    return $out
}

function Merge-ByovdWhitelist {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Target,
        $Source
    )
    if ($null -eq $Source) { return $Target }

    if (-not ($Source -is [System.Collections.IDictionary])) {
        $asLines = ConvertFrom-ByovdListLines -Lines @($Source)
        $Source = $asLines
    }
    if (-not ($Source -is [System.Collections.IDictionary])) { return $Target }

    foreach ($n in @('Hashes','Authentihashes','Imphashes','Names','Paths','Companies','Publishers','Services')) {
        $vals = $null
        try { $vals = $Source[$n] } catch { $vals = $null }
        if ($null -eq $vals) { continue }
        foreach ($v in @($vals)) {
            if ($null -eq $v) { continue }
            $val = [string]$v
            if (-not $val) { continue }
            $norm = if ($n -in @('Hashes','Authentihashes','Imphashes')) { $val.ToLowerInvariant() } else { $val }
            if (-not $Target[$n].Contains($norm)) { [void]$Target[$n].Add($norm) }
        }
    }
    $flag = $null
    try { $flag = $Source['SuppressValidMicrosoftSigned'] } catch { $flag = $null }
    if ($flag) { $Target.SuppressValidMicrosoftSigned = $true }
    return $Target
}

function Test-ByovdWhitelisted {
    [CmdletBinding()]
    param(
        $Evidence,
        $Row,
        [Parameter(Mandatory)][hashtable]$Whitelist
    )

    if ($null -eq $Whitelist) { return $null }

    foreach ($h in @($Evidence.SHA256, $Evidence.SHA1, $Evidence.MD5)) {
        if (-not $h) { continue }
        $hl = $h.ToLowerInvariant()
        if ($Whitelist.Hashes.Contains($hl)) { return "hash $hl esta na whitelist" }
    }
    if ($Evidence.Authentihash -and $Whitelist.Authentihashes.Contains($Evidence.Authentihash.ToLowerInvariant())) {
        return "authentihash $($Evidence.Authentihash) esta na whitelist"
    }
    if ($Evidence.Imphash -and $Whitelist.Imphashes.Contains($Evidence.Imphash.ToLowerInvariant())) {
        return "imphash $($Evidence.Imphash) esta na whitelist"
    }

    foreach ($pat in @($Whitelist.Names)) {
        if (-not $pat) { continue }
        if ($Evidence.FileName -and $Evidence.FileName -like $pat) { return "nome '$($Evidence.FileName)' casa com o padrão '$pat'" }
        if ($Evidence.OriginalFilename -and $Evidence.OriginalFilename -like $pat) { return "OriginalFilename '$($Evidence.OriginalFilename)' casa com '$pat'" }
    }

    foreach ($pat in @($Whitelist.Paths)) {
        if (-not $pat) { continue }
        if ($Evidence.Path -and $Evidence.Path -like $pat) { return "caminho '$($Evidence.Path)' casa com o padrão '$pat'" }
    }

    foreach ($pat in @($Whitelist.Companies)) {
        if (-not $pat) { continue }
        if ($Evidence.Company -and $Evidence.Company -like $pat) { return "CompanyName '$($Evidence.Company)' casa com '$pat'" }
    }

    foreach ($pat in @($Whitelist.Publishers)) {
        if (-not $pat) { continue }
        if ($Evidence.SigSubject -and $Evidence.SigSubject -like $pat) { return "emissor '$($Evidence.SigSubject)' casa com '$pat'" }
        if ($Evidence.SigIssuer  -and $Evidence.SigIssuer  -like $pat) { return "emissor '$($Evidence.SigIssuer)' casa com '$pat'" }
    }

    if ($Row) {
        foreach ($pat in @($Whitelist.Services)) {
            if (-not $pat) { continue }
            if ($Row.ServiceName -and $Row.ServiceName -like $pat) { return "servico '$($Row.ServiceName)' casa com '$pat'" }
            if ($Row.DisplayName -and $Row.DisplayName -like $pat) { return "servico '$($Row.DisplayName)' casa com '$pat'" }
        }
    }

    if ($Whitelist.SuppressValidMicrosoftSigned -and $Evidence.SigValid -and $Evidence.SigMicrosoft) {
        return 'assinatura valida da Microsoft suprimida pela configuracao'
    }

    return $null
}

function New-ByovdIocIndex {
    [CmdletBinding()]
    param()
    return @{ Sha256 = @{}; Sha1 = @{}; Md5 = @{}; Imphash = @{}; Authentihash = @{}; Count = 0 }
}

function Import-ByovdIocFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $idx = New-ByovdIocIndex
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $idx }

    foreach ($raw in @(Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue)) {
        $line = ([string]$raw).Trim()
        if (-not $line -or $line.StartsWith('#') -or $line.StartsWith(';')) { continue }

        $type = ''; $value = $line
        $c = $line.IndexOf(':')
        if ($c -gt 0 -and $c -lt 24) {
            $maybe = $line.Substring(0, $c).ToLowerInvariant()
            if ($maybe -in @('hash','sha256','sha1','md5','authentihash','imphash','ioc')) {
                $type = $maybe; $value = $line.Substring($c + 1).Trim()
            }
        }
        if (-not $value) { continue }

        $v = $value.ToLowerInvariant()
        if (-not $type) {
            if     ($v -match '^[0-9a-f]{64}$') { $type = 'sha256' }
            elseif ($v -match '^[0-9a-f]{40}$') { $type = 'sha1' }
            elseif ($v -match '^[0-9a-f]{32}$') { $type = 'md5' }
            else { continue }
        }
        switch ($type) {
            'sha256'       { if ($v -match '^[0-9a-f]{64}$') { $idx.Sha256[$v] = $true } }
            'sha1'         { if ($v -match '^[0-9a-f]{40}$') { $idx.Sha1[$v]   = $true } }
            'md5'          { if ($v -match '^[0-9a-f]{32}$') { $idx.Md5[$v]    = $true } }
            'imphash'      { if ($v -match '^[0-9a-f]{32}$') { $idx.Imphash[$v]= $true } }
            'authentihash' { if ($v -match '^[0-9a-f]{64}$') { $idx.Authentihash[$v] = $true } }
            'hash'         {
                if     ($v -match '^[0-9a-f]{64}$') { $idx.Sha256[$v] = $true }
                elseif ($v -match '^[0-9a-f]{40}$') { $idx.Sha1[$v]   = $true }
                elseif ($v -match '^[0-9a-f]{32}$') { $idx.Md5[$v]    = $true }
            }
        }
    }
    $idx.Count = $idx.Sha256.Count + $idx.Sha1.Count + $idx.Md5.Count + $idx.Imphash.Count + $idx.Authentihash.Count
    return $idx
}

$script:ByovdFieldLabels = @{
    'company'          = 'CompanyName'
    'description'      = 'FileDescription'
    'product'          = 'ProductName'
    'copyright'        = 'LegalCopyright'
    'fileversion'      = 'FileVersion'
    'productversion'   = 'ProductVersion'
    'originalfilename' = 'OriginalFilename'
    'internalname'     = 'InternalName'
}

function Add-ByovdReason {
    [CmdletBinding()]
    param(
        [System.Collections.Generic.List[string]]$List,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text
    )
    if ($null -eq $List) { return }
    if (-not $Text) { return }
    if ($List.Contains($Text)) { return }
    [void]$List.Add($Text)
}

function Find-ByovdDetection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Database,
        [Parameter(Mandatory)]$Evidence,
        $Row = $null,
        $Iocs = $null,
        $Config = $null,
        $Whitelist = $null
    )
    if ($null -eq $Config) { $Config = $script:ByovdConfig }

    if ($Whitelist) {
        $wl = Test-ByovdWhitelisted -Evidence $Evidence -Row $Row -Whitelist $Whitelist
        if ($wl) {
            return ([pscustomobject]@{
                Suppressed = $true
                Reason     = $wl
                Confidence = 'Whitelisted'
            })
        }
    }

    $reasons = New-Object System.Collections.Generic.List[string]
    $strong  = @{}
    $weak    = @{}
    $nameHit = @{}
    $hashHit = @{}
    $peHit   = @{}
    $baseHit = New-Object System.Collections.Generic.List[int]

    $iocShaHit = $false
    $iocImpHit = $false
    if ($Iocs) {
        if ($Evidence.SHA256 -and $Iocs.Sha256.ContainsKey($Evidence.SHA256.ToLowerInvariant())) {
            Add-ByovdReason -List $reasons -Text "[ioc] SHA256 $($Evidence.SHA256) consta na sua lista de IOC (-IocFile)"
            $iocShaHit = $true
        }
        if ($Evidence.SHA1 -and $Iocs.Sha1.ContainsKey($Evidence.SHA1.ToLowerInvariant())) {
            Add-ByovdReason -List $reasons -Text "[ioc] SHA1 $($Evidence.SHA1) consta na sua lista de IOC (-IocFile)"
            $iocShaHit = $true
        }
        if ($Evidence.MD5 -and $Iocs.Md5.ContainsKey($Evidence.MD5.ToLowerInvariant())) {
            Add-ByovdReason -List $reasons -Text "[ioc] MD5 $($Evidence.MD5) consta na sua lista de IOC (-IocFile)"
            $iocShaHit = $true
        }
        if ($Evidence.Authentihash -and $Iocs.Authentihash.ContainsKey($Evidence.Authentihash.ToLowerInvariant())) {
            Add-ByovdReason -List $reasons -Text "[ioc] authentihash $($Evidence.Authentihash) consta na sua lista de IOC"
            $iocImpHit = $true
        }
        if ($Evidence.Imphash -and $Iocs.Imphash.ContainsKey($Evidence.Imphash.ToLowerInvariant())) {
            Add-ByovdReason -List $reasons -Text "[ioc] imphash $($Evidence.Imphash) consta na sua lista de IOC (-IocFile)"
            $iocImpHit = $true
        }
    }

    $hashAlgo = @(
        @{ V = $Evidence.SHA256;     T = $Database.Sha256; L = 'SHA256' },
        @{ V = $Evidence.SHA1;       T = $Database.Sha1;   L = 'SHA1' },
        @{ V = $Evidence.MD5;        T = $Database.Md5;    L = 'MD5' }
    )
    foreach ($h in $hashAlgo) {
        $v = [string]$h.V
        if (-not $v) { continue }
        $k = $v.ToLowerInvariant()
        if (-not $h.T.ContainsKey($k)) { continue }
        $label = [string]$h.L
        foreach ($i in $h.T[$k]) {
            $hashHit[$i] = "[hash] $label $v corresponde a um sample registrado na base"
            if (-not $baseHit.Contains($i)) { [void]$baseHit.Add($i) }
        }
        Add-ByovdReason -List $reasons -Text "[hash] $label $v corresponde a um sample registrado na base"
    }

    if ($Evidence.Authentihash) {
        $k = $Evidence.Authentihash.ToLowerInvariant()
        if ($Database.Authentihash.ContainsKey($k)) {
            foreach ($i in $Database.Authentihash[$k]) {
                $peHit[$i] = '[authentihash] casamento com a base (imune a renomeacao e a troca de certificado)'
                if (-not $baseHit.Contains($i)) { [void]$baseHit.Add($i) }
            }
            Add-ByovdReason -List $reasons -Text "[authentihash] $($Evidence.Authentihash) corresponde a base (imune a renomeacao e a troca de certificado)"
        }
    }
    if ($Evidence.Imphash) {
        $k = $Evidence.Imphash.ToLowerInvariant()
        if ($Database.Imphash.ContainsKey($k)) {
            $n = 0
            foreach ($i in $Database.Imphash[$k]) {
                if (-not $peHit.ContainsKey($i)) { $peHit[$i] = '[imphash] conjunto de importacoes igual ao de um driver vulneravel da base' }
                if (-not $baseHit.Contains($i)) { [void]$baseHit.Add($i) }
                $n++
            }
            if ($n -gt 0) { Add-ByovdReason -List $reasons -Text "[imphash] $($Evidence.Imphash) igual ao de $n registro(s) da base (renomeacao nao esconde)" }
        }
    }

    $identityFields = @('description','product','fileversion','productversion',
                        'originalfilename','internalname')
    $metaValues = [ordered]@{
        'company'          = $Evidence.Company
        'description'      = $Evidence.Description
        'product'          = $Evidence.Product
        'copyright'        = $Evidence.Copyright
        'fileversion'      = $Evidence.FileVersion
        'productversion'   = $Evidence.ProductVersion
        'originalfilename' = $Evidence.OriginalFilename
        'internalname'     = $Evidence.InternalName
    }
    $strongId = @{}
    $weakId   = @{}
    foreach ($field in $metaValues.Keys) {
        $raw = [string]$metaValues[$field]
        if (-not $raw) { continue }
        $key = Get-ByovdMetaKey -Field $field -Value $raw
        if (-not $key) { continue }
        if (-not $Database.Meta.ContainsKey($key)) { continue }
        $idxs = $Database.Meta[$key]
        if ($null -eq $idxs) { continue }

        $count = $idxs.Count
        if ($count -gt [int]$Config.WeakValueMaxDrivers) {
            continue
        }
        $isStrong = ($count -le [int]$Config.StrongValueMaxDrivers)
        $label = $script:ByovdFieldLabels[$field]
        $qual  = if ($isStrong) { 'valor raro: visto em {0} registro(s)' -f $count }
                 else            { 'valor de apoio: visto em {0} registros' -f $count }
        Add-ByovdReason -List $reasons -Text ("[metadata] {0} = '{1}' ({2})" -f $label, $raw, $qual)

        $isIdentity = ($identityFields -contains $field)
        foreach ($i in $idxs) {
            if (-not $baseHit.Contains($i)) { [void]$baseHit.Add($i) }
            if (-not $strong.ContainsKey($i)) { $strong[$i] = 0 }
            if (-not $weak.ContainsKey($i))   { $weak[$i] = 0 }
            if ($isStrong) { $strong[$i]++ } else { $weak[$i]++ }
            if ($isIdentity) {
                $tbl = if ($isStrong) { $strongId } else { $weakId }
                if (-not $tbl.ContainsKey($i)) { $tbl[$i] = 0 }
                $tbl[$i]++
            }
        }
    }

    foreach ($nm in @($Evidence.FileName, $Evidence.FileNameNoExt, $Evidence.OriginalFilename)) {
        if (-not $nm) { continue }
        $norm = ConvertTo-ByovdNormalizedText -Value $nm
        if (-not $norm) { continue }
        if (-not $Database.Names.ContainsKey($norm)) { continue }
        $idxs = $Database.Names[$norm]
        if ($null -eq $idxs) { continue }
        foreach ($i in $idxs) {
            if (-not $baseHit.Contains($i)) { [void]$baseHit.Add($i) }
            if (-not $nameHit.ContainsKey($i)) { $nameHit[$i] = 0 }
            $nameHit[$i]++
        }
        Add-ByovdReason -List $reasons -Text "[nome] '$nm' coincide com o nome original registrado na base (apoio, nao detecta sozinho)"
    }

    $contexto = New-Object System.Collections.Generic.List[string]
    $inSys = $false
    if ($Evidence.Path) {
        $drvDir = (Join-Path $env:SystemRoot 'System32\drivers').ToLowerInvariant()
        $inSys = $Evidence.Path.ToLowerInvariant().StartsWith($drvDir)
    }
    if ($Row) {
        if ($Row.Started -or $Row.State -eq 'Running') {
            [void]$contexto.Add('[contexto] servico/driver em execucao nesta maquina')
        }
        if ($Row.StartMode -in @('Boot','System')) {
            [void]$contexto.Add("[contexto] tipo de inicializacao '$($Row.StartMode)' (carrega antes do usuario)")
        }
    }
    if ($Evidence.SigStatus) {
        if (-not $Evidence.SigValid) {
            [void]$contexto.Add("[contexto] assinatura Authenticode nao valida (status: $($Evidence.SigStatus))")
        }
    }
    if ($Evidence.IsPe -and $Evidence.Length -gt 0 -and -not $inSys) {
        [void]$contexto.Add('[contexto] arquivo .sys fora de %SystemRoot%\System32\drivers')
    }
    $renamed = $false
    if ($Evidence.OriginalFilename -and $Evidence.FileName) {
        $of = (ConvertTo-ByovdNormalizedText -Value $Evidence.OriginalFilename)
        $fn = (ConvertTo-ByovdNormalizedText -Value $Evidence.FileName)
        if ($of -and $fn -and $of -ne $fn) {
            $ofAlt = $of -replace '\.mui$', ''
            if (-not $ofAlt) { $ofAlt = $of }
            if ($ofAlt -ne $fn) { $renamed = $true }
        }
    }
    if ($renamed -and $baseHit.Count -gt 0) {
        [void]$contexto.Add("[contexto] nome do arquivo ('$($Evidence.FileName)') difere do OriginalFilename ('$($Evidence.OriginalFilename)') - provavel renomeacao")
    }

    $minWeak = [int]$Config.MinWeakMetaFields

    $best = $null
    $bestConf = 'None'
    $order = @{ None = 0; Confirmed = 4; High = 3; Medium = 2; Low = 1 }
    $confByIndex = @{}

    foreach ($i in $baseHit) {
        $conf = 'None'
        if ($hashHit.ContainsKey($i))     { $conf = 'Confirmed' }
        elseif ($peHit.ContainsKey($i))   { $conf = 'High' }
        else {
            $si = 0; if ($strongId.ContainsKey($i))  { $si = $strongId[$i] }
            $wi = 0; if ($weakId.ContainsKey($i))    { $wi = $weakId[$i] }
            $n  = 0; if ($nameHit.ContainsKey($i))   { $n  = $nameHit[$i] }
            if ($si -ge 1)            { $conf = 'Medium' }
            elseif ($wi -ge $minWeak) { $conf = 'Medium' }
            elseif ($n -ge 1)         { $conf = 'Medium' }
            else {
                $conf = 'None'
            }
        }
        if ($conf -eq 'None') { continue }
        $confByIndex[$i] = $conf
        if (-not $best -or $order[$conf] -gt $order[$bestConf]) { $best = $i; $bestConf = $conf }
    }

    if ($iocShaHit) { $bestConf = 'Confirmed' }
    elseif ($iocImpHit -and $order[$bestConf] -lt $order['High']) { $bestConf = 'High' }

    if ($bestConf -eq 'None') {
        $susp = 0
        if (-not $Evidence.SigValid) { $susp++ }
        if ($Row -and ($Row.Started -or $Row.State -eq 'Running')) { $susp++ }
        if (-not $inSys -and $Evidence.IsPe) { $susp++ }
        if ($susp -ge 3) {
            $bestConf = 'Low'
            foreach ($c in $contexto) { Add-ByovdReason -List $reasons -Text $c }
            Add-ByovdReason -List $reasons -Text '[heuristica] nenhum indicador forte da base casou (no maximo metadado generico isolado), mas a combinacao assinatura invalida + driver em execucao + local incomum justifica revisao manual'
        }
        else { return $null }
    }
    else {
        foreach ($c in $contexto) { Add-ByovdReason -List $reasons -Text $c }
    }

    $driverInfo = @()
    foreach ($i in ($confByIndex.Keys | Sort-Object)) {
        if ($i -lt 0 -or $i -ge $Database.Drivers.Count) { continue }
        $d = $Database.Drivers[$i]
        $driverInfo += [pscustomobject]@{
            Id         = $d.Id
            Name       = $d.Name
            Category   = $d.Category
            Tags       = @($d.Tags)
            Mitre      = $d.Mitre
            Hvci       = $d.Hvci
            Confidence = $confByIndex[$i]
            Strong     = $(if ($strong.ContainsKey($i)) { $strong[$i] } else { 0 })
            Weak       = $(if ($weak.ContainsKey($i))   { $weak[$i] }   else { 0 })
            Hash       = $hashHit.ContainsKey($i)
            PeHash     = $peHit.ContainsKey($i)
        }
    }

    return ([pscustomobject]@{
        Suppressed   = $false
        Confidence   = $bestConf
        Evidence     = $Evidence
        Row          = $Row
        Drivers      = @($driverInfo)
        Reasons      = @($reasons)
        Context      = @($contexto)
        Renamed      = $renamed
        OutsideSys32 = (-not $inSys)
    })
}

function Get-ByovdConfidenceRank {
    [CmdletBinding()]
    param([string]$Confidence)
    switch ($Confidence) {
        'Confirmed'    { return 4 }
        'High'         { return 3 }
        'Medium'       { return 2 }
        'Low'          { return 1 }
        'Whitelisted'  { return 0 }
        default        { return 0 }
    }
}

function Format-ByovdConfidence {
    [CmdletBinding()]
    param([string]$Confidence)
    switch ($Confidence) {
        'Confirmed'   { return 'CONFIRMADO (hash da base)' }
        'High'        { return 'ALTA (assinatura estrutural do PE)' }
        'Medium'      { return 'MEDIA (metadados/nome coincidente)' }
        'Low'         { return 'BAIXA (heuristica de contexto)' }
        'Whitelisted' { return 'SUPRIMIDO (whitelist)' }
        default       { return [string]$Confidence }
    }
}

function Get-ByovdConfidenceColor {
    [CmdletBinding()]
    param([string]$Confidence, [switch]$NoColor)
    if ($NoColor) { return 'Gray' }
    switch ($Confidence) {
        'Confirmed'   { return 'Red' }
        'High'        { return 'Magenta' }
        'Medium'      { return 'Yellow' }
        'Low'         { return 'DarkGray' }
        'Whitelisted' { return 'DarkGray' }
        default       { return 'Gray' }
    }
}

function Get-ByovdReasonColor {
    [CmdletBinding()]
    param([string]$Text, [switch]$NoColor)
    if ($NoColor) { return 'Gray' }
    $t = [string]$Text
    if ($t.IndexOf('[hash]') -ge 0 -or $t.IndexOf('[ioc]') -ge 0) { return 'Red' }
    if ($t.IndexOf('[authentihash]') -ge 0 -or $t.IndexOf('[imphash]') -ge 0) { return 'Magenta' }
    if ($t.IndexOf('[metadata]') -ge 0) { return 'Yellow' }
    if ($t.IndexOf('[nome]') -ge 0 -or $t.IndexOf('[contexto]') -ge 0) { return 'DarkYellow' }
    if ($t.IndexOf('[heuristica]') -ge 0) { return 'DarkGray' }
    return 'Gray'
}

function Write-ByovdField {
    [CmdletBinding()]
    param([string]$Label, [string]$Value, [string]$ValueColor = 'Gray', [switch]$NoColor)
    $l = ('    {0}' -f $Label).PadRight(17)
    if ($NoColor) { Write-Host ($l + $Value); return }
    Write-Host $l -NoNewline -ForegroundColor Cyan
    Write-Host $Value -ForegroundColor $ValueColor
}

function Write-ByovdSummaryLine {
    [CmdletBinding()]
    param([string]$Label, [string]$Value, [string]$ValueColor = 'Gray', [switch]$NoColor)
    $l = ('  {0} ' -f $Label).PadRight(17)
    if ($NoColor) { Write-Host ($l + $Value); return }
    Write-Host $l -NoNewline -ForegroundColor Cyan
    Write-Host $Value -ForegroundColor $ValueColor
}

function Write-ByovdBullet {
    [CmdletBinding()]
    param([string]$Text, [switch]$NoColor)
    $c = Get-ByovdReasonColor -Text $Text -NoColor:$NoColor
    if ($NoColor) { Write-Host ('      - {0}' -f $Text); return }
    Write-Host '      - ' -NoNewline -ForegroundColor DarkGray
    Write-Host $Text -ForegroundColor $c
}

function Write-ByovdBanner {
    [CmdletBinding()]
    param([switch]$NoColor, [switch]$Json)
    $txt = '[*] SCANNER ABUSIVE BYOVD'
    if ($Json) { Write-ByovdLog -Color 'Cyan' -Message $txt; return }
    Write-Host ''
    Write-Host ''
    if ($NoColor) { Write-Host $txt; return }
    Write-Host $txt -ForegroundColor Cyan
}

function Write-ByovdFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Finding,
        [switch]$NoColor
    )
    $ev = $Finding.Evidence
    $row = $Finding.Row

    $nome = ''
    if ($ev) { $nome = [string]$ev.FileName }
    if (-not $nome -and $row) { $nome = [string]$row.ServiceName }
    if (-not $nome) { $nome = '(nome desconhecido)' }

    $confText = Format-ByovdConfidence -Confidence $Finding.Confidence
    $confColor = Get-ByovdConfidenceColor -Confidence $Finding.Confidence -NoColor:$NoColor
    if ($NoColor) {
        Write-Host ('[!] POSSÍVEL BYOVD  {0}  [{1}]' -f $nome, $confText)
    }
    else {
        Write-Host '[!] POSSÍVEL BYOVD' -NoNewline -ForegroundColor Red
        Write-Host ('  {0}' -f $nome) -NoNewline -ForegroundColor White
        Write-Host ('  [{0}]' -f $confText) -ForegroundColor $confColor
    }

    $path = '(sem caminho resolvido)'
    if ($ev -and $ev.Path) { $path = [string]$ev.Path }
    Write-ByovdField -Label 'Caminho:' -Value $path -ValueColor 'White' -NoColor:$NoColor

    $semServico = ($row -and (@($row.Source) -contains 'filesystem'))
    if ($row -and -not $semServico) {
        $servico = [string]$row.ServiceName
        if (-not $servico) { $servico = [string]$row.DisplayName }
        if (-not $servico) { $servico = '(sem servico)' }
        $estado = [string]$row.State
        if (-not $estado) { $estado = 'desconhecido' }
        $iniciado = 'nao'
        $rodando = $false
        if ($row.Started -or $row.State -eq 'Running') { $iniciado = 'sim'; $rodando = $true }
        elseif ($row.StartMode) { $iniciado = "nao (start $($row.StartMode))" }
        $sc = 'Gray'
        if ($rodando) { $sc = 'Green' }
        $sv = '{0}  [{1}; iniciado: {2}]' -f $servico, $estado, $iniciado
        Write-ByovdField -Label 'Servico:' -Value $sv -ValueColor $sc -NoColor:$NoColor
    }

    $assinatura = 'Desconhecida'
    $sigColor = 'DarkGray'
    if ($ev) {
        if ($ev.SigStatus) { $assinatura = [string]$ev.SigStatus }
        if ($ev.SigValid -and $ev.SigSubject) {
            $sub = [string]$ev.SigSubject
            $parts = @()
            foreach ($m in [regex]::Matches($sub, '(?:^|,\s*)((?:CN|O)="[^"]*")')) {
                $parts += $m.Groups[1].Value
            }
            if ($parts.Count -eq 0) {
                foreach ($m in [regex]::Matches($sub, '(?:^|,\s*)((?:CN|O)=[^,]+)')) {
                    $parts += $m.Groups[1].Value
                }
            }
            if ($parts.Count -eq 0) {
                $short = $sub
                if ($short.Length -gt 120) { $short = $short.Substring(0, 120) + '...' }
            }
            else { $short = $parts -join ', ' }
            $assinatura = '{0} - {1}' -f $ev.SigStatus, $short
        }
    }
    if (-not $NoColor) {
        if ($assinatura -like 'Valid*')        { $sigColor = 'Green' }
        elseif ($assinatura -like 'NotSigned*') { $sigColor = 'DarkYellow' }
        elseif ($assinatura -like 'Desconhecida*') { $sigColor = 'DarkGray' }
        else { $sigColor = 'Red' }
    }
    Write-ByovdField -Label 'Assinatura:' -Value $assinatura -ValueColor $sigColor -NoColor:$NoColor

    $sha = '(arquivo ilegivel ou ausente)'
    if ($ev -and $ev.SHA256) { $sha = [string]$ev.SHA256 }
    Write-ByovdField -Label 'SHA256:' -Value $sha -ValueColor 'Cyan' -NoColor:$NoColor

    $drvLine = '(nao consta na base local: casamento vem da sua lista de IOC)'
    if (@($Finding.Drivers).Count -gt 0) {
        $rank = @{ Confirmed = 4; High = 3; Medium = 2; Low = 1 }
        $drvSorted = @(@($Finding.Drivers) | Sort-Object `
            @{ Expression = { if ($_.Confidence -and $rank.ContainsKey($_.Confidence)) { -$rank[$_.Confidence] } else { 0 } } },
            @{ Expression = { [string]$_.Name } })
        $d = $drvSorted[0]
        $dn = if ($d.Name) { [string]$d.Name } else { [string]$d.Id }
        $extra = @()
        if ($d.Category)   { $extra += "categoria: $($d.Category)" }
        if ($d.Hvci)       { $extra += 'carrega apesar do HVCI' }
        if ($d.Hash)       { $extra += 'hash' }
        if ($d.PeHash)     { $extra += 'imphash/authentihash' }
        if ($d.Confidence) { $extra += "confianca $($d.Confidence)" }
        if ($d.Strong -gt 0) { $extra += "$($d.Strong) meta rara(s)" }
        if ($d.Weak -gt 0)   { $extra += "$($d.Weak) meta de apoio" }
        $drvLine = $dn
        if ($extra.Count -gt 0) { $drvLine = '{0}  [{1}]' -f $dn, ($extra -join '; ') }
        if ($drvSorted.Count -gt 1) {
            $drvLine = '{0}  (+{1} outro(s) registro(s) - veja o JSON)' -f $drvLine, ($drvSorted.Count - 1)
        }
    }
    Write-ByovdField -Label 'Base:' -Value $drvLine -ValueColor 'Yellow' -NoColor:$NoColor

    $reasons = @($Finding.Reasons)
    $metaItems = New-Object System.Collections.Generic.List[string]
    $ctxItems = New-Object System.Collections.Generic.List[string]
    foreach ($r in $reasons) {
        $s = [string]$r
        if ($s.StartsWith('[metadata]')) { [void]$metaItems.Add($s); continue }
        if ($s.StartsWith('[contexto]'))  { [void]$ctxItems.Add($s); continue }
    }

    $metaLine = $null
    if ($metaItems.Count -gt 0) {
        $pairs = New-Object System.Collections.Generic.List[string]
        foreach ($m in $metaItems) {
            $g = [regex]::Match($m, "^\[metadata\]\s*(.+?)\s*=\s*'(.+?)'\s*\(")
            if ($g.Success) {
                $val = [string]$g.Groups[2].Value
                if ($val.Length -gt 40) { $val = $val.Substring(0, 39) + '...' }
                [void]$pairs.Add(("{0}='{1}'" -f $g.Groups[1].Value, $val))
            }
            else { [void]$pairs.Add(($m -replace '^\[metadata\]\s*', '')) }
        }
        $shown = New-Object System.Collections.Generic.List[string]
        $maxShow = 3
        for ($i = 0; $i -lt $pairs.Count; $i++) {
            if ($i -lt $maxShow) { [void]$shown.Add($pairs[$i]) } else { break }
        }
        $left = $pairs.Count - $shown.Count
        if ($left -gt 0) { [void]$shown.Add(('+{0}' -f $left)) }
        $metaLine = '[metadata] {0} campo(s): {1}' -f $pairs.Count, ($shown -join ' | ')
    }

    $ctxLine = $null
    if ($ctxItems.Count -gt 0) {
        $txt = @()
        foreach ($c in $ctxItems) { $txt += ($c -replace '^\[contexto\]\s*', '') }
        $ctxLine = '[contexto] {0}' -f ($txt -join '; ')
    }

    if ($NoColor) { Write-Host '    Motivos:' } else { Write-Host '    Motivos:' -ForegroundColor Cyan }
    $metaDone = $false
    $ctxDone = $false
    foreach ($r in $reasons) {
        $s = [string]$r
        if ($s.StartsWith('[metadata]')) {
            if (-not $metaDone -and $metaLine) { Write-ByovdBullet -Text $metaLine -NoColor:$NoColor; $metaDone = $true }
            continue
        }
        if ($s.StartsWith('[contexto]')) {
            if (-not $ctxDone -and $ctxLine) { Write-ByovdBullet -Text $ctxLine -NoColor:$NoColor; $ctxDone = $true }
            continue
        }
        Write-ByovdBullet -Text $s -NoColor:$NoColor
    }
    if (-not $metaDone -and $metaLine) { Write-ByovdBullet -Text $metaLine -NoColor:$NoColor }
    if (-not $ctxDone -and $ctxLine)   { Write-ByovdBullet -Text $ctxLine -NoColor:$NoColor }

    if ($NoColor) { Write-Host ('-' * 78) } else { Write-Host ('-' * 78) -ForegroundColor DarkGray }
}

function Write-ByovdSuppressed {
    [CmdletBinding()]
    param($Finding)
    $ev = $Finding.Evidence
    $p = if ($ev -and $ev.Path) { $ev.Path } else { '(sem caminho)' }
    Write-Host ('[i] SUPRIMIDO PELA WHITELIST: {0}' -f $p) -ForegroundColor DarkGray
    Write-Host ('    Motivo: {0}' -f $Finding.Reason) -ForegroundColor DarkGray
}

function Write-ByovdSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Result,
        [switch]$NoColor
    )
    $s = $Result.Stats
    Write-Host ''
    if ($NoColor) {
        Write-Host ('=' * 78)
        Write-Host ' RESUMO DA VARREDURA BYOVD (somente leitura)'
        Write-Host ('=' * 78)
    }
    else {
        Write-Host ('=' * 78) -ForegroundColor DarkCyan
        Write-Host ' RESUMO DA VARREDURA BYOVD (somente leitura)' -ForegroundColor White
        Write-Host ('=' * 78) -ForegroundColor DarkCyan
    }

    $m = '{0} ({1} registros, {2} samples)' -f $s.DatabaseSources, $s.DatabaseDrivers, $s.DatabaseSamples
    Write-ByovdSummaryLine -Label 'Base .........' -Value $m -ValueColor 'White' -NoColor:$NoColor

    $m = 'sha256 {0} | imphash {1} | authenti {2} | meta {3} | nomes {4}' -f `
        $s.DatabaseSha256, $s.DatabaseImphashes, $s.DatabaseAuthentihashes, $s.DatabaseMetaKeys, $s.DatabaseNames
    Write-ByovdSummaryLine -Label 'Indice ........' -Value $m -NoColor:$NoColor

    $m = '{0} inventariados | {1} analisados | {2} sem arquivo/ilegiveis | {3} suprimidos' -f `
        $s.Inventory, $s.FilesAnalyzed, $s.FilesSkipped, $s.Suppressed
    Write-ByovdSummaryLine -Label 'Analise ......' -Value $m -NoColor:$NoColor

    if ($NoColor) {
        $m = '{0} confirmado | {1} alta | {2} media | {3} baixa' -f $s.Confirmed, $s.High, $s.Medium, $s.Low
        Write-ByovdSummaryLine -Label 'Achados ......' -Value $m -NoColor
    }
    else {
        Write-Host '  Achados ...... ' -NoNewline -ForegroundColor Cyan
        $seg = New-Object System.Collections.Generic.List[object]
        $seg.Add(@{ N = $s.Confirmed; T = 'confirmado'; C = 'Red' })
        $seg.Add(@{ N = $s.High;      T = 'alta';       C = 'Magenta' })
        $seg.Add(@{ N = $s.Medium;    T = 'media';      C = 'Yellow' })
        $seg.Add(@{ N = $s.Low;       T = 'baixa';      C = 'DarkGray' })
        for ($i = 0; $i -lt $seg.Count; $i++) {
            $p = $seg[$i]
            $c = [string]$p.C
            if ([int]$p.N -le 0) { $c = 'DarkGray' }
            if ($i -gt 0) { Write-Host ' | ' -NoNewline -ForegroundColor DarkGray }
            Write-Host ('{0} {1}' -f $p.N, $p.T) -NoNewline -ForegroundColor $c
        }
        Write-Host ''
    }

    if ($s.ExternalBase)  { Write-ByovdSummaryLine -Label 'Base externa .' -Value $s.ExternalBase -ValueColor 'Gray' -NoColor:$NoColor }
    if ($s.IocFile)       { $m = '{0} ({1} entradas)' -f $s.IocFile, $s.IocEntries
                            Write-ByovdSummaryLine -Label 'IOC ...........' -Value $m -ValueColor 'Gray' -NoColor:$NoColor }
    if ($s.WhitelistFile) { Write-ByovdSummaryLine -Label 'Whitelist ....' -Value $s.WhitelistFile -ValueColor 'Gray' -NoColor:$NoColor }

    $m = '{0:n2} s' -f $s.ElapsedSeconds
    Write-ByovdSummaryLine -Label 'Tempo ........' -Value $m -ValueColor 'White' -NoColor:$NoColor

    $total = $s.Confirmed + $s.High + $s.Medium + $s.Low
    if ($total -gt 0) {
        if ($NoColor) {
            Write-Host '  Legenda ...... [hash]/[ioc] identidade | [authentihash]/[imphash] estrutura do PE'
            Write-Host '                 [metadata] recursos internos | [nome]/[contexto] so apoio'
        }
        else {
            Write-Host '  Legenda ...... ' -NoNewline -ForegroundColor Cyan
            Write-Host '[hash]/[ioc]' -NoNewline -ForegroundColor Red
            Write-Host ' identidade | ' -NoNewline -ForegroundColor Gray
            Write-Host '[authentihash]/[imphash]' -NoNewline -ForegroundColor Magenta
            Write-Host ' estrutura do PE' -ForegroundColor Gray
            Write-Host ('                 {0} ' -f '[metadata]') -NoNewline -ForegroundColor Yellow
            Write-Host 'recursos internos | ' -NoNewline -ForegroundColor Gray
            Write-Host '[nome]/[contexto]' -NoNewline -ForegroundColor DarkYellow
            Write-Host ' so apoio' -ForegroundColor Gray
        }
    }

    if ($NoColor) {
        Write-Host ('=' * 78)
        if (($s.Confirmed + $s.High) -gt 0) { Write-Host '  [!] Houve Deteccoes de alta confianca - revise os blocos acima.' }
        else { Write-Host '  [ok] Nenhum driver vulneravel confirmado nesta maquina.' }
    }
    else {
        Write-Host ('=' * 78) -ForegroundColor DarkCyan
        if (($s.Confirmed + $s.High) -gt 0) {
            Write-Host '  [!] ' -NoNewline -ForegroundColor Red
            Write-Host 'Houve Deteccoes de alta confianca - revise os blocos acima.' -ForegroundColor Red
        }
        else {
            Write-Host '  [ok] ' -NoNewline -ForegroundColor Green
            Write-Host 'Nenhum driver vulneravel confirmado nesta maquina.' -ForegroundColor Green
        }
    }
    Write-Host ''
}

function Invoke-BYOVDScanner {
    [CmdletBinding()]
    param(
        [string]$LolDriversPath   = $script:LolDriversPath,
        [string[]]$ExtraScanPath  = $script:ExtraScanPath,
        [string]$IocFile          = $script:IocFile,
        [string]$WhitelistFile    = $script:WhitelistFile,
        [switch]$NoExternalBase   = $(if ($script:NoExternalBase) { $true } else { $false }),
        [switch]$NoBeep           = $(if ($script:NoBeep) { $true } else { $false }),
        [switch]$IncludeMedium    = $(if ($script:IncludeMedium) { $true } else { $false }),
        [switch]$IncludeLow       = $(if ($script:IncludeLow) { $true } else { $false }),
        [switch]$ShowReport,
        [switch]$Json,
        [switch]$ImportOnly,
        [switch]$NoProgress    = $(if ($script:NoProgress) { $true } else { $false }),
        [switch]$Progress      = $(if ($script:Progress) { $true } else { $false }),
        [switch]$NoColor
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Reset-ByovdEvidenceCache

    $wantProgress = [bool]$script:ByovdConfig.ShowProgress
    if ($NoProgress)     { $wantProgress = $false }
    elseif ($Progress)   { $wantProgress = $true }

    if (-not $wantProgress) { $script:ByovdProgressMode = 'none' }
    elseif ($Json)          { $script:ByovdProgressMode = 'stderr' }
    else                    { $script:ByovdProgressMode = 'host' }
    $script:ByovdLogNoColor = [bool]$NoColor
    Write-ByovdBanner -NoColor:$NoColor -Json:$Json

    $minConf = 'High'
    if ($IncludeMedium) { $minConf = 'Medium' }
    if ($IncludeLow)    { $minConf = 'Low' }

    Write-ByovdLog -Color 'Cyan'    -Message ('=' * 74)
    Write-ByovdLog -Color 'Cyan'    -Message ' SCANNER BYOVD - SOMENTE LEITURA (nao escreve, nao baixa, nao carrega nem executa drivers)'
    Write-ByovdLog -Color 'Cyan'    -Message ('=' * 74)
    Write-ByovdLog -Color 'Gray'    -Message ('  Inicio ............ {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    Write-ByovdLog -Color 'Gray'    -Message ('  Pasta do script ... {0}' -f $script:ByovdScriptRoot)
    Write-ByovdLog -Color 'Gray'    -Message ('  Exibe a partir de ... {0}' -f $minConf)
    if (@($ExtraScanPath).Count -gt 0) {
        Write-ByovdLog -Color 'Gray' -Message ('  Pastas extras ..... {0}' -f (@($ExtraScanPath) -join '; '))
    }
    if ($IocFile)        { Write-ByovdLog -Color 'Gray' -Message ('  Lista de IOC ...... {0}' -f $IocFile) }
    if ($WhitelistFile)  { Write-ByovdLog -Color 'Gray' -Message ('  Whitelist ......... {0}' -f $WhitelistFile) }
    if ($NoExternalBase) { Write-ByovdLog -Color 'Gray' -Message '  Base externa ...... ignorada (-NoExternalBase)' }

    Write-ByovdLog -Color 'Cyan' -Message '[1/6] Carregando a base de deteccao (payload embutido no proprio .ps1)...'
    $db = New-ByovdDatabase
    $embeddedRows = 0
    try { $embeddedRows = Import-ByovdEmbeddedBase -Database $db -Text $script:ByovdEmbeddedPayload } catch { $embeddedRows = 0 }
    Write-ByovdLog -Color 'Green' -Message ('      embutida ok: {0} registro(s) / {1} sample(s) / {2} sha256 / {3} authentihash / {4} imphash' -f
        $db.Drivers.Count, $db.PayloadSamples, $db.Sha256.Count, $db.Authentihash.Count, $db.Imphash.Count)

    $externalDesc = ''
    if (-not $NoExternalBase) {
        $base = $null
        try { $base = Find-LolDriversBase -Path $LolDriversPath } catch { $base = $null }
        if ($base -and $base.JsonPath) {
            Write-ByovdLog -Color 'Gray' -Message ('      enriquecendo com drivers.json local: {0}' -f $base.JsonPath)
            Write-ByovdLog -Color 'Gray' -Message '      lendo o JSON (pode levar ~15 s)...'
            try {
                $n = Import-ByovdJsonBase -Database $db -JsonPath $base.JsonPath `
                       -HashesPath $(if ($base.HashesPath) { $base.HashesPath } else { '' })
                if ($n -gt 0) {
                    $externalDesc = "$($base.JsonPath) (+$n samples)"
                    Write-ByovdLog -Color 'Green' -Message ('      +{0} sample(s) fundidos da base externa' -f $n)
                }
            }
            catch { Write-ByovdLog -Color 'DarkYellow' -Message '      base externa falhou - seguindo so com a embutida' }
        }
        else {
            Write-ByovdLog -Color 'DarkYellow' -Message '      nenhuma copia local do LOLDrivers encontrada - usando so a embutida'
        }
    }
    else {
        Write-ByovdLog -Color 'DarkYellow' -Message '      (-NoExternalBase) usando somente a base embutida'
    }

    if ($embeddedRows -eq 0 -and $db.Drivers.Count -eq 0) {
        Write-Warning 'Payload embutido vazio: rode o passo de build para gerar a base dentro do .ps1.'
    }

    $dbStats = Get-ByovdDatabaseStats -Database $db
    Write-ByovdLog -Color 'Green' -Message ('      base pronta: {0} registro(s), {1} sample(s), fonte {2} ({3:n1} s)' -f
        $dbStats.Drivers, $dbStats.Samples, $dbStats.Sources, $sw.Elapsed.TotalSeconds)

    if ($ImportOnly) {
        Write-ByovdLog -Color 'Cyan' -Message '[fim] -ImportOnly: base carregada, encerrando antes da varredura.'
        $sw.Stop()
        return ([pscustomobject]@{
            ImportOnly      = $true
            Drivers         = $dbStats.Drivers
            Samples         = $dbStats.Samples
            Sha256          = $dbStats.Sha256
            Md5             = $dbStats.Md5
            Sha1            = $dbStats.Sha1
            Authentihashes  = $dbStats.Authentihashes
            Imphashes       = $dbStats.Imphashes
            MetaKeys        = $dbStats.MetaKeys
            Names           = $dbStats.Names
            PayloadChars    = $dbStats.PayloadChars
            Sources         = $dbStats.Sources
            ExternalBase    = $externalDesc
            ElapsedSeconds  = $sw.Elapsed.TotalSeconds
        })
    }

    Write-ByovdLog -Color 'Cyan' -Message '[2/6] Carregando a whitelist (supressao explicita)...'
    $wl = New-ByovdWhitelist
    if ($script:ByovdConfig.Whitelist) {
        try { $null = Merge-ByovdWhitelist -Target $wl -Source $script:ByovdConfig.Whitelist } catch { }
    }
    $wlFileDesc = ''
    if ($WhitelistFile) {
        if (Test-Path -LiteralPath $WhitelistFile -PathType Leaf) {
            $fromFile = Import-ByovdListFile -Path $WhitelistFile
            $null = Merge-ByovdWhitelist -Target $wl -Source $fromFile
            $wlFileDesc = $WhitelistFile
        }
        else {
            Write-Warning "WhitelistFile nao encontrado: $WhitelistFile"
        }
    }
    $wlEntries = $wl.Hashes.Count + $wl.Authentihashes.Count + $wl.Imphashes.Count +
                 $wl.Names.Count + $wl.Paths.Count + $wl.Companies.Count +
                 $wl.Publishers.Count + $wl.Services.Count
    if ($wlEntries -gt 0 -or $wl.SuppressValidMicrosoftSigned) {
        Write-ByovdLog -Color 'Gray' -Message ('      {0} entrada(s) de whitelist{1}' -f
            $wlEntries, $(if ($wl.SuppressValidMicrosoftSigned) { ' + suprime assinatura valida da Microsoft' } else { '' }))
    }
    else { Write-ByovdLog -Color 'Gray' -Message '      nenhuma whitelist ativa' }

    Write-ByovdLog -Color 'Cyan' -Message '[3/6] Carregando sua lista de IOC (-IocFile)...'
    $iocs = $null
    $iocDesc = ''; $iocEntries = 0
    if ($IocFile) {
        if (Test-Path -LiteralPath $IocFile -PathType Leaf) {
            $iocs = Import-ByovdIocFile -Path $IocFile
            $iocDesc = $IocFile
            $iocEntries = [int]$iocs.Count
            Write-ByovdLog -Color 'Green' -Message ('      {0} hash/imphash proprio(s) carregado(s) de {1}' -f $iocEntries, $IocFile)
        }
        else {
            Write-Warning "IocFile nao encontrado: $IocFile"
        }
    }
    else { Write-ByovdLog -Color 'Gray' -Message '      nenhuma lista de IOC informada' }

    Write-ByovdLog -Color 'Cyan' -Message '[4/6] Inventariando drivers (registro, CIM, servicos, varredura de pastas)...'
    $inventory = @()
    try { $inventory = @(Get-ByovdDriverInventory -ExtraPaths @($ExtraScanPath) -Config $script:ByovdConfig) }
    catch { Write-Warning "Falha no inventario: $($_.Exception.Message)" }
    Write-ByovdLog -Color 'Green' -Message ('      {0} item(s) no inventario' -f @($inventory).Count)

    $findings   = New-Object System.Collections.Generic.List[object]
    $suppressed = New-Object System.Collections.Generic.List[object]
    $analyzed   = 0
    $skipped    = 0
    $processed  = 0

    $totalInv = @($inventory).Count
    $every = [int]$script:ByovdConfig.ProgressEvery
    if ($every -lt 1) { $every = 25 }

    Write-ByovdLog -Color 'Cyan' -Message ('[5/6] Analisando {0} arquivo(s): SHA256/SHA1/MD5, imphash, authentihash, metadados, assinatura...' -f $totalInv)

    foreach ($row in $inventory) {
        $path = [string]$row.Path
        $processed++

        if (($processed -eq 1) -or (($processed % $every) -eq 0) -or ($processed -eq $totalInv)) {
            $pct = if ($totalInv -gt 0) { [int](($processed * 100) / $totalInv) } else { 100 }
            $msg = '      ... {0}/{1} ({2}%) - ate agora: {3} analisado(s), {4} ignorado(s), {5} achado(s), {6} suprimido(s)'
            Write-ByovdLog -Color 'DarkGray' -Message ($msg -f
                $processed, $totalInv, $pct, $analyzed, $skipped, $findings.Count, $suppressed.Count)
        }

        if ([string]::IsNullOrWhiteSpace($path)) { $skipped++; continue }
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { $skipped++; continue }

        $ev = $null
        try { $ev = Get-ByovdFileEvidence -Path $path -MaxHashBytes ([int]$script:ByovdConfig.MaxFileBytes) }
        catch { $ev = $null }
        if ($null -eq $ev -or -not $ev.Readable) { $skipped++; continue }
        $analyzed++

        $det = $null
        try {
            $det = Find-ByovdDetection -Database $db -Evidence $ev -Row $row -Iocs $iocs `
                     -Config $script:ByovdConfig -Whitelist $wl
        }
        catch { $det = $null }

        if ($null -eq $det) { continue }

        if ($det.Suppressed) {
            $det | Add-Member -NotePropertyName 'Evidence' -NotePropertyValue $ev -Force
            $det | Add-Member -NotePropertyName 'Row'      -NotePropertyValue $row  -Force
            [void]$suppressed.Add($det)
            Write-ByovdLog -Color 'DarkGray' -Message ('      [i] suprimido pela whitelist: {0}' -f $path)
            continue
        }

        $rank = Get-ByovdConfidenceRank -Confidence $det.Confidence
        $minRank = Get-ByovdConfidenceRank -Confidence $minConf
        if ($rank -lt $minRank) {
            Write-ByovdLog -Color 'DarkYellow' -Message ('      [-] {0} (fora do limiar {1}): {2}' -f $det.Confidence, $minConf, $path)
            continue
        }

        [void]$findings.Add($det)
        Write-ByovdLog -Color 'Red' -Message ('      [!] {0} - {1}' -f $det.Confidence, $path)
    }

    $msg = '      analise concluida: {0} analisado(s), {1} ignorado(s), {2} achado(s), {3} suprimido(s)'
    Write-ByovdLog -Color 'Green' -Message ($msg -f $analyzed, $skipped, $findings.Count, $suppressed.Count)

    Write-ByovdLog -Color 'Cyan' -Message '[6/6] Correlacionando com a base e ordenando por confianca...'

    $findingsArr   = $findings.ToArray()
    $suppressedArr = $suppressed.ToArray()

    $ordered = @($findingsArr | Sort-Object `
        @{ Expression = { -(Get-ByovdConfidenceRank -Confidence $_.Confidence) } },
        @{ Expression = { if ($_.Evidence) { [string]$_.Evidence.Path } else { '' } } })

    $stats = [pscustomobject]@{
        DatabaseSources        = $dbStats.Sources
        DatabaseDrivers        = $dbStats.Drivers
        DatabaseSamples        = $dbStats.Samples
        DatabaseSha256         = $dbStats.Sha256
        DatabaseImphashes      = $dbStats.Imphashes
        DatabaseAuthentihashes = $dbStats.Authentihashes
        DatabaseMetaKeys       = $dbStats.MetaKeys
        DatabaseNames          = $dbStats.Names
        DatabasePayloadChars   = $dbStats.PayloadChars
        Inventory              = @($inventory).Count
        FilesAnalyzed          = $analyzed
        FilesSkipped           = $skipped
        Suppressed             = $suppressedArr.Count
        Confirmed              = @($ordered | Where-Object { $_.Confidence -eq 'Confirmed' }).Count
        High                   = @($ordered | Where-Object { $_.Confidence -eq 'High' }).Count
        Medium                 = @($ordered | Where-Object { $_.Confidence -eq 'Medium' }).Count
        Low                    = @($ordered | Where-Object { $_.Confidence -eq 'Low' }).Count
        ExternalBase           = $externalDesc
        IocFile                = $iocDesc
        IocEntries             = $iocEntries
        WhitelistFile          = $wlFileDesc
        ElapsedSeconds         = 0
    }

    $sw.Stop()
    $stats.ElapsedSeconds = $sw.Elapsed.TotalSeconds

    $msg = 'Concluido em {0:n1} s | inventariado {1} | analisado {2} | ignorado {3} | suprimido {4} | achados {5} confirmed, {6} high, {7} medium, {8} low'
    Write-ByovdLog -Color 'Green' -Message ($msg -f $stats.ElapsedSeconds, $stats.Inventory, $stats.FilesAnalyzed, $stats.FilesSkipped, $stats.Suppressed, $stats.Confirmed, $stats.High, $stats.Medium, $stats.Low)

    $result = [pscustomobject]@{
        Findings   = @($ordered)
        Suppressed = $suppressedArr
        Inventory  = @($inventory)
        Database   = $db
        DatabaseStats = $dbStats
        Stats      = $stats
    }

    if ($Json) {
        $payload = [pscustomobject]@{
            Stats      = $stats
            Findings   = @($ordered | ForEach-Object {
                [pscustomobject]@{
                    Confidence = $_.Confidence
                    Renamed    = $_.Renamed
                    OutsideSys32 = $_.OutsideSys32
                    Path       = if ($_.Evidence) { $_.Evidence.Path } else { '' }
                    Service    = if ($_.Row) { $_.Row.ServiceName } else { '' }
                    State      = if ($_.Row) { $_.Row.State } else { '' }
                    Started    = if ($_.Row) { [bool]$_.Row.Started } else { $false }
                    SHA256     = if ($_.Evidence) { $_.Evidence.SHA256 } else { '' }
                    Imphash    = if ($_.Evidence) { $_.Evidence.Imphash } else { '' }
                    Authentihash = if ($_.Evidence) { $_.Evidence.Authentihash } else { '' }
                    Signature  = if ($_.Evidence) { $_.Evidence.SigStatus } else { '' }
                    SignatureSubject = if ($_.Evidence) { $_.Evidence.SigSubject } else { '' }
                    Length     = if ($_.Evidence) { $_.Evidence.Length } else { 0 }
                    Drivers    = @($_.Drivers | ForEach-Object {
                                     [pscustomobject]@{ Id = $_.Id; Name = $_.Name; Category = $_.Category; Hvci = $_.Hvci; Confidence = $_.Confidence }
                                 })
                    Reasons    = @($_.Reasons)
                }
            })
            Suppressed = @($suppressedArr | ForEach-Object {
                [pscustomobject]@{
                    Path   = if ($_.Evidence) { $_.Evidence.Path } else { '' }
                    Reason = $_.Reason
                }
            })
        }
        return ($payload | ConvertTo-Json -Depth 8)
    }

    if ($ShowReport) {
        $msg = '--- Relatorio (confianca minima {0}: {1} achado(s), {2} suprimido(s)) ---'
        Write-ByovdLog -Color 'Cyan' -Message ($msg -f $minConf, $ordered.Count, $suppressedArr.Count)
        foreach ($d in $suppressedArr) { Write-ByovdSuppressed -Finding $d }
        foreach ($f in $ordered) { Write-ByovdFinding -Finding $f -NoColor:$NoColor }
        Write-ByovdSummary -Result $result -NoColor:$NoColor
    }

    return ,$ordered
}

if (-not $script:ByovdDotSourced) {
    $autoParams = @{
        ShowReport    = $true
        NoColor       = [bool]$NoColor
        NoBeep        = [bool]$NoBeep
        IncludeMedium = [bool]$IncludeMedium
        IncludeLow    = [bool]$IncludeLow
        Json          = [bool]$Json
        ImportOnly    = [bool]$ImportOnly
        NoExternalBase= [bool]$NoExternalBase
        NoProgress    = [bool]$NoProgress
        Progress      = [bool]$Progress
    }
    if ($LolDriversPath)  { $autoParams.LolDriversPath  = $LolDriversPath }
    if ($ExtraScanPath)   { $autoParams.ExtraScanPath   = @($ExtraScanPath) }
    if ($IocFile)         { $autoParams.IocFile         = $IocFile }
    if ($WhitelistFile)   { $autoParams.WhitelistFile   = $WhitelistFile }

    $standalone = Test-ByovdStandaloneLaunch
    $exitCode = 0

    try {
        $out = Invoke-BYOVDScanner @autoParams
        if ($Json) { $out }
    }
    catch {
        Write-Host ''
        Write-Host ('[x] Erro na varredura: {0}' -f $_.Exception.Message) -ForegroundColor Red
        if ($_.ScriptStackTrace) {
            $st = ([string]$_.ScriptStackTrace) -replace "`r?`n", ' | '
            if ($st) { Write-Host ('    {0}' -f $st) -ForegroundColor DarkYellow }
        }
        $exitCode = 2
    }

    if (-not $NoPause -and $standalone) {
        if ($exitCode -eq 0) { Wait-ByovdKey -Message 'Varredura terminada. Pressione ENTER para fechar...' }
        else                 { Wait-ByovdKey -Message 'Ocorreu o erro mostrado acima. Pressione ENTER para fechar...' }
    }

    if ($standalone -and $exitCode -ne 0) { exit $exitCode }
}

Write-Host "`n[*] Archives unsigned ( no .exe )" -ForegroundColor Cyan

$min = 500KB
$max = 30MB

$whitelistPastas = @(
    "C:\Windows\WinSxS\",
    "C:\Windows\SoftwareDistribution\",
    "C:\Windows\Installer\",
    "C:\Windows\System32\DriverStore\",
    "C:\Windows\Servicing\",
    "C:\Windows\Logs\",
    "C:\ProgramData\Microsoft\Windows\WER\",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\",
    "C:\Users\$env:USERNAME\AppData\Local\Packages\",
    "C:\ProgramData\Microsoft\Windows Defender\",
    "C:\Program Files\WindowsApps\",
    "C:\Windows\assembly\",
    "C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\",
    "C:\ProgramData\Microsoft\Diagnosis\",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\",
    "C:\Sysmon\",
    "C:\Windows\System32\",

    # Shockwave / Macromed (plugins legados da Adobe, sem assinatura)
    "C:\Windows\SysWOW64\Macromed\Shockwave *",
    "C:\Windows\SysWOW64\Adobe\Shockwave *",
    "C:\Windows\System32\Macromed\Shockwave *",
    "C:\Windows\System32\Adobe\Shockwave *",

    # GAC do .NET (assemblies de framework nao carregam assinatura Authenticode)
    "C:\Windows\Microsoft.NET\assembly\",

    # Jogos / launchers - arquivos de usuario (mods, bibliotecas, cliente)
    "C:\Users\*\curseforge\",
    "C:\Users\*\AppData\Roaming\.minecraft\",
    "C:\Users\*\AppData\Local\RedM\",

    # Steam - jogos instalados (DLLs de engine/physx/oodle sem assinatura)
    "C:\Program Files (x86)\Steam\steamapps\common\",
    "C:\Program Files\Steam\steamapps\common\",

    # Logitech G Hub extrai o instalador numa subpasta aleatoria daqui
    "C:\Windows\SystemTemp\ghub-*"
)

$whitelistArquivos = @(
    "C:\Program Files\7-Zip\7z.dll",
    "C:\Program Files\AMD\CNext\CNext\Qt6Core.dll",
    "C:\Program Files\AMD\CNext\CNext\Qt6Gui.dll",
    "C:\Program Files\AMD\CNext\CNext\Qt6Multimedia.dll",
    "C:\Program Files\AMD\CNext\CNext\Qt6Network.dll",
    "C:\Program Files\AMD\CNext\CNext\Qt6OpenGL.dll",
    "C:\Program Files\AMD\CNext\CNext\Qt6Pdf.dll",
    "C:\Program Files\AMD\CNext\CNext\Qt6Qml.dll",
    "C:\Program Files\AMD\CNext\CNext\Qt6QmlModels.dll",
    "C:\Program Files\AMD\CNext\CNext\Qt6Quick.dll",
    "C:\Program Files\AMD\CNext\CNext\Qt6QuickControls2Basic.dll",
    "C:\Program Files\AMD\CNext\CNext\Qt6QuickControls2Fusion.dll",
    "C:\Program Files\AMD\CNext\CNext\Qt6QuickControls2Imagine.dll",
    "C:\Program Files\AMD\CNext\CNext\Qt6QuickControls2Material.dll",
    "C:\Program Files\AMD\CNext\CNext\Qt6QuickControls2Universal.dll",
    "C:\Program Files\AMD\CNext\CNext\Qt6QuickDialogs2QuickImpl.dll",
    "C:\Program Files\AMD\CNext\CNext\Qt6QuickTemplates2.dll",
    "C:\Program Files\AMD\CNext\CNext\Qt6ShaderTools.dll",
    "C:\Program Files\AMD\CNext\CNext\Qt6Svg.dll",
    "C:\Program Files\AMD\CNext\CNext\Qt6WebEngineQuick.dll",
    "C:\Program Files\AMD\CNext\CNext\Qt6Widgets.dll",
    "C:\Program Files\AMD\CNext\CNext\plugins\imageformats\qjpeg.dll",
    "C:\Program Files\AMD\CNext\CNext\plugins\imageformats\qwebp.dll",
    "C:\Program Files\AMD\CNext\CNext\plugins\multimedia\ffmpegmediaplugin.dll",
    "C:\Program Files\AMD\CNext\CNext\plugins\platforms\qwindows.dll",
    "C:\Program Files\AMD\CNext\CNext\plugins\sqldrivers\qsqlite.dll",
    "C:\Program Files\AMD\CNext\CNext\qml\Qt5Compat\GraphicalEffects\qtgraphicaleffectsplugin.dll",
    "C:\Program Files\AMD\CNext\CNext\qml\QtQuick\Controls\FluentWinUI3\qtquickcontrols2fluentwinui3styleplugin.dll",
    "C:\Program Files\AMD\CNext\CNext\qml\QtQuick\NativeStyle\qtquickcontrols2nativestyleplugin.dll",
    "C:\Program Files\AMD\WVR\OpenVR\bin\win64\amf-component-ffmpeg64.dll",
    "C:\Program Files\AMD\WVR\OpenVR\bin\win64\avcodec-59.dll",
    "C:\Program Files\AMD\WVR\OpenVR\bin\win64\avdevice-59.dll",
    "C:\Program Files\AMD\WVR\OpenVR\bin\win64\avfilter-8.dll",
    "C:\Program Files\AMD\WVR\OpenVR\bin\win64\avformat-59.dll",
    "C:\Program Files\AMD\WVR\OpenVR\bin\win64\avutil-57.dll",
    "C:\Program Files\AMD\WVR\OpenVR\bin\win64\swresample-4.dll",
    "C:\Program Files\AMD\WVR\OpenVR\bin\win64\swscale-6.dll",

    "C:\Program Files\Bambu Studio\avcodec-61.dll",
"C:\Program Files\Bambu Studio\avutil-59.dll",
"C:\Program Files\Bambu Studio\freetype.dll",
"C:\Program Files\Bambu Studio\libgmp-10.dll",
"C:\Program Files\Bambu Studio\swresample-5.dll",
"C:\Program Files\Bambu Studio\swscale-8.dll",
"C:\Program Files\Bambu Studio\TKBO.dll",
"C:\Program Files\Bambu Studio\TKBRep.dll",
"C:\Program Files\Bambu Studio\TKernel.dll",
"C:\Program Files\Bambu Studio\TKG3d.dll",
"C:\Program Files\Bambu Studio\TKGeomAlgo.dll",
"C:\Program Files\Bambu Studio\TKGeomBase.dll",
"C:\Program Files\Bambu Studio\TKHLR.dll",
"C:\Program Files\Bambu Studio\TKLCAF.dll",
"C:\Program Files\Bambu Studio\TKMath.dll",
"C:\Program Files\Bambu Studio\TKMesh.dll",
"C:\Program Files\Bambu Studio\TKService.dll",
"C:\Program Files\Bambu Studio\TKShHealing.dll",
"C:\Program Files\Bambu Studio\TKSTEP.dll",
"C:\Program Files\Bambu Studio\TKSTEPAttr.dll",
"C:\Program Files\Bambu Studio\TKSTEPBase.dll",
"C:\Program Files\Bambu Studio\TKTopAlgo.dll",
"C:\Program Files\Bambu Studio\TKV3d.dll",
"C:\Program Files\Bambu Studio\TKXCAF.dll",
"C:\Program Files\Bambu Studio\TKXDESTEP.dll",
"C:\Program Files\Bambu Studio\TKXSBase.dll",
"C:\Program Files\Bambu Studio\mesa\opengl32.dll",

"C:\Program Files\Blender Foundation\Blender 5.2\python313.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\bin\python313.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\DLLs\libcrypto-3.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\DLLs\libssl-3.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\DLLs\sqlite3.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\DLLs\unicodedata.pyd",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\lib\site-packages\openvdb.cp313-win_amd64.pyd",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\lib\site-packages\Cython\Compiler\Code.cp313-win_amd64.pyd",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\lib\site-packages\Cython\Compiler\Parsing.cp313-win_amd64.pyd",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\lib\site-packages\MaterialX\PyMaterialXCore.pyd",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\lib\site-packages\numpy\linalg\_umath_linalg.cp313-win_amd64.pyd",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\lib\site-packages\numpy\random\mtrand.cp313-win_amd64.pyd",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\lib\site-packages\numpy\random\_generator.cp313-win_amd64.pyd",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\lib\site-packages\numpy\_core\_multiarray_umath.cp313-win_amd64.pyd",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\lib\site-packages\numpy\_core\_simd.cp313-win_amd64.pyd",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\lib\site-packages\OpenImageIO\OpenImageIO.pyd",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\lib\site-packages\pxr\Gf\_gf.pyd",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\lib\site-packages\pxr\Pcp\_pcp.pyd",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\lib\site-packages\pxr\Sdf\_sdf.pyd",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\lib\site-packages\pxr\Sdr\_sdr.pyd",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\lib\site-packages\pxr\Tf\_tf.pyd",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\lib\site-packages\pxr\Usd\_usd.pyd",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\lib\site-packages\pxr\UsdGeom\_usdGeom.pyd",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\lib\site-packages\pxr\UsdLux\_usdLux.pyd",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\lib\site-packages\pxr\UsdPhysics\_usdPhysics.pyd",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\lib\site-packages\pxr\UsdShade\_usdShade.pyd",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\lib\site-packages\pxr\UsdSkel\_usdSkel.pyd",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\lib\site-packages\pxr\UsdVol\_usdVol.pyd",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\lib\site-packages\pxr\Vt\_vt.pyd",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\lib\site-packages\PyOpenColorIO\PyOpenColorIO.pyd",
"C:\Program Files\Blender Foundation\Blender 5.2\5.2\python\lib\site-packages\zstandard\backend_c.cp313-win_amd64.pyd",

"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\aom.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\avfilter-11.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\avformat-62.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\avutil-60.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\ceres.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\draco.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\embree4.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\epoxy-0.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\gmp-10.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\hiprt0200564.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\MaterialXCore.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\MaterialXGenShader.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\MaterialXRender.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\OpenAL32.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\opencolorio_2_5.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\OpenEXR.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\OpenImageDenoise_device_cpu.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\OpenImageDenoise_device_cuda.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\OpenImageDenoise_device_hip.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\OpenImageDenoise_device_sycl.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\openimageio.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\openimageio_util.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\openvdb.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\oslcomp.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\SDL3.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\shaderc_shared.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\sndfile.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\swscale-9.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\sycl8.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\ur_adapter_level_zero.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\ur_adapter_level_zero_v2.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\ur_loader.dll",
"C:\Program Files\Blender Foundation\Blender 5.2\blender.shared\vulkan-1.dll",

"C:\Program Files (x86)\DELUX Gaming Driver\DuiLib.dll",
"C:\Program Files (x86)\DELUX Gaming Driver\DuiLib_d.dll",

"C:\Program Files (x86)\RivaTuner Statistics Server\Codec\rtvcvfw32.dll",
"C:\Program Files (x86)\RivaTuner Statistics Server\Codec\rtvcvfw64.dll",
"C:\Program Files (x86)\RivaTuner Statistics Server\Plugins\amf-core-windesktop32.dll",
"C:\Program Files (x86)\RivaTuner Statistics Server\Plugins\Client\OverlayEditor.dll",
"C:\Program Files (x86)\RivaTuner Statistics Server\Plugins\Client\LHMDataProvider\LibreHardwareMonitorLib.dll",
"C:\Program Files (x86)\RivaTuner Statistics Server\Plugins64\amf-core-windesktop64.dll",
"C:\Program Files (x86)\RivaTuner Statistics Server\SDK\Include\LHM\LibreHardwareMonitorLib.dll",

"C:\Users\$env:USERNAME\AppData\Local\Programs\Lively Wallpaper\Lively.dll",
"C:\Users\$env:USERNAME\AppData\Local\Programs\Lively Wallpaper\MathNet.Numerics.dll",
"C:\Users\$env:USERNAME\AppData\Local\Programs\Lively Wallpaper\NLog.dll",
"C:\Users\$env:USERNAME\AppData\Local\Programs\Lively Wallpaper\Octokit.dll",
"C:\Users\$env:USERNAME\AppData\Local\Programs\Lively Wallpaper\Plugins\UI\Lively.UI.WinUI.dll",
"C:\Users\$env:USERNAME\AppData\Local\Programs\Lively Wallpaper\Plugins\UI\MathNet.Numerics.dll",
"C:\Users\$env:USERNAME\AppData\Local\Programs\Lively Wallpaper\Plugins\UI\NLog.dll",
"C:\Users\$env:USERNAME\AppData\Local\Programs\Lively Wallpaper\Plugins\UI\Octokit.dll",
"C:\Users\$env:USERNAME\AppData\Local\Programs\Lively Wallpaper\Plugins\WebView2\MathNet.Numerics.dll",
"C:\Users\$env:USERNAME\AppData\Local\Programs\Lively Wallpaper\Plugins\WebView2\Octokit.dll",

"C:\Users\$env:USERNAME\AppData\Roaming\uTorrent Web\avcodec-58.dll",
"C:\Users\$env:USERNAME\AppData\Roaming\uTorrent Web\avformat-58.dll",
"C:\Users\$env:USERNAME\AppData\Roaming\uTorrent Web\avutil-56.dll",
"C:\Users\$env:USERNAME\AppData\Roaming\uTorrent Web\libcrypto-1_1.dll",
"C:\Users\$env:USERNAME\AppData\Roaming\uTorrent Web\libssl-1_1.dll",
"C:\Users\$env:USERNAME\AppData\Roaming\uTorrent Web\swscale-5.dll"

    "C:\Users\$env:USERNAME\AppData\Local\FiveM\FiveM.app\v8-9.3.345.16.dll",
    "C:\Users\$env:USERNAME\AppData\Local\FiveM\FiveM.app\bin\avutil-56.dll",
    "C:\Users\$env:USERNAME\AppData\Local\FiveM\FiveM.app\bin\chrome_elf.dll",
    "C:\Users\$env:USERNAME\AppData\Local\FiveM\FiveM.app\bin\d3d_rendering.dll",
    "C:\Users\$env:USERNAME\AppData\Local\FiveM\FiveM.app\bin\GFSDK_ShadowLib.dll",
    "C:\Users\$env:USERNAME\AppData\Local\FiveM\FiveM.app\bin\icui18n.dll",
    "C:\Users\$env:USERNAME\AppData\Local\FiveM\FiveM.app\bin\icuuc.dll",
    "C:\Users\$env:USERNAME\AppData\Local\FiveM\FiveM.app\bin\libGLESv2.dll",
    "C:\Users\$env:USERNAME\AppData\Local\FiveM\FiveM.app\bin\mono-2.0-sgen.dll",
    "C:\Users\$env:USERNAME\AppData\Local\FiveM\FiveM.app\bin\sdk_rendering.dll",
    "C:\Users\$env:USERNAME\AppData\Local\FiveM\FiveM.app\bin\SwiftShaderD3D9_64.dll",
    "C:\Users\$env:USERNAME\AppData\Local\FiveM\FiveM.app\bin\vk_swiftshader.dll",
    "C:\Users\$env:USERNAME\AppData\Local\FiveM\FiveM.app\bin\vulkan-1.dll",
    "C:\Users\$env:USERNAME\AppData\Local\FiveM\FiveM.app\citizen\clr2\lib\mono\4.5\CitizenFX.Core.dll",
    "C:\Users\$env:USERNAME\AppData\Local\FiveM\FiveM.app\citizen\clr2\lib\mono\4.5\Mono.CSharp.dll",
    "C:\Users\$env:USERNAME\AppData\Local\FiveM\FiveM.app\citizen\clr2\lib\mono\4.5\mscorlib.dll",
    "C:\Users\$env:USERNAME\AppData\Local\FiveM\FiveM.app\citizen\clr2\lib\mono\4.5\System.Core.dll",
    "C:\Users\$env:USERNAME\AppData\Local\FiveM\FiveM.app\citizen\clr2\lib\mono\4.5\System.dll",
    "C:\Users\$env:USERNAME\AppData\Local\FiveM\FiveM.app\citizen\clr2\lib\mono\4.5\System.Xml.dll",
    "C:\Users\$env:USERNAME\AppData\Local\FiveM\FiveM.app\citizen\clr2\lib\mono\4.5\ref\CitizenFX.Core.Client.dll",
    "C:\Users\$env:USERNAME\AppData\Local\FiveM\FiveM.app\citizen\clr2\lib\mono\4.5\v2\CitizenFX.FiveM.NativeImpl.dll",
    "C:\Users\$env:USERNAME\AppData\Local\FiveM\FiveM.app\citizen\clr2\lib\mono\4.5\v2\Native\CitizenFX.FiveM.Native.dll",
    "C:\Users\$env:USERNAME\AppData\Local\FiveM\FiveM.app\citizen\clr2\lib\mono\4.5\v2\Native\ref\CitizenFX.FiveM.Native.dll",

    "C:\Users\$env:USERNAME\AppData\Local\Programs\@opencode-aidesktop\dxcompiler.dll",
    "C:\Users\$env:USERNAME\AppData\Local\Programs\@opencode-aidesktop\ffmpeg.dll",
    "C:\Users\$env:USERNAME\AppData\Local\Programs\@opencode-aidesktop\libGLESv2.dll",
    "C:\Users\$env:USERNAME\AppData\Local\Programs\@opencode-aidesktop\vk_swiftshader.dll",
    "C:\Users\$env:USERNAME\AppData\Local\Programs\@opencode-aidesktop\vulkan-1.dll",
    "C:\Users\$env:USERNAME\AppData\Local\Programs\@opencode-aidesktop\resources\app.asar.unpacked\node_modules\@parcel\watcher-win32-x64\watcher.node",

    "C:\Users\$env:USERNAME\AppData\Local\Programs\feather\dxcompiler.dll",
    "C:\Users\$env:USERNAME\AppData\Local\Programs\feather\ffmpeg.dll",
    "C:\Users\$env:USERNAME\AppData\Local\Programs\feather\libGLESv2.dll",
    "C:\Users\$env:USERNAME\AppData\Local\Programs\feather\vk_swiftshader.dll",
    "C:\Users\$env:USERNAME\AppData\Local\Programs\feather\vulkan-1.dll",

    "C:\Users\$env:USERNAME\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\cv2\opencv_videoio_ffmpeg500_64.dll",
    "C:\Users\$env:USERNAME\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\numpy\random\mtrand.cp314-win_amd64.pyd",
    "C:\Users\$env:USERNAME\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\numpy\random\_generator.cp314-win_amd64.pyd",
    "C:\Users\$env:USERNAME\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\numpy\_core\_multiarray_umath.cp314-win_amd64.pyd",
    "C:\Users\$env:USERNAME\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\numpy\_core\_simd.cp314-win_amd64.pyd",
    "C:\Users\$env:USERNAME\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\numpy.libs\libscipy_openblas64_-ed4f167a5330424524f45258e7ca2c8d.dll",
    "C:\Users\$env:USERNAME\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\PIL\_avif.cp314-win_amd64.pyd",
    "C:\Users\$env:USERNAME\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\PIL\_imaging.cp314-win_amd64.pyd",
    "C:\Users\$env:USERNAME\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\PIL\_imagingft.cp314-win_amd64.pyd",
    "C:\Users\$env:USERNAME\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\pymupdf\mupdfcpp64.dll",
    "C:\Users\$env:USERNAME\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\pymupdf\_mupdf.pyd",

    "C:\Users\$env:USERNAME\AppData\Roaming\ModrinthApp\meta\natives\1.21.4-0.19.5\OpenAL.dll",

    "C:\Users\$env:USERNAME\Downloads\die_win64_portable_3.21_x64\die\libcrypto-1_1-x64.dll",
    "C:\Users\$env:USERNAME\Downloads\die_win64_portable_3.21_x64\die\libssl-1_1-x64.dll"
    "C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2636.100.0_x64__cv1g1gvanyjgm\PhoneNumbers.dll"
    "C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2636.100.0_x64__cv1g1gvanyjgm\WhatsApp.Core.dll"
    "C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2636.100.0_x64__cv1g1gvanyjgm\WhatsApp.Design.dll"
    "C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2636.100.0_x64__cv1g1gvanyjgm\WhatsApp.Protobuf.dll"
    "C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2636.100.0_x64__cv1g1gvanyjgm\WhatsApp.Root.dll"
    "C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2636.100.0_x64__cv1g1gvanyjgm\WhatsApp.VoIP.dll"
    "C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2636.100.0_x64__cv1g1gvanyjgm\WhatsAppNative.dll"
    "C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2636.100.0_x64__cv1g1gvanyjgm\WhatsAppNative.Voip.dll"
    "C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2636.100.0_x64__cv1g1gvanyjgm\WhatsAppNativeProjection.dll"
    "C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2636.100.0_x64__cv1g1gvanyjgm\WhatsAppRust.dll"
    "C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2636.100.0_x64__cv1g1gvanyjgm\WinRTAdapter.dll"
    "C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2636.100.0_x64__cv1g1gvanyjgm\zxing.dll"

    "C:\Program Files\WindowsApps\Microsoft.549981C3F5F10_1.1911.21713.0_x64__8wekyb3d8bbwe\Cortana.dll"
    "C:\Program Files\WindowsApps\Microsoft.549981C3F5F10_1.1911.21713.0_x64__8wekyb3d8bbwe\e_sqlite3.dll"
    "C:\Program Files\WindowsApps\Microsoft.549981C3F5F10_1.1911.21713.0_x64__8wekyb3d8bbwe\Microsoft.IoT.Cortana.dll"

    "C:\Program Files\WindowsApps\Microsoft.BingWeather_4.25.20211.0_x64__8wekyb3d8bbwe\Microsoft.Msn.Weather.dll"
    "C:\Program Files\WindowsApps\Microsoft.BingWeather_4.25.20211.0_x64__8wekyb3d8bbwe\sqlite3.dll"

    "C:\Program Files\WindowsApps\Microsoft.GetHelp_10.1706.13331.0_x64__8wekyb3d8bbwe\GetHelp.dll"
    "C:\Program Files\WindowsApps\Microsoft.GetHelp_10.1706.13331.0_x64__8wekyb3d8bbwe\Microsoft.Support.SDK.dll"

    "C:\Program Files\WindowsApps\Microsoft.Getstarted_8.2.22942.0_x64__8wekyb3d8bbwe\RuntimeConfiguration.dll"
    "C:\Program Files\WindowsApps\Microsoft.Getstarted_8.2.22942.0_x64__8wekyb3d8bbwe\WhatsNew.Store.dll"
    "C:\Program Files\WindowsApps\Microsoft.Getstarted_8.2.22942.0_x64__8wekyb3d8bbwe\fmui\Newtonsoft.Json.dll"

    "C:\Program Files\WindowsApps\Microsoft.Microsoft3DViewer_6.1908.2042.0_x64__8wekyb3d8bbwe\3DViewer.dll"
    "C:\Program Files\WindowsApps\Microsoft.Microsoft3DViewer_6.1908.2042.0_x64__8wekyb3d8bbwe\Mira.Core.Engine.UWP.dll"
    "C:\Program Files\WindowsApps\Microsoft.Microsoft3DViewer_6.1908.2042.0_x64__8wekyb3d8bbwe\OnlineMediaComponent.dll"
    "C:\Program Files\WindowsApps\Microsoft.Microsoft3DViewer_6.1908.2042.0_x64__8wekyb3d8bbwe\RuntimeConfiguration.dll"
    "C:\Program Files\WindowsApps\Microsoft.Microsoft3DViewer_6.1908.2042.0_x64__8wekyb3d8bbwe\TrackingDLL.dll"

    "C:\Program Files\WindowsApps\Microsoft.MicrosoftOfficeHub_18.1903.1152.0_x64__8wekyb3d8bbwe\Newtonsoft.Json.dll"
    "C:\Program Files\WindowsApps\Microsoft.MicrosoftOfficeHub_18.1903.1152.0_x64__8wekyb3d8bbwe\Windows.winmd"
    "C:\Program Files\WindowsApps\Microsoft.MicrosoftOfficeHub_18.1903.1152.0_x64__8wekyb3d8bbwe\WinMetadata\Windows.winmd"

    "C:\Program Files\WindowsApps\Microsoft.MicrosoftSolitaireCollection_4.4.8204.0_x64__8wekyb3d8bbwe\Microsoft.Advertising.dll"
    "C:\Program Files\WindowsApps\Microsoft.MicrosoftSolitaireCollection_4.4.8204.0_x64__8wekyb3d8bbwe\Microsoft.MicrosoftSolitaireCollection.dll"

    "C:\Program Files\WindowsApps\Microsoft.MicrosoftStickyNotes_3.6.73.0_x64__8wekyb3d8bbwe\e_sqlite3.dll"
    "C:\Program Files\WindowsApps\Microsoft.MicrosoftStickyNotes_3.6.73.0_x64__8wekyb3d8bbwe\RuntimeConfiguration.dll"

    "C:\Program Files\WindowsApps\Microsoft.MSPaint_6.1907.29027.0_x64__8wekyb3d8bbwe\FreshPaint.Model.CX.dll"
    "C:\Program Files\WindowsApps\Microsoft.MSPaint_6.1907.29027.0_x64__8wekyb3d8bbwe\OnlineMediaComponent.dll"
    "C:\Program Files\WindowsApps\Microsoft.MSPaint_6.1907.29027.0_x64__8wekyb3d8bbwe\PaintStudio.ViewElements.dll"
    "C:\Program Files\WindowsApps\Microsoft.MSPaint_6.1907.29027.0_x64__8wekyb3d8bbwe\PaintStudio.ViewModel.dll"
    "C:\Program Files\WindowsApps\Microsoft.MSPaint_6.1907.29027.0_x64__8wekyb3d8bbwe\RuntimeConfiguration.dll"
    "C:\Program Files\WindowsApps\Microsoft.MSPaint_6.1907.29027.0_x64__8wekyb3d8bbwe\ServiceProvider.dll"
    "C:\Program Files\WindowsApps\Microsoft.MSPaint_6.1907.29027.0_x64__8wekyb3d8bbwe\TelemetryUWP.dll"
    "C:\Program Files\WindowsApps\Microsoft.MSPaint_6.1907.29027.0_x64__8wekyb3d8bbwe\Utils.CX.dll"

    "C:\Program Files\WindowsApps\Microsoft.Office.OneNote_16001.12026.20112.0_x64__8wekyb3d8bbwe\react.uwp.dll"

    "C:\Program Files\WindowsApps\Microsoft.People_10.1902.633.0_x64__8wekyb3d8bbwe\Microsoft.People.NativeComponents.dll"
    "C:\Program Files\WindowsApps\Microsoft.People_10.1902.633.0_x64__8wekyb3d8bbwe\Microsoft.People.Relevance.dll"
    "C:\Program Files\WindowsApps\Microsoft.People_10.1902.633.0_x64__8wekyb3d8bbwe\Microsoft.People.Relevance.QueryClient.dll"
    "C:\Program Files\WindowsApps\Microsoft.People_10.1902.633.0_x64__8wekyb3d8bbwe\People.BackgroundTasks.dll"
    "C:\Program Files\WindowsApps\Microsoft.People_10.1902.633.0_x64__8wekyb3d8bbwe\PeopleApp.dll"

    "C:\Program Files\WindowsApps\Microsoft.Services.Store.Engagement_10.0.18101.0_x64__8wekyb3d8bbwe\Microsoft.Services.Store.Engagement.dll"
    "C:\Program Files\WindowsApps\Microsoft.Services.Store.Engagement_10.0.18101.0_x86__8wekyb3d8bbwe\Microsoft.Services.Store.Engagement.dll"

    "C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.53.77.0_x64__kzf8qxf38zg5c\LibWrapper.dll"
    "C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.53.77.0_x64__kzf8qxf38zg5c\rtmcodecs.dll"
    "C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.53.77.0_x64__kzf8qxf38zg5c\RtmMediaManager.dll"
    "C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.53.77.0_x64__kzf8qxf38zg5c\RtmMvrUap.dll"
    "C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.53.77.0_x64__kzf8qxf38zg5c\rtmpal.dll"
    "C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.53.77.0_x64__kzf8qxf38zg5c\rtmpltfm.dll"
    "C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.53.77.0_x64__kzf8qxf38zg5c\RuntimeConfiguration.dll"
    "C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.53.77.0_x64__kzf8qxf38zg5c\SkypeApp.dll"
    "C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.53.77.0_x64__kzf8qxf38zg5c\skypert.dll"
    "C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.53.77.0_x64__kzf8qxf38zg5c\TxNdi.dll"
    "C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.53.77.0_x64__kzf8qxf38zg5c\SkypeBridge\Newtonsoft.Json.dll"

    "C:\Program Files\WindowsApps\Microsoft.StorePurchaseApp_11811.1001.18.0_x64__8wekyb3d8bbwe\StoreExperienceHost.dll"
    "C:\Program Files\WindowsApps\Microsoft.Wallet_2.4.18324.0_x64__8wekyb3d8bbwe\Microsoft.Wallet.dll"

    "C:\Program Files\WindowsApps\Microsoft.WebMediaExtensions_1.0.20875.0_x64__8wekyb3d8bbwe\avcodec-58_ms.dll"
    "C:\Program Files\WindowsApps\Microsoft.WebMediaExtensions_1.0.20875.0_x64__8wekyb3d8bbwe\swscale-5_ms.dll"

    "C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2019.19071.12548.0_x64__8wekyb3d8bbwe\AppCore.Windows.dll"
    "C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2019.19071.12548.0_x64__8wekyb3d8bbwe\Edit.AppTk.SceneGraph.dll"
    "C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2019.19071.12548.0_x64__8wekyb3d8bbwe\ipp_uwp.dll"
    "C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2019.19071.12548.0_x64__8wekyb3d8bbwe\Lumia.AppTk.SceneGraph.dll"
    "C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2019.19071.12548.0_x64__8wekyb3d8bbwe\Lumia.Imaging.dll"
    "C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2019.19071.12548.0_x64__8wekyb3d8bbwe\Microsoft.Membership.MeControl.dll"
    "C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2019.19071.12548.0_x64__8wekyb3d8bbwe\Microsoft.Photos.dll"
    "C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2019.19071.12548.0_x64__8wekyb3d8bbwe\Microsoft.RichMedia.Ink.Controls.dll"
    "C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2019.19071.12548.0_x64__8wekyb3d8bbwe\Microsoft.RichMedia.Ink.dll"
    "C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2019.19071.12548.0_x64__8wekyb3d8bbwe\PhotosApp.Windows.dll"
    "C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2019.19071.12548.0_x64__8wekyb3d8bbwe\RuntimeConfiguration.dll"

    "C:\Program Files\WindowsApps\Microsoft.WindowsAlarms_10.1906.2182.0_x64__8wekyb3d8bbwe\TimeAppService.dll"
    "C:\Program Files\WindowsApps\Microsoft.WindowsAlarms_10.1906.2182.0_x64__8wekyb3d8bbwe\TimeBackground.dll"
    "C:\Program Files\WindowsApps\Microsoft.WindowsAlarms_10.1906.2182.0_x64__8wekyb3d8bbwe\TimeControls.dll"

    "C:\Program Files\WindowsApps\Microsoft.WindowsCamera_2018.826.98.0_x64__8wekyb3d8bbwe\CameraApp.Native.dll"
    "C:\Program Files\WindowsApps\Microsoft.WindowsCamera_2018.826.98.0_x64__8wekyb3d8bbwe\RuntimeConfiguration.dll"
    "C:\Program Files\WindowsApps\Microsoft.WindowsCamera_2018.826.98.0_x64__8wekyb3d8bbwe\WindowsCamera.dll"

    "C:\Program Files\WindowsApps\Microsoft.WindowsFeedbackHub_1.1907.3152.0_x64__8wekyb3d8bbwe\Helper.dll"
    "C:\Program Files\WindowsApps\Microsoft.WindowsFeedbackHub_1.1907.3152.0_x64__8wekyb3d8bbwe\PilotshubApp.dll"
    "C:\Program Files\WindowsApps\Microsoft.WindowsFeedbackHub_1.1907.3152.0_x64__8wekyb3d8bbwe\RuntimeConfiguration.dll"

    "C:\Program Files\WindowsApps\Microsoft.WindowsMaps_5.1906.1972.0_x64__8wekyb3d8bbwe\Maps.dll"

    "C:\Program Files\WindowsApps\Microsoft.WindowsSoundRecorder_10.1906.1972.0_x64__8wekyb3d8bbwe\Inbox.Shared.dll"

    "C:\Program Files\WindowsApps\Microsoft.WindowsStore_22608.1401.3.0_x64__8wekyb3d8bbwe\e_sqlite3.dll"

    "C:\Program Files\WindowsApps\Microsoft.Xbox.TCUI_1.23.28002.0_x64__8wekyb3d8bbwe\TCUI-App.dll"

    "C:\Program Files\WindowsApps\Microsoft.XboxApp_48.49.31001.0_x64__8wekyb3d8bbwe\Microsoft.Xbox.SmartGlass.dll"
    "C:\Program Files\WindowsApps\Microsoft.XboxApp_48.49.31001.0_x64__8wekyb3d8bbwe\PartyChat.dll"
    "C:\Program Files\WindowsApps\Microsoft.XboxApp_48.49.31001.0_x64__8wekyb3d8bbwe\XboxNano.dll"

    "C:\Program Files\WindowsApps\Microsoft.XboxGameOverlay_1.46.11001.0_x64__8wekyb3d8bbwe\GameBarTasks.dll"

    "C:\Program Files\WindowsApps\Microsoft.XboxIdentityProvider_12.50.6001.0_x64__8wekyb3d8bbwe\XboxIdp.dll"

    "C:\Program Files\WindowsApps\Microsoft.ZuneMusic_10.19071.19011.0_x64__8wekyb3d8bbwe\EntCommon.dll"
    "C:\Program Files\WindowsApps\Microsoft.ZuneMusic_10.19071.19011.0_x64__8wekyb3d8bbwe\EntPlat.dll"
    "C:\Program Files\WindowsApps\Microsoft.ZuneMusic_10.19071.19011.0_x64__8wekyb3d8bbwe\EntSyncFx.dll"

    "C:\Program Files\WindowsApps\Microsoft.ZuneVideo_10.19071.19011.0_x64__8wekyb3d8bbwe\EntCommon.dll"
    "C:\Program Files\WindowsApps\Microsoft.ZuneVideo_10.19071.19011.0_x64__8wekyb3d8bbwe\EntPlat.dll"
    "C:\Program Files\WindowsApps\Microsoft.ZuneVideo_10.19071.19011.0_x64__8wekyb3d8bbwe\EntSyncFx.dll"

    "C:\Program Files (x86)\Common Files\Microsoft Shared\VC\msdia80.dll"
    "C:\Program Files (x86)\Common Files\Microsoft Shared\VC\amd64\msdia80.dll"

    "C:\Riot Games\Riot Client\RiotClientElectron\ffmpeg.dll"
    "C:\Riot Games\Riot Client\RiotClientElectron\libGLESv2.dll"
    "C:\Riot Games\Riot Client\RiotClientElectron\vk_swiftshader.dll"
    "C:\Riot Games\Riot Client\RiotClientElectron\vulkan-1.dll"

    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\IManagementEngine\AppHost\app.pyd"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\IManagementEngine\Lib\site-packages\av.libs\avcodec-62-984de33114b7fa384296817dec999c9d.dll"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\IManagementEngine\Lib\site-packages\av.libs\avfilter-11-aef80fc767dc77e0319469b5bdcdf998.dll"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\IManagementEngine\Lib\site-packages\av.libs\avformat-62-b6d6bb16ff0b7753371e2d0b285c9dc0.dll"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\IManagementEngine\Lib\site-packages\av.libs\avutil-60-cc1777f859dcfd98b8019bdf459e774e.dll"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\IManagementEngine\Lib\site-packages\av.libs\libdav1d-959ebc1340f7dfcbcf8e299a26281738.dll"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\IManagementEngine\Lib\site-packages\av.libs\libiconv-2-6ce5f4ff92ada49d6f23a8e413455502.dll"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\IManagementEngine\Lib\site-packages\av.libs\libstdc++-6-2d5c346d47ad531ef9f5185db0e8cef3.dll"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\IManagementEngine\Lib\site-packages\av.libs\libSvtAv1Enc-c4dd99c98ddcdb013e820dbd68a30e26.dll"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\IManagementEngine\Lib\site-packages\av.libs\libvpx-1-d869f8b2cb42d58b35545ffbfb0f7509.dll"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\IManagementEngine\Lib\site-packages\av.libs\libwebp-4bf4e57964c7a01c09ce39470d6b67ca.dll"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\IManagementEngine\Lib\site-packages\av.libs\libx264-165-f3a909470ddc2d85ed21eda3d0fb7954.dll"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\IManagementEngine\Lib\site-packages\av.libs\libx265-efe48a158520a59ef99c0a0b3eb835ae.dll"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\IManagementEngine\Lib\site-packages\av.libs\swscale-9-0c9886c118598c54e159ef2267ff99f3.dll"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\IManagementEngine\Lib\site-packages\cryptography\hazmat\bindings\_rust.pyd"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\IManagementEngine\Lib\site-packages\numpy\random\mtrand.cp312-win_amd64.pyd"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\IManagementEngine\Lib\site-packages\numpy\random\_generator.cp312-win_amd64.pyd"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\IManagementEngine\Lib\site-packages\numpy\_core\_multiarray_umath.cp312-win_amd64.pyd"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\IManagementEngine\Lib\site-packages\numpy\_core\_simd.cp312-win_amd64.pyd"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\IManagementEngine\Lib\site-packages\numpy.libs\libscipy_openblas64_-ed4f167a5330424524f45258e7ca2c8d.dll"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\IManagementEngine\Lib\site-packages\PIL\_avif.cp312-win_amd64.pyd"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\IManagementEngine\Lib\site-packages\PIL\_imaging.cp312-win_amd64.pyd"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\IManagementEngine\Lib\site-packages\PIL\_imagingft.cp312-win_amd64.pyd"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\IManagementEngine\Lib\site-packages\pythonwin\scintilla.dll"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\IManagementEngine\Lib\site-packages\pythonwin\win32ui.pyd"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\IManagementEngine\Lib\site-packages\pywin32_system32\pythoncom312.dll"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\IManagementEngine\Lib\site-packages\win32comext\shell\shell.pyd"

    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\NtProfileIndex\AppHost\app.pyd"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\NtProfileIndex\Lib\site-packages\Crypto\PublicKey\_ec_ws.pyd"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\NtProfileIndex\Lib\site-packages\PIL\_imaging.cp312-win_amd64.pyd"
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\NtProfileIndex\Lib\site-packages\pywin32_system32\pythoncom312.dll"

    "C:\Users\$env:USERNAME\AppData\Local\Temp\.bun-74065123-3cba9b8dc4fa4e45.node"
    "C:\Users\$env:USERNAME\AppData\Local\Temp\nsh96E6.tmp\nsDui.dll"
    "C:\Users\$env:USERNAME\AppData\Local\Temp\nsm961B.tmp\nsDui.dll"
    "C:\Users\$env:USERNAME\AppData\Local\Temp\nsu3187.tmp\7z-out\dxcompiler.dll"
    "C:\Users\$env:USERNAME\AppData\Local\Temp\nsu3187.tmp\7z-out\ffmpeg.dll"
    "C:\Users\$env:USERNAME\AppData\Local\Temp\nsu3187.tmp\7z-out\libGLESv2.dll"
    "C:\Users\$env:USERNAME\AppData\Local\Temp\nsu3187.tmp\7z-out\vk_swiftshader.dll"
    "C:\Users\$env:USERNAME\AppData\Local\Temp\nsu3187.tmp\7z-out\vulkan-1.dll"
    "C:\Users\$env:USERNAME\AppData\Local\Temp\nsz4ECC.tmp\nsDui.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\EventViewer\4b1723dacb9a0717b501f4bddb8ab10c\EventViewer.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\Microsoft.A26c32abb#\9ca9453e2e9618c5bbaa9eabb133e809\Microsoft.ApplicationId.RuleWizard.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\Microsoft.I0cd65b90#\e6a56f9eb141e9e042357dfa569638c4\Microsoft.Isam.Esent.Interop.Wsa.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\Microsoft.Ic1a2041b#\0b61d7cae239bab2b62926922a9e1883\Microsoft.Isam.Esent.Interop.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\Microsoft.Mf49f6405#\ba60de152b9c7bf3fbc59f257d33ad8e\Microsoft.Management.Infrastructure.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\Microsoft.Mff1be75b#\344a431903326c6f7ee4f377d5498bde\Microsoft.ManagementConsole.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\Microsoft.P047767ce#\946aec639a90d4af6d0ae3ecb95bf142\Microsoft.PowerShell.Core.Activities.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\Microsoft.P08ac43d5#\9d205b9a23c7c5f2ae23cd5301288384\Microsoft.PowerShell.Utility.Activities.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\Microsoft.P655586bb#\c969d113b555f6449a0b52608ab6deaa\Microsoft.PowerShell.Activities.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\Microsoft.P9de5a786#\3ce3fa979372852548634665d24e9f5f\Microsoft.PowerShell.Management.Activities.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\Microsoft.Pefb7a36b#\eea2822edab3dcdecaf8d0429833e795\Microsoft.PowerShell.Workflow.ServiceCore.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\Microsoft.S0f8e494c#\56bcf4072d4db977d09a2282eed07d8c\Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\Microsoft.Sa56e3556#\a8d25e07b0ef188b8edbc157446689b3\Microsoft.Security.ApplicationId.Wizards.AutomaticRuleGenerationWizard.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\MMCEx\660c2942d2c628a0c992196bf5c56c6e\MMCEx.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\Presentatio5ae0f00f#\7d47f41ef185df9a3b0798a121681f4f\PresentationFramework.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\Presentatioaec034ca#\6309cd0760423837bf013cc787a7dd37\PresentationFramework.Aero2.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\PresentationCore\68533ae883db815ac7c1aee70431a789\PresentationCore.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\SrpUxSnapIn\9e7ae1d0a9b2aa6e6d132a59c35b8da1\SrpUxSnapIn.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\System\3057ae3d6dc8bc273d72a38629839e47\System.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\System.Configuration\9f8ed0b141faededfe3c3b76984b3d76\System.Configuration.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\System.Core\45d2bf3c3b7fae8e71b2c79b73827933\System.Core.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\System.Net.Http\966e2ee625634b40adab4c94dac976ed\System.Net.Http.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\System.Runteb92aa12#\df850e0f26ff5650eb255cbeef4def5a\System.Runtime.Serialization.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\System.Xaml\1093f16025d3b55aeebf6b11ea8917ea\System.Xaml.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\System.Xml\930c81c283c1ffe68f9d7c4fea8cfa9e\System.Xml.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\WindowsBase\3cedf19effddbdea9e35e3342bec291f\WindowsBase.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\EventViewer\0c430115e0450ddd111471f4aa5ce78a\EventViewer.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.A26c32abb#\73d56688abd46ddaa85452903953a119\Microsoft.ApplicationId.RuleWizard.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.C26a36d2b#\7a04c8cebdce531081d21e9a2892c23f\Microsoft.CertificateServices.PKIClient.Cmdlets.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.C99be4d25#\c3268fe5122343290b74291fcbb21c6d\Microsoft.ConfigCI.Commands.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.G91a07420#\78df75578d9a9f2b1fa0d878830d79d7\Microsoft.GroupPolicy.Reporting.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.Ga41585c2#\989701d643a2301e52c390ff8f488fa7\Microsoft.GroupPolicy.AdmTmplEditor.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.I0cd65b90#\4cb6c13aa3de253bc290f762aec326cf\Microsoft.Isam.Esent.Interop.Wsa.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.Ic1a2041b#\8bf71741f200747083e718383b8d783c\Microsoft.Isam.Esent.Interop.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.M870d558a#\9fe64f288d8a8628ba35ac474bd85577\Microsoft.Management.Infrastructure.Native.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.Mf49f6405#\e5951896725b6e7f7be9e8196595d656\Microsoft.Management.Infrastructure.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.Mf5ac9168#\3c6d4f91134040106ab9ad0c0c47e667\Microsoft.Management.Infrastructure.CimCmdlets.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.Mff1be75b#\9486356ba108f827a66b17a1486bffae\Microsoft.ManagementConsole.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.P047767ce#\84833da952204202b364e1633ea46914\Microsoft.PowerShell.Core.Activities.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.P08ac43d5#\528d9de827311cf50591bef9a165ed1a\Microsoft.PowerShell.Utility.Activities.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.P0e11b656#\a438b45e92aee6454971724d4e53a18d\Microsoft.PowerShell.GPowerShell.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.P10d01611#\72c81f34ba6bf5fc5c38a61adac47a21\Microsoft.PowerShell.Editor.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.P39041136#\42bdb4f5a6cd014f3b45ad71c5dddb75\Microsoft.PowerShell.ScheduledJob.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.P521220ea#\152aa9a6d23f8ee37af16554ddecb17d\Microsoft.PowerShell.Commands.Utility.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.P655586bb#\2cf0fb326c9a582cfccb3d87b4e01804\Microsoft.PowerShell.Activities.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.P9de5a786#\f1b350ea9aafd6b16530ac869def4e22\Microsoft.PowerShell.Management.Activities.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.Pae3498d9#\ed4f56d8c182a41e0100329317a898db\Microsoft.PowerShell.Commands.Management.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.Pb378ec07#\6a82dd1e67fbc1f82d208c19dd09b800\Microsoft.PowerShell.ConsoleHost.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.Pcd26229b#\11fbbefd4f2bb9cafbd15c01052d0a72\Microsoft.PowerShell.GraphicalHost.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.Pefb7a36b#\6aa079fd8965033ee603cccb15cf5bb0\Microsoft.PowerShell.Workflow.ServiceCore.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.S0f8e494c#\eede56db2ef5708502a7e7cf84a9ed7b\Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.Sa56e3556#\e9333bac1820071f11f74250a53a165a\Microsoft.Security.ApplicationId.Wizards.AutomaticRuleGenerationWizard.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.V9921e851#\bb8a646f0236a95f15e0f95ec2835f6e\Microsoft.VisualBasic.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.W2d29a719#\8d8a1eef1b70a5f762798dffbfe7f70d\Microsoft.Windows.DSC.CoreConfProviders.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.We0722664#\7705edc5d36e073600e9d8f5ae4e35e5\Microsoft.WSMan.Management.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.We9f24001#\9b02f1d8b28a57533f7d6ecd92ea5c72\Microsoft.WSMan.Management.Activities.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\MIGUIControls\f273550137b438f3304fb677d16a341f\MIGUIControls.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\MMCEx\704dae1995b4cf3e492a3b027295a34c\MMCEx.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Presentatio5ae0f00f#\a8f4a1ebc2e524586867f63bef48993d\PresentationFramework.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Presentatioaec034ca#\5c51541683ca82cb007c73fd089c6eaf\PresentationFramework.Aero2.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\PresentationCore\f75e036cf7cc403c691828db8fb7c58f\PresentationCore.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\SrpUxSnapIn\4789105cc02a87c1644503f9ee5dc156\SrpUxSnapIn.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\System\df9795fe2c47c21e4933c375448a822c\System.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Configuration\baf8d31c258e3bb460651f937e92aecf\System.Configuration.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Core\fd68e6eb2de266528c13e28e0398bcff\System.Core.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Data\aa8ecad015f8559c135cdf03809beab8\System.Data.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Dired13b18a9#\f843c983199095d64a7fe442f96111b5\System.DirectoryServices.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Drawing\925942a4de15cbda4715be2d16a49a82\System.Drawing.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Management\5e6bc8b9cf1f6644f2bc6108cbd3ad0e\System.Management.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Net.Http\86b6708ebfd622be5089a7ddbd472a38\System.Net.Http.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Runt73a1fc9d#\5a1209099cf7ec0ed6b8cac8a7b3f70d\System.Runtime.Remoting.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Runteb92aa12#\bd25621435529623957ecaf78dd82cc6\System.Runtime.Serialization.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\System.ServiceModel\63e8a405a7485494be92a0a40571ed5a\System.ServiceModel.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Transactions\e2c17a115d15005a33f0a19dea7cf0f8\System.Transactions.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Web.Services\7c5ccb95239f1e32bb582af76cf48a35\System.Web.Services.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Windows.Forms\de1a2062d1727cd022da4e072c567569\System.Windows.Forms.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Xaml\cf5989eaf60ad5753a05996a469dcbaf\System.Xaml.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Xml\088cc71e44f12dee82aada482ee7c74a\System.Xml.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\WindowsBase\400782d6a70fc2b6340b6c6f17763287\WindowsBase.ni.dll"
"C:\Windows\assembly\temp\0CIZNNVWPM\System.ni.dll"
"C:\Windows\assembly\temp\9HP4RYX4B7\System.Management.ni.dll"
"C:\Windows\assembly\temp\CPV00N9BEI\System.Core.ni.dll"
"C:\Windows\assembly\temp\TQP9FITYG1\System.ni.dll"
"C:\Windows\assembly\temp\XK3R420ZB3\System.Core.ni.dll"
"C:\Windows\Logs\CBS\CbsPersist_20260921111908.cab"
"C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~19041.6456.1.21\msil_microsoft.updateservices.baseapi_31bf3856ad364e35_10.0.19041.5794_none_227725072c0c66d4\microsoft.updateservices.baseapi.dll"
"C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~19041.6466.1.0\msil_microsoft.updateservices.baseapi_31bf3856ad364e35_10.0.19041.5794_none_227725072c0c66d4\microsoft.updateservices.baseapi.dll"
"C:\Windows\System32\spool\drivers\W32X86\PCC\ntprint.inf_x86_906f4b456b58c7f3.cab"
"C:\Windows\System32\spool\drivers\W32X86\PCC\prnms003.inf_x86_dfbfa985b550d950.cab"
"C:\Windows\System32\spool\drivers\x64\PCC\ntprint.inf_amd64_906f4b456b58c7f3.cab"
"C:\Windows\System32\spool\drivers\x64\PCC\prnms002.inf_amd64_a51e172297d3fe22.cab"
"C:\Windows\System32\spool\drivers\x64\PCC\prnms003.inf_amd64_ddecfc8d679b6224.cab"
"C:\Windows\System32\wbem\AutoRecover\21BD8E9B6A3575C7E6CFD05471F4DE86.mof"
"C:\Windows\WinSxS\amd64_microsoft.vc80.crt_1fc8b3b9a1e18e3b_8.0.50727.6195_none_88e41e092fab0294\msvcm80.dll"
"C:\Windows\WinSxS\amd64_microsoft.vc80.mfc_1fc8b3b9a1e18e3b_8.0.50727.6195_none_8448b2bd328df189\mfc80.dll"
"C:\Windows\WinSxS\amd64_microsoft.vc80.mfc_1fc8b3b9a1e18e3b_8.0.50727.6195_none_8448b2bd328df189\mfc80u.dll"
"C:\Windows\WinSxS\x86_microsoft.vc80.mfc_1fc8b3b9a1e18e3b_8.0.50727.6195_none_cbf5e994470a1a8f\mfc80.dll"
"C:\Ghost Toolbox\wget\wget2\bin\libgmp-10.dll"
"C:\Ghost Toolbox\wget\wget2\bin\libgnutls-30.dll"
"C:\Ghost Toolbox\wget\wget2\bin\libiconv-2.dll"
"C:\Ghost Toolbox\wget\wget2\bin\libp11-kit-0.dll"
"C:\Ghost Toolbox\wget\wget2\bin\libunistring-2.dll"
"C:\Ghost Toolbox\wget\wget2\bin\libwget-0.dll"
"C:\Ghost Toolbox\wget\wget2\bin\libzstd.dll"
"C:\Program Files\BlueStacks\HD-Common.dll"
"C:\Program Files\BlueStacks\libGLESv2.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\EventViewer\14e70e26de0d293868c02e7479ef62c8\EventViewer.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\Microsoft.A26c32abb#\58b17a841fe20cde75d6bda4b7e411d9\Microsoft.ApplicationId.RuleWizard.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\Microsoft.Mf49f6405#\a83ceaeb618fa738c0ac31aba7a4525b\Microsoft.Management.Infrastructure.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\Microsoft.P047767ce#\3bd7d4783ed94fdaeeee4b3e0bbfd23a\Microsoft.PowerShell.Core.Activities.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\Microsoft.P08ac43d5#\063f3157e11ca3b94aae5e6ad6256f1c\Microsoft.PowerShell.Utility.Activities.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\Microsoft.P521220ea#\4b107269baf872118482025447c7a5d4\Microsoft.PowerShell.Commands.Utility.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\Microsoft.P655586bb#\753d25375dff235a3e522e45a1e6d968\Microsoft.PowerShell.Activities.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\Microsoft.P9de5a786#\997a75a376f5d2972c30a143843c5066\Microsoft.PowerShell.Management.Activities.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\Microsoft.Pae3498d9#\33cd7bf7faa245fdab7a2f1f346b0953\Microsoft.PowerShell.Commands.Management.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\Microsoft.Pb378ec07#\44a322586f366211617518ac0ffd9b04\Microsoft.PowerShell.ConsoleHost.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\Microsoft.Pefb7a36b#\4bb42fe6be980139a83dfad43ec5ffd3\Microsoft.PowerShell.Workflow.ServiceCore.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\Microsoft.Sa56e3556#\b01da1d6c3266eee7af9637c6066258a\Microsoft.Security.ApplicationId.Wizards.AutomaticRuleGenerationWizard.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\Microsoft.We0722664#\97fc3adcca51ee38e8cc59cc56c38718\Microsoft.WSMan.Management.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\SrpUxSnapIn\4e29d22fc305f6284ae3db6e7f4a1328\SrpUxSnapIn.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_32\System.Management\b7ea621a99f428c18af898966b979326\System.Management.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\EventViewer\e78224dca944271fe8fa055fd217ec48\EventViewer.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.A26c32abb#\b28c3d14aa94f08bab86dd2b5c9e5aea\Microsoft.ApplicationId.RuleWizard.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.A9acaf597#\934f9d7f2f88c1ec6544a13bbe6c541f\Microsoft.AppV.AppvClientComConsumer.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.C26a36d2b#\424207102032545cefb5f06b3e0bcea6\Microsoft.CertificateServices.PKIClient.Cmdlets.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.C99be4d25#\c6898d7084d7bda30d73d7b61900972c\Microsoft.ConfigCI.Commands.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.G91a07420#\35a8fe4e59a15d08d331493fd00bd932\Microsoft.GroupPolicy.Reporting.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.Ga41585c2#\4d40e2ec9baf8d2a5898326334a162d1\Microsoft.GroupPolicy.AdmTmplEditor.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.Ink\22b32c7518556ff99c9917928b18311f\Microsoft.Ink.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.M870d558a#\3848311070796cb1ab1cbaa71369c098\Microsoft.Management.Infrastructure.Native.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.Mf49f6405#\86c715ed00d4b6abda11387adaa131d6\Microsoft.Management.Infrastructure.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.Mf5ac9168#\0a2d5f5d46fc257f77b68c90e1d7bc68\Microsoft.Management.Infrastructure.CimCmdlets.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.P047767ce#\13128cb79f3154cd58284912652a9402\Microsoft.PowerShell.Core.Activities.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.P08ac43d5#\728f17027ca38f455adf4818755f740d\Microsoft.PowerShell.Utility.Activities.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.P0e11b656#\4d10bb20197f548b0da893fdb389ea6e\Microsoft.PowerShell.GPowerShell.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.P10d01611#\5851b53256099aede1e39749bff6dfa1\Microsoft.PowerShell.Editor.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.P39041136#\0bcdd00116b74165d40d0a848679cb4e\Microsoft.PowerShell.ScheduledJob.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.P521220ea#\eba186c70e0d984563eab947ae28908e\Microsoft.PowerShell.Commands.Utility.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.P655586bb#\29c7223bf267eb2976ca2b95e14e4f02\Microsoft.PowerShell.Activities.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.P9de5a786#\77af8d6b09715480ee63e4eb9deac272\Microsoft.PowerShell.Management.Activities.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.Pae3498d9#\ad95798b1f9b30371b99feb7f2238bc5\Microsoft.PowerShell.Commands.Management.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.Pb378ec07#\68873625e1cd00d2f064fd0f732fe17a\Microsoft.PowerShell.ConsoleHost.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.Pcd26229b#\9c7b77a1b0b82a0ae8baa1d1873e326a\Microsoft.PowerShell.GraphicalHost.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.Pefb7a36b#\e7ad3f0a72f3671133c4408300b09a31\Microsoft.PowerShell.Workflow.ServiceCore.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.Sa56e3556#\e130054e4e4659d5390172812fb2c9e4\Microsoft.Security.ApplicationId.Wizards.AutomaticRuleGenerationWizard.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.W2d29a719#\92765552f2ba1db053af88c2295f5d91\Microsoft.Windows.DSC.CoreConfProviders.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.We0722664#\1d9de2138ee94c45ee78bf66ab496da8\Microsoft.WSMan.Management.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.We0722664#\5573a15efb51acc002f8f42187ee8676\Microsoft.WSMan.Management.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.We9f24001#\406fda920795c50adec1d85e7229e5b2\Microsoft.WSMan.Management.Activities.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\MIGUIControls\486f1071f6721dc655783ab04f82e3d7\MIGUIControls.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\SrpUxSnapIn\ae609e9dc28c254fec83cd75442824de\SrpUxSnapIn.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Web\226f41c0db7c45d9ce4a70d1114fd343\System.Web.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Web.28b9ef5a#\e473b0ce47b2cbe426ae81e60c818538\System.Web.Extensions.ni.dll"
"C:\Windows\assembly\NativeImages_v4.0.30319_64\UIAutomationTypes\64216bb503113ecb0ddd48035e1024c1\UIAutomationTypes.ni.dll"
"C:\Windows\System32\wbem\AutoRecover\9A0866672C16F45B521DC208BAC0B757.mof"
"C:\Windows\System32\wbem\AutoRecover\9C369BD8D75D5EDA2CD1AF1A943E5466.mof"
"C:\Windows\System32\wbem\AutoRecover\ADB2352B5D095374B56B19476EBCED3F.mof"
"C:\Windows\SystemResources\imageres.dll.mun"
"C:\Windows\SystemResources\imagesp1.dll.mun"
"C:\Windows\SystemResources\shell32.dll.mun"
"C:\Program Files\BorisFX\ContinuumOFX\17\utilities\pylib\Lib\site-packages\PyQt5\QtCore.pyd",
"C:\Program Files\BorisFX\ContinuumOFX\17\utilities\pylib\Lib\site-packages\PyQt5\QtGui.pyd",
"C:\Program Files\BorisFX\ContinuumOFX\17\utilities\pylib\Lib\site-packages\PyQt5\QtWidgets.pyd",

"C:\Program Files\Common Files\OFX\Plugins\BCC_DFT\resources\ML\bin\MLBackend_ort_cpu.dll",
"C:\Program Files\Common Files\OFX\Plugins\BCC_DFT\resources\ML\bin\MLBackend_ort_dml.dll",
"C:\Program Files\Common Files\OFX\Plugins\BCC_DFT\resources\ML\bin\MLPlugin_Denoiser.dll",
"C:\Program Files\Common Files\OFX\Plugins\BCC_DFT\resources\ML\bin\MLPlugin_Upres.dll",
"C:\Program Files\Common Files\OFX\Plugins\BCC_DFT\resources\ML\bin\onnxruntime.dll",

"C:\Program Files\Common Files\OFX\Plugins\motion_vectors_create.ofx.bundle\Contents\Win32\motion_vectors_create.ofx",
"C:\Program Files\Common Files\OFX\Plugins\motion_vectors_create.ofx.bundle\Contents\Win64\motion_vectors_create.ofx",

"C:\Program Files\Common Files\OFX\Plugins\rsmb.ofx.bundle\Contents\Win32\rsmb.ofx",
"C:\Program Files\Common Files\OFX\Plugins\rsmb.ofx.bundle\Contents\Win64\rsmb.ofx",
"C:\Program Files\Common Files\OFX\Plugins\rsmbvectors.ofx.bundle\Contents\Win32\rsmbvectors.ofx",
"C:\Program Files\Common Files\OFX\Plugins\rsmbvectors.ofx.bundle\Contents\Win64\rsmbvectors.ofx",

"C:\Program Files\Common Files\OFX\Plugins\twixtor.ofx.bundle\Contents\Win32\twixtor.ofx",
"C:\Program Files\Common Files\OFX\Plugins\twixtor.ofx.bundle\Contents\Win64\twixtor.ofx",
"C:\Program Files\Common Files\OFX\Plugins\twixtor_pro.ofx.bundle\Contents\Win32\twixtor_pro.ofx",
"C:\Program Files\Common Files\OFX\Plugins\twixtor_pro.ofx.bundle\Contents\Win64\twixtor_pro.ofx",
"C:\Program Files\Common Files\OFX\Plugins\twixtor_vectors_in.ofx.bundle\Contents\Win32\twixtor_vectors_in.ofx",
"C:\Program Files\Common Files\OFX\Plugins\twixtor_vectors_in.ofx.bundle\Contents\Win64\twixtor_vectors_in.ofx",

"C:\Program Files\GenArts\SapphireOFX\lib64\BFXExternalMonitor.dll",
"C:\Program Files\GenArts\SapphireOFX\lib64\GenArts.Sapphire.CUDA.em64t\cudart64_42_9.dll",
"C:\Program Files\GenArts\SapphireOFX\lib64\GenArts.Sapphire.OpenImageIO.em64t\boost_regex-vc100-mt-1_59.dll",
"C:\Program Files\GenArts\SapphireOFX\lib64\GenArts.Sapphire.OpenImageIO.em64t\IlmImf.dll",
"C:\Program Files\GenArts\SapphireOFX\lib64\GenArts.Sapphire.OpenImageIO.em64t\libtiff.dll",
"C:\Program Files\GenArts\SapphireOFX\lib64\GenArts.Sapphire.OpenImageIO.em64t\OpenImageIO.dll",
"C:\Program Files\GenArts\SapphireOFX\pylib\PyQt5.QtCore.pyd",
"C:\Program Files\GenArts\SapphireOFX\pylib\PyQt5.QtGui.pyd",
"C:\Program Files\GenArts\SapphireOFX\pylib\PyQt5.QtNetwork.pyd",
"C:\Program Files\GenArts\SapphireOFX\pylib\PyQt5.QtWidgets.pyd",
"C:\Program Files\GenArts\SapphireOFX\pylib\python27.dll",
"C:\Program Files\GenArts\SapphireOFX\pylib\Qt5Core.dll",
"C:\Program Files\GenArts\SapphireOFX\pylib\Qt5Gui.dll",
"C:\Program Files\GenArts\SapphireOFX\pylib\Qt5Network.dll",
"C:\Program Files\GenArts\SapphireOFX\pylib\Qt5Widgets.dll",
"C:\Program Files\GenArts\SapphireOFX\pylib\unicodedata.pyd",
"C:\Program Files\GenArts\SapphireOFX\pylib\_hashlib.pyd",
"C:\Program Files\GenArts\SapphireOFX\pylib\_license_activation.pyd",
"C:\Program Files\GenArts\SapphireOFX\pylib\_ssl.pyd",
"C:\Program Files\GenArts\SapphireOFX\pylib\qt5_plugins\imageformats\qjpegd.dll",
"C:\Program Files\GenArts\SapphireOFX\pylib\qt5_plugins\imageformats\qtiffd.dll",
"C:\Program Files\GenArts\SapphireOFX\pylib\qt5_plugins\imageformats\qwebpd.dll",
"C:\Program Files\GenArts\SapphireOFX\pylib\qt5_plugins\platforms\qdirect2d.dll",
"C:\Program Files\GenArts\SapphireOFX\pylib\qt5_plugins\platforms\qdirect2dd.dll",
"C:\Program Files\GenArts\SapphireOFX\pylib\qt5_plugins\platforms\qminimal.dll",
"C:\Program Files\GenArts\SapphireOFX\pylib\qt5_plugins\platforms\qminimald.dll",
"C:\Program Files\GenArts\SapphireOFX\pylib\qt5_plugins\platforms\qoffscreen.dll",
"C:\Program Files\GenArts\SapphireOFX\pylib\qt5_plugins\platforms\qoffscreend.dll",
"C:\Program Files\GenArts\SapphireOFX\pylib\qt5_plugins\platforms\qwindows.dll",
"C:\Program Files\GenArts\SapphireOFX\pylib\qt5_plugins\platforms\qwindowsd.dll",

"C:\Program Files\VEGAS\VEGAS Pro 16.0\AAFCOAPI.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\Microsoft.WindowsAPICodePack.Shell.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\proDADMercalli20.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\sonymvd2pro_xp.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\FileIO Plug-Ins\mcmp4plug2\mc_open_cl\mc_enc_avc_ocl.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\FileIO Plug-Ins\mcmp4xavcs\mc_cuda\mc_enc_avc_cuda.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\FileIO Plug-Ins\mp4plug3\savce.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\FileIO Plug-Ins\mp4plug3\sgcudme.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\FileIO Plug-Ins\mvcplug\sonyjvtd.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\FileIO Plug-Ins\mxfhdcamsrplug\mp4decoder_dll.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\FileIO Plug-Ins\mxfhdcamsrplug\mp4encoder_dll.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\FileIO Plug-Ins\mxfhdcamsrplug\SMDK-VC110-x64-4_0_0.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\FileIO Plug-Ins\mxfp2\SMDK-VC110-x64-4_0_0_scs.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\FileIO Plug-Ins\mxfplug\mc_dec_mp2v.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\FileIO Plug-Ins\mxfplug\mc_enc_mp2v.001",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\FileIO Plug-Ins\mxfplug\mc_enc_mp2v.002",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\FileIO Plug-Ins\mxfplug\mc_enc_mp2v.003",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\FileIO Plug-Ins\mxfplug\mc_enc_mp2v.004",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\FileIO Plug-Ins\mxfplug\mc_mfimport.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\FileIO Plug-Ins\mxfplug\mc_mux_mp2.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\FileIO Plug-Ins\mxfplug\SMDK-VC110-x86-4_0_0.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\FileIO Plug-Ins\mxfplug3\mc_dec_mp2v.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\FileIO Plug-Ins\mxfplug3\mc_demux_mp2.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\FileIO Plug-Ins\mxfplug3\mc_enc_mp2v.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\FileIO Plug-Ins\mxfplug3\mc_mfimport.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\FileIO Plug-Ins\mxfplug3\mc_mux_mp2.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\FileIO Plug-Ins\mxfplug3\mc_mux_mp4.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\FileIO Plug-Ins\mxfplug3\mc_mux_mxf.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\FileIO Plug-Ins\mxfplug3\SMDK-VC110-x64-4_0_0_scs.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\FileIO Plug-Ins\mxfxavc\SMDK-VC110-x64-4_8_0.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\FileIO Plug-Ins\redplug\REDR3D-x64.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\Online\facebook_x64.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\Online\feebs_x64.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\Online\filmpjes_x64.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\Online\flickr_x64.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\Online\shutterfly_x64.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\Online\vimeo_x64.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\Online\youtube_x64.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\Protein\MFL_rel_u_x64_vc12.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\Protein\VistaCooperation_rel_u_x64_vc12.dll",
"C:\Program Files\VEGAS\VEGAS Pro 16.0\RegModule_x64\mpeg2_x64.dll",

"C:\Program Files (x86)\Epic Games\Epic Online Services\managedArtifacts\98bc04bc842e4906993fd6d6644ffb8d\Win32\chrome_elf.dll",
"C:\Program Files (x86)\Epic Games\Epic Online Services\managedArtifacts\98bc04bc842e4906993fd6d6644ffb8d\Win32\libGLESv2.dll",
"C:\Program Files (x86)\Epic Games\Epic Online Services\managedArtifacts\98bc04bc842e4906993fd6d6644ffb8d\Win32\vk_swiftshader.dll",
"C:\Program Files (x86)\Epic Games\Epic Online Services\managedArtifacts\98bc04bc842e4906993fd6d6644ffb8d\Win32\vulkan-1.dll",
"C:\Program Files (x86)\Epic Games\Epic Online Services\managedArtifacts\98bc04bc842e4906993fd6d6644ffb8d\Win64\chrome_elf.dll",
"C:\Program Files (x86)\Epic Games\Epic Online Services\managedArtifacts\98bc04bc842e4906993fd6d6644ffb8d\Win64\dxcompiler.dll",
"C:\Program Files (x86)\Epic Games\Epic Online Services\managedArtifacts\98bc04bc842e4906993fd6d6644ffb8d\Win64\libEGL.dll",
"C:\Program Files (x86)\Epic Games\Epic Online Services\managedArtifacts\98bc04bc842e4906993fd6d6644ffb8d\Win64\libGLESv2.dll",
"C:\Program Files (x86)\Epic Games\Epic Online Services\managedArtifacts\98bc04bc842e4906993fd6d6644ffb8d\Win64\vk_swiftshader.dll",
"C:\Program Files (x86)\Epic Games\Epic Online Services\managedArtifacts\98bc04bc842e4906993fd6d6644ffb8d\Win64\vulkan-1.dll",

"C:\Program Files (x86)\Red Giant Link\cefpython3.cefpython_py27.pyd",
"C:\Program Files (x86)\Red Giant Link\Cython.Compiler.Code.pyd",
"C:\Program Files (x86)\Red Giant Link\ffmpegsumo.dll",
"C:\Program Files (x86)\Red Giant Link\icudt.dll",
"C:\Program Files (x86)\Red Giant Link\libGLESv2.dll",
"C:\Program Files (x86)\Red Giant Link\python27.dll",
"C:\Program Files (x86)\Red Giant Link\pythoncom27.dll",
"C:\Program Files (x86)\Red Giant Link\rglib._rglib.pyd",
"C:\Program Files (x86)\Red Giant Link\rglib._rgt.pyd",
"C:\Program Files (x86)\Red Giant Link\sqlite3.dll",
"C:\Program Files (x86)\Red Giant Link\unicodedata.pyd",
"C:\Program Files (x86)\Red Giant Link\win32ui.pyd",
"C:\Program Files (x86)\Red Giant Link\wx._controls_.pyd",
"C:\Program Files (x86)\Red Giant Link\wx._core_.pyd",
"C:\Program Files (x86)\Red Giant Link\wx._gdi_.pyd",
"C:\Program Files (x86)\Red Giant Link\wx._misc_.pyd",
"C:\Program Files (x86)\Red Giant Link\wx._windows_.pyd",
"C:\Program Files (x86)\Red Giant Link\wxbase30u_vc90_x64.dll",
"C:\Program Files (x86)\Red Giant Link\wxmsw30u_adv_vc90_x64.dll",
"C:\Program Files (x86)\Red Giant Link\wxmsw30u_core_vc90_x64.dll",
"C:\Program Files (x86)\Red Giant Link\wxmsw30u_html_vc90_x64.dll",
"C:\Program Files (x86)\Red Giant Link\_hashlib.pyd",
"C:\Program Files (x86)\Red Giant Link\_ssl.pyd",

"C:\ProgramData\Red Giant\Universe\Libraries\libexpat-1.dll",
"C:\ProgramData\Red Giant\Universe\Libraries\libfreetype-6.dll",
"C:\ProgramData\Red Giant\Universe\Libraries\libgcc_s_sjlj-1.dll",
"C:\ProgramData\Red Giant\Universe\Libraries\libglib-2.0-0.dll",
"C:\ProgramData\Red Giant\Universe\Libraries\libgobject-2.0-0.dll",
"C:\ProgramData\Red Giant\Universe\Libraries\libharfbuzz-0.dll",
"C:\ProgramData\Red Giant\Universe\Libraries\libintl-8.dll",
"C:\ProgramData\Red Giant\Universe\Libraries\libpng16-16.dll",

"C:\ProgramData\VEGAS\VEGAS Pro\16.0.307\sonyinstall_x64.dll",

"C:\Program Files (x86)\Epic Games\Epic Online Services\managedArtifacts\98bc04bc842e4906993fd6d6644ffb8d\Win32\chrome_elf.dll",
"C:\Program Files (x86)\Epic Games\Epic Online Services\managedArtifacts\98bc04bc842e4906993fd6d6644ffb8d\Win32\libGLESv2.dll",
"C:\Program Files (x86)\Epic Games\Epic Online Services\managedArtifacts\98bc04bc842e4906993fd6d6644ffb8d\Win32\vk_swiftshader.dll",
"C:\Program Files (x86)\Epic Games\Epic Online Services\managedArtifacts\98bc04bc842e4906993fd6d6644ffb8d\Win32\vulkan-1.dll",

"C:\Program Files (x86)\Epic Games\Epic Online Services\managedArtifacts\98bc04bc842e4906993fd6d6644ffb8d\Win64\chrome_elf.dll",
"C:\Program Files (x86)\Epic Games\Epic Online Services\managedArtifacts\98bc04bc842e4906993fd6d6644ffb8d\Win64\dxcompiler.dll",
"C:\Program Files (x86)\Epic Games\Epic Online Services\managedArtifacts\98bc04bc842e4906993fd6d6644ffb8d\Win64\libEGL.dll",
"C:\Program Files (x86)\Epic Games\Epic Online Services\managedArtifacts\98bc04bc842e4906993fd6d6644ffb8d\Win64\libGLESv2.dll",
"C:\Program Files (x86)\Epic Games\Epic Online Services\managedArtifacts\98bc04bc842e4906993fd6d6644ffb8d\Win64\vk_swiftshader.dll",
"C:\Program Files (x86)\Epic Games\Epic Online Services\managedArtifacts\98bc04bc842e4906993fd6d6644ffb8d\Win64\vulkan-1.dll",

"C:\Program Files (x86)\Gigabyte\AppCenter\FBIOS.dll",
"C:\Program Files (x86)\Gigabyte\AppCenter\Flash.dll",
"C:\Program Files (x86)\Gigabyte\AppCenter\osvi.dll",
"C:\Program Files (x86)\Gigabyte\AppCenter\SetBiosLang.dll",

"C:\Program Files (x86)\InstallShield Installation Information\{D50BEE9A-0EC6-4A58-BF90-35BDC6D6495D}\ISSetup.dll",

"C:\Users\$env:USERNAME\AppData\Local\Programs\bluestacks-services\ffmpeg.dll",
"C:\Users\$env:USERNAME\AppData\Local\Programs\bluestacks-services\libGLESv2.dll",
"C:\Users\$env:USERNAME\AppData\Local\Programs\bluestacks-services\vk_swiftshader.dll",
"C:\Users\$env:USERNAME\AppData\Local\Programs\bluestacks-services\vulkan-1.dll"

"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Blur_Blur_OFX.ofx.bundle\Contents\Win64\Universe_Blur_Blur_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Blur_Blur_Premium_OFX.ofx.bundle\Contents\Win64\Universe_Blur_Blur_Premium_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Blur_Channel_Blur_OFX.ofx.bundle\Contents\Win64\Universe_Blur_Channel_Blur_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Blur_Compound_Blur_OFX.ofx.bundle\Contents\Win64\Universe_Blur_Compound_Blur_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Blur_Compound_Blur_Premium_OFX.ofx.bundle\Contents\Win64\Universe_Blur_Compound_Blur_Premium_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Blur_Hyperbolic_Blur_OFX.ofx.bundle\Contents\Win64\Universe_Blur_Hyperbolic_Blur_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Blur_Masked_Blur_OFX.ofx.bundle\Contents\Win64\Universe_Blur_Masked_Blur_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Blur_Radial_Blur_OFX.ofx.bundle\Contents\Win64\Universe_Blur_Radial_Blur_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Blur_Spot_Blur_OFX.ofx.bundle\Contents\Win64\Universe_Blur_Spot_Blur_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Blur_Streak_Blur_OFX.ofx.bundle\Contents\Win64\Universe_Blur_Streak_Blur_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Blur_Zoom_Blur_OFX.ofx.bundle\Contents\Win64\Universe_Blur_Zoom_Blur_OFX.ofx",

"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_CrumplePop_Finisher_OFX.ofx.bundle\Contents\Win64\Universe_CrumplePop_Finisher_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_CrumplePop_Fisheye_Fixer_OFX.ofx.bundle\Contents\Win64\Universe_CrumplePop_Fisheye_Fixer_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_CrumplePop_Grain16_OFX.ofx.bundle\Contents\Win64\Universe_CrumplePop_Grain16_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_CrumplePop_Noir_Moderne_OFX.ofx.bundle\Contents\Win64\Universe_CrumplePop_Noir_Moderne_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_CrumplePop_OverLight_OFX.ofx.bundle\Contents\Win64\Universe_CrumplePop_OverLight_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_CrumplePop_Photo2_OFX.ofx.bundle\Contents\Win64\Universe_CrumplePop_Photo2_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_CrumplePop_ShrinkRay_OFX.ofx.bundle\Contents\Win64\Universe_CrumplePop_ShrinkRay_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_CrumplePop_SplitScreen_Blocks_OFX.ofx.bundle\Contents\Win64\Universe_CrumplePop_SplitScreen_Blocks_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_CrumplePop_SplitScreen_Custom_Block_OFX.ofx.bundle\Contents\Win64\Universe_CrumplePop_SplitScreen_Custom_Block_OFX.ofx",

"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Distort_Camera_Shake_OFX.ofx.bundle\Contents\Win64\Universe_Distort_Camera_Shake_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Distort_Camera_Shake_Pro_OFX.ofx.bundle\Contents\Win64\Universe_Distort_Camera_Shake_Pro_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Distort_Chromatic_Aberration_OFX.ofx.bundle\Contents\Win64\Universe_Distort_Chromatic_Aberration_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Distort_Elliptical_Distortion_OFX.ofx.bundle\Contents\Win64\Universe_Distort_Elliptical_Distortion_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Distort_Fish_Eye_Distortion_OFX.ofx.bundle\Contents\Win64\Universe_Distort_Fish_Eye_Distortion_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Distort_Heatwave_OFX.ofx.bundle\Contents\Win64\Universe_Distort_Heatwave_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Distort_Masked_Clone_OFX.ofx.bundle\Contents\Win64\Universe_Distort_Masked_Clone_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Distort_Masked_Mosaic_OFX.ofx.bundle\Contents\Win64\Universe_Distort_Masked_Mosaic_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Distort_Picture_in_Picture_OFX.ofx.bundle\Contents\Win64\Universe_Distort_Picture_in_Picture_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Distort_Prism_Displacement_OFX.ofx.bundle\Contents\Win64\Universe_Distort_Prism_Displacement_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Distort_RGB_Displacement_OFX.ofx.bundle\Contents\Win64\Universe_Distort_RGB_Displacement_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Distort_RGB_Separation_OFX.ofx.bundle\Contents\Win64\Universe_Distort_RGB_Separation_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Distort_Ripples_OFX.ofx.bundle\Contents\Win64\Universe_Distort_Ripples_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Distort_Simple_RGB_Separation_OFX.ofx.bundle\Contents\Win64\Universe_Distort_Simple_RGB_Separation_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Distort_Singularity_OFX.ofx.bundle\Contents\Win64\Universe_Distort_Singularity_OFX.ofx",

"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Generators_Billowed_Background_OFX.ofx.bundle\Contents\Win64\Universe_Generators_Billowed_Background_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Generators_Checkerboard_OFX.ofx.bundle\Contents\Win64\Universe_Generators_Checkerboard_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Generators_Fractal_Background_OFX.ofx.bundle\Contents\Win64\Universe_Generators_Fractal_Background_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Generators_Gradient_Ramp_OFX.ofx.bundle\Contents\Win64\Universe_Generators_Gradient_Ramp_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Generators_Grid_OFX.ofx.bundle\Contents\Win64\Universe_Generators_Grid_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Generators_Soft_Gradient_Background_OFX.ofx.bundle\Contents\Win64\Universe_Generators_Soft_Gradient_Background_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Generators_Spectralicious_OFX.ofx.bundle\Contents\Win64\Universe_Generators_Spectralicious_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Generators_Three_Color_Ramp_OFX.ofx.bundle\Contents\Win64\Universe_Generators_Three_Color_Ramp_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Generators_Two_Color_Ramp_OFX.ofx.bundle\Contents\Win64\Universe_Generators_Two_Color_Ramp_OFX.ofx",

"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Glow_Chromatic_Glow_OFX.ofx.bundle\Contents\Win64\Universe_Glow_Chromatic_Glow_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Glow_Diffuse_Color_Glow_OFX.ofx.bundle\Contents\Win64\Universe_Glow_Diffuse_Color_Glow_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Glow_Diffuse_Glow_OFX.ofx.bundle\Contents\Win64\Universe_Glow_Diffuse_Glow_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Glow_Edge_Glow_OFX.ofx.bundle\Contents\Win64\Universe_Glow_Edge_Glow_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Glow_Edge_Glow_Premium_OFX.ofx.bundle\Contents\Win64\Universe_Glow_Edge_Glow_Premium_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Glow_Glimmer_OFX.ofx.bundle\Contents\Win64\Universe_Glow_Glimmer_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Glow_Glow_Highlights_OFX.ofx.bundle\Contents\Win64\Universe_Glow_Glow_Highlights_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Glow_Glow_OFX.ofx.bundle\Contents\Win64\Universe_Glow_Glow_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Glow_Glo_Fi_OFX.ofx.bundle\Contents\Win64\Universe_Glow_Glo_Fi_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Glow_Glo_Fi_Premium_OFX.ofx.bundle\Contents\Win64\Universe_Glow_Glo_Fi_Premium_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Glow_Pixel_Glow_EZ_OFX.ofx.bundle\Contents\Win64\Universe_Glow_Pixel_Glow_EZ_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Glow_Point_Zoom_OFX.ofx.bundle\Contents\Win64\Universe_Glow_Point_Zoom_OFX.ofx",

"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Motion_Graphics_HUD_Components_OFX.ofx.bundle\Contents\Win64\Universe_Motion_Graphics_HUD_Components_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Motion_Graphics_Line_OFX.ofx.bundle\Contents\Win64\Universe_Motion_Graphics_Line_OFX.ofx",

"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Noise_Luminance_Noise_OFX.ofx.bundle\Contents\Win64\Universe_Noise_Luminance_Noise_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Noise_Turbulence_Noise_EZ_OFX.ofx.bundle\Contents\Win64\Universe_Noise_Turbulence_Noise_EZ_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Noise_Turbulence_Noise_OFX.ofx.bundle\Contents\Win64\Universe_Noise_Turbulence_Noise_OFX.ofx",

"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Stylize_Carousel_OFX.ofx.bundle\Contents\Win64\Universe_Stylize_Carousel_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Stylize_Glitch_OFX.ofx.bundle\Contents\Win64\Universe_Stylize_Glitch_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Stylize_Holomatrix_EZ_OFX.ofx.bundle\Contents\Win64\Universe_Stylize_Holomatrix_EZ_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Stylize_Holomatrix_OFX.ofx.bundle\Contents\Win64\Universe_Stylize_Holomatrix_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Stylize_Knoll_Light_Factory_EZ_OFX.ofx.bundle\Contents\Win64\Universe_Stylize_Knoll_Light_Factory_EZ_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Stylize_MisFire_OFX.ofx.bundle\Contents\Win64\Universe_Stylize_MisFire_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Stylize_Misfire_Premium_OFX.ofx.bundle\Contents\Win64\Universe_Stylize_Misfire_Premium_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Stylize_Noir_Moderne_OFX.ofx.bundle\Contents\Win64\Universe_Stylize_Noir_Moderne_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Stylize_RetroGrade_OFX.ofx.bundle\Contents\Win64\Universe_Stylize_RetroGrade_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Stylize_Sobel_Edges_OFX.ofx.bundle\Contents\Win64\Universe_Stylize_Sobel_Edges_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Stylize_Texturize_OFX.ofx.bundle\Contents\Win64\Universe_Stylize_Texturize_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Stylize_ToonIt_Studio_OFX.ofx.bundle\Contents\Win64\Universe_Stylize_ToonIt_Studio_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Stylize_VHS_OFX.ofx.bundle\Contents\Win64\Universe_Stylize_VHS_OFX.ofx",

    "C:\Program Files\Common Files\OFX\Plugins\Sapphire.ofx.bundle\Contents\Win64\GenArts.Sapphire.CUDA.em64t\cudart64_42_9.dll",
    "C:\Program Files\Common Files\OFX\Plugins\Sapphire.ofx.bundle\Contents\Win64\GenArts.Sapphire.OpenImageIO.em64t\boost_regex-vc100-mt-1_59.dll",
    "C:\Program Files\Common Files\OFX\Plugins\Sapphire.ofx.bundle\Contents\Win64\GenArts.Sapphire.OpenImageIO.em64t\IlmImf.dll",
    "C:\Program Files\Common Files\OFX\Plugins\Sapphire.ofx.bundle\Contents\Win64\GenArts.Sapphire.OpenImageIO.em64t\libtiff.dll",
    "C:\Program Files\Common Files\OFX\Plugins\Sapphire.ofx.bundle\Contents\Win64\GenArts.Sapphire.OpenImageIO.em64t\OpenImageIO.dll",

    "C:\Program Files (x86)\Red Giant Link\tools\update_installer\CRYPT32.dll",
    "C:\Program Files (x86)\Red Giant Link\tools\update_installer\iertutil.dll",
    "C:\Program Files (x86)\Red Giant Link\tools\update_installer\python27.dll",
    "C:\Program Files (x86)\Red Giant Link\tools\update_installer\pythoncom27.dll",
    "C:\Program Files (x86)\Red Giant Link\tools\update_installer\SETUPAPI.dll",
    "C:\Program Files (x86)\Red Giant Link\tools\update_installer\sqlite3.dll",
    "C:\Program Files (x86)\Red Giant Link\tools\update_installer\tcl85.dll",
    "C:\Program Files (x86)\Red Giant Link\tools\update_installer\tk85.dll",
    "C:\Program Files (x86)\Red Giant Link\tools\update_installer\urlmon.dll",
    "C:\Program Files (x86)\Red Giant Link\tools\update_installer\USP10.dll",
    "C:\Program Files (x86)\Red Giant Link\tools\update_installer\WININET.dll",
    "C:\Program Files (x86)\Red Giant Link\tools\update_installer\wxbase30u_vc90_x64.dll",
    "C:\Program Files (x86)\Red Giant Link\tools\update_installer\wxmsw30u_adv_vc90_x64.dll",
    "C:\Program Files (x86)\Red Giant Link\tools\update_installer\wxmsw30u_core_vc90_x64.dll",
    "C:\Program Files (x86)\Red Giant Link\tools\update_installer\wxmsw30u_html_vc90_x64.dll",

    "C:\Windows\System32\Gpu_Shader_Engine_x64.dll",
    "C:\Windows\System32\Noesis.dll",
    "C:\Windows\System32\UniChooser.dll"

"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Text_AV_Club_OFX.ofx.bundle\Contents\Win64\Universe_Text_AV_Club_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Text_Ecto_OFX.ofx.bundle\Contents\Win64\Universe_Text_Ecto_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Text_Glo_Fi_II_OFX.ofx.bundle\Contents\Win64\Universe_Text_Glo_Fi_II_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Text_Long_Shadow_OFX.ofx.bundle\Contents\Win64\Universe_Text_Long_Shadow_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Text_Luster_OFX.ofx.bundle\Contents\Win64\Universe_Text_Luster_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Text_Title_Motion_OFX.ofx.bundle\Contents\Win64\Universe_Text_Title_Motion_OFX.ofx",

"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_ToonIt_ToonIt_Cartoon_OFX.ofx.bundle\Contents\Win64\Universe_ToonIt_ToonIt_Cartoon_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_ToonIt_ToonIt_Expressionist_Noise_OFX.ofx.bundle\Contents\Win64\Universe_ToonIt_ToonIt_Expressionist_Noise_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_ToonIt_ToonIt_Outlines_OFX.ofx.bundle\Contents\Win64\Universe_ToonIt_ToonIt_Outlines_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_ToonIt_ToonIt_Paint_OFX.ofx.bundle\Contents\Win64\Universe_ToonIt_ToonIt_Paint_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_ToonIt_ToonIt_Presets_OFX.ofx.bundle\Contents\Win64\Universe_ToonIt_ToonIt_Presets_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_ToonIt_ToonIt_Retouch_OFX.ofx.bundle\Contents\Win64\Universe_ToonIt_ToonIt_Retouch_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_ToonIt_ToonIt_Sketch_OFX.ofx.bundle\Contents\Win64\Universe_ToonIt_ToonIt_Sketch_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_ToonIt_ToonIt_Thermal_OFX.ofx.bundle\Contents\Win64\Universe_ToonIt_ToonIt_Thermal_OFX.ofx",

"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Utilities_Color_and_Gamma_Conversion_OFX.ofx.bundle\Contents\Win64\Universe_Utilities_Color_and_Gamma_Conversion_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Utilities_Compare_Frames_OFX.ofx.bundle\Contents\Win64\Universe_Utilities_Compare_Frames_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Utilities_Fill_Alpha_OFX.ofx.bundle\Contents\Win64\Universe_Utilities_Fill_Alpha_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Utilities_Logo_Motion_OFX.ofx.bundle\Contents\Win64\Universe_Utilities_Logo_Motion_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Utilities_Unmult_OFX.ofx.bundle\Contents\Win64\Universe_Utilities_Unmult_OFX.ofx",
"C:\Program Files\Common Files\OFX\Plugins\Red Giant Universe\Universe_Utilities_Unmult_Premium_OFX.ofx.bundle\Contents\Win64\Universe_Utilities_Unmult_Premium_OFX.ofx"

"C:\Users\$env:USERNAME\Downloads\sony vegas wlnx\sony vegas wlnx\2 - EFEITOS\4 - RSMB\RSMB\rsmb.ofx.bundle\Contents\Win32\rsmb.ofx",
"C:\Users\$env:USERNAME\Downloads\sony vegas wlnx\sony vegas wlnx\2 - EFEITOS\4 - RSMB\RSMB\rsmb.ofx.bundle\Contents\Win64\rsmb.ofx",
"C:\Users\$env:USERNAME\Downloads\sony vegas wlnx\sony vegas wlnx\2 - EFEITOS\4 - RSMB\RSMB\rsmbvectors.ofx.bundle\Contents\Win32\rsmbvectors.ofx",
"C:\Users\$env:USERNAME\Downloads\sony vegas wlnx\sony vegas wlnx\2 - EFEITOS\4 - RSMB\RSMB\rsmbvectors.ofx.bundle\Contents\Win64\rsmbvectors.ofx"
"C:\Windows\WinSxS\x86_microsoft.vc80.mfc_1fc8b3b9a1e18e3b_8.0.50727.6195_none_cbf5e994470a1a8f\mfc80u.dll",

    # CrystalDiskInfo
    "C:\Program Files\CrystalDiskInfo\CdiResource\MailKit.dll",
    "C:\Program Files\CrystalDiskInfo\CdiResource\MimeKit.dll",

    # Attack Shark X3
    "C:\Program Files (x86)\Attack SharkX3Mouse\DuiLib.dll",
    "C:\Program Files (x86)\Attack SharkX3Mouse\DuiLib_d.dll",

    # Steam
    "C:\Program Files (x86)\Steam\libpyrowave-shared-0.dll",

    # Instaladores NSIS: criam pastas nsXXXX.tmp com nome aleatorio
    "C:\Users\$env:USERNAME\AppData\Local\Temp\ns*.tmp\nsDui.dll",

    # Modulos temporarios do Node.js
    "C:\Users\$env:USERNAME\AppData\Local\Temp\*.tmp.node",

    # Cabos de drivers de impressao (PCC)
    "C:\Windows\System32\spool\drivers\W32X86\PCC\*.cab",
    "C:\Windows\System32\spool\drivers\x64\PCC\*.cab",

    # DLLs legadas do MFC / Visual Basic (SysWOW64)
    "C:\Windows\SysWOW64\mfc70.dll",
    "C:\Windows\SysWOW64\mfc70u.dll",
    "C:\Windows\SysWOW64\mfc71.dll",
    "C:\Windows\SysWOW64\mfc71u.dll",
    "C:\Windows\SysWOW64\msvbvm50.dll",
    "C:\Windows\SysWOW64\vb40032.dll",

    # AlecrinBypass (DLLs proprias do bypass)
    "C:\Users\$env:USERNAME\AppData\Local\AlecrinBypass\cimgui.dll",
    "C:\Users\$env:USERNAME\AppData\Local\AlecrinBypass\UIDBypassDll.dll",

    # DLLs / drivers do Windows sem assinatura (Holo, codecs RTSS, WMI)
    "C:\Windows\ShellComponents\WindowsInternal.ComposableShell.Experiences.DragDrop.dll",
    "C:\Windows\System32\DHolographicDisplay.dll",
    "C:\Windows\System32\HologramCompositor.dll",
    "C:\Windows\System32\HologramWorld.dll",
    "C:\Windows\System32\HolographicExtensions.dll",
    "C:\Windows\System32\HoloSI.PCShell.dll",
    "C:\Windows\System32\Hydrogen.dll",
    "C:\Windows\System32\MixedRealityCapture.Pipeline.dll",
    "C:\Windows\System32\rtvcvfw64.dll",
    "C:\Windows\System32\usosvcimpl.dll",
    "C:\Windows\System32\drivers\BthA2dp.sys",
    "C:\Windows\System32\PerceptionSimulation\PerceptionSimulationInput.dll",
    "C:\Windows\System32\wbem\DMWmiBridgeProv1 (1).dll",
    "C:\Windows\System32\wbem\Microsoft.Uev.AgentWmi (1).dll",
    "C:\Windows\SysWOW64\rtvcvfw32.dll",
    "C:\Windows\SysWOW64\Windows.Media.MixedRealityCapture.dll",
    "C:\Windows\SysWOW64\Windows.Mirage.Internal.dll",
    "C:\Windows\SysWOW64\wbem\Microsoft.Uev.AgentWmi (1).dll",

    # Hydra (launcher) - DLLs embutidas (ffmpeg, EGL/GLES, 7z, libvips)
    "C:\Users\*\AppData\Local\Programs\Hydra\*.dll",

    # Roblox - profiling da Datadog que vem com o cliente
    "C:\Users\*\AppData\Local\Roblox\Versions\*\datadog_profiling_ffi.dll",
    "C:\Users\*\AppData\Local\Roblox\Versions\*\dd-win-prof.dll",

    # Cache de imagem do webp-imageio (Java) no Temp
    "C:\Users\*\AppData\Local\Temp\webp-imageio-*.dll",

    # Discord - metadados .winmd (a pasta app-X muda a cada update)
    "C:\Users\*\AppData\Local\Discord\app-*\*.winmd",
    "C:\Users\*\AppData\Roaming\Discord\app-*\*.winmd",

    # Ubisoft Connect - rotina de deteccao de hardware da propria launcher
    "C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\gear_detection_win32SA.dll",

    # Iriun Webcam - build do ffmpeg (avcodec/avutil/swscale) sem assinatura
    "C:\Program Files (x86)\Iriun Webcam\avcodec-62.dll",
    "C:\Program Files (x86)\Iriun Webcam\avutil-60.dll",
    "C:\Program Files (x86)\Iriun Webcam\swscale-9.dll"
)

Write-Host "Scanneando arquivos..." -ForegroundColor Red

# Whitelist de arquivos com suporte a curinga (* e ?), usada nos dois filtros
# de "SEM ASSINATURA". Entrada sem curinga mantem a comparacao exata de antes.
function Test-WhitelistedFile {
    param(
        [string]$Path
    )

    foreach ($item in $whitelistArquivos) {

        if ($item.Contains("*") -or $item.Contains("?")) {

            if ($Path -like $item) {
                return $true
            }

            continue
        }

        if ([string]::Equals($Path, $item, [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

# Caminhos ja impressos como "[SEM ASSINATURA]": garantem 1 linha por arquivo
# na saida, mesmo com varias secoes do script varrendo a mesma arvore.
$unsignedReported = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)

$extensoesIgnoradas = @(".exe", ".js", ".txt", ".ofx", ".pyd", ".py", ".log", ".node", ".tmp.node", ".evtx", ".ps1", ".msi")

# Pastas da whitelist normalizadas (sem barra final, caixa ignorada).
# Elas sao cortadas ANTES da recursao: o conteudo delas nunca e enumerado,
# logo nenhum arquivo de la chega ao Get-AuthenticodeSignature.
$pastasIgnoradas = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)

foreach ($pasta in $whitelistPastas) {

    $base = $pasta.TrimEnd('\')

    if (-not [string]::IsNullOrWhiteSpace($base)) {
        $null = $pastasIgnoradas.Add($base)
    }
}

function Test-PastaIgnorada {
    param(
        [string]$Caminho
    )

    $atual = $Caminho.TrimEnd('\')

    foreach ($pasta in $pastasIgnoradas) {

        # Entrada com curinga (* ?) casa a propria pasta e qualquer
        # descendente: "C:\Users\*\AppData\Roaming\.minecraft" cobre
        # tambem "C:\Users\MICHA\...\bin\1.20\mods".
        if ($pasta.Contains("*") -or $pasta.Contains("?")) {

            if ($atual -like $pasta -or $atual -like ($pasta + '\*')) {
                return $true
            }

            continue
        }

        if ([string]::Equals(
            $atual,
            $pasta,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            return $true
        }

        # Rede de seguranca: alguma pasta da whitelist acima do caminho atual.
        if ($atual.StartsWith(
            $pasta + '\',
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            return $true
        }
    }

    return $false
}

# Percorre C:\ pasta a pasta (sem -Recurse). Cada subpasta e testada contra a
# whitelist antes de entrar na pilha: pasta ignorada nunca e aberta, o que
# elimina a maior parte da varredura e tambem o custo por arquivo que existia
# no Where-Object anterior.
$pilhaDiretorios = [System.Collections.Generic.Stack[string]]::new()

$pilhaDiretorios.Push("C:\")

while ($pilhaDiretorios.Count -gt 0) {

    $pastaAtual = $pilhaDiretorios.Pop()

    $pastaInfo = $null
    $subpastas = $null
    $arquivos = $null

    try {
        $pastaInfo = [System.IO.DirectoryInfo]::new($pastaAtual)
        $subpastas = $pastaInfo.EnumerateDirectories()
    } catch {
        $subpastas = $null
    }

    if ($null -ne $subpastas) {

        try {
            foreach ($subpasta in $subpastas) {

                # Junctions/symlinks nao sao seguidos: evita loop infinito
                # (ex.: "C:\ProgramData\Application Data") e re-entrar em
                # arvores ja cobertas, igual ao comportamento do -Recurse.
                if (($subpasta.Attributes -band
                    [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                    continue
                }

                if (-not (Test-PastaIgnorada -Caminho $subpasta.FullName)) {
                    $pilhaDiretorios.Push($subpasta.FullName)
                }
            }
        } catch {
        }
    }

    try {
        $arquivos = $pastaInfo.EnumerateFiles()
    } catch {
        $arquivos = $null
    }

    if ($null -eq $arquivos) {
        continue
    }

    try {
        foreach ($arquivo in $arquivos) {

            try {
                if ($arquivo.Length -lt $min -or $arquivo.Length -gt $max) {
                    continue
                }

                if ($extensoesIgnoradas -contains $arquivo.Extension.ToLower()) {
                    continue
                }

                if (Test-WhitelistedFile -Path $arquivo.FullName) {
                    continue
                }

                $assinatura = Get-AuthenticodeSignature `
                    -FilePath $arquivo.FullName `
                    -ErrorAction SilentlyContinue

                if ($assinatura.Status -eq "NotSigned") {

                    if ($unsignedReported.Add($arquivo.FullName)) {
                        Write-Host "[SEM ASSINATURA] $($arquivo.FullName)" -ForegroundColor Yellow
                    }
                }
            } catch {
            }
        }
    } catch {
    }
}

$nomesApps = @(
    "obs-studio",
    "Google\Chrome",
    "BraveSoftware",
    "Opera GX",
    "Discord",
    "BlueStacks",
    "BlueStacks X_msi5",
    "MSI App Player",
    "Microsoft\Edge",
    "Spotify"
)

$locais = @(
    "C:\Program Files",
    "C:\Program Files (x86)",
    "C:\Users\$env:USERNAME\AppData\Local",
    "C:\Users\$env:USERNAME\AppData\Roaming"
)

$whitelistArquivos = @(
    "C:\Program Files\obs-studio\uninstall.exe",
    "C:\Users\$env:USERNAME\AppData\Local\Discord\app-1.0.9258\profapi.dll",
    "C:\Users\$env:USERNAME\AppData\Local\Google\Chrome\User Data\Default\Extensions\ghbmnnjooekpmoecnnnilnnbdlolhkhi\1.110.1_0\offscreendocument_main.js",
    "C:\Users\$env:USERNAME\AppData\Local\Google\Chrome\User Data\Default\Extensions\ghbmnnjooekpmoecnnnilnnbdlolhkhi\1.110.1_0\page_embed_script.js",
    "C:\Users\$env:USERNAME\AppData\Local\Google\Chrome\User Data\Default\Extensions\ghbmnnjooekpmoecnnnilnnbdlolhkhi\1.110.1_0\service_worker_bin_prod.js",
    "C:\Users\$env:USERNAME\AppData\Local\Google\Chrome\User Data\Default\Extensions\nmmhkkegccagdldgiimedpiccmgmieda\1.0.0.6_0\craw_background.js",
    "C:\Users\$env:USERNAME\AppData\Local\Google\Chrome\User Data\Default\Extensions\nmmhkkegccagdldgiimedpiccmgmieda\1.0.0.6_0\craw_window.js",
    "C:\Users\$env:USERNAME\AppData\Local\Google\Chrome\User Data\WasmTtsEngine\20260904.1\background_compiled.js",
    "C:\Users\$env:USERNAME\AppData\Local\Google\Chrome\User Data\WasmTtsEngine\20260904.1\bindings_main.js",
    "C:\Users\$env:USERNAME\AppData\Local\Google\Chrome\User Data\WasmTtsEngine\20260904.1\offscreen_compiled.js",
    "C:\Users\$env:USERNAME\AppData\Local\Google\Chrome\User Data\WasmTtsEngine\20260904.1\streaming_worklet_processor.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\cgjgjfacjflmgphhhepmbhhbgjieaecn\135.0.3176.0_1\DevToolsPlugin.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\cgjgjfacjflmgphhhepmbhhbgjieaecn\135.0.3176.0_1\NamedFunctionRange.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\cgjgjfacjflmgphhhepmbhhbgjieaecn\135.0.3176.0_1\third_party\typescript\typescript.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\ghbmnnjooekpmoecnnnilnnbdlolhkhi\1.110.1_1\offscreendocument_main.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\ghbmnnjooekpmoecnnnilnnbdlolhkhi\1.110.1_1\page_embed_script.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\ghbmnnjooekpmoecnnnilnnbdlolhkhi\1.110.1_1\service_worker_bin_prod.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\jmjflgjpcpepeafmmgdpfkogkghcpiha\1.2.1_1\content.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\jmjflgjpcpepeafmmgdpfkogkghcpiha\1.2.1_1\content_new.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\kfbdpdaobnofkbopebjglnaadopfikhh\113.0.1765.0_1\third_party\babylon\babylon.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\kfbdpdaobnofkbopebjglnaadopfikhh\113.0.1765.0_1\third_party\typescript\typescript.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Shopping\2.1.114.0\auto_open_controller.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Shopping\2.1.114.0\edge_checkout_page_validator.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Shopping\2.1.114.0\edge_confirmation_page_validator.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Shopping\2.1.114.0\edge_driver.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Shopping\2.1.114.0\edge_tracking_page_validator.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Shopping\2.1.114.0\product_page.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Shopping\2.1.114.0\shopping_iframe_driver.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\app-setup.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\bnpl_driver.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\buynow_driver.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\crypto.bundle.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\edge_driver.js",
    "C:\Program Files (x86)\BlueStacks X_msi5\green.vbs",
    "C:\Program Files (x86)\BlueStacks X_msi5\www\js\flexible.js",
    "C:\Program Files (x86)\BlueStacks X_msi5\www\js\index.js",
    "C:\Program Files (x86)\BlueStacks X_msi5\www\js\jquery.min.js",
    "C:\Program Files (x86)\BlueStacks X_msi5\www\js\language.js",
    "C:\Program Files (x86)\BlueStacks X_msi5\www\js\localize.js",
    "C:\Program Files (x86)\BlueStacks X_msi5\www\js\qwebchannel.js",
    "C:\Program Files (x86)\BlueStacks X_msi5\www\js\utils.js",
    "C:\Program Files (x86)\BlueStacks X_msi5\www\localization\index.js",
    "C:\Program Files (x86)\BlueStacks X_msi5\www\script\index.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\load-hub-i18n.bundle.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\runtime.bundle.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\shopping_iframe_driver.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\vendor.bundle.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\wallet-webui-101.079f5d74a18127cd9d6a.chunk.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\wallet-webui-227.bb2c3c84778e2589775f.chunk.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\wallet-webui-560.da6c8914bf5007e1044c.chunk.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\wallet-webui-708.de49febeeb0e9c77883f.chunk.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\wallet-webui-792.b1180305c186d50631a2.chunk.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\wallet-webui-925.baa79171a74ad52b0a67.chunk.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\wallet-webui-992.268aa821c3090dce03cb.chunk.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\wallet.bundle.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\wallet_checkout_autofill_driver.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\wallet_donation_driver.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\webui-setup.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\bnpl\bnpl.bundle.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\Mini-Wallet\miniwallet.bundle.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\Notification\notification.bundle.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\Notification\notification_fast.bundle.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\Tokenized-Card\tokenized-card.bundle.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\Wallet-BuyNow\wallet-buynow.bundle.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\Wallet-Checkout\app-setup.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\Wallet-Checkout\load-ec-deps.bundle.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\Wallet-Checkout\load-ec-i18n.bundle.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\Wallet-Checkout\wallet-drawer.bundle.js",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Subresource Filter\Unindexed Rules\10.34.0.84\adblock_snippet.js",

    # Discord - metadados .winmd (a pasta app-X muda a cada update)
    "C:\Users\*\AppData\Local\Discord\app-*\*.winmd",
    "C:\Users\*\AppData\Roaming\Discord\app-*\*.winmd"
)

Write-Host "[*] Analisando possíveis arquivos suspeitos em pastas legítimas ( chrome, obs-studio, etc... )" -ForegroundColor Cyan
Write-Host "Scanneando arquivos..." -ForegroundColor Red

$pastasEncontradas = @()

foreach ($local in $locais) {
    if (Test-Path $local) {
        foreach ($nome in $nomesApps) {
            $caminho = Join-Path $local $nome

            if (Test-Path $caminho) {
                $pastasEncontradas += $caminho
            }
        }
    }
}

$pastasEncontradas = $pastasEncontradas | Sort-Object -Unique

foreach ($pasta in $pastasEncontradas) {
    Write-Host "[ANALISANDO] $pasta" -ForegroundColor Cyan

    Get-ChildItem -Path $pasta -File -Recurse -Force -ErrorAction SilentlyContinue |
    ForEach-Object {
        try {
            if (Test-WhitelistedFile -Path $_.FullName) {
                return
            }

            if ($_.Extension -ieq ".js") {
                return
            }

            $assinatura = Get-AuthenticodeSignature -FilePath $_.FullName -ErrorAction SilentlyContinue

            if ($assinatura.Status -eq "NotSigned") {

                if ($unsignedReported.Add($_.FullName)) {
                    Write-Host "[SEM ASSINATURA] $($_.FullName)" -ForegroundColor Yellow
                }
            }
        } catch {}
    }
}

Write-Host "[APP SCANNER] Análise concluída." -ForegroundColor Green

Write-Host "`n[*] UNSIGNED MODULES (SYSMON ID 7 AFTER BOOT)" -ForegroundColor Cyan

# Whitelists usam o perfil do usuario atual (%USERNAME%/%USERPROFILE%)
# para nao ficarem presas a um nome especifico.
$whitelistUsername = [Environment]::ExpandEnvironmentVariables("%USERNAME%")
$whitelistUserProfile = [Environment]::ExpandEnvironmentVariables("%USERPROFILE%")
$whitelistLocalAppData = [Environment]::ExpandEnvironmentVariables("%LOCALAPPDATA%")
$whitelistProgramFiles = [Environment]::ExpandEnvironmentVariables("%ProgramFiles%")
$whitelistProgramFilesX86 = [Environment]::ExpandEnvironmentVariables("%ProgramFiles(x86)%")

if ([string]::IsNullOrWhiteSpace($whitelistUserProfile)) {
    $whitelistUserProfile = "C:\Users\$whitelistUsername"
}

if ([string]::IsNullOrWhiteSpace($whitelistLocalAppData)) {
    $whitelistLocalAppData = "$whitelistUserProfile\AppData\Local"
}

# Whitelist do campo ImageLoaded do Sysmon ID 7.
# As versoes de aplicativos sao mantidas como wildcard.
$imageLoadedWhitelist = @(
    "$whitelistUserProfile\Downloads\PIN-*.exe",
    "$whitelistUserProfile\Downloads\vibranceGUI.exe",
    "$whitelistProgramFiles\WindowsApps\Microsoft.ZuneVideo_*\*",
    "$whitelistProgramFilesX86\Microsoft\Copilot\Application\*\bho\*",
    "$whitelistProgramFilesX86\Microsoft\EdgeWebView\Application\*\undocked_copilot\*",

    # Shockwave / Macromed (plugins legados da Adobe, sem assinatura)
    "C:\Windows\SysWOW64\Macromed\Shockwave *\*",
    "C:\Windows\SysWOW64\Adobe\Shockwave *\*",
    "C:\Windows\System32\Macromed\Shockwave *\*",
    "C:\Windows\System32\Adobe\Shockwave *\*",

    # GAC do .NET (assemblies de framework nao carregam assinatura Authenticode)
    "C:\Windows\Microsoft.NET\assembly\*",

    # Jogos / launchers - arquivos de usuario (mods, bibliotecas, cliente)
    "C:\Users\*\curseforge\*",
    "C:\Users\*\AppData\Roaming\.minecraft\*",
    "C:\Users\*\AppData\Local\RedM\*",
    "C:\Users\*\AppData\Local\Programs\Hydra\*",
    "C:\Users\*\AppData\Local\Roblox\Versions\*\datadog_profiling_ffi.dll",
    "C:\Users\*\AppData\Local\Roblox\Versions\*\dd-win-prof.dll",
    "C:\Users\*\AppData\Local\Temp\webp-imageio-*.dll"
)

$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

try {

    $events = Get-WinEvent -FilterHashtable @{
        LogName   = "Microsoft-Windows-Sysmon/Operational"
        Id        = 7
        StartTime = $boot
    } -ErrorAction Stop

    $count = 0
    $repetidos = 0

    # O Sysmon ID 7 gera um evento por carregamento: o mesmo modulo carregado
    # 50x aparece uma unica vez aqui (as repeticoes sao contadas em $repetidos).
    $seenModules = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    foreach ($evt in $events) {

        $xml = [xml]$evt.ToXml()

        $data = @{}

        foreach ($d in $xml.Event.EventData.Data) {
            $data[$d.Name] = [string]$d.'#text'
        }

        $path   = $data["ImageLoaded"]
        $signed = $data["Signed"].Trim().ToLowerInvariant()
        $sig    = $data["Signature"].Trim()
        $status = $data["SignatureStatus"].Trim().ToLowerInvariant()

        if ([string]::IsNullOrWhiteSpace($path)) {
            continue
        }

        $isWhitelistedImage = $false

        foreach ($whitelistPath in $imageLoadedWhitelist) {

            if ($path -like $whitelistPath) {
                $isWhitelistedImage = $true
                break
            }
        }

        if ($isWhitelistedImage) {
            continue
        }

        # ============================================================
        # IGNORAR POWERSHELL.EXE
        # ============================================================

        if ($path -ieq "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe") {
            continue
        }

        # ============================================================
        # IGNORAR QUALQUER Sysmon.exe
        # ============================================================

        if ([IO.Path]::GetFileName($path) -ieq "Sysmon.exe") {
            continue
        }

        # ============================================================
        # IGNORAR C:\Windows\assembly\ E TUDO DENTRO DELA
        # ============================================================

        if ($path -like "C:\Windows\assembly\*") {
            continue
        }

        # ============================================================
        # VERIFICAR SOMENTE OS 3 CAMPOS
        # ============================================================

        if ($signed -ne "false") {
            continue
        }

        # Mesmo modulo ja reportado nesta execucao: imprime 1x so.
        if (-not $seenModules.Add($path)) {
            $repetidos++
            continue
        }

        $count++

        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Red
        Write-Host "[!] UNSIGNED MODULE DETECTED" -ForegroundColor Red
        Write-Host "==================================================" -ForegroundColor Red

        Write-Host "Time            : $($evt.TimeCreated)" -ForegroundColor Yellow
        Write-Host "Image           : $($data["Image"])" -ForegroundColor Yellow
        Write-Host "ImageLoaded     : $path" -ForegroundColor White
        Write-Host "ProcessId       : $($data["ProcessId"])" -ForegroundColor White
        Write-Host "Signed          : $($data["Signed"])" -ForegroundColor Red
        Write-Host "Signature       : $($data["Signature"])" -ForegroundColor Red
        Write-Host "SignatureStatus : $($data["SignatureStatus"])" -ForegroundColor Red

        Write-Host "==================================================" -ForegroundColor Red
    }

    Write-Host ""

    if ($count -eq 0) {
        Write-Host "[+] No matching modules found." -ForegroundColor Green
    }
    else {
        Write-Host "[!] Total matches: $count" -ForegroundColor Red
    }

    if ($repetidos -gt 0) {
        Write-Host "[*] Eventos repetidos do mesmo modulo ignorados: $repetidos" -ForegroundColor DarkGray
    }

}
catch {
    Write-Host ""
    Write-Host "[!] Could not read Sysmon Event ID 7." -ForegroundColor Yellow
    Write-Host $_.Exception.Message -ForegroundColor DarkYellow
}

Write-Host "`n[ID 1] Rundll32/Regsvr32 / Commands / LOLBin Execution" -ForegroundColor Cyan

try {

    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

    $CommandEvents = Get-WinEvent -FilterHashtable @{
        LogName   = "Microsoft-Windows-Sysmon/Operational"
        Id        = 1
        StartTime = $boot
    } -ErrorAction Stop

    # Whitelist estreita dos comandos benignos observados no Sysmon ID 1.
    # As regras exigem o processo pai e/ou o comando exatos para nao
    # liberar qualquer LOLBin com o mesmo nome.
    $CommandWhitelist = @(
        [PSCustomObject]@{
            Name        = "AMD - inventario de aplicativos"
            ParentImage = "C:\Program Files\AMD\CNext\CNext\RadeonSoftware.exe"
            Image       = "powershell.exe"
            CommandLine = '(?i)\bGet-AppxPackage\b'
        },

        [PSCustomObject]@{
            Name        = "AMD - Ryzen Master"
            ParentImage = "C:\Program Files\AMD\CNext\CNext\RadeonSoftware.exe"
            Image       = "cmd.exe"
            CommandLine = '(?i)\bschtasks(?:\.exe)?\s+/run\s+/tn\s+"?AMDRyzenMasterSDKTask"?(?:["\s]|$)'
        },

        [PSCustomObject]@{
            Name        = "AMD - RSServCmd"
            ParentImage = "C:\Program Files\AMD\CNext\CNext\RSServCmd.exe"
            Image       = "cmd.exe"
            CommandLine = '(?i)\bAMDRSServ\.exe\b'
        },

        [PSCustomObject]@{
            Name        = "BlueStacks - catalogo Winsock"
            ParentImage = "C:\Program Files\BlueStacks_msi5\HD-Player.exe"
            Image       = "cmd.exe"
            CommandLine = '(?i)\bnetsh(?:\.exe)?\s+winsock\s+show\s+catalog\b'
        },

        [PSCustomObject]@{
            Name               = "DCOM local server"
            ParentImage        = "C:\Windows\System32\svchost.exe"
            Image              = "rundll32.exe"
            ParentCommandLine  = '(?i)(?:^|\s)-k\s+DcomLaunch(?:\s|$)'
            CommandLine        = '(?i)\bshell32\.dll,SHCreateLocalServerRunDll\s+\{(?:9AA46009-3CE0-458A-A354-715610A075E6|9BA05972-F6A8-11CF-A442-00A0C90A8F39)\}\s+-Embedding\b'
        },

        [PSCustomObject]@{
            Name              = "Scanner-Basic update"
            ParentImage       = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
            Image             = "powershell.exe"
            DecodedCommand    = '(?i)\birm\b\s+https://raw/githubuserconuent\.com/dnbbs/Scanners-Basic/main/Scanner-Basic\.ps1\s*\|\s*iex\b'
        }
    )

    foreach ($evt in $CommandEvents) {

        $xml = [xml]$evt.ToXml()

        $Data = @{}

        foreach ($d in $xml.Event.EventData.Data) {
            $Data[$d.Name] = [string]$d.'#text'
        }

        $image = $Data["Image"]
        $cmd   = $Data["CommandLine"]
        $parent = $Data["ParentImage"]

        if ([string]::IsNullOrWhiteSpace($image)) {
            continue
        }

        $fileName = [IO.Path]::GetFileName($image)

        $isRundll32   = $fileName -ieq "rundll32.exe"
        $isRegsvr32   = $fileName -ieq "regsvr32.exe"
        $isCmd        = $fileName -ieq "cmd.exe"
        $isPowerShell = (
            $fileName -ieq "powershell.exe" -or
            $fileName -ieq "pwsh.exe"
        )

        if (-not ($isRundll32 -or $isRegsvr32 -or $isCmd -or $isPowerShell)) {
            continue
        }

        $Skip = $false

        $parentCmd = $Data["ParentCommandLine"]
        $decodedCommand = $null

        if (
            $isPowerShell -and
            $cmd -match '(?i)(?:-enc|-encodedcommand)\s+([A-Za-z0-9+/=]+)'
        ) {
            try {
                $decodedCommand = [Text.Encoding]::Unicode.GetString(
                    [Convert]::FromBase64String($Matches[1])
                )
            }
            catch {}
        }

        foreach ($rule in $CommandWhitelist) {

            if ($rule.ParentImage -and $parent -ine $rule.ParentImage) {
                continue
            }

            if ($rule.Image -and $fileName -ine $rule.Image) {
                continue
            }

            if (
                $rule.ParentCommandLine -and
                $parentCmd -notmatch $rule.ParentCommandLine
            ) {
                continue
            }

            if (
                $rule.CommandLine -and
                $cmd -notmatch $rule.CommandLine
            ) {
                continue
            }

            if (
                $rule.DecodedCommand -and
                $decodedCommand -notmatch $rule.DecodedCommand
            ) {
                continue
            }

            $Skip = $true
            break
        }

        if (
            $isPowerShell -and
            $parent -ieq "C:\Windows\System32\CompatTelRunner.exe" -and
            $cmd -match "Final result:"
        ) {
            $Skip = $true
        }

        if (
            $isRundll32 -and
            $cmd -match "PcaSvc\.dll,PcaPatchSdbTask"
        ) {
            $Skip = $true
        }

        if (
            $isPowerShell -and
            $parent -ieq "C:\Windows\explorer.exe"
        ) {
            $Skip = $true
        }

        if (
            $isCmd -and
            $parent -ieq "C:\Windows\explorer.exe" -and
            ($cmd -match '^\s*"?C:\\Windows\\system32\\cmd\.exe"?\s*$')
        ) {
            $Skip = $true
        }

        if (
            $parent -match '(?i)^' + [regex]::Escape($whitelistUserProfile) + '\\Downloads\\[^\\]+\.exe$'
        ) {

            if (
                $isPowerShell -and
                $cmd -match '(?i)\.\\Sysmon\.exe\s+-i\s+-accepteula'
            ) {
                $Skip = $true
            }

            if (
                $isPowerShell -and
                $cmd -match '(?i)\.\\Sysmon\.exe\s+-c\s+[^\\\s]+\.xml'
            ) {
                $Skip = $true
            }

            if (
                $isCmd -and
                $cmd -match '(?i)\.bat'
            ) {
                $Skip = $true
            }

            if (
                $isPowerShell -and
                $cmd -match '(?i)Start-Process\s+cmd\.exe' -and
                $cmd -match '(?i)wevtutil\s+sl\s+"?Microsoft-Windows-Sysmon/Operational"?\s+/ms:1073741824\s+/rt:false\s+/ab:false' -and
                $cmd -match '(?i)-WindowStyle\s+Hidden' -and
                $cmd -match '(?i)-Verb\s+RunAs'
            ) {
                $Skip = $true
            }
        }

        if (
            $isRundll32 -and
            $parent -ieq "C:\Windows\System32\svchost.exe" -and
            $parentCmd -match '(?i)-k\s+wsappx\s+-p\s+-s\s+AppXSvc' -and
            $cmd -match '(?i)AppXDeploymentExtensions\.OneCore\.dll,ShellRefresh'
        ) {
            $Skip = $true
        }

        if (
            $isCmd -and
            $cmd -match '(?i)wevtutil\s+sl\s+"?Microsoft-Windows-Sysmon/Operational"?'
        ) {
            $Skip = $true
        }

        if (
            $isPowerShell -and
            $cmd -match '(?i)wevtutil\s+sl\s+"?Microsoft-Windows-Sysmon/Operational"?'
        ) {
            $Skip = $true
        }

        if ($Skip) {
            continue
        }

        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Yellow
        Write-Host "[!] COMMAND EXECUTION DETECTED" -ForegroundColor Yellow
        Write-Host "==================================================" -ForegroundColor Yellow

        Write-Host "Time         : $($evt.TimeCreated)"
        Write-Host "Image        : $image" -ForegroundColor White
        Write-Host "CommandLine  : $cmd" -ForegroundColor White
        Write-Host "ProcessId    : $($Data["ProcessId"])"
        Write-Host "ParentImage  : $parent"
        Write-Host "ParentCmd    : $($Data["ParentCommandLine"])"

        if ($isRundll32) {
            Write-Host "Type         : rundll32.exe" -ForegroundColor Red
        }
        elseif ($isRegsvr32) {
            Write-Host "Type         : regsvr32.exe" -ForegroundColor Red
        }
        elseif ($isCmd) {
            Write-Host "Type         : cmd.exe" -ForegroundColor Red
        }
        elseif ($isPowerShell) {
            Write-Host "Type         : PowerShell" -ForegroundColor Red
        }

        Write-Host "==================================================" -ForegroundColor Yellow
    }

}
catch {
    Write-Host "Failed to read Sysmon Event ID 1 command execution events." -ForegroundColor Red
}

Write-Host "`n[ID 10] Process Access - HD-Player" -ForegroundColor Cyan

try {

    $BootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

    $SuspiciousAccess = @(
        "0x143A",
        "0x1F0FFF",
        "0x1FFFFF",
        "0x1F3FFF",
        "0x001F0FFF",
        "UNKNOWN"
    )

    $ProcessWhitelist = @(
        "svchost.exe",
        "csrss.exe"
    )

    # Busca TODOS os eventos ID 10 desde o boot
    $Events = Get-WinEvent -FilterHashtable @{
        LogName   = "Microsoft-Windows-Sysmon/Operational"
        Id        = 10
        StartTime = $BootTime
    } -ErrorAction SilentlyContinue

    $Found = $false

    foreach ($Evt in $Events) {

        $Xml = [xml]$Evt.ToXml()

        $Data = @{}

        foreach ($Item in $Xml.Event.EventData.Data) {
            $Data[$Item.Name] = $Item.'#text'
        }

        # Verifica se existe TargetImage
        if ([string]::IsNullOrWhiteSpace($Data["TargetImage"])) {
            continue
        }

        # Somente HD-Player
        if ($Data["TargetImage"] -notlike "*HD-Player.exe*") {
            continue
        }

        # Verifica SourceImage
        if ([string]::IsNullOrWhiteSpace($Data["SourceImage"])) {
            continue
        }

        $SourceExe = [System.IO.Path]::GetFileName(
            $Data["SourceImage"]
        ).ToLower()

        # Whitelist
        if ($SourceExe -in $ProcessWhitelist) {
            continue
        }

        # GrantedAccess
        $GrantedAccess = $Data["GrantedAccess"]

        if ([string]::IsNullOrWhiteSpace($GrantedAccess)) {
            continue
        }

        # Detecta os acessos definidos + qualquer UNKNOWN
        if (
            ($GrantedAccess -notin $SuspiciousAccess) -and
            ($GrantedAccess -ne "UNKNOWN")
        ) {
            continue
        }

        $Found = $true

        Write-Host ""
        Write-Host "========================================" -ForegroundColor DarkGray
        Write-Host "[!] HD-PLAYER - PROCESS ACCESS" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor DarkGray

        Write-Host "Time           : $($Evt.TimeCreated)"
        Write-Host "Source Process : $($Data["SourceImage"])"
        Write-Host "Target Process : $($Data["TargetImage"])"
        Write-Host "Source PID     : $($Data["SourceProcessId"])"
        Write-Host "Target PID     : $($Data["TargetProcessId"])"
        Write-Host "GrantedAccess  : $GrantedAccess"

        if (-not [string]::IsNullOrWhiteSpace($Data["CallTrace"])) {
            Write-Host "CallTrace      : $($Data["CallTrace"])"
        }

        if (-not [string]::IsNullOrWhiteSpace($Data["SourceUser"])) {
            Write-Host "Source User    : $($Data["SourceUser"])"
        }

        if (-not [string]::IsNullOrWhiteSpace($Data["TargetUser"])) {
            Write-Host "Target User    : $($Data["TargetUser"])"
        }
    }

    if (-not $Found) {
        Write-Host ""
        Write-Host "[OK] Nenhum acesso correspondente encontrado no HD-Player." -ForegroundColor Green
    }

}
catch {

    Write-Host ""
    Write-Host "[ERRO] Falha ao ler os eventos do Sysmon ID 10:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
}

Write-Host "`n[ID 5] Processos Terminados - Ultimos 10 Minutos" -ForegroundColor Cyan

try {

    $Now = Get-Date
    $TenMinutesAgo = $Now.AddMinutes(-10)

    Write-Host ""
    Write-Host "Inicio da busca : $TenMinutesAgo"
    Write-Host "Execucao        : $Now"

    $ProcessWhitelist = @(
        "discord.exe",
        "updater.exe",
        "discordptb.exe",
        "taskkill.exe",
        "cmd.exe",
        "fsutil.exe",
        "conhost.exe",
        "cncmd.exe",

        "svchost.exe",
        "csrss.exe",
        "dwm.exe",
        "RuntimeBroker.exe",
        "SearchHost.exe",
        "StartMenuExperienceHost.exe",
        "ShellExperienceHost.exe",
        "TextInputHost.exe",
        "ctfmon.exe",
        "spoolsv.exe",
        "WmiPrvSE.exe"
    )

    $Events = Get-WinEvent -FilterHashtable @{
        LogName   = "Microsoft-Windows-Sysmon/Operational"
        Id        = 5
        StartTime = $TenMinutesAgo
        EndTime   = $Now
    } -ErrorAction SilentlyContinue

    $DisplayedProcesses = @{}

    $Found = $false

    foreach ($Evt in $Events) {

        $Xml = [xml]$Evt.ToXml()

        $Data = @{}

        foreach ($Item in $Xml.Event.EventData.Data) {
            $Data[$Item.Name] = $Item.'#text'
        }


        if ([string]::IsNullOrWhiteSpace($Data["Image"])) {
            continue
        }


        $ProcessName = [System.IO.Path]::GetFileName(
            $Data["Image"]
        ).ToLower()


        if ($ProcessName -in $ProcessWhitelist) {
            continue
        }

        $ProcessGuid = $Data["ProcessGuid"]

        if ([string]::IsNullOrWhiteSpace($ProcessGuid)) {

            $ProcessGuid = "$($Data["Image"])|$($Data["ProcessId"])"
        }

        if ($DisplayedProcesses.ContainsKey($ProcessGuid)) {
            continue
        }

        $DisplayedProcesses[$ProcessGuid] = $true


        $Found = $true

        Write-Host ""
        Write-Host "========================================" -ForegroundColor DarkGray
        Write-Host "[!] PROCESSO TERMINADO" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor DarkGray

        Write-Host "Time     : $($Evt.TimeCreated)"
        Write-Host "Processo : $($Data["Image"])"
        Write-Host "PID      : $($Data["ProcessId"])"


        if ($Data["User"]) {
            Write-Host "User     : $($Data["User"])"
        }


        if ($Data["UtcTime"]) {
            Write-Host "UTC Time : $($Data["UtcTime"])"
        }


        if ($Data["ProcessGuid"]) {
            Write-Host "GUID     : $($Data["ProcessGuid"])"
        }
    }


    if (-not $Found) {

        Write-Host ""
        Write-Host "[OK] Nenhum processo terminado fora da whitelist nos ultimos 10 minutos." -ForegroundColor Green
    }

}
catch {

    Write-Host ""
    Write-Host "[ERRO] Falha ao ler Sysmon ID 5:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
}

<#
.SYNOPSIS
    Audita logs de boot e arquivos EFI para detectar anomalias (bootkit/cheat via .efi).
.DESCRIPTION
    Verifica Secure Boot, entradas BCD, eventos Kernel-Boot/Code Integrity
    e inventaria .efi na particao ESP com assinatura digital e hash SHA256.
#>

[int]$Dias = 30

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

Write-Host "[6] Arquivos .efi na particao ESP" -ForegroundColor Yellow
$espPath = $null
$espLetter = $null

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

# Whitelist compartilhada entre o REGISTRY TRACE e o AMCACHE FORENSIC:
# instaladores, jogos e apps da Store que nao carregam assinatura Authenticode.
# O caminho vem das chaves Store/AppSwitched/ShowJumpView e do Amcache.
$trustedExePaths = @(
    # Steam - qualquer biblioteca (jogos e _commonredist)
    "*:\SteamLibrary\steamapps\common\*",
    "*:\Program Files\Steam\steamapps\common\*",
    "*:\Program Files (x86)\Steam\steamapps\common\*",

    # Pastas de jogo fora da Steam
    "D:\games\BOMBANANA!\*",
    "D:\Beholder1\*",
    "D:\RedDeadRedemption2\*",
    "D:\Ore Factory Squad\*",
    "D:\Satisfactory-steamrip.com\*",
    "D:\Dale and Dawson Stationery Supplies\*",

    # Pacotes da Store (EXEs stub sem assinatura)
    "C:\Program Files\WindowsApps\*",

    # Programas instalados com EXEs proprios sem assinatura
    "C:\Program Files (x86)\ASRock Utility\*",
    "C:\Program Files (x86)\Common Files\BattlEye\*",
    "C:\Program Files\Common Files\BattlEye\*",
    "C:\Program Files\Common Files\Discord\*",
    "C:\Program Files\Electronic Arts\*",
    "C:\Program Files\Epic Games\Launcher\Portal\Extras\Overlay\*",
    "C:\Program Files\Voicemod V3\*",
    "C:\Program Files\AMD\*",

    # Hydra (launcher)
    "C:\Users\*\AppData\Local\Programs\Hydra\*",
    "C:\Users\*\AppData\Local\HydraLauncher-updater\*",
    "C:\Users\*\AppData\Roaming\HydraLauncher\*",

    # Medal / Roblox / Voicemod / EasyAntiCheat (qualquer perfil de usuario)
    "C:\Users\*\AppData\Local\Medal\*",
    "C:\Users\*\AppData\Local\Roblox\*",
    "C:\Users\*\AppData\Local\Temp\Roblox\*",
    "C:\Users\*\AppData\Local\VoicemodV3\*",
    "C:\Users\*\AppData\Roaming\EasyAntiCheat\*",

    # Downloads: somente instaladores ja identificados.
    # Qualquer outro .exe baixado continua aparecendo.
    "C:\Users\*\Downloads\ReShade_Setup_*.exe",
    "C:\Users\*\Downloads\aio-runtimes*.exe",
    "C:\Users\*\Downloads\JournalTrace.exe",
    "C:\Users\*\Downloads\hydra-installer.exe",
    "C:\Users\*\Downloads\pbucon.exe",
    "C:\Users\*\Downloads\pbsetup\*",
    "C:\Users\*\Downloads\phasmophobia - steamgg.net\*",
    "C:\Users\*\Downloads\voicemodinstaller_*.exe",
    "C:\Users\*\OneDrive\*aio-runtimes*.exe",

    # Ferramentas, caches de instalador e pastas do Windows
    "C:\AiO-Files\*",
    "C:\ProgramData\package cache\*",
    "C:\ProgramData\Microsoft\Windows Defender\platform\*",
    "C:\Windows\System32\DriverStore\*",
    "C:\Windows\WinSxS\*",
    "C:\Windows\Temp\*",
    "*:\WPSystem\*"
)

function Test-TrustedExePath {
    param(
        [string]$Path
    )

    foreach ($item in $trustedExePaths) {

        if ($item.Contains("*") -or $item.Contains("?")) {

            if ($Path -like $item) {
                return $true
            }

            continue
        }

        if ($Path.StartsWith($item, [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

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

            if($Path -notlike "*.exe") { continue }

            if(!(Test-Path $Path)) { continue }

            if(Test-TrustedExePath -Path $Path) { continue }

            try
            {
                $Item = Get-Item $Path -ErrorAction Stop

                $Sig = Get-AuthenticodeSignature $Path

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

Write-Host ""
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host " UNSIGNED EXECUTABLES ONLY" -ForegroundColor Cyan
Write-Host " (REGISTRY TRACE)" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# O mesmo EXE e registrado em varias chaves (Store, AppSwitched,
# ShowJumpView) e aparecia repetido na tabela: agrupa por caminho e junta as
# fontes numa linha so.
$registryResults = @()

foreach ($group in ($Results | Group-Object -Property FullPath)) {

    $last = $group.Group | Sort-Object LastSeen -Descending | Select-Object -First 1

    $registryResults += [PSCustomObject]@{
        FileName  = $last.FileName
        FullPath  = $last.FullPath
        Signature = $last.Signature
        Registry  = ($group.Group.Registry | Sort-Object -Unique) -join ", "
        LastSeen  = $last.LastSeen
    }
}

$registryResults = @($registryResults | Sort-Object LastSeen -Descending)

if($registryResults.Count -eq 0)
{
    Write-Host "[+] Nenhum executÃ¡vel nÃ£o assinado encontrado." -ForegroundColor Green
}
else
{
    Write-Host "Executaveis unicos: $($registryResults.Count)  (eventos na chave: $($Results.Count))" -ForegroundColor DarkGray
    Write-Host ""

    $registryResults |
    Format-Table FileName,Signature,LastSeen,Registry -AutoSize

    Write-Host ""
    Write-Host "Detalhes completos:" -ForegroundColor Yellow
    Write-Host ""

    $registryResults |
    Select-Object FileName,FullPath,Signature,Registry,LastSeen |
    Format-List
}

if (-not ("AmcacheCS" -as [type])) {
    Add-Type @"
using System;
using System.Diagnostics;

public static class AmcacheCS
{
    public static string Run(string file, string args)
    {
        using (var p = new Process())
        {
            p.StartInfo.FileName = file;
            p.StartInfo.Arguments = args;
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.CreateNoWindow = true;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;

            p.Start();

            string output = p.StandardOutput.ReadToEnd();
            string error = p.StandardError.ReadToEnd();

            p.WaitForExit();

            return output + error;
        }
    }
}
"@
}

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "=============================================="
Write-Host "          AMCACHE FORENSIC SCANNER"
Write-Host "=============================================="
Write-Host ""

$shadow = "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2"
$source = "$shadow\Windows\AppCompat\Programs\Amcache.hve"
$key = "HKLM\AMCACHE_FORENSIC"

$tempPattern = Join-Path $env:TEMP "Amcache_Forensic.hve*"

$whitelist = @(
    "C:\Program Files\WindowsApps\Microsoft.549981c3f5f10_1.1911.21713.0_x64__8wekyb3d8bbwe\",
    "C:\Program Files\WindowsApps\Microsoft.BingWeather_",
    "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_",
    "C:\Program Files\WindowsApps\Microsoft.GetHelp_",
    "C:\Program Files\WindowsApps\Microsoft.GetStarted_",
    "C:\Program Files\WindowsApps\Microsoft.HEIFImageExtension_",
    "C:\Program Files\WindowsApps\Microsoft.Microsoft3DViewer_",
    "C:\Program Files\WindowsApps\Microsoft.MicrosoftSolitaireCollection_",
    "C:\Program Files\WindowsApps\Microsoft.MicrosoftStickyNotes_",
    "C:\Program Files\WindowsApps\Microsoft.MixedReality.Portal_",
    "C:\Program Files\WindowsApps\Microsoft.MSPaint_",
    "C:\Program Files\WindowsApps\Microsoft.People_",
    "C:\Program Files\WindowsApps\Microsoft.ScreenSketch_",
    "C:\Program Files\WindowsApps\Microsoft.SkypeApp_",
    "C:\Program Files\WindowsApps\Microsoft.StorePurchaseApp_",
    "C:\Program Files\WindowsApps\Microsoft.VP9VideoExtensions_",
    "C:\Program Files\WindowsApps\Microsoft.Wallet_",
    "C:\Program Files\WindowsApps\Microsoft.WebMediaExtensions_",
    "C:\Program Files\WindowsApps\Microsoft.WebpImageExtension_",
    "C:\Program Files\WindowsApps\Microsoft.Windows.Photos_",
    "C:\Program Files\WindowsApps\Microsoft.WindowsAlarms_",
    "C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_",
    "C:\Program Files\WindowsApps\Microsoft.WindowsCamera_",
    "C:\Program Files\WindowsApps\Microsoft.WindowsCommunicationsApps_",
    "C:\Program Files\WindowsApps\Microsoft.WindowsFeedbackHub_",
    "C:\Program Files\WindowsApps\Microsoft.WindowsMaps_",
    "C:\Program Files\WindowsApps\Microsoft.WindowsSoundRecorder_",
    "C:\Program Files\WindowsApps\Microsoft.WindowsStore_",
    "C:\Program Files\WindowsApps\Microsoft.Xbox.TCUI_",
    "C:\Program Files\WindowsApps\Microsoft.XboxApp_",
    "C:\Program Files\WindowsApps\Microsoft.XboxGameOverlay_",
    "C:\Program Files\WindowsApps\Microsoft.XboxGamingOverlay_",
    "C:\Program Files\WindowsApps\Microsoft.XboxIdentityProvider_",
    "C:\Program Files\WindowsApps\Microsoft.XboxSpeechToTextOverlay_",
    "C:\Program Files\WindowsApps\Microsoft.YourPhone_",
    "C:\Program Files\WindowsApps\Microsoft.ZuneMusic_",
    "C:\Program Files\WindowsApps\Microsoft.ZuneVideo_",
    "C:\AMD\",
    "C:\Program Files\AMD\",

    # Perfil do usuario atual; usa %USERPROFILE%/%USERNAME% em vez de
    # fixar um usuario especifico.
    "$whitelistLocalAppData\Microsoft\OneDrive\",
    "$whitelistLocalAppData\Python\PythonCore-",

    # Microsoft Copilot (inclui o diretório bho)
    "$whitelistProgramFilesX86\Microsoft\Copilot\Application\*\bho\",

    # Ghost Toolbox
    "C:\Ghost Toolbox\",

    # 7-Zip
    "C:\Program Files\7-Zip\",

    # CPU-Z
    "C:\Program Files\CPUID\",

    # OBS Studio
    "C:\Program Files\OBS Studio\",

    # IObit Driver Booster
    "C:\ProgramData\IObitDriverBooster\",

    # Microsoft Edge Core
    "C:\Program Files (x86)\Microsoft\EdgeCore\",

    # Microsoft Edge Update
    "C:\Program Files (x86)\Microsoft\EdgeUpdate\",

    # Microsoft Edge WebView (inclui undocked_copilot)
    "C:\Program Files (x86)\Microsoft\EdgeWebView\",
    "$whitelistProgramFilesX86\Microsoft\EdgeWebView\Application\*\undocked_copilot\",

    # Google Chrome
    "C:\Program Files\Google\Chrome\",

    # Discord
    "$whitelistLocalAppData\Discord\",

    # FiveM
    "$whitelistLocalAppData\FiveM\"
)

# Reutiliza no Amcache as mesmas entradas do ImageLoaded, incluindo
# PIN/vibranceGUI e os diretorios do Copilot/Edge especificados acima.
$whitelist += $imageLoadedWhitelist

# E as mesmas entradas do REGISTRY TRACE (jogos, Store, instaladores).
$whitelist += $trustedExePaths

# Entradas da Amcache que apontam para arquivos ja removidos (versoes antigas
# do Edge, pacotes da Store e patch do Windows Update). O "*" cobre a pasta da
# versao, para nao voltar a apitar quando o programa atualizar.
$whitelist += @(
    # Microsoft Edge
    "$whitelistProgramFilesX86\Microsoft\Edge\Application\*\bho\ie_to_edge_stub.exe",
    "$whitelistProgramFilesX86\Microsoft\Edge\Application\*\cookie_exporter.exe",
    "$whitelistProgramFilesX86\Microsoft\Edge\Application\*\elevated_tracing_service.exe",
    "$whitelistProgramFilesX86\Microsoft\Edge\Application\*\elevation_service.exe",
    "$whitelistProgramFilesX86\Microsoft\Edge\Application\*\identity_helper.exe",
    "$whitelistProgramFilesX86\Microsoft\Edge\Application\*\installer\setup.exe",
    "$whitelistProgramFilesX86\Microsoft\Edge\Application\*\msedge.exe",
    "$whitelistProgramFilesX86\Microsoft\Edge\Application\*\msedge_proxy.exe",
    "$whitelistProgramFilesX86\Microsoft\Edge\Application\*\msedge_pwa_launcher.exe",
    "$whitelistProgramFilesX86\Microsoft\Edge\Application\*\notification_click_helper.exe",
    "$whitelistProgramFilesX86\Microsoft\Edge\Application\*\notification_helper.exe",
    "$whitelistProgramFilesX86\Microsoft\Edge\Application\*\passkey_authenticator_plugin.exe",
    "$whitelistProgramFilesX86\Microsoft\Edge\Application\*\platform_experiences_helper.exe",
    "$whitelistProgramFilesX86\Microsoft\Edge\Application\*\pwahelper.exe",

    # WindowsApps (pacotes removidos ou atualizados)
    "$whitelistProgramFiles\WindowsApps\Microsoft.BingSearch_*\MicrosoftBing.exe",
    "$whitelistProgramFiles\WindowsApps\Microsoft.MicrosoftOfficeHub_*\LocalBridge.exe",
    "$whitelistProgramFiles\WindowsApps\Microsoft.Office.Onenote_*\OneNoteIM.exe",
    "$whitelistProgramFiles\WindowsApps\Microsoft.Office.Onenote_*\OneNoteShare.exe",
    "$whitelistProgramFiles\WindowsApps\Microsoft.Windows.DevHome_*\WindowsAdvancedSettings.exe",
    "$whitelistProgramFiles\WindowsApps\Microsoft.Windows.DevHome_*\WindowsAdvancedSettingsStub\WindowsAdvancedSettings.exe",

    # Windows Update (patch ja aplicado e apagado)
    "C:\Windows\SoftwareDistribution\Download\Install\am_delta_patch_*.exe",

    # EXEs sem assinatura aceitos somente pelo caminho (sem trava de hash)
    "$whitelistUserProfile\Downloads\fcsvb*.exe",
    "$whitelistLocalAppData\kellerss\platform-tools\adb.exe"
)

function Test-Whitelist {
    param(
        [string]$Path
    )

    foreach ($item in $whitelist) {

        if ($item.Contains("*") -or $item.Contains("?")) {

            if ($Path -like $item) {
                return $true
            }

            continue
        }

        if ($item.EndsWith("\")) {

            if ($Path.StartsWith($item, [StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }

        }
        else {

            if ($Path.StartsWith($item, [StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
    }

    return $false
}

# Entrada liberada pelo SHA256, nao pelo caminho: se o binario mudar, o
# arquivo volta a apitar. O Pattern cobre qualquer pasta (inclusive as
# scoped_dir temporarias do Chrome).
$whitelistHashes = @(
    [PSCustomObject]@{
        Pattern = "*kellerss phantom*.exe"
        SHA256  = "E5AE5B8EBC7DBFEC0B15FFEA29CE4AA4015D948866559C33A9228E5261ACC07B"
    }
)

function Get-HashWhitelistEntry {
    param(
        [string]$Path
    )

    foreach ($item in $whitelistHashes) {

        if ($Path -like $item.Pattern) {
            return $item
        }
    }

    return $null
}

function Remove-TempAmcache {

    for ($i = 0; $i -lt 5; $i++) {

        Get-ChildItem $tempPattern -Force -ErrorAction SilentlyContinue |
            ForEach-Object {

                try {
                    Remove-Item `
                        -LiteralPath $_.FullName `
                        -Force `
                        -Recurse `
                        -ErrorAction Stop
                }
                catch {
                }
            }

        Start-Sleep -Milliseconds 500
    }
}

if (-not (Test-Path -LiteralPath $source)) {

    Write-Host "[!] Amcache nao encontrado na Shadow Copy." -ForegroundColor Red
    Write-Host "[!] Shadow Copy usada: $shadow" -ForegroundColor DarkYellow

    Remove-TempAmcache

    Read-Host "Pressione ENTER para sair"
    return
}

Write-Host "[+] Amcache encontrado na Shadow Copy."
Write-Host "[+] Caminho:"
Write-Host $source -ForegroundColor Cyan
Write-Host ""

Write-Host "[+] Verificando hive anterior..."

[AmcacheCS]::Run(
    "reg.exe",
    "unload `"$key`""
) | Out-Null

Write-Host "[+] Carregando hive..."
Write-Host ""

$loadOutput = [AmcacheCS]::Run(
    "reg.exe",
    "load `"$key`" `"$source`""
)

if (-not (Test-Path "HKLM:\AMCACHE_FORENSIC")) {

    Write-Host "[!] Falha ao carregar o Amcache." -ForegroundColor Red
    Write-Host ""
    Write-Host $loadOutput -ForegroundColor Red
    Write-Host ""

    Remove-TempAmcache

    Read-Host "Pressione ENTER para sair"
    return
}

Write-Host "[+] Amcache carregado com sucesso." -ForegroundColor Green
Write-Host ""

try {

    $roots = @(
        "HKLM:\AMCACHE_FORENSIC\Root\InventoryApplicationFile",
        "HKLM:\AMCACHE_FORENSIC\Root\File"
    )

    $entries = New-Object System.Collections.Generic.List[object]

    foreach ($root in $roots) {

        if (-not (Test-Path -LiteralPath $root)) {
            continue
        }

        Get-ChildItem `
            -LiteralPath $root `
            -Recurse `
            -ErrorAction SilentlyContinue |
            ForEach-Object {

                $properties = Get-ItemProperty `
                    -LiteralPath $_.PSPath `
                    -ErrorAction SilentlyContinue

                if ($null -eq $properties) {
                    return
                }

                $path = $null

                foreach ($property in $properties.PSObject.Properties) {

                    if ($property.Value -isnot [string]) {
                        continue
                    }

                    $value = $property.Value.Trim()

                    if (
                        $value -match '(?i)\.exe$' -and
                        $value -match '(?i)\\'
                    ) {
                        $path = $value
                        break
                    }
                }

                if ($path) {

                    $path = $path.Trim('"')
                    $path = $path -replace '/', '\'

                    if (-not (Test-Whitelist $path)) {

                        $entries.Add(
                            [PSCustomObject]@{
                                Path = $path
                            }
                        )
                    }
                }
            }
    }

    $entries = $entries |
        Sort-Object Path -Unique

    Write-Host "[+] Entradas encontradas: $($entries.Count)"
    Write-Host ""
    Write-Host "[+] Verificando arquivos..."
    Write-Host ""

    $foundUnsigned = 0
    $foundDeleted = 0

    foreach ($entry in $entries) {

        $file = $entry.Path

        if (Test-Whitelist $file) {
            continue
        }

        # Entrada com trava de hash: quem libera e o SHA256, nao o caminho.
        $hashEntry = Get-HashWhitelistEntry $file

        if (Test-Path -LiteralPath $file -PathType Leaf) {

            $signature = Get-AuthenticodeSignature `
                -LiteralPath $file `
                -ErrorAction SilentlyContinue

            if ($signature.Status -ne "NotSigned") {
                continue
            }

            $hash = "Nao disponivel"

            try {

                $hash = (
                    Get-FileHash `
                        -LiteralPath $file `
                        -Algorithm SHA256 `
                        -ErrorAction Stop
                ).Hash

            }
            catch {
            }

            # Binario identico ao registrado na whitelist: nao apita.
            if (
                $null -ne $hashEntry -and
                [string]::Equals(
                    $hash,
                    $hashEntry.SHA256,
                    [StringComparison]::OrdinalIgnoreCase
                )
            ) {
                continue
            }

            $foundUnsigned++

            Write-Host ""
            Write-Host "==================================================" -ForegroundColor Red
            Write-Host "[!] EXE SEM ASSINATURA" -ForegroundColor Red
            Write-Host "==================================================" -ForegroundColor Red
            Write-Host "Arquivo       : $file" -ForegroundColor Yellow
            Write-Host "SHA256        : $hash" -ForegroundColor Yellow

            if ($null -ne $hashEntry) {

                Write-Host "SHA256 esperado: $($hashEntry.SHA256)" -ForegroundColor DarkGray
                Write-Host "[!] CONTEUDO DIFERENTE DO REGISTRADO NA WHITELIST" -ForegroundColor Red
            }
        }
        else {

            # Arquivo sumiu da maquina. Sem o arquivo nao da para conferir o
            # hash, mas a entrada ja foi aceita pelo caminho, entao nao apita.
            if ($null -ne $hashEntry) {
                continue
            }

            $foundDeleted++

            Write-Host ""
            Write-Host "==================================================" -ForegroundColor DarkYellow
            Write-Host "[!] EXE DELETADO / AUSENTE" -ForegroundColor DarkYellow
            Write-Host "==================================================" -ForegroundColor DarkYellow
            Write-Host "Arquivo       : $file" -ForegroundColor Yellow
            Write-Host "SHA256        : Nao disponivel" -ForegroundColor DarkYellow
        }
    }

    Write-Host ""
    Write-Host "=================================================="
    Write-Host "RESULTADO"
    Write-Host "=================================================="
    Write-Host ""

    Write-Host "EXE sem assinatura : $foundUnsigned" -ForegroundColor Red
    Write-Host "EXE deletados      : $foundDeleted" -ForegroundColor DarkYellow
}
catch {

    Write-Host ""
    Write-Host "==================================================" -ForegroundColor Red
    Write-Host "[!] ERRO DURANTE O SCAN" -ForegroundColor Red
    Write-Host "==================================================" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
}
finally {

    Write-Host ""
    Write-Host "[+] Desmontando Amcache..."

    [AmcacheCS]::Run(
        "reg.exe",
        "unload `"$key`""
    ) | Out-Null

    Start-Sleep -Seconds 2

    Write-Host "[+] Limpando arquivos temporarios..."

    Remove-TempAmcache

    Write-Host "[+] Limpeza concluida."
    Write-Host "[+] Finalizado."
}

Write-Host ""