#Requires -RunAsAdministrator

Clear-Host


$ErrorActionPreference = "SilentlyContinue"

Write-Host @"
 
·▄▄▄▄   ▐ ▄ ▄▄▄▄· ▄▄▄▄· .▄▄ · 
██▪ ██ •█▌▐█▐█ ▀█▪▐█ ▀█▪▐█ ▀. 
▐█· ▐█▌▐█▐▐▌▐█▀▀█▄▐█▀▀█▄▄▀▀▀█▄
██. ██ ██▐█▌██▄▪▐███▄▪▐█▐█▄▪▐█
▀▀▀▀▀• ▀▀ █▪·▀▀▀▀ ·▀▀▀▀  ▀▀▀▀ 

Create By dnbbs
Discord: https://discord.gg/qdsG44Jz88                                                  
"@ -ForegroundColor Cyan

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

            if($Path -notlike "*.exe") { continue }

            if(!(Test-Path $Path)) { continue }

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

if($Results.Count -eq 0)
{
    Write-Host "[+] Nenhum executÃ¡vel nÃ£o assinado encontrado." -ForegroundColor Green
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

Write-Host "`n[*] Archives unsigned ( no .exe )" -ForegroundColor Cyan

$min = 500KB
$max = 30MB

$whitelistPastas = @(
    "C:\Windows\WinSxS",
    "C:\Windows\SoftwareDistribution",
    "C:\Windows\Installer",
    "C:\Windows\System32\DriverStore",
    "C:\Windows\Servicing",
    "C:\Windows\Logs",
    "C:\ProgramData\Microsoft\Windows\WER",
    "C:\ProgramData\Microsoft\Windows Defender",
    "C:\Program Files\WindowsApps\",
    "C:\ProgramData\Microsoft\Diagnosis",
    "C:\Windows\assembly",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows"
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
"C:\Users\rhuan\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Cache\Cache_Data\f_000664"
"C:\Users\rhuan\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data\f_000106"
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
"C:\Windows\WinSxS\x86_microsoft.vc80.mfc_1fc8b3b9a1e18e3b_8.0.50727.6195_none_cbf5e994470a1a8f\mfc80u.dll"
)

Write-Host "Scanneando arquivos..." -ForegroundColor Red

$extensoesIgnoradas = @(".exe", ".js", ".txt", ".log")

Get-ChildItem -Path "C:\" -File -Recurse -Force -ErrorAction SilentlyContinue |
Where-Object {
    $_.Length -ge $min -and
    $_.Length -le $max -and
    $extensoesIgnoradas -notcontains $_.Extension.ToLower() -and
    $whitelistArquivos -notcontains $_.FullName -and
    -not ($whitelistPastas | Where-Object { $_.FullName -like "$($_)\*" })
} |
ForEach-Object {
    try {
        $assinatura = Get-AuthenticodeSignature -FilePath $_.FullName -ErrorAction SilentlyContinue

        if ($assinatura.Status -eq "NotSigned") {
            Write-Host "[SEM ASSINATURA] $($_.FullName)" -ForegroundColor Yellow
        }
    } catch {}
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
    "C:\Users\danie\AppData\Local\Discord\app-1.0.9258\profapi.dll",
    "C:\Users\danie\AppData\Local\Google\Chrome\User Data\Default\Extensions\ghbmnnjooekpmoecnnnilnnbdlolhkhi\1.110.1_0\offscreendocument_main.js",
    "C:\Users\danie\AppData\Local\Google\Chrome\User Data\Default\Extensions\ghbmnnjooekpmoecnnnilnnbdlolhkhi\1.110.1_0\page_embed_script.js",
    "C:\Users\danie\AppData\Local\Google\Chrome\User Data\Default\Extensions\ghbmnnjooekpmoecnnnilnnbdlolhkhi\1.110.1_0\service_worker_bin_prod.js",
    "C:\Users\danie\AppData\Local\Google\Chrome\User Data\Default\Extensions\nmmhkkegccagdldgiimedpiccmgmieda\1.0.0.6_0\craw_background.js",
    "C:\Users\danie\AppData\Local\Google\Chrome\User Data\Default\Extensions\nmmhkkegccagdldgiimedpiccmgmieda\1.0.0.6_0\craw_window.js",
    "C:\Users\danie\AppData\Local\Google\Chrome\User Data\WasmTtsEngine\20260904.1\background_compiled.js",
    "C:\Users\danie\AppData\Local\Google\Chrome\User Data\WasmTtsEngine\20260904.1\bindings_main.js",
    "C:\Users\danie\AppData\Local\Google\Chrome\User Data\WasmTtsEngine\20260904.1\offscreen_compiled.js",
    "C:\Users\danie\AppData\Local\Google\Chrome\User Data\WasmTtsEngine\20260904.1\streaming_worklet_processor.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\cgjgjfacjflmgphhhepmbhhbgjieaecn\135.0.3176.0_1\DevToolsPlugin.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\cgjgjfacjflmgphhhepmbhhbgjieaecn\135.0.3176.0_1\NamedFunctionRange.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\cgjgjfacjflmgphhhepmbhhbgjieaecn\135.0.3176.0_1\third_party\typescript\typescript.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\ghbmnnjooekpmoecnnnilnnbdlolhkhi\1.110.1_1\offscreendocument_main.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\ghbmnnjooekpmoecnnnilnnbdlolhkhi\1.110.1_1\page_embed_script.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\ghbmnnjooekpmoecnnnilnnbdlolhkhi\1.110.1_1\service_worker_bin_prod.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\jmjflgjpcpepeafmmgdpfkogkghcpiha\1.2.1_1\content.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\jmjflgjpcpepeafmmgdpfkogkghcpiha\1.2.1_1\content_new.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\kfbdpdaobnofkbopebjglnaadopfikhh\113.0.1765.0_1\third_party\babylon\babylon.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\kfbdpdaobnofkbopebjglnaadopfikhh\113.0.1765.0_1\third_party\typescript\typescript.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Shopping\2.1.114.0\auto_open_controller.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Shopping\2.1.114.0\edge_checkout_page_validator.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Shopping\2.1.114.0\edge_confirmation_page_validator.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Shopping\2.1.114.0\edge_driver.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Shopping\2.1.114.0\edge_tracking_page_validator.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Shopping\2.1.114.0\product_page.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Shopping\2.1.114.0\shopping_iframe_driver.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\app-setup.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\bnpl_driver.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\buynow_driver.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\crypto.bundle.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\edge_driver.js",
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
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\load-hub-i18n.bundle.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\runtime.bundle.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\shopping_iframe_driver.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\vendor.bundle.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\wallet-webui-101.079f5d74a18127cd9d6a.chunk.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\wallet-webui-227.bb2c3c84778e2589775f.chunk.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\wallet-webui-560.da6c8914bf5007e1044c.chunk.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\wallet-webui-708.de49febeeb0e9c77883f.chunk.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\wallet-webui-792.b1180305c186d50631a2.chunk.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\wallet-webui-925.baa79171a74ad52b0a67.chunk.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\wallet-webui-992.268aa821c3090dce03cb.chunk.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\wallet.bundle.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\wallet_checkout_autofill_driver.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\wallet_donation_driver.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\webui-setup.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\bnpl\bnpl.bundle.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\Mini-Wallet\miniwallet.bundle.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\Notification\notification.bundle.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\Notification\notification_fast.bundle.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\Tokenized-Card\tokenized-card.bundle.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\Wallet-BuyNow\wallet-buynow.bundle.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\Wallet-Checkout\app-setup.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\Wallet-Checkout\load-ec-deps.bundle.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\Wallet-Checkout\load-ec-i18n.bundle.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Edge Wallet\128.18367.18366.1\Wallet-Checkout\wallet-drawer.bundle.js",
    "C:\Users\danie\AppData\Local\Microsoft\Edge\User Data\Subresource Filter\Unindexed Rules\10.34.0.84\adblock_snippet.js"
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
            if ($whitelistArquivos -contains $_.FullName) {
                return
            }

            $assinatura = Get-AuthenticodeSignature -FilePath $_.FullName -ErrorAction SilentlyContinue

            if ($assinatura.Status -eq "NotSigned") {
                Write-Host "[SEM ASSINATURA] $($_.FullName)" -ForegroundColor Yellow
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
    "$whitelistProgramFilesX86\Microsoft\EdgeWebView\Application\*\undocked_copilot\*"
)

$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

try {

    $events = Get-WinEvent -FilterHashtable @{
        LogName   = "Microsoft-Windows-Sysmon/Operational"
        Id        = 7
        StartTime = $boot
    } -ErrorAction Stop

    $count = 0

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

        if ($sig -ne "-") {
            continue
        }

        if ($status -ne "unavailable") {
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

Write-Host "`n[*] UNSIGNED KERNEL DRIVERS (.SYS)" -ForegroundColor Cyan

$drivers = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue

$unsignedDrivers = @()


foreach ($driver in $drivers) {

    $path = $driver.PathName


    if ([string]::IsNullOrWhiteSpace($path)) {
        continue
    }

    $cleanPath = $path.Replace('"','')

    if ($cleanPath -match "\.sys") {
        $cleanPath = $cleanPath.Substring(0, $cleanPath.ToLower().IndexOf(".sys") + 4)
    }


    if (-not (Test-Path $cleanPath)) {
        continue
    }


    try {

        $signature = Get-AuthenticodeSignature $cleanPath

        if ($signature.Status -ne "Valid") {


            $file = Get-Item $cleanPath


            $unsignedDrivers += [PSCustomObject]@{

                Name        = $driver.Name
                DisplayName = $driver.DisplayName
                Path        = $cleanPath
                Signature   = $signature.Status
                Created     = $file.CreationTime
                Modified    = $file.LastWriteTime
                StartMode   = $driver.StartMode
                State       = $driver.State

            }

        }

    }
    catch {}

}



if ($unsignedDrivers.Count -eq 0) {

    Write-Host "No unsigned drivers found." -ForegroundColor Green

}
else {


    foreach ($driver in $unsignedDrivers) {


        Write-Host "`n[!] UNSIGNED DRIVER FOUND" -ForegroundColor Red


        Write-Host "Name:"
        Write-Host " $($driver.Name)"


        Write-Host "Display Name:"
        Write-Host " $($driver.DisplayName)"


        Write-Host "Path:"
        Write-Host " $($driver.Path)"


        Write-Host "Signature:"
        Write-Host " $($driver.Signature)"


        Write-Host "Created:"
        Write-Host " $($driver.Created)"


        Write-Host "Modified:"
        Write-Host " $($driver.Modified)"


        Write-Host "Start Mode:"
        Write-Host " $($driver.StartMode)"


        Write-Host "State:"
        Write-Host " $($driver.State)"


        Write-Host "----------------------------------------" -ForegroundColor DarkGray

    }

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

        if (Test-Path -LiteralPath $file -PathType Leaf) {

            $signature = Get-AuthenticodeSignature `
                -LiteralPath $file `
                -ErrorAction SilentlyContinue

            if ($signature.Status -ne "NotSigned") {
                continue
            }

            $foundUnsigned++

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

            Write-Host ""
            Write-Host "==================================================" -ForegroundColor Red
            Write-Host "[!] EXE SEM ASSINATURA" -ForegroundColor Red
            Write-Host "==================================================" -ForegroundColor Red
            Write-Host "Arquivo       : $file" -ForegroundColor Yellow
            Write-Host "SHA256        : $hash" -ForegroundColor Yellow
        }
        else {

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