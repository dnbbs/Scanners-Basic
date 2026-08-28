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

$Whitelist = @(

    "*\Microsoft\Edge\User Data\Well Known Domains\*\well_known_domains.dll",
    "*\Microsoft\Edge\User Data\Domain Actions\*\domain_actions.dll",

    "*\Discord\app-*\profapi.dll",

    "*\AppData\Local\Temp\*",

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

    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

    $Whitelist = @(

        "*\msedge.exe",
        "*\C:\Program Files\WindowsApps\Microsoft.MicrosoftOfficeHub_19.2606.58031.0_x64__8wekyb3d8bbwe\",
        "*\Microsoft\Edge\Application\msedge.exe",
        "*C:\Program Files\WindowsApps\Microsoft.MicrosoftOfficeHub_19.2606.58031.0_x64__8wekyb3d8bbwe\m365copilot_autostarter.exe",

        "*\Discord\app-*\Discord.exe",
        "\ffmpeng.exe",
        "*\Discord\app-*\modules\*",

        "*\Windows\System32\atieah64.exe",

        "*\Program Files (x86)\Steam\*",

        "*\AppData\Local\Temp\*",

        "*\Program Files\WindowsApps\Microsoft.GamingServices_*\GamingServicesUI\*",

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

        $Exists = Test-Path $image

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

Write-Host "`n[ID 10] Process Access - HD-Player" -ForegroundColor Cyan

try {
    $BootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

    $SuspiciousAccess = @(
        "0x143A",
        "0x1F0FFF",
        "0x1FFFFF",
        "0x1F3FFF",
        "0x001F0FFF"
    )

    $ProcessWhitelist = @(
        "svchost.exe",
        "csrss.exe"
    )

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

        if ([string]::IsNullOrWhiteSpace($Data["TargetImage"])) {
            continue
        }

        $TargetExe = [System.IO.Path]::GetFileName(
            $Data["TargetImage"]
        ).ToLower()

        if ($TargetExe -ne "hd-player.exe") {
            continue
        }

        if ([string]::IsNullOrWhiteSpace($Data["SourceImage"])) {
            continue
        }

        $SourceExe = [System.IO.Path]::GetFileName(
            $Data["SourceImage"]
        ).ToLower()

        if ($SourceExe -in $ProcessWhitelist) {
            continue
        }

        if ($Data["GrantedAccess"] -notin $SuspiciousAccess) {
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
        Write-Host "GrantedAccess  : $($Data["GrantedAccess"])"

        if ($Data["CallTrace"]) {
            Write-Host "CallTrace      : $($Data["CallTrace"])"
        }

        if ($Data["SourceUser"]) {
            Write-Host "Source User    : $($Data["SourceUser"])"
        }

        if ($Data["TargetUser"]) {
            Write-Host "Target User    : $($Data["TargetUser"])"
        }
    }

    if (-not $Found) {
        Write-Host ""
        Write-Host "[OK] Nenhum acesso correspondente encontrado no HD-Player." -ForegroundColor Green
    }
}
catch {
    Write-Host "Erro ao ler os eventos do Sysmon ID 10: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n[ID 10] Process Access - Todos os Processos" -ForegroundColor Cyan

try {
    $BootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

    $SuspiciousAccess = @(
        "0x143A",
        "0x1F0FFF",
        "0x1FFFFF",
        "0x1F3FFF",
        "0x001F0FFF"
    )

    $ProcessWhitelist = @(
        "svchost.exe",
        "csrss.exe",
        "discord.exe",
        "discordptb.exe"
    )

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

        if ([string]::IsNullOrWhiteSpace($Data["SourceImage"])) {
            continue
        }

        if ([string]::IsNullOrWhiteSpace($Data["TargetImage"])) {
            continue
        }

        $SourceExe = [System.IO.Path]::GetFileName(
            $Data["SourceImage"]
        ).ToLower()

        if ($SourceExe -in $ProcessWhitelist) {
            continue
        }

        if ($Data["GrantedAccess"] -notin $SuspiciousAccess) {
            continue
        }

        $Found = $true

        Write-Host ""
        Write-Host "========================================" -ForegroundColor DarkGray
        Write-Host "[!] SUSPICIOUS PROCESS ACCESS" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor DarkGray

        Write-Host "Time           : $($Evt.TimeCreated)"
        Write-Host "Source Process : $($Data["SourceImage"])"
        Write-Host "Target Process : $($Data["TargetImage"])"
        Write-Host "Source PID     : $($Data["SourceProcessId"])"
        Write-Host "Target PID     : $($Data["TargetProcessId"])"
        Write-Host "GrantedAccess  : $($Data["GrantedAccess"])"

        if ($Data["CallTrace"]) {
            Write-Host "CallTrace      : $($Data["CallTrace"])"
        }

        if ($Data["SourceUser"]) {
            Write-Host "Source User    : $($Data["SourceUser"])"
        }

        if ($Data["TargetUser"]) {
            Write-Host "Target User    : $($Data["TargetUser"])"
        }
    }

    if (-not $Found) {
        Write-Host ""
        Write-Host "[OK] Nenhum acesso suspeito encontrado." -ForegroundColor Green
    }
}
catch {
    Write-Host "Erro ao ler os eventos do Sysmon ID 10: $($_.Exception.Message)" -ForegroundColor Red
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

$ErrorActionPreference = "SilentlyContinue"

$StartTime = (Get-Date).AddMinutes(-20)
$EndTime = Get-Date

$Whitelist = @(
    "RobloxPlayerInstaller.exe"
)

$Extensions = @(
    ".exe",
    ".dll",
    ".pf"
)

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "             ARQUIVOS DELETADOS OU RENOMEADOS ( .EXE + .DLL + .PF )" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "De  : $($StartTime.ToString('dd/MM/yyyy HH:mm:ss'))"
Write-Host "Ate : $($EndTime.ToString('dd/MM/yyyy HH:mm:ss'))"
Write-Host ""

if (-not ("USNReader.Native" -as [type])) {

Add-Type @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace USNReader
{
    public static class Native
    {
        const uint GENERIC_READ = 0x80000000;

        const uint FILE_SHARE_READ  = 0x00000001;
        const uint FILE_SHARE_WRITE = 0x00000002;

        const uint OPEN_EXISTING = 3;

        const uint FSCTL_QUERY_USN_JOURNAL = 0x000900f4;
        const uint FSCTL_READ_USN_JOURNAL  = 0x000900bb;

        public const uint CREATE     = 0x00000100;
        public const uint DELETE     = 0x00000200;
        public const uint RENAME_OLD = 0x00001000;
        public const uint RENAME_NEW = 0x00002000;

        [StructLayout(LayoutKind.Sequential)]
        public struct JOURNAL_DATA
        {
            public ulong UsnJournalID;
            public long FirstUsn;
            public long NextUsn;
            public long LowestValidUsn;
            public long MaxUsn;
            public ulong MaximumSize;
            public ulong AllocationDelta;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct READ_DATA
        {
            public long StartUsn;
            public uint ReasonMask;
            public uint ReturnOnlyOnClose;
            public ulong Timeout;
            public ulong BytesToWaitFor;
            public ulong UsnJournalID;
            public ushort MinMajorVersion;
            public ushort MaxMajorVersion;
        }

        [DllImport(
            "kernel32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true
        )]
        static extern SafeFileHandle CreateFile(
            string name,
            uint access,
            uint share,
            IntPtr security,
            uint creation,
            uint flags,
            IntPtr template
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DeviceIoControl(
            SafeFileHandle device,
            uint code,
            IntPtr input,
            uint inputSize,
            IntPtr output,
            uint outputSize,
            out uint returned,
            IntPtr overlapped
        );

        public class Record
        {
            public long FRN;
            public long ParentFRN;
            public long USN;
            public DateTime Time;
            public uint Reason;
            public string Name;
        }

        public static Record[] Read(string drive)
        {
            string device =
                @"\\.\" + drive.TrimEnd(':', '\\') + ":";

            using (
                SafeFileHandle h = CreateFile(
                    device,
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    IntPtr.Zero,
                    OPEN_EXISTING,
                    0,
                    IntPtr.Zero
                )
            )
            {
                if (h == null || h.IsInvalid)
                    return new Record[0];

                int journalSize =
                    Marshal.SizeOf(typeof(JOURNAL_DATA));

                IntPtr journalPtr =
                    Marshal.AllocHGlobal(journalSize);

                try
                {
                    uint returned;

                    bool query =
                        DeviceIoControl(
                            h,
                            FSCTL_QUERY_USN_JOURNAL,
                            IntPtr.Zero,
                            0,
                            journalPtr,
                            (uint)journalSize,
                            out returned,
                            IntPtr.Zero
                        );

                    if (!query)
                        return new Record[0];

                    JOURNAL_DATA journal =
                        (JOURNAL_DATA)
                        Marshal.PtrToStructure(
                            journalPtr,
                            typeof(JOURNAL_DATA)
                        );

                    READ_DATA read =
                        new READ_DATA();

                    read.StartUsn =
                        journal.FirstUsn;

                    read.ReasonMask =
                        CREATE |
                        DELETE |
                        RENAME_OLD |
                        RENAME_NEW;

                    read.ReturnOnlyOnClose = 0;
                    read.Timeout = 0;
                    read.BytesToWaitFor = 0;
                    read.UsnJournalID =
                        journal.UsnJournalID;

                    read.MinMajorVersion = 2;
                    read.MaxMajorVersion = 2;

                    int readSize =
                        Marshal.SizeOf(typeof(READ_DATA));

                    IntPtr input =
                        Marshal.AllocHGlobal(readSize);

                    try
                    {
                        Marshal.StructureToPtr(
                            read,
                            input,
                            false
                        );

                        const int BUFFER_SIZE =
                            1024 * 1024;

                        IntPtr output =
                            Marshal.AllocHGlobal(
                                BUFFER_SIZE
                            );

                        try
                        {
                            List<Record> results =
                                new List<Record>();

                            while (true)
                            {
                                uint bytesReturned;

                                bool ok =
                                    DeviceIoControl(
                                        h,
                                        FSCTL_READ_USN_JOURNAL,
                                        input,
                                        (uint)readSize,
                                        output,
                                        BUFFER_SIZE,
                                        out bytesReturned,
                                        IntPtr.Zero
                                    );

                                if (!ok ||
                                    bytesReturned <= 8)
                                    break;

                                byte[] buffer =
                                    new byte[
                                        bytesReturned
                                    ];

                                Marshal.Copy(
                                    output,
                                    buffer,
                                    0,
                                    (int)bytesReturned
                                );

                                long nextUsn =
                                    BitConverter.ToInt64(
                                        buffer,
                                        0
                                    );

                                int offset = 8;

                                while (
                                    offset + 60 <=
                                    buffer.Length
                                )
                                {
                                    uint recordLength =
                                        BitConverter.ToUInt32(
                                            buffer,
                                            offset
                                        );

                                    if (
                                        recordLength < 60 ||
                                        offset + recordLength >
                                        buffer.Length
                                    )
                                        break;

                                    ushort major =
                                        BitConverter.ToUInt16(
                                            buffer,
                                            offset + 4
                                        );

                                    if (major == 2)
                                    {
                                        long frn =
                                            BitConverter.ToInt64(
                                                buffer,
                                                offset + 8
                                            );

                                        long parentFrn =
                                            BitConverter.ToInt64(
                                                buffer,
                                                offset + 16
                                            );

                                        long usn =
                                            BitConverter.ToInt64(
                                                buffer,
                                                offset + 24
                                            );

                                        long timestamp =
                                            BitConverter.ToInt64(
                                                buffer,
                                                offset + 32
                                            );

                                        uint reason =
                                            BitConverter.ToUInt32(
                                                buffer,
                                                offset + 40
                                            );

                                        ushort nameLength =
                                            BitConverter.ToUInt16(
                                                buffer,
                                                offset + 56
                                            );

                                        ushort nameOffset =
                                            BitConverter.ToUInt16(
                                                buffer,
                                                offset + 58
                                            );

                                        string name = "";

                                        if (
                                            nameOffset +
                                            nameLength <=
                                            recordLength
                                        )
                                        {
                                            name =
                                                Encoding.Unicode.GetString(
                                                    buffer,
                                                    offset +
                                                    nameOffset,
                                                    nameLength
                                                );
                                        }

                                        DateTime time;

                                        try
                                        {
                                            time =
                                                DateTime
                                                .FromFileTimeUtc(
                                                    timestamp
                                                )
                                                .ToLocalTime();
                                        }
                                        catch
                                        {
                                            time =
                                                DateTime.MinValue;
                                        }

                                        results.Add(
                                            new Record
                                            {
                                                FRN =
                                                    frn,

                                                ParentFRN =
                                                    parentFrn,

                                                USN =
                                                    usn,

                                                Time =
                                                    time,

                                                Reason =
                                                    reason,

                                                Name =
                                                    name
                                            }
                                        );
                                    }

                                    offset +=
                                        (int)recordLength;
                                }

                                if (
                                    nextUsn <=
                                    read.StartUsn
                                )
                                    break;

                                if (
                                    nextUsn >=
                                    journal.NextUsn
                                )
                                    break;

                                read.StartUsn =
                                    nextUsn;

                                Marshal.WriteInt64(
                                    input,
                                    0,
                                    nextUsn
                                );
                            }

                            return results.ToArray();
                        }
                        finally
                        {
                            Marshal.FreeHGlobal(
                                output
                            );
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(
                            input
                        );
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(
                        journalPtr
                    );
                }
            }
        }
    }
}
"@
}


$Events =
    New-Object System.Collections.Generic.List[object]

$Volumes =
    Get-Volume |
    Where-Object {
        $_.DriveLetter -and
        $_.FileSystem -eq "NTFS"
    }

foreach ($Volume in $Volumes) {

    $Drive = $Volume.DriveLetter

    Write-Host "[*] Lendo USN Journal de $Drive`: ..." `
        -ForegroundColor DarkGray

    try {

        $Records =
            [USNReader.Native]::Read($Drive)

        foreach ($R in $Records) {

            if ($R.Time -lt $StartTime) {
                continue
            }

            if ($R.Time -gt $EndTime) {
                continue
            }

            $Extension =
                [System.IO.Path]::GetExtension(
                    $R.Name
                ).ToLowerInvariant()

            if ($Extension -notin $Extensions) {
                continue
            }

            if ($Whitelist -contains $R.Name) {
                continue
            }

            $Action = $null

            if (
                ($R.Reason -band
                [USNReader.Native]::CREATE) -ne 0
            ) {
                $Action = "CREATE"
            }
            elseif (
                ($R.Reason -band
                [USNReader.Native]::DELETE) -ne 0
            ) {
                $Action = "DELETE"
            }
            elseif (
                ($R.Reason -band
                [USNReader.Native]::RENAME_OLD) -ne 0
            ) {
                $Action = "RENAME_OLD"
            }
            elseif (
                ($R.Reason -band
                [USNReader.Native]::RENAME_NEW) -ne 0
            ) {
                $Action = "RENAME_NEW"
            }

            if (-not $Action) {
                continue
            }

            $Events.Add(
                [PSCustomObject]@{
                    Drive     = $Drive
                    FRN       = $R.FRN
                    ParentFRN = $R.ParentFRN
                    USN       = $R.USN
                    Time      = $R.Time
                    Action    = $Action
                    Name      = $R.Name
                }
            )
        }
    }
    catch {

        Write-Host ""
        Write-Host "[ERRO] Falha ao ler $Drive`:" `
            -ForegroundColor Red

        Write-Host $_.Exception.Message `
            -ForegroundColor DarkRed
    }
}


$Events =
    $Events |
    Sort-Object Time, USN


$Seen = @{}

$CleanEvents =
    New-Object System.Collections.Generic.List[object]

foreach ($E in $Events) {

    $Key =
        "$($E.Drive)|$($E.FRN)|$($E.Action)|$($E.Name)|$($E.Time.ToString('yyyyMMddHHmmss'))"

    if ($Seen.ContainsKey($Key)) {
        continue
    }

    $Seen[$Key] = $true

    $CleanEvents.Add($E)
}


Write-Host ""
Write-Host "============================================================" `
    -ForegroundColor Cyan

Write-Host "                     RESULTADOS" `
    -ForegroundColor Cyan

Write-Host "============================================================" `
    -ForegroundColor Cyan

$Found = $false


$Used = @{}

foreach ($Old in $CleanEvents) {

    if ($Old.Action -ne "RENAME_OLD") {
        continue
    }

    $New =
        $CleanEvents |
        Where-Object {

            $_.Action -eq "RENAME_NEW" -and
            $_.FRN -eq $Old.FRN -and
            $_.USN -gt $Old.USN

        } |
        Sort-Object USN |
        Select-Object -First 1

    if (-not $New) {
        continue
    }

    $Found = $true

    $Used[
        "$($Old.FRN)|$($Old.USN)"
    ] = $true

    $Used[
        "$($New.FRN)|$($New.USN)"
    ] = $true

    Write-Host ""
    Write-Host "------------------------------------------------------------" `
        -ForegroundColor DarkGray

    Write-Host "[RENOMEADO]" `
        -ForegroundColor Yellow

    Write-Host "Horario : $(
        $New.Time.ToString(
            'dd/MM/yyyy HH:mm:ss'
        )
    )"

    Write-Host "Antigo  : $($Old.Name)"
    Write-Host "Novo    : $($New.Name)"

    $CurrentFile =
        Get-ChildItem `
            -Path "$($New.Drive):\" `
            -Filter $New.Name `
            -File `
            -Recurse `
            -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if ($CurrentFile) {

        Write-Host "Pasta   : $(
            $CurrentFile.DirectoryName
        )"

        Write-Host "No PC   : SIM" `
            -ForegroundColor Green

    }
    else {

        Write-Host "Pasta   : não localizada"
        Write-Host "No PC   : NÃO" `
            -ForegroundColor Red
    }
}


foreach ($E in $CleanEvents) {

    $Key =
        "$($E.FRN)|$($E.USN)"

    if ($Used.ContainsKey($Key)) {
        continue
    }

    if ($E.Action -eq "RENAME_NEW") {
        continue
    }

    if (
        $E.Action -ne "CREATE" -and
        $E.Action -ne "DELETE"
    ) {
        continue
    }

    $Found = $true

    Write-Host ""
    Write-Host "------------------------------------------------------------" `
        -ForegroundColor DarkGray

    if ($E.Action -eq "CREATE") {

        Write-Host "[NOVO]" `
            -ForegroundColor Green
    }
    else {

        Write-Host "[APAGADO]" `
            -ForegroundColor Red
    }

    Write-Host "Horario : $(
        $E.Time.ToString(
            'dd/MM/yyyy HH:mm:ss'
        )
    )"

    Write-Host "Arquivo : $($E.Name)"

    $CurrentFile =
        Get-ChildItem `
            -Path "$($E.Drive):\" `
            -Filter $E.Name `
            -File `
            -Recurse `
            -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if ($CurrentFile) {

        Write-Host "Pasta   : $(
            $CurrentFile.DirectoryName
        )"

        Write-Host "No PC   : SIM" `
            -ForegroundColor Green
    }
    else {

        Write-Host "Pasta   : não localizada"

        Write-Host "No PC   : NÃO" `
            -ForegroundColor Red
    }
}


Write-Host ""
Write-Host "============================================================" `
    -ForegroundColor Cyan

if ($Found) {

    Write-Host "[!] Eventos encontrados." `
        -ForegroundColor Yellow
}
else {

    Write-Host "[OK] Nenhum .exe ou .dll criado, renomeado ou apagado na última hora." `
        -ForegroundColor Green
}

Write-Host "============================================================" `
    -ForegroundColor Cyan
Write-Host ""