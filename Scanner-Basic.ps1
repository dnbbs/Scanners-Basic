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
            $parent -match '(?i)^C:\\Users\\' + [regex]::Escape($env:USERNAME) + '\\Downloads\\[^\\]+\.exe$'
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

$EvtxPath = "C:\Windows\System32\winevt\Logs\Windows PowerShell.evtx"

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "      SCANNER FILELESS EXECUTION / LOGS CLEANER " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path -LiteralPath $EvtxPath)) {
    Write-Host "[!] EVTX não encontrado." -ForegroundColor Red
    exit
}

## ==================================================
# REGRAS DE DETECÇÃO
# ==================================================

$Rules = @(
    [PSCustomObject]@{
        Name="EncodedCommand"
        Weight=4
        Regex='(?i)(^|\s)(-enc|-encodedcommand)(\s|$)'
    }

    [PSCustomObject]@{
        Name="Base64Conversion"
        Weight=3
        Regex='(?i)FromBase64String|ToBase64String|Convert::FromBase64String'
    }

    [PSCustomObject]@{
        Name="InvokeExpression"
        Weight=4
        Regex='(?i)\bInvoke-Expression\b|\bIEX\b'
    }

    [PSCustomObject]@{
        Name="DynamicScriptBlock"
        Weight=4
        Regex='(?i)ScriptBlock\.Create|\[scriptblock\]'
    }

    [PSCustomObject]@{
        Name="Reflection"
        Weight=4
        Regex='(?i)System\.Reflection|Reflection\.Assembly|Assembly::Load'
    }

    [PSCustomObject]@{
        Name="DynamicAssembly"
        Weight=5
        Regex='(?i)Reflection\.Emit|AssemblyBuilder|DynamicMethod|TypeBuilder'
    }

    [PSCustomObject]@{
        Name="MemoryExecution"
        Weight=5
        Regex='(?i)VirtualAlloc|VirtualProtect|CreateThread|WriteProcessMemory'
    }

    [PSCustomObject]@{
        Name="DynamicType"
        Weight=3
        Regex='(?i)\bAdd-Type\b'
    }

    [PSCustomObject]@{
        Name="RemoteContent"
        Weight=3
        Regex='(?i)DownloadString|DownloadFile|WebClient|Invoke-WebRequest|Invoke-RestMethod'
    }

    [PSCustomObject]@{
        Name="RemoteExecution"
        Weight=3
        Regex='(?i)Invoke-Command|Enter-PSSession|New-PSSession'
    }

    [PSCustomObject]@{
        Name="ProcessCreation"
        Weight=3
        Regex='(?i)Start-Process|ProcessStartInfo|CreateProcess'
    }

    [PSCustomObject]@{
        Name="CommandShellInvocation"
        Weight=2
        Regex='(?i)\bcmd(\.exe)?\b\s+/(c|k)\b'
    }

    [PSCustomObject]@{
        Name="NativeApiInvocation"
        Weight=5
        Regex='(?i)\[DllImport|Marshal::|GetProcAddress|LoadLibrary'
    }

    [PSCustomObject]@{
        Name="ExecutionPolicy"
        Weight=3
        Regex='(?i)-ExecutionPolicy\s+(Bypass|Unrestricted)|Set-ExecutionPolicy'
    }

    [PSCustomObject]@{
        Name="CharacterConstruction"
        Weight=3
        Regex='(?i)\[char\]|\[convert\]|\[byte\]\s*\d+'
    }

    [PSCustomObject]@{
        Name="InvokeMember"
        Weight=4
        Regex='(?i)InvokeMember|\.Invoke\(|::Invoke\('
    }

    [PSCustomObject]@{
        Name="Compression"
        Weight=4
        Regex='(?i)GZipStream|DeflateStream|Compression\.'
    }

    [PSCustomObject]@{
        Name="EncodedUnicode"
        Weight=2
        Regex='(?i)UTF-8|UTF8|UTF-16|Unicode|ASCIIEncoding|UnicodeEncoding'
    }

    [PSCustomObject]@{
        Name="HiddenWindow"
        Weight=3
        Regex='(?i)(^|\s)(-w|-windowstyle)\s+(hidden|0)\b'
    }

    [PSCustomObject]@{
        Name="NoProfile"
        Weight=2
        Regex='(?i)(^|\s)-nop(rofile)?\b'
    }

    [PSCustomObject]@{
        Name="CommandExecution"
        Weight=2
        Regex='(?i)(^|\s)(-c|-command)\s+'
    }

    [PSCustomObject]@{
        Name="RegistryEnvironment"
        Weight=3
        Regex='(?i)HKCU:\\Environment|HKLM:\\.*Environment'
    }

    [PSCustomObject]@{
        Name="Chams"
        Weight=3
        Regex='(?i)(?<![A-Za-z0-9_-])Chams(?![A-Za-z0-9_-])'
    }

    [PSCustomObject]@{
        Name="Aimbot"
        Weight=3
        Regex='(?i)(?<![A-Za-z0-9_-])Aimbot(?![A-Za-z0-9_-])'
    }

    [PSCustomObject]@{
        Name="Hd-player"
        Weight=3
        Regex='(?i)(?<![A-Za-z0-9_-])Hd-player(?![A-Za-z0-9_-])'
    }

    [PSCustomObject]@{
        Name="Bypass"
        Weight=3
        Regex='(?i)(?<![A-Za-z0-9_-])Bypass(?![A-Za-z0-9_-])'
    }

    [PSCustomObject]@{
        Name="Cheat"
        Weight=3
        Regex='(?i)(?<![A-Za-z0-9_-])Cheat(?![A-Za-z0-9_-])'
    }

    [PSCustomObject]@{
        Name="Esp"
        Weight=3
        Regex='(?i)(?<![A-Za-z0-9_-])Esp(?![A-Za-z0-9_-])'
    }
)

# ==================================================
# WHITELIST - SYSMON
#
# Qualquer conteúdo claramente relacionado ao Sysmon
# será ignorado antes das regras de detecção.
# ==================================================

$SysmonWhitelist = @(
    '(?i)\bSysmon\b',
    '(?i)\bSysmon\.exe\b',
    '(?i)\bSysmon64\.exe\b',
    '(?i)\bSysmon32\.exe\b',
    '(?i)\bSysmonDrv\b',
    '(?i)\bSysmonConfig\b',
    '(?i)\bSysmon[-_ ]?config\b',
    '(?i)\bSysmon[-_ ]?configuration\b',
    '(?i)\bMicrosoft-Windows-Sysmon\b',
    '(?i)\bMicrosoft-Windows-Sysmon/Operational\b',
    '(?i)\bSysmon/Operational\b',
    '(?i)\bSysmon/Debug\b',
    '(?i)\bSysmonDrv\.sys\b',
    '(?i)\bSysmonFilter\b',
    '(?i)\bSysmonEvent\b',
    '(?i)\bSysmonRule\b',
    '(?i)\bSysmonRules\b'
)

$PowerShellWhitelist = @(
    '(?i)HostApplication=powershell\.exe\s+-ExecutionPolicy\s+Restricted\s+-Command\s+Write-Host\s+[''"]Final result:\s*1[''"]',
    '(?is)HostApplication=powershell\.exe\s+-ExecutionPolicy\s+Restricted\s+-Command[\s\S]*\$InboxIMEs[\s\S]*\$InboxPattern[\s\S]*\$LanguageProfiles[\s\S]*HKLM:\\SOFTWARE\\Microsoft\\CTF\\TIP[\s\S]*Write-Host\s+[''"]Final result:',
    '(?is)AdvancedMicroDevicesInc-2\.[\s\S]*Get-AppxPackage\s+-AllUsers[\s\S]*Get-AppXProvisionedPackage\s+-Online[\s\S]*Remove-AppxPackage\s+-AllUsers[\s\S]*Remove-AppXProvisionedPackage\s+-Online'
)

# ==================================================
# WHITELIST EXTERNO - arquivo a.txt
# Padrao por linha. Linhas com # ou vazias ignoradas.
# Tenta varios metodos para localizar o a.txt:
#   1. $PSScriptRoot (quando executado como .ps1)
#   2. $PSCommandPath (fallback)
#   3. Diretorio do arquivo .ps1 no disco
#   4. Diretorio atual (quando colado no PowerShell)
# ==================================================

$aTxtDir = ""

if (-not [string]::IsNullOrEmpty($PSScriptRoot)) {
    $aTxtDir = $PSScriptRoot
}
elseif (-not [string]::IsNullOrEmpty($PSCommandPath)) {
    $aTxtDir = Split-Path -Parent $PSCommandPath
}
else {
    # Quando o codigo e colado direto no PowerShell, tentar encontrar
    # o scanner-basic.ps1 no disco e usar o diretorio dele
    $scriptDir = "C:\Users\danie\OneDrive\Documentos\scanner-basic"
    if (Test-Path -LiteralPath (Join-Path $scriptDir "a.txt")) {
        $aTxtDir = $scriptDir
    }
    elseif (Test-Path -LiteralPath (Join-Path (Get-Location).Path "a.txt")) {
        $aTxtDir = (Get-Location).Path
    }
}

$aTxtPath = ""

if (-not [string]::IsNullOrEmpty($aTxtDir)) {
    $aTxtPath = Join-Path $aTxtDir "a.txt"
}

if (-not [string]::IsNullOrEmpty($aTxtPath) -and (Test-Path -LiteralPath $aTxtPath)) {

    $aTxtLines = Get-Content -LiteralPath $aTxtPath -ErrorAction SilentlyContinue

    foreach ($line in $aTxtLines) {

        $trimmed = $line.Trim()

        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
        if ($trimmed.StartsWith("#")) { continue }

        $PowerShellWhitelist += $trimmed
    }

    Write-Host "[+] Whitelist: $($PowerShellWhitelist.Count) padroes carregados (a.txt + internos)" -ForegroundColor DarkGray

} else {

    Write-Host "[!] a.txt nao encontrado - usando whitelist interna apenas" -ForegroundColor DarkYellow
    Write-Host "    Procurado em: $aTxtPath" -ForegroundColor DarkYellow
}

# ==================================================
# ENTROPIA
# ==================================================

function Get-Entropy {
    param(
        [string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return 0
    }

    if ($Text.Length -lt 100) {
        return 0
    }

    $groups = $Text.ToCharArray() | Group-Object

    $entropy = 0.0

    foreach ($group in $groups) {
        $p = $group.Count / $Text.Length

        if ($p -gt 0) {
            $entropy -= $p * [Math]::Log($p, 2)
        }
    }

    return [Math]::Round($entropy, 3)
}

# ==================================================
# TESTE BASE64
# ==================================================

function Test-Base64 {
    param(
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    if ($Value.Length -lt 24) {
        return $null
    }

    if (($Value.Length % 4) -ne 0) {
        return $null
    }

    if ($Value -notmatch '^[A-Za-z0-9+/]+={0,2}$') {
        return $null
    }

    try {
        $bytes = [Convert]::FromBase64String($Value)

        if ($bytes.Length -lt 16) {
            return $null
        }

        foreach ($encoding in @(
            [Text.Encoding]::UTF8,
            [Text.Encoding]::Unicode
        )) {

            $decoded = $encoding.GetString($bytes)

            if ([string]::IsNullOrWhiteSpace($decoded)) {
                continue
            }

            $printable = 0

            foreach ($char in $decoded.ToCharArray()) {

                $n = [int][char]$char

                if (
                    ($n -ge 32 -and $n -le 126) -or
                    $n -eq 9 -or
                    $n -eq 10 -or
                    $n -eq 13
                ) {
                    $printable++
                }
            }

            $ratio = $printable / [Math]::Max(1, $decoded.Length)

            if ($ratio -ge 0.80) {
                return $decoded
            }
        }
    }
    catch {
    }

    return $null
}

# ==================================================
# CONTEÚDO ÚTIL DO EVENTO
# ==================================================

function Get-UsefulContent {
    param(
        [System.Diagnostics.Eventing.Reader.EventRecord]$Event
    )

    try {
        $message = [string]$Event.Message
    }
    catch {
        $message = ""
    }

    # ==================================================
    # MONTAR CONTEÚDO COMPLETO A PARTIR DO XML
    # O $Event.Message contém só o template traduzido.
    # HostApplication, CommandLine, ParameterBinding,
    # CommandInvocation, ProviderName, etc. estão no XML.
    # ==================================================

    $xmlText = ""

    try {
        $xml = [xml]$Event.ToXml()

        if ($xml.Event.EventData.Data) {
            foreach ($d in $xml.Event.EventData.Data) {
                $name  = [string]$d.Name
                $value = [string]$d.'#text'

                if ($name -and $value) {
                    $xmlText += "$name=$value`n"
                }
            }
        }
    }
    catch {}

    $fullContent = ($message + "`n" + $xmlText).Trim()

    if ([string]::IsNullOrWhiteSpace($fullContent)) {
        return ""
    }

    return $fullContent
}

# ==================================================
# ABRIR EVTX
# ==================================================

try {

    $events = Get-WinEvent `
        -Path $EvtxPath `
        -ErrorAction Stop

}
catch {

    Write-Host "[!] Erro ao abrir o EVTX." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor DarkYellow

    exit
}

Write-Host "[+] Eventos totais no EVTX: $($events.Count)" -ForegroundColor Green
Write-Host "[*] Analisando conteúdo..." -ForegroundColor Cyan
Write-Host ""

# ==================================================
# RESULTADOS
# ==================================================

$Results = New-Object System.Collections.Generic.List[object]

# ==================================================
# ANÁLISE
# ==================================================

foreach ($evt in $events) {

    $content = Get-UsefulContent -Event $evt

    if ([string]::IsNullOrWhiteSpace($content)) {
        continue
    }

    # ==================================================
    # WHITELIST GLOBAL DO SYSMON
    # ==================================================
    #
    # Se o evento mencionar Sysmon em qualquer um dos
    # contextos definidos acima, ele é completamente
    # ignorado e não passa pelas regras.
    #
    # ==================================================

    $isSysmon = $false

    foreach ($sysmonPattern in $SysmonWhitelist) {

        if ($content -match $sysmonPattern) {

            $isSysmon = $true
            break
        }
    }

    if ($isSysmon) {
        continue
    }

$PowerShellSkip = $false

foreach ($White in $PowerShellWhitelist) {
    if ($content -match $White) {
        $PowerShellSkip = $true
        break
    }
}

if ($PowerShellSkip) {
    continue
}

    # ==================================================
    # IDENTIFICAR EVENTOS RELEVANTES
    # ==================================================

    $interestingEvent = $false

    if ($evt.Id -in @(4103,4104,4105,4106)) {
        $interestingEvent = $true
    }

    if ($content -match '(?i)HostApplication=') {
        $interestingEvent = $true
    }

    if ($content -match '(?i)CommandLine=') {
        $interestingEvent = $true
    }

    if ($content -match '(?i)ScriptName=') {
        $interestingEvent = $true
    }

    if ($content -match '(?i)CommandName=') {
        $interestingEvent = $true
    }

    if (-not $interestingEvent) {
        continue
    }

    # ==================================================
    # INDICADORES
    # ==================================================

    $indicators = New-Object System.Collections.Generic.List[string]

    $score = 0

    foreach ($rule in $Rules) {

        if ($content -match $rule.Regex) {

            if (-not $indicators.Contains($rule.Name)) {

                [void]$indicators.Add($rule.Name)

                $score += $rule.Weight
            }
        }
    }

    # ==================================================
    # PROCURAR BASE64
    # ==================================================

    $decodedItems = New-Object System.Collections.Generic.List[object]

    $tokens = [regex]::Matches(
        $content,
        '(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])'
    )

    foreach ($token in $tokens) {

        $decoded = Test-Base64 $token.Value

        if ($null -eq $decoded) {
            continue
        }

        $exists = $false

        foreach ($item in $decodedItems) {

            if ($item.Encoded -eq $token.Value) {

                $exists = $true

                break
            }
        }

        if (-not $exists) {

            [void]$decodedItems.Add(
                [PSCustomObject]@{
                    Encoded = $token.Value
                    Decoded = $decoded
                }
            )
        }
    }

    # ==================================================
    # BASE64 DECODIFICADO
    # ==================================================

    if ($decodedItems.Count -gt 0) {

        if (-not $indicators.Contains("Base64DecodedContent")) {

            [void]$indicators.Add(
                "Base64DecodedContent"
            )

            $score += 4
        }
    }

    # ==================================================
    # ENTROPIA
    # ==================================================

    $entropy = 0

    if ($indicators.Count -gt 0) {

        $entropy = Get-Entropy $content
    }

    if (
        $entropy -ge 6.2 -and
        $content.Length -ge 250
    ) {

        if (-not $indicators.Contains("HighEntropyContent")) {

            [void]$indicators.Add(
                "HighEntropyContent"
            )

            $score += 3
        }
    }

    # ==================================================
    # SCRIPT BLOCK GRANDE
    # ==================================================

    if (
        $content.Length -ge 5000 -and
        $indicators.Count -gt 0
    ) {

        if (-not $indicators.Contains("LargeScriptBlock")) {

            [void]$indicators.Add(
                "LargeScriptBlock"
            )

            $score += 2
        }
    }

    # ==================================================
    # NENHUM INDICADOR
    # ==================================================

    if ($indicators.Count -eq 0) {
        continue
    }

    # ==================================================
    # CLASSIFICAÇÃO
    # ==================================================

    $level = "REVIEW"

    if ($score -ge 8) {
        $level = "HIGH"
    }

    if ($score -ge 13) {
        $level = "CRITICAL"
    }

    # ==================================================
    # SALVAR RESULTADO
    # ==================================================

    [void]$Results.Add(
        [PSCustomObject]@{
            Time       = $evt.TimeCreated
            EventId    = $evt.Id
            RecordId   = $evt.RecordId
            Level      = $level
            Score      = $score
            Indicators = ($indicators -join ", ")
            Entropy    = $entropy
            Length     = $content.Length
            Content    = $content
            Decoded    = $decodedItems
        }
    )
}

# ==================================================
# ORDENAR RESULTADOS
# ==================================================

$Results = $Results |
    Sort-Object Time

# ==================================================
# MOSTRAR RESULTADOS
# ==================================================

foreach ($result in $Results) {

    $color = "Yellow"

    if ($result.Level -eq "HIGH") {
        $color = "Red"
    }

    if ($result.Level -eq "CRITICAL") {
        $color = "Magenta"
    }

    Write-Host ""
    Write-Host "==================================================" -ForegroundColor $color
    Write-Host "[!] $($result.Level) POWERSHELL FORENSIC INDICATOR" -ForegroundColor $color
    Write-Host "==================================================" -ForegroundColor $color

    Write-Host "Time       : $($result.Time)"
    Write-Host "Event ID   : $($result.EventId)"
    Write-Host "Record ID  : $($result.RecordId)"
    Write-Host "Score      : $($result.Score)"
    Write-Host "Entropy    : $($result.Entropy)"
    Write-Host "Length     : $($result.Length)"

    Write-Host ""
    Write-Host "Indicators :" -ForegroundColor $color
    Write-Host $result.Indicators -ForegroundColor $color

    Write-Host ""
    Write-Host "--- Evento ---" -ForegroundColor DarkCyan

    if ($result.Content.Length -gt 6000) {

        Write-Host $result.Content.Substring(0,6000)

        Write-Host "... [truncado]" -ForegroundColor DarkGray
    }
    else {

        Write-Host $result.Content
    }

    # ==================================================
    # BASE64 DECODIFICADO
    # ==================================================

    if ($result.Decoded.Count -gt 0) {

        Write-Host ""
        Write-Host "--- BASE64 DECODIFICADO ---" -ForegroundColor Magenta

        foreach ($item in $result.Decoded) {

            Write-Host ""

            Write-Host "Encoded:" -ForegroundColor DarkYellow
            Write-Host $item.Encoded

            Write-Host "Decoded:" -ForegroundColor Green

            if ($item.Decoded.Length -gt 4000) {

                Write-Host $item.Decoded.Substring(0,4000)

                Write-Host "... [truncado]" -ForegroundColor DarkGray
            }
            else {

                Write-Host $item.Decoded
            }
        }
    }

    Write-Host "==================================================" -ForegroundColor $color
}

# ==================================================
# RESUMO
# ==================================================

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "RESUMO FORENSE" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

Write-Host "Eventos totais     : $($events.Count)"
Write-Host "Indicadores        : $($Results.Count)"
Write-Host ""

$critical = @(
    $Results |
    Where-Object Level -eq "CRITICAL"
).Count

$high = @(
    $Results |
    Where-Object Level -eq "HIGH"
).Count

$review = @(
    $Results |
    Where-Object Level -eq "REVIEW"
).Count

Write-Host "CRITICAL : $critical" -ForegroundColor Magenta
Write-Host "HIGH     : $high" -ForegroundColor Red
Write-Host "REVIEW   : $review" -ForegroundColor Yellow

Write-Host "==================================================" -ForegroundColor Cyan

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

$SysmonLog = "Microsoft-Windows-Sysmon/Operational"

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "        SYSMON EVENT ID 8 SCANNER"
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

try {
    $Events = @(Get-WinEvent -FilterHashtable @{
        LogName = $SysmonLog
        Id      = 8
    } -ErrorAction Stop)
}
catch {
    if ($_.Exception.Message -match "No events were found") {
        $Events = @()
    }
    else {
        Write-Host "[!] Erro ao ler o log do Sysmon." -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor DarkYellow
        exit
    }
}

Write-Host "[+] Eventos ID 8 encontrados: $($Events.Count)" -ForegroundColor Green
Write-Host ""

$Results = New-Object System.Collections.Generic.List[object]
$Whitelisted = 0

foreach ($Event in $Events) {

    try {
        $Xml = [xml]$Event.ToXml()
        $Data = @{}

        foreach ($Item in $Xml.Event.EventData.Data) {
            $Data[$Item.Name] = [string]$Item.'#text'
        }
    }
    catch {
        continue
    }

    $SourceImage     = [string]$Data["SourceImage"]
    $TargetImage     = [string]$Data["TargetImage"]
    $SourceProcessId = [string]$Data["SourceProcessId"]
    $TargetProcessId = [string]$Data["TargetProcessId"]
    $StartAddress    = [string]$Data["StartAddress"]
    $StartModule     = [string]$Data["StartModule"]
    $StartFunction   = [string]$Data["StartFunction"]

    $SourceName = Split-Path $SourceImage -Leaf
    $TargetName = Split-Path $TargetImage -Leaf

    if (
        $SourceName -match '(?i)^csrss(\.exe)?$' -and
        $TargetName -match '(?i)^cmd(\.exe)?$' -and
        $StartFunction -ieq "CtrlRoutine"
    ) {
        $Whitelisted++
        continue
    }

    if (
        $SourceName -match '(?i)^csrss(\.exe)?$' -and
        $TargetName -match '(?i)^Sysmon(\.exe)?$' -and
        $StartFunction -ieq "CtrlRoutine"
    ) {
        $Whitelisted++
        continue
    }

    if (
        $SourceName -match '(?i)^powershell(\.exe)?$' -or
        $TargetName -match '(?i)^powershell(\.exe)?$'
    ) {
        $Whitelisted++
        continue
    }

    [void]$Results.Add(
        [PSCustomObject]@{
            Time            = $Event.TimeCreated
            RecordId        = $Event.RecordId
            SourceImage     = $SourceImage
            TargetImage     = $TargetImage
            SourceProcessId = $SourceProcessId
            TargetProcessId = $TargetProcessId
            StartAddress    = $StartAddress
            StartModule     = $StartModule
            StartFunction   = $StartFunction
        }
    )
}

foreach ($Result in $Results) {

    Write-Host ""
    Write-Host "==================================================" -ForegroundColor Yellow
    Write-Host "[!] SYSMON EVENT ID 8" -ForegroundColor Yellow
    Write-Host "==================================================" -ForegroundColor Yellow
    Write-Host "Time             : $($Result.Time)"
    Write-Host "Record ID        : $($Result.RecordId)"
    Write-Host "SourceImage      : $($Result.SourceImage)"
    Write-Host "TargetImage      : $($Result.TargetImage)"
    Write-Host "SourceProcessId  : $($Result.SourceProcessId)"
    Write-Host "TargetProcessId  : $($Result.TargetProcessId)"
    Write-Host "StartAddress     : $($Result.StartAddress)"
    Write-Host "StartModule      : $($Result.StartModule)"
    Write-Host "StartFunction    : $($Result.StartFunction)"
    Write-Host "==================================================" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "             RESUMO EVENT ID 8" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "Eventos ID 8       : $($Events.Count)"
Write-Host "Whitelist          : $Whitelisted"
Write-Host "Encontrados        : $($Results.Count)"
Write-Host "==================================================" -ForegroundColor Cyan

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
    "C:\Users\danie\AppData\Local\Microsoft\OneDrive\",
    "C:\Users\danie\AppData\Local\Python\PythonCore-3.14-64\"
)

function Test-Whitelist {
    param(
        [string]$Path
    )

    foreach ($item in $whitelist) {

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