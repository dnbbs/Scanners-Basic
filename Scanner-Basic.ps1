Clear-Host
$ErrorActionPreference = "SilentlyContinue"

Write-Host "========================================" -ForegroundColor Magenta
Write-Host "     ADVANCED FORENSIC SS TOOL          " -ForegroundColor Magenta
Write-Host "          Create by dnbbs               " -ForegroundColor Magenta
Write-Host " Discord:https://discord.gg/qdsG44Jz88  " -ForegroundColor Magenta
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

        # pegar datas reais do registry
        $regKey = Get-Item $dev.PSPath
        $lastWrite = $regKey.LastWriteTime

        # extrair serial (MUITO IMPORTANTE)
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

# Kernel-PnP Event ID 2102 / 2100 (device removal)
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
    # Check if service exists
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

    # pegar caminho
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

        # versão REAL
        $version = (Get-Item $sysPath).VersionInfo.FileVersion
        Write-Host (" -> Version: {0}" -f $version) -ForegroundColor Cyan

        # comparação simples
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

# keywords reais (sem exagero pra evitar fake)
$susKeywords = @("cheat","inject","spoofer","aim","hack","bypass","mod","dump","dll","loader")

if ($bin -and $bin.Items().Count -gt 0) {

    Write-Host (" Total Items: {0}" -f $bin.Items().Count) -ForegroundColor Yellow

    $binItems = @()

    foreach ($item in $bin.Items()) {

        $delDate = $item.ExtendedProperty("System.Recycle.DateDeleted")
        $origPath = $item.ExtendedProperty("System.ItemFolderPathDisplay")
        $sizeMB = [math]::Round($item.Size / 1MB, 2)

        $nameLower = $item.Name.ToLower()

        # tempo relativo (MUITO IMPORTANTE)
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

Write-Host "`n[*] BAM EXECUTION" -ForegroundColor Cyan

$bamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
$validExt = @(".exe", ".dll", ".tmp")

$hdProc = Get-Process | Where-Object {
    $_.ProcessName -like "*hd-player*"
} | Select-Object -First 1

if (-not $hdProc) {
    Write-Host " HD-Player not running." -ForegroundColor Red
    return
}

$hdTime = $hdProc.StartTime

Write-Host " HD-Player Start: $hdTime`n" -ForegroundColor DarkGray

function Convert-DevicePath {
    param ($path)

    if ($path -match "\\device\\harddiskvolume\d+") {
        return $path -replace "\\device\\harddiskvolume\d+", "C:"
    }

    return $path
}

Get-ChildItem $bamPath | ForEach-Object {

    $bamItems = Get-ItemProperty $_.PSPath

    $bamItems.PSObject.Properties | Where-Object {
        $_.Name -like "*\*"
    } | ForEach-Object {

        $path = $_.Name.ToLower()
        $ext = [System.IO.Path]::GetExtension($path)

        if (-not ($validExt -contains $ext)) {
            return
        }

        try {
            $bytes = [byte[]]$_.Value
            $fileTime = [BitConverter]::ToInt64($bytes, 0)
            $date = [DateTime]::FromFileTimeUtc($fileTime).ToLocalTime()
        }
        catch {
            return
        }

        if ($date.Year -lt 2000 -or $date.Year -gt (Get-Date).Year + 1) {
            return
        }

        if ($date -lt $hdTime) {
            return
        }

        $realPath = Convert-DevicePath $path
        $sigStatus = "Unknown"

        if (Test-Path $realPath) {
            try {
                $sig = Get-AuthenticodeSignature $realPath
                $sigStatus = $sig.Status
            } catch {}
        }

        if ($sigStatus -eq "Valid") {
            return
        }

        Write-Host ("[{0}] {1}" -f $date, $path)
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

# Display Settings Status
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

param(
    [switch]$ResetBaseline
)

$ProcessName = "hd-player"
$BaseFile = "$PSScriptRoot\hd-player_baseline.json"
$LogFile  = "$PSScriptRoot\hd-player_security.log"

Write-Host "`n[*] INJECTION " -ForegroundColor Cyan

$ScanDirs = @(
    # Windows core
    "C:\Windows\System32",
    "C:\Windows",
    "C:\Windows\SysWOW64",
    "C:\Windows\WinSxS",

    # Program Files
    "C:\Program Files",
    "C:\Program Files (x86)",
    "C:\ProgramData",

    # User profile (MUITO importante)
    "$env:USERPROFILE\AppData\Local",
    "$env:USERPROFILE\AppData\Roaming",
    "$env:USERPROFILE\AppData\LocalLow",

    # Temp / cache
    "$env:TEMP",
    "C:\Windows\Temp",

    # Gaming / emuladores (injeção comum)
    "$env:LOCALAPPDATA\Steam",
    "$env:PROGRAMFILES(X86)\Steam",
    "$env:LOCALAPPDATA\Roblox",
    "$env:LOCALAPPDATA\Google\Chrome",
    "$env:LOCALAPPDATA\Microsoft\Edge",

    # Android emulators (onde DLL injection é MUITO comum)
    "$env:LOCALAPPDATA\BlueStacks",
    "$env:LOCALAPPDATA\Nox",
    "$env:LOCALAPPDATA\LDPlayer",
    "$env:LOCALAPPDATA\Android",

    # Dev / tools (injeção em debug tools)
    "$env:LOCALAPPDATA\JetBrains",
    "$env:USERPROFILE\.vscode",
    "$env:LOCALAPPDATA\GitHubDesktop",

    # Drivers / system extensions (alto risco)
    "C:\Windows\System32\DriverStore",
    "C:\Windows\System32\drivers"
)

function Write-Log {
    param($msg)
    Add-Content $LogFile "[$(Get-Date)] $msg"
}

function Beep-Alert {
    [console]::Beep(1200, 500)
}

function Get-FastDllInventory {

    $dlls = New-Object System.Collections.Generic.List[object]

    foreach ($dir in $ScanDirs) {

        if (Test-Path $dir) {
            try {
                $files = Get-ChildItem $dir -Filter *.dll -ErrorAction SilentlyContinue

                foreach ($f in $files) {
                    $dlls.Add([PSCustomObject]@{
                        Name = $f.Name
                        Path = $f.FullName
                        Size = $f.Length
                        Type = "DISK"
                    })
                }
            } catch {}
        }
    }

    return $dlls
}

function Get-ProcessModules {
    $p = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
    if (-not $p) { return $null }

    $mods = New-Object System.Collections.Generic.List[object]

    foreach ($proc in $p) {
        foreach ($m in $proc.Modules) {
            $mods.Add([PSCustomObject]@{
                Name = $m.ModuleName
                Path = $m.FileName
                Type = "PROCESS"
            })
        }
    }

    return $mods
}

if ($ResetBaseline -or -not (Test-Path $BaseFile)) {

    $base = Get-ProcessModules
    if ($base) {
        $base | ConvertTo-Json -Depth 3 | Set-Content $BaseFile
        Write-Host "[+] Baseline pronto ( Use o codigo do powershell denovo )" -ForegroundColor Green
    }

    return
}

$baseline = Get-Content $BaseFile | ConvertFrom-Json
$current  = Get-ProcessModules
$disk     = Get-FastDllInventory

if (-not $current) { return }

$baselinePaths = $baseline.Path
$currentPaths  = $current.Path
$diskPaths     = $disk.Path

$newDlls = $current | Where-Object { $_.Path -notin $baselinePaths }

$suspicious = @()

foreach ($dll in $newDlls) {

    $existsOnDisk = $diskPaths -contains $dll.Path

    if (-not $existsOnDisk) {

        $suspicious += $dll

        Write-Host "[🚨 INJECTION MEMÓRIA]" -ForegroundColor Red
        Write-Host "DLL: $($dll.Path)" -ForegroundColor DarkRed

        Write-Log "MEMORY INJECTION: $($dll.Path)"
        Beep-Alert
    }
    else {
        Write-Host "[!] Nova DLL: $($dll.Name)" -ForegroundColor Yellow
    }
}

if ($suspicious.Count -eq 0) {
    Write-Host "[OK] Nenhuma injeção detectada" -ForegroundColor Green
} else {
    Write-Host "[ALERTA] Possível injection!" -ForegroundColor Red
}

Write-Log "Final | Suspicious: $($suspicious.Count)"

$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$uptime = (Get-Date) - $boot

$recentMinutes = 30
$recentTime = (Get-Date).AddMinutes(-$recentMinutes)

$suspiciousParents = "powershell","cmd","wscript","mshta"

$trustedPaths = @(
    "c:\windows\",
    "c:\program files\",
    "c:\program files (x86)\"
)

Get-CimInstance Win32_Process | ForEach-Object {

    if (-not $_.CommandLine) { return }

    $score = 0
    $reasons = @()

    $name = $_.Name
    $cmd = $_.CommandLine.ToLower()
    $path = $_.ExecutablePath
    $pid = $_.ProcessId

    if ($_.CreationDate) {
        $procAge = (Get-Date) - $_.CreationDate

        if ($procAge.TotalMinutes -lt 10 -and $uptime.TotalMinutes -gt 30) {
            $score += 1
            $reasons += "Recent start"
        }
    }

    if ($path) {
        $lowerPath = $path.ToLower()

        if ($lowerPath -match "appdata|temp|downloads|desktop") {
            if (-not ($trustedPaths | Where-Object { $lowerPath -like "$_*" })) {
                $score += 3
                $reasons += "User-space execution"
            }
        }
    }

    if ($cmd -match "-enc|-nop|-w hidden") {
        $score += 4
        $reasons += "Obfuscated command"
    }

    if ($cmd -match "invoke|downloadstring|reflection|frombase64") {
        $score += 4
        $reasons += "Memory execution"
    }

    if ($cmd.Length -gt 120 -and $name -match "powershell|cmd") {
        $score += 2
        $reasons += "Long command"
    }

    if ($_.ParentProcessId) {
        $parent = Get-CimInstance Win32_Process -Filter "ProcessId = $($_.ParentProcessId)" -ErrorAction SilentlyContinue

        if ($parent) {
            $pName = $parent.Name.ToLower()

            if ($pName -match ($suspiciousParents -join "|")) {
                $score += 2
                $reasons += "Spawned by $pName"
            }
        }
    }

    if ($score -ge 5) {
        Write-Host "`n[SUSPICIOUS PROCESS] Score: $score" -ForegroundColor Yellow
        Write-Host "Process : $name (PID: $pid)"
        Write-Host "Path    : $path"
        Write-Host "CmdLine : $($_.CommandLine)"
        Write-Host "Reason  : $($reasons -join ', ')"
    }
}

Write-Host "`n[*] EMULATOR / MEMORY ANALYSIS" -ForegroundColor Cyan

$emuList = "hd-player","bluestacks","msiplayer","memu","nox","smartgaga","ld9boxheadless"

Get-Process | Where-Object { $emuList -contains $_.Name.ToLower() } | ForEach-Object {

    Write-Host "`n[EMULATOR DETECTED] $($_.Name) PID: $($_.Id)" -ForegroundColor Yellow

    try {
        $modules = $_.Modules
        $seen = @{}

        foreach ($mod in $modules) {

            $modPath = $mod.FileName.ToLower()
            $modName = $mod.ModuleName

            # IGNORE TRUSTED PATHS
            if ($trustedPaths | Where-Object { $modPath -like "$_*" }) {
                continue
            }

            # USER PATH DLL
            if ($modPath -match "appdata|temp|users") {
                Write-Host " [SUSPICIOUS DLL PATH] $modName -> $modPath" -ForegroundColor Red
            }

            # DUPLICATE LOAD (ONLY FLAG IF NOT SYSTEM DLL)
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

Write-Host "`n[*] SCAN KEYWORDS" -ForegroundColor Cyan

$keywords = @(
    "hd-player",
    "powershell",
    "fsutil",
    "chams",
    "bypass",
    "cheat",
    "xit",
    "aimbot",
    "aim silent"
)

$ignore = @(
    "windows\\winsxs",
    "programdata",
    "appdata\\local\\microsoft",
    "_mei",
    "cache",
    "logs"
)

$whitelistPaths = @(
    "c:\\windows\\appcompat",
    "c:\\windows\\system32\\catroot2",
    "c:\\program files\\amd",
    "hd-player_security.log"
)

$systemIgnoreNames = @(
    "api-ms-","ext-ms-","kernel","ntdll","msvcp","ucrt","vcruntime"
)

$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -gt 0 }

foreach ($drive in $drives) {

    Write-Host "`n[+] Scanning Drive: $($drive.Name):\" -ForegroundColor DarkCyan

    Get-ChildItem "$($drive.Name):\" -Recurse -File -ErrorAction SilentlyContinue | Where-Object {

        $_.LastWriteTime -gt $recentTime -and
        $_.Extension -in @(".exe",".dll",".tmp",".txt",".log",".ini",".cfg")

    } | ForEach-Object {

        $file = $_
        $path = $file.FullName.ToLower()

        # ==========================
        # IGNORE PATHS
        # ==========================
        foreach ($i in $ignore) {
            if ($path -match $i) { return }
        }

        # ==========================
        # WHITELIST (ANTI FAKE LOG)
        # ==========================
        foreach ($w in $whitelistPaths) {
            if ($path -match $w) { return }
        }

        $isSystemFolder = $path -match "windows\\system32" -or $path -match "windows\\syswow64"

        # ==========================
        # SIGNATURE CHECK
        # ==========================
        $sigStatus = "Unknown"
        try {
            $sig = Get-AuthenticodeSignature $file.FullName
            $sigStatus = $sig.Status
        } catch {}

        if ($sigStatus -eq "Valid") { return }

        # ==========================
        # IGNORE COMMON SYSTEM DLLs
        # ==========================
        if ($isSystemFolder -and $file.Extension -eq ".dll") {
            foreach ($n in $systemIgnoreNames) {
                if ($file.Name.ToLower().StartsWith($n)) {
                    return
                }
            }
        }

        $matched = $false

        # ==========================
        # KEYWORD CHECK
        # ==========================
        if ($file.Extension -in @(".txt",".log",".ini",".cfg",".tmp")) {

            try {
                $content = Get-Content $file.FullName -ErrorAction SilentlyContinue

                foreach ($word in $keywords) {
                    if ($content -match "\b$word\b") {

                        Write-Host (" [!!!] KEYWORD MATCH") -ForegroundColor Red
                        Write-Host ("     -> {0}" -f $file.FullName) -ForegroundColor Yellow
                        Write-Host ("     -> Keyword: {0}" -f $word) -ForegroundColor Cyan
                        Write-Host ("     -> LastWrite: {0}" -f $file.LastWriteTime) -ForegroundColor DarkGray
                        $matched = $true
                        break
                    }
                }

            } catch {}
        }

        # ==========================
        # SYSTEM32 STRICT MODE
        # ==========================
        if ($isSystemFolder -and -not $matched) {

            if ($file.Name -match "hack|cheat|inject|bypass") {

                Write-Host (" [!!!] SUSPICIOUS SYSTEM FILE") -ForegroundColor Red
                Write-Host ("     -> {0}" -f $file.FullName) -ForegroundColor Yellow
                Write-Host ("     -> LastWrite: {0}" -f $file.LastWriteTime) -ForegroundColor DarkGray
            }

            return
        }

        # ==========================
        # UNSIGNED FILE DETECTION
        # ==========================
        if (-not $matched -and $file.Extension -in @(".exe",".dll",".tmp")) {

            Write-Host (" [!] UNSIGNED FILE") -ForegroundColor Yellow
            Write-Host ("     -> {0}" -f $file.FullName) -ForegroundColor DarkGray
            Write-Host ("     -> LastWrite: {0}" -f $file.LastWriteTime) -ForegroundColor DarkGray
        }

    }
}

Write-Host "`n[*] SCAN COMPLETE" -ForegroundColor Green

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

                # 🔥 correlação tempo real
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
}00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000