Clear-Host
$host.ui.RawUI.WindowTitle = "Basic Checks - https://discord.gg/DvdWgcpbkp"

Write-Host @"
   ____        _      _    _____      _          _____ _____ 
  / __ \      (_)    | |  |  __ \    | |        / ____/ ____|
 | |  | |_   _ _  ___| | _| |__) |__ | |_ ___  | (___| (___  
 | |  | | | | | |/ __| |/ /  ___/ _ \| __/ __|  \___ \\___ \ 
 | |__| | |_| | | (__|   <| |  | (_) | |_\__ \  ____) |___) |
  \___\_\\__,_|_|\___|_|\_\_|   \___/ \__|___/ |_____/_____/ 
                                                             
"@ -ForegroundColor Cyan

Write-Host "Made by QuickPots. DM @mcvitiesbiscuit for assistance" -ForegroundColor Yellow
timeout /t 5 | out-null


# admin check

Write-Host ""
Write-Host "[ ADMIN CHECK ]" -ForegroundColor Cyan
Write-Host ""

$isAdmin = [System.Security.Principal.WindowsPrincipal]::new(
    [System.Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole(
    [System.Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $isAdmin) {
    Write-Host "Run as admin" -ForegroundColor Red
    Write-Host ""
    Write-Host "Press enter to exit..." -ForegroundColor Yellow
    Read-Host
    return
}

Write-Host "Administrator privileges confirmed." -ForegroundColor Green


# event log functions

function Check-EventLog {
    param ($logName, $eventID, $message)

    $event = Get-WinEvent `
        -LogName $logName `
        -FilterXPath "*[System[EventID=$eventID]]" `
        -MaxEvents 1 `
        -ErrorAction SilentlyContinue

    if ($event) {
        $eventTime = $event.TimeCreated.ToString("MM/dd/yyyy hh:mm:ss tt")

        Write-Host "$message at: " -NoNewline -ForegroundColor Magenta
        Write-Host $eventTime -ForegroundColor Yellow
    }
    else {
        Write-Host "$message logs were not found." -ForegroundColor Magenta
    }
}

function Check-RecentEventLog {
    param ($logName, $eventIDs, $message)

    $event = Get-WinEvent `
        -LogName $logName `
        -FilterXPath "*[System[EventID=$($eventIDs -join ' or EventID=')]]" `
        -MaxEvents 1 `
        -ErrorAction SilentlyContinue

    if ($event) {
        $eventTime = $event.TimeCreated.ToString("MM/dd/yyyy hh:mm:ss tt")
        $eventID = $event.Id

        Write-Host "$message (Event ID: $eventID) at: " `
            -NoNewline `
            -ForegroundColor Magenta

        Write-Host $eventTime -ForegroundColor Yellow
    }
    else {
        Write-Host "$message logs were not found." -ForegroundColor Magenta
    }
}


# pc boot time

Write-Host ""
Write-Host "[ PC BOOT TIME ]" -ForegroundColor Cyan
Write-Host ""

$lastBootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
$formattedBootTime = $lastBootTime.ToString("yyyy-MM-dd hh:mm tt")

Write-Host "PC BOOTED AT: " -NoNewline -ForegroundColor Cyan
Write-Host $formattedBootTime -ForegroundColor Yellow


# recycle bin

Write-Host ""
Write-Host "[ RECYCLE BIN ]" -ForegroundColor Cyan
Write-Host ""

$currentUserSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$recycleBinFolderPath = "C:\`$Recycle.Bin\$currentUserSID"

if (Test-Path -Path $recycleBinFolderPath) {
    try {
        $recycleBinFolder = Get-Item -Path $recycleBinFolderPath -Force
        $lastModifiedTime = $recycleBinFolder.LastWriteTime.ToString("MM/dd/yyyy hh:mm:ss tt")

        Write-Host "LAST MODIFIED: " -NoNewline -ForegroundColor Cyan
        Write-Host $lastModifiedTime -ForegroundColor Yellow
    }
    catch {
        Write-Host "Unable to access the Recycle Bin folder for the current user." -ForegroundColor Red
    }
}
else {
    Write-Host "Recycle Bin folder for the current user not found at $recycleBinFolderPath." -ForegroundColor Red
}


# connected drives

Write-Host ""
Write-Host "[ CONNECTED DRIVES ]" -ForegroundColor Cyan
Write-Host ""

$drives = Get-CimInstance -ClassName Win32_LogicalDisk |
    Where-Object { $_.DriveType -ne 5 }

if ($drives) {
    foreach ($drive in $drives) {
        Write-Host "$($drive.DeviceID): $($drive.FileSystem)" -ForegroundColor Green
    }
}
else {
    Write-Host "No drives found." -ForegroundColor Red
}


# services

Write-Host ""
Write-Host "[ SERVICES ]" -ForegroundColor Cyan
Write-Host ""

$services = 'SysMain','PcaSvc','DPS','EventLog','Schedule','WSearch','BAM','DusmSvc','Appinfo'

$all = $services + ((Get-Service | Where-Object {
    $_.Name -like 'CDPUserSvc_*'
}).Name)

$all | ForEach-Object {

    try {
        $s = Get-Service -Name $_ -ErrorAction Stop

        $cfg = (
            Get-CimInstance `
                -ClassName Win32_Service `
                -Filter "Name='$($_)'"
        ).StartMode

        if ($cfg -eq 'Disabled') {
            Write-Host "$($_) : Disabled" -ForegroundColor Red
        }
        elseif ($s.Status -eq 'Running') {
            Write-Host "$($_) : Running" -ForegroundColor Green
        }
        else {
            Write-Host "$($_) : $($s.Status)" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "$($_) : Not Found" -ForegroundColor Red
    }
}


# windows settings

Write-Host ""
Write-Host "[ WINDOWS SETTINGS ]" -ForegroundColor Cyan
Write-Host ""

$settings = @(
    @{
        Name = "CMD"
        Path = "HKCU:\Software\Policies\Microsoft\Windows\System"
        Key = "DisableCMD"
        Warning = "Disabled"
        Safe = "Available"
    },
    @{
        Name = "PowerShell Logging"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        Key = "EnableScriptBlockLogging"
        Warning = "Disabled"
        Safe = "Enabled"
    },
    @{
        Name = "Activities Cache"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
        Key = "EnableActivityFeed"
        Warning = "Disabled"
        Safe = "Enabled"
    },
    @{
        Name = "Prefetch"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
        Key = "EnablePrefetcher"
        Warning = "Disabled"
        Safe = "Enabled"
    }
)

foreach ($s in $settings) {

    $status = Get-ItemProperty `
        -Path $s.Path `
        -Name $s.Key `
        -ErrorAction SilentlyContinue

    Write-Host "$($s.Name): " -NoNewLine

    if ($status -and $status.$($s.Key) -eq 0) {
        Write-Host "$($s.Warning)" -ForegroundColor Red
    }
    else {
        Write-Host "$($s.Safe)" -ForegroundColor Green
    }
}


# event log checks

Write-Host ""
Write-Host "[ EVENT LOG CHECKS ]" -ForegroundColor Cyan
Write-Host ""

Check-EventLog "Application" 3079 "USN Journal last deleted"
Check-RecentEventLog "System" @(104, 1102) "Event Logs last cleared"
Check-EventLog "System" 1074 "User recent PC Shutdown"
Check-EventLog "Security" 4616 "System time changed"
Check-EventLog "System" 6005 "Event Log Service started"


# prefetch integrity

Write-Host ""
Write-Host "[ PREFETCH FILES INTEGRITY ]" -ForegroundColor Cyan
Write-Host ""

$prefetchPath = "C:\Windows\Prefetch"

$hiddenFiles = Get-ChildItem `
    -Path $prefetchPath `
    -Force `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.Attributes -match "Hidden" }

if ($hiddenFiles) {
    Write-Host "$($hiddenFiles.Count) Hidden files found in Prefetch:" -ForegroundColor Red

    foreach ($file in $hiddenFiles) {
        Write-Host $file.Name -ForegroundColor Red
    }
}
else {
    Write-Host "No hidden files found in Prefetch." -ForegroundColor Green
}

$readOnlyFiles = Get-ChildItem `
    -Path $prefetchPath `
    -Force `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.Attributes -match "ReadOnly" }

if ($readOnlyFiles) {
    Write-Host "$($readOnlyFiles.Count) Read-only files found in Prefetch:" -ForegroundColor Red

    foreach ($file in $readOnlyFiles) {
        Write-Host $file.Name -ForegroundColor Red
    }
}
else {
    Write-Host "No read-only files found in Prefetch." -ForegroundColor Green
}


# vpn check

Write-Host ""
Write-Host "[ VPN CHECK ]" -ForegroundColor Cyan
Write-Host ""

try {
    $ip = (
        Invoke-WebRequest "https://ifconfig.me/ip"
    ).Content.Trim()

    $proxyPath = "$env:TEMP\proxy.json"

    (
        Invoke-WebRequest "https://proxycheck.io/v2/$ip`?vpn=1&asn=1"
    ).Content |
        Set-Content $proxyPath

    Get-Content $proxyPath |
        Select-String "proxy"
}
catch {
    Write-Host "VPN check failed." -ForegroundColor Red
}


Write-Host ""
Write-Host "Press enter to exit..." -ForegroundColor Yellow
Read-Host

