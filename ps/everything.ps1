$isAdmin = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Run as admin" -ForegroundColor Red
    return
}

function Check-EventLog {
    param ($logName, $eventID, $message)
    $event = Get-WinEvent -LogName $logName -FilterXPath "*[System[EventID=$eventID]]" -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($event) {
        $eventTime = $event.TimeCreated.ToString("MM/dd/yyyy hh:mm:ss tt")
        Write-Host "$message at: " -NoNewline -ForegroundColor Magenta
        Write-Host $eventTime -ForegroundColor Yellow
    } else {
        Write-Host "$message logs were not found." -ForegroundColor Magenta
    }
}

function Check-RecentEventLog {
    param ($logName, $eventIDs, $message)

    $event = Get-WinEvent -LogName $logName -FilterXPath "*[System[EventID=$($eventIDs -join ' or EventID=')]]" -MaxEvents 1 -ErrorAction SilentlyContinue

    if ($event) {
        $eventTime = $event.TimeCreated.ToString("MM/dd/yyyy hh:mm:ss tt")
        $eventID = $event.Id
        Write-Host "$message (Event ID: $eventID) at: " -NoNewline -ForegroundColor Magenta
        Write-Host $eventTime -ForegroundColor Yellow
    } else {
        Write-Host "$message logs were not found." -ForegroundColor Magenta
    }
}

$lastBootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
$formattedBootTime = $lastBootTime.ToString("yyyy-MM-dd hh:mm tt")
Write-Host "PC BOOTED AT: " -NoNewline -ForegroundColor Cyan
Write-Host $formattedBootTime -ForegroundColor Yellow

$currentUserSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$recycleBinFolderPath = "C:\`$Recycle.Bin\$currentUserSID"
if (Test-Path -Path $recycleBinFolderPath) {
    try {
        $recycleBinFolder = Get-Item -Path $recycleBinFolderPath -Force
        $lastModifiedTime = $recycleBinFolder.LastWriteTime.ToString("MM/dd/yyyy hh:mm:ss tt")
        Write-Host -ForegroundColor Cyan "RECYCLE BIN: " -NoNewline
        Write-Host -ForegroundColor Yellow $lastModifiedTime
    } catch {
        Write-Host "Unable to access the Recycle Bin folder for the current user." -ForegroundColor Red
    }
} else {
    Write-Host "Recycle Bin folder for the current user not found at $recycleBinFolderPath." -ForegroundColor Red
}

Write-Host ""

$drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -ne 5 }
if ($drives) {
    Write-Host "Connected Drives:" -ForegroundColor Yellow
    foreach ($drive in $drives) {
        Write-Host "$($drive.DeviceID): $($drive.FileSystem)" -ForegroundColor Green
    }
} else {
    Write-Host "No drives found." -ForegroundColor Red
}
Write-Host ""


$services='SysMain','PcaSvc','DPS','EventLog','Schedule','WSearch','BAM','DusmSvc','Appinfo';$all=$services+((Get-Service|Where-Object{$_.Name -like 'CDPUserSvc_*'}).Name);$all|ForEach-Object{try{$s=Get-Service -Name $_ -ErrorAction Stop;$cfg=(Get-WmiObject -Class Win32_Service -Filter "Name='$($_)'").StartMode;if($cfg -eq 'Disabled'){Write-Host "$($_) : Disabled" -ForegroundColor Red}elseif($s.Status -eq 'Running'){Write-Host "$($_) : Running" -ForegroundColor Green}else{Write-Host "$($_) : $($s.Status)" -ForegroundColor Red}}catch{Write-Host "$($_) : Not Found" -ForegroundColor Red}}

write-host ""

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

Write-Host ""

Write-Host "Event Log Checks:" -ForegroundColor Yellow
Check-EventLog "Application" 3079 "USN Journal last deleted"
Check-RecentEventLog "System" @(104, 1102) "Event Logs last cleared"
Check-EventLog "System" 1074 "User recent PC Shutdown"
Check-EventLog "Security" 4616 "System time changed"
Check-EventLog "System" 6005 "Event Log Service started"
Write-Host ""

Write-Host "Prefetch Files Integrity:" -ForegroundColor Yellow
$prefetchPath = "C:\Windows\Prefetch"

$hiddenFiles = Get-ChildItem -Path $prefetchPath -Force | Where-Object { $_.Attributes -match "Hidden" }
if ($hiddenFiles) {
    Write-Host "$($hiddenFiles.Count) Hidden files found in Prefetch:" -ForegroundColor Red
    foreach ($file in $hiddenFiles) {
        Write-Host $file.Name -ForegroundColor Red
    }
} else {
    Write-Host "No hidden files found in Prefetch." -ForegroundColor Green
}

$readOnlyFiles = Get-ChildItem -Path $prefetchPath -Force | Where-Object { $_.Attributes -match "ReadOnly" }
if ($readOnlyFiles) {
    Write-Host "$($readOnlyFiles.Count) Read-only files found in Prefetch:" -ForegroundColor Red
    foreach ($file in $readOnlyFiles) {
        Write-Host $file.Name -ForegroundColor Red
    }
} else {
    Write-Host "No read-only files found in Prefetch." -ForegroundColor Green
}
Write-Host ""


Write-Host "VPN Check:"

$ip = (Invoke-WebRequest ifconfig.me/ip).Content ; (Invoke-WebRequest "https://proxycheck.io/v2/$ip\?vpn=1&asn=1").content >> $env:temp\proxy.json ; (Get-Content $env:temp\proxy.json) -match 'proxy'

write-host ""
Write-Host "Press any key to exit..." -ForegroundColor Yellow
$null = Read-Host
