Start-Sleep -Seconds 1
Write-Host @"

   ____        _      _    _____      _       
  / __ \      (_)    | |  |  __ \    | |      
 | |  | |_   _ _  ___| | _| |__) |__ | |_ ___ 
 | |  | | | | | |/ __| |/ /  ___/ _ \| __/ __|
 | |__| | |_| | | (__|   <| |  | (_) | |_\__ \
  \___\_\\__,_|_|\___|_|\_\_|   \___/ \__|___/
                                              
                                              


"@ -ForegroundColor Blue
Write-Host "Based on Nolws script with modifications to find bruzens bypass" -ForegroundColor Red
Start-Sleep -Seconds 1

function Resolve-PathSafe {
    param($Path)
    try {
        if (-not $Path) { return $null }
        $expanded = [Environment]::ExpandEnvironmentVariables($Path)
        $expanded = $expanded.Trim('"')
        return $expanded
    } catch {
        return $null
    }
}

function Test-IsUnsigned($FilePath) {
    try {
        $resolved = Resolve-PathSafe $FilePath
        if (-not $resolved) { return $true }
        if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { return $true }

        $sig = Get-AuthenticodeSignature -FilePath $resolved -ErrorAction Stop
        return ($sig.Status -ne 'Valid')
    } catch {
        return $true
    }
}

$unsignedTasks = @()

foreach ($task in Get-ScheduledTask) {
    foreach ($action in $task.Actions) {
        if ($action.Execute) {
            $exe = Resolve-PathSafe $action.Execute

            # Only check executables inside SysWOW64 (changed it cus he tried changing path XDD)
            if ($exe -and ($exe -match "\\System32\")) {
                if (Test-IsUnsigned $exe) {
                    $unsignedTasks += [PSCustomObject]@{
                        TaskName  = $task.TaskName
                        TaskPath  = $task.TaskPath
                        ExecutedFile   = $exe
                        Arguments = if ($action.Arguments) { $action.Arguments } else { "No Args" }
                    }
                }
            }
        }
    }
}

if ($unsignedTasks.Count -gt 0) {
    $unsignedTasks | Out-GridView -Title "ColdKiller - Made by QuickPots"
} else {
    Write-Host "Scheduled Task wasn't found." -ForegroundColor Green
}

Read-Host "Press Enter to exit"
