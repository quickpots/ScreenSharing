```powershell
Clear-Host
$host.ui.RawUI.WindowTitle = "Scheduled Task Parser - https://discord.gg/DvdWgcpbkp"

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


# somehow I managed to fork a fork. I wonder what kind of idiot thinks of this other than myself...……..

$UserCurrent = $Env:Username

Start-Sleep -Seconds 1
Write-Host "Optimized just a wee bit more by QuickPots (Silly Yapper & Chronic SSer)" -ForegroundColor Red
Write-Host "Code includes pieces from Lilith (added signatures) and Nolw (made most of the script) with improved suspicious files and additional columns." -ForegroundColor Red 
Write-Host "Analyzing scheduled tasks..." -ForegroundColor Red
Start-Sleep -Seconds 1


function Test-Signature {
    param([string]$Path)

    try {
        return (Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop).Status -eq "Valid"
    }
    catch {
        return $false
    }
}


function Get-FullPath {
    param([string]$ExePath)

    if ([string]::IsNullOrWhiteSpace($ExePath)) {
        return $null
    }

    $ExePath = $ExePath.Trim('"')

    $paths = @(
        $ExePath,
        [Environment]::ExpandEnvironmentVariables($ExePath)
    )

    if ($ExePath -notmatch '\\') {
        $paths += "$env:WINDIR\$ExePath"
        $paths += "$env:WINDIR\System32\$ExePath"
    }

    foreach ($path in $paths) {
        try {
            if (Test-Path -LiteralPath $path) {
                return $path
            }
        }
        catch {
            continue
        }
    }

    return $null
}


$suspectPrograms = @(
    "cmd.exe",
    "powershell.exe",
    "powershell_ise.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "taskmgr.exe",
    "LaunchTM.exe",
    "WinRAR.exe",
    "7zFM.exe",
    "7z.exe",
    "notepad.exe",
    "notepad++.exe",
    "node.exe",
    "py.exe",
    "devenv.exe",
    "systeminformer.exe",
    "conhost.exe",
    "processhacker.exe"
)


$tasks = Get-ScheduledTask | ForEach-Object {

    $task = $_

    if ($task.Actions) {

        $task.Actions | ForEach-Object {

            $exeName = if ($_.Execute) {
                [System.IO.Path]::GetFileName($_.Execute.Trim('"'))
            }
            else {
                ""
            }

            $exePath = Get-FullPath $_.Execute

            [PSCustomObject]@{
                TaskName   = $task.TaskName
                TaskPath   = $task.TaskPath
                Action     = $_.Execute
                Arguments  = $_.Arguments

                Suspicion = if ($suspectPrograms -contains $exeName) {
                    "Suspicious"
                }
                else {
                    "Not Suspicious"
                }

                Signed = if ($exePath) {
                    if (Test-Signature $exePath) {
                        "Signed"
                    }
                    else {
                        "Not Signed"
                    }
                }
                else {
                    "Invalid Path"
                }

                Author = $task.Author

                Manual = if ($task.Author -Match $UserCurrent) {
                    "Manually Created"
                }
                else {
                    "Not Manually Created"
                }
            }
        }
    }
}


if ($tasks) {
    $tasks |
        Out-GridView `
            -Title "Scheduler Parser (Improved by QuickPots)" `
            -PassThru
}
else {
    Write-Host "No tasks found (Ensure Schedule service is running)"
}


Write-Host ""
Write-Host "Press enter to exit..." -ForegroundColor Yellow
Read-Host
```
