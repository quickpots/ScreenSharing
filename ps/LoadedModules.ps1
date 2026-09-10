Clear-Host
$host.ui.RawUI.WindowTitle = "Loaded DLL Signature Check - https://discord.gg/DvdWgcpbkp"

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


# sus dll names to flag

$suspiciousDlls = @(
    "penis.dll",
    "slinky_library.dll",
    "slinkyhook.dll"
) 

$javaprocess = Get-Process java*

if (-not $javaprocess) {
    Write-Host "No Java process was found (Perhaps their game is closed)?" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Press enter to exit..." -ForegroundColor Yellow
   Read-Host
    return
}

$results = foreach ($process in $javaprocess) {
    try {
        foreach ($module in $process.Modules) {
            $signature = Get-AuthenticodeSignature $module.FileName

            $isSuspicious = $suspiciousDlls -contains $module.ModuleName.ToLower()

            [PSCustomObject]@{
                DLL        = $module.ModuleName
                Path       = $module.FileName
                Status     = $signature.Status
                Suspicious = if ($isSuspicious) { "Yes" } else { "No" }
            }
        }
    }
    catch {
        [PSCustomObject]@{
            DLL        = ""
            Path       = ""
            Status     = "Error"
            Suspicious = ""
        }
    }
}

$results | Out-GridView -Title "Loaded DLL Signature Check by QuickPots - https://discord.gg/DvdWgcpbkp" -Wait
Write-Host ""
Write-Host "Press enter to exit..." -ForegroundColor Yellow
Read-Host
