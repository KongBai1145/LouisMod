# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Not admin. Re-launching as admin..."
    Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs -Wait
    exit
}

Write-Host "Running as admin."
$bcdOutput = bcdedit /enum 2>&1 | Out-String
Write-Host $bcdOutput

if ($bcdOutput -match "testsigning\s+Yes") {
    Write-Host "`nTESTSIGNING IS ENABLED!"
    Write-Host "After a reboot, the driver should load."
} else {
    Write-Host "`nTESTSIGNING IS NOT ENABLED."
    Write-Host "Enabling now..."
    bcdedit /set testsigning on
}
