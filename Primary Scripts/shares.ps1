Write-host "################################################"
Write-host "###    THE OFFICIAL CYBERPATRIOT SCRIPTS     ###"
Write-host "##########   OF SHARON HIGH SCHOOL   ###########"
Write-host "###        FOR WINDOWS/SERVER MACHINES       ###"
Write-host "################################################"

# Administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

Write-host "################################################"
Write-host "#########    IF YOU DO NOT KNOW ME     #########"
Write-host "####  YOU ARE VIOLATING CYBERPATRIOT RULES  ####"
Write-host "########    FOR RUNNING THIS PROGRAM    ########"
Write-host "################################################"

#Delete shares
net share

do {
$Share = Read-host -Prompt "Should a share be removed? Y/N"
    if ($Share -eq "Y") {
        $DelShare = Read-Host -Prompt "Share?"
            net share $DelShare /delete | out-null }
    else {break}
    net share
    } while ($Share -eq "Y") 