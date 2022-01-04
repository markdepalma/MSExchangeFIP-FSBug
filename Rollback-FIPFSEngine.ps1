###Change this to the restored FIP-FS location####
$BackupPathFIPFSPath = 'C:\TEMP\RESTORE\Program Files\Microsoft\Exchange Server\V15\FIP-FS'
##################################################

$InstallFIPFSPath = "$($env:ExchangeInstallPath)FIP-FS"

#Re-enable filtering before restore
Add-PSSnapin "Microsoft.Forefront.Filtering.Management.Powershell" -ErrorAction SilentlyContinue
Set-AntivirusScanSettings -Enabled $true
Set-ConfigurationValue -XPath "/fs-conf:Configuration/fs-sys:System/fs-sys:AntiMalwareSettings/fs-sys:Enabled" -Value "true" -Confirm:$false
Enable-TransportAgent -Identity 'Malware Agent' -Confirm:$False
Set-MalwareFilteringServer -Identity $env:COMPUTERNAME -BypassFiltering $false

#Disable engine updates globally
Set-EngineUpdateCommonSettings -EnableUpdates $false

#Stop services (BITS could possibly be downloading updates and needs to be stopped)
Stop-Service -Name BITS
Stop-Service -Name MSExchangeTransport
Stop-Service -Name MSExchangeAntispamUpdate

#Rename/backup engine and config
Rename-Item -Path "$InstallFIPFSPath\Data\Engines" -NewName "$InstallFIPFSPath\Data\Engines.bak"
Rename-Item -Path "$InstallFIPFSPath\Data\Configuration.xml" -NewName "$InstallFIPFSPath\Data\Configuration.xml.bak2"
Rename-Item -Path "$InstallFIPFSPath\Data\ConfigurationServer.xml" -NewName "$InstallFIPFSPath\Data\ConfigurationServer.xml.bak2"
Rename-Item -Path "$InstallFIPFSPath\Data\UpdateInformation.xml" -NewName "$InstallFIPFSPath\Data\UpdateInformation.xml.bak2"

#Restore engine and config
robocopy "$BackupPathFIPFSPath\Data\Engines" "$InstallFIPFSPath\Data\Engines" /MIR /MT
Copy-Item -Path "$BackupPathFIPFSPath\Data\Configuration.xml" -Destination "$InstallFIPFSPath\Data\Configuration.xml"
Copy-Item -Path "$BackupPathFIPFSPath\Data\ConfigurationServer.xml" -Destination "$InstallFIPFSPath\Data\ConfigurationServer.xml"
Copy-Item -Path "$BackupPathFIPFSPath\Data\UpdateInformation.xml" -Destination "$InstallFIPFSPath\Data\UpdateInformation.xml"

#Set proper ACL on Engines directory
$Sddl = 'O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;LS)(A;OICI;FA;;;NS)(A;OICI;FA;;;BA)'
$NewSddl = Get-Acl -Path "$InstallFIPFSPath\Data\Engines"
$NewSddl.SetSecurityDescriptorSddlForm($Sddl)
Set-Acl -Path "$InstallFIPFSPath\Data\Engines" -AclObject $NewSddl

#Start services
Start-Service -Name MSExchangeTransport
Start-Service -Name MSExchangeAntispamUpdate
Start-Service -Name BITS
