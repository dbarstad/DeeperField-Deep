#Configure HPEiLO
Import-Module HpeIloCmdlets

$iLOHandle = Connect-HPEiLO -Address 10.177.250.183 -Password X6T8YRY5 -Username administrator -DisableCertificateAuthentication

$foo=Get-HPEiLOChassisInfo -Connection $iLOHandle
$HostName = "NCE-DFCI-01-ILO" + $foo.SerialNumber

Set-HPEiLOLicense -Connection $iLOHandle -Key "332N6-VJMMM-MHTPD-L7XNR-29G8B"

$iLO_adminilo_pw = "Trace3_2021!"
$iLO_apouser_pw = "Trace3_2021!"
$serverIP = "10.177.250.183"
$servername = "fubar"
$iLOIP = "10.177.250.183"
$iLOGW = "10.177.250.1"
$iLONM = "255.255.255.0"

# Static entries for DeepField
$dnsserver = ,@("71.10.216.1","71.10.216.2")
$dnsserverv6 = ,@("2607:f428:ffff:ffff::1","2607:f428:ffff:ffff::2")
$dnstype = ,@("Primary","Secondary")
$iloDomain = "chrnc.xx"


Add-HPEiLOUser -Connection $iLOHandle -LoginName adminilo -Password $iLO_adminilo_pw -Username "adminilo" -HostBIOSConfigPrivilege Yes -HostNICConfigPrivilege Yes -HostStorageConfigPrivilege Yes -iLOConfigPrivilege Yes -LoginPrivilege Yes  -RemoteConsolePrivilege Yes -SystemRecoveryConfigPrivilege Yes -UserConfigPrivilege Yes -VirtualMediaPrivilege Yes -VirtualPowerAndResetPrivilege Yes
Add-HPEiLOUser -Connection $iLOHandle -LoginName "APO Support Desk" -Password $iLO_apouser_pw -Username apouser -HostBIOSConfigPrivilege No -HostNICConfigPrivilege No -HostStorageConfigPrivilege No -iLOConfigPrivilege No -LoginPrivilege Yes  -RemoteConsolePrivilege No -ServiceAccount Yes -SystemRecoveryConfigPrivilege No -UserConfigPrivilege No -VirtualMediaPrivilege No
Set-HPEiLOLoginSecurityBanner -Connection $iLOHandle -SecurityMessageEnabled Yes
Set-HPEiLOAccessSetting -Connection $iLOHandle -AuthenticationFailuresBeforeDelay 0 -PasswordComplexityEnabled Yes -ServerFQDN $serverIP -ServerName $servername

Set-HPEiLOSNMPSetting -Connection $iLOHandle -ReadCommunity1 ChangeMe -SystemContact DL-OSS-Cont-Integ-Eng@charter.com -SystemLocation CHRCNCTR
Set-HPEiLOSNMPAlertSetting -Connection $iLOHandle -AlertEnabled Yes -ColdStartTrapBroadcast Enabled -PeriodicHSATrapConfiguration Disabled -SNMPv1Enabled Disabled -TrapSourceIdentifier iLOHostname
Set-HPEiLOAlertMailSetting -AlertMailEmail DL-OSS-Cont-Integ-Eng@charter.com -AlertMailEnabled Yes -AlertMailSenderDomain charter.com -AlertMailSMTPServer nce.mail.chartercom.com -Connection $iLOHandle -AlertMailSMTPAuthEnabled No -AlertMailSMTPSecureEnabled Yes

# Set-HPEiLOIPv6NetworkSetting -Connection $iLOHandle -DHCPv6StatefulMode Disabled -DHCPv6StatelessMode Disabled -DNSServer $dnsserverv6 -DNSServerType $dnstype

Set-HPEiLOIPv6NetworkSetting -Connection $iLOHandle -InterfaceType Dedicated -DHCPv6StatefulMode Disabled -DHCPv6StatelessMode Disabled -DNSName $HostName -DNSServer $dnsserverv6 -DNSServerType $dnstype -DomainName $iloDomain
Set-HPEiLOIPv4NetworkSetting -Connection $iLOHandle -InterfaceType Dedicated -DHCPv4Enabled No -DNSName $HostName -DNSServer $dnsserver -DNSServerType $dnstype -DomainName $iLODomain -LinkSpeedMbps Automatic

# Set-HPEiLOIPv4NetworkSetting -Connection $iLOHandle -InterfaceType Dedicated -DHCPv4DNSServer Disabled -DHCPv4DomainName Disabled -DHCPv4Enabled No -DHCPv4Gateway Disabled -DHCPv4NTPServer Disabled -DHCPv4StaticRoute Disabled -DHCPv4WINSServer Disabled -DNSName $HostName -DNSServer $dnsserver -IPv4Address $iLOIP -IPv4Gateway $iLOGW -IPv4SubnetMask $iLONM -LinkSpeedMbps Automatic -NICEnabled Yes -DNSServerType $dnstype

Reset-HPEiLO -Connection $iLOHandle -Device iLO -Force -ResetType ForceRestart

Start-Sleep 180

$iLOHandle = Connect-HPEiLO -Address 10.177.250.183 -Password X6T8YRY5 -Username administrator -DisableCertificateAuthentication
Mount-HPEiLOVirtualMedia -Connection $iLOConnection  -Device CD -ImageURL http://10.177.250.84/Nokia_Deep/deepfield-T3.iso

#  Set-HPEiLOServerPower -Connection $iLOHandle -Power ColdBoot -Force
#  Reset-HPEiLO -Connection $iLOHandle -Device Server -Confirm -Force -ResetType ForceRestart

#Configure HPESmartArray
import-module HPESmartArrayCmdlets

$SAHandle = Connect-HPESA -IP 10.177.250.183 -Password X6T8YRY5 -Username administrator -DisableCertificateAuthentication

$Physdrives = Get-HPESAPhysicalDrive -Connection $SAHandle -ControllerLocation "Slot 0"
$DataDriveVAR = @(,@($Physdrives.PhysicalDrive.Item(0).Location, $Physdrives.PhysicalDrive.Item(1).Location, $Physdrives.PhysicalDrive.Item(2).Location, $Physdrives.PhysicalDrive.Item(3).Location, $Physdrives.PhysicalDrive.Item(4).Location, $Physdrives.PhysicalDrive.Item(5).Location))

$OSresult = New-HPESALogicalDrive -Connection $SAHandle -ControllerLocation "Slot 0" -LogicalDriveName LogicalDrive1 -Raid Raid10 -CapacityGiB -1 -DataDrive $DataDriveVAR

#$PhysDriveNum = 6
#Do {
#$PhysDriveIter = @(,@($Physdrives.PhysicalDrive.Item($PhysDriveNum).Location))
#$LDN = "LogicalDrive" + ($PhysDriveNum -4).ToString()
#$APPresult = New-HPESALogicalDrive -Connection $SAHandle -ControllerLocation "Slot 0" -LogicalDriveName $LDN -Raid Raid0 -CapacityGiB -1 -DataDrive $PhysDriveIter
#$PhysDriveNum = $PhysDriveNum + 1
#}
#while ($APPresult -eq $true)

Disconnect-HPESA $SAHandle

#Configure HPEBIOS
import-module HPEBIOSCmdlets

# Set one time boot from PXE
Set-HPEiLOOneTimeBootOption -Connection $BIOSHandle -BootSourceOverrideEnable Once -BootSourceOverrideTarget PXE 

Enable-HPEBIOSLog -Verbose
$BIOSHandle = Connect-HPEBIOS -IP 10.10.10.10 -Credential (Get-Credential) -DisableCertificateAuthentication

Set-HPEBIOSWorkloadProfile -Connection $BIOSHandle -WorkloadProfile GeneralPowerEfficientCompute
Disconnect-HPEBIOS -Connection $BIOSHandle
Disable-HPEBIOSLog

Disconnect-HPEiLO $iLOHandle
$SAHandle = Connect-HPESA -IP 10.177.250.183 -Password X6T8YRY5 -Username administrator -DisableCertificateAuthentication