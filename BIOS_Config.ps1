#Configure HPEiLO
Import-Module HpeIloCmdlets

$iLOHandle = Connect-HPEiLO -Address 10.177.250.183 -Password X6T8YRY5 -Username administrator -DisableCertificateAuthentication

$foo=Get-HPEiLOChassisInfo -Connection $iLOHandle
$HostName = "NCE-DFCI-01-ILO" + $foo.SerialNumber

# Set-HPEiLOLicense -Connection $iLOHandle -Key "332N6-VJMMM-MHTPD-L7XNR-29G8B"

Add-HPEiLOUser -Connection $iLOHandle -LoginName adminilo -Password xxx -Username adminilo -HostBIOSConfigPrivilege Yes -HostNICConfigPrivilege Yes -HostStorageConfigPrivilege Yes -iLOConfigPrivilege Yes -LoginPrivilege Yes -OutputType RawResponse -RemoteConsolePrivilege Yes -SystemRecoveryConfigPrivilege Yes -UserConfigPrivilege Yes -VirtualMediaPrivilege Yes -VirtualPowerAndResetPrivilege Yes
Add-HPEiLOUser -Connection $iLOHandle -LoginName apouser -Password xxx -Username APO Support Desk -HostBIOSConfigPrivilege No -HostNICConfigPrivilege No -HostStorageConfigPrivilege No -iLOConfigPrivilege No -LoginPrivilege Yes -OutputType RawResponse -RemoteConsolePrivilege No -ServiceAccount Yes -SystemRecoveryConfigPrivilege No -UserConfigPrivilege No -VirtualMediaPrivilege No
Set-HPEiLOLoginSecurityBanner -Connection $iLOHandle -OutputType RawResponse -SecurityMessageEnabled Yes
Set-HPEiLOAccessSetting -Connection $iLOHandle -AuthenticationFailuresBeforeDelay 0 -PasswordComplexityEnabled Yes -ServerFQDN $serverIP -ServerName $servername

Set-HPEiLOSNMPSetting -Connection $iLOHandle -OutputType RawResponse -ReadCommunity1 ChangeMe -SystemContact DL-OSS-Cont-Integ-Eng@charter.com -SystemLocation CHRCNCTR
Set-HPEiLOSNMPAlertSetting -Connection $iLOHandle -AlertEnabled Yes -ColdStartTrapBroadcast Enabled -PeriodicHSATrapConfiguration Disabled -SNMPv1Enabled Disabled -TrapSourceIdentifier iLOHostname
Set-HPEiLOAlertMailSetting -AlertMailEmail DL-OSS-Cont-Integ-Eng@charter.com -AlertMailEnabled Yes -AlertMailSenderDomain charter.com -AlertMailSMTPServer nce.mail.chartercom.com -Connection $iLOHandle -AlertMailSMTPAuthEnabled No -AlertMailSMTPSecureEnabled Yes


$dnsserver = ,@("71.10.216.1","71.10.216.2")
$dnsserverv6 = ,@("2607:f428:ffff:ffff::1","2607:f428:ffff:ffff::2")
$dnstype = ,@("Primary","Secondary")
$iLOIP = "10.177.250.183"
$iLOGW = "10.177.250.1"
$iLONM = "255.255.255.0"
$iloDomain = "chrnc.xx"

# Set-HPEiLOIPv6NetworkSetting -Connection $iLOHandle -DHCPv6StatefulMode Disabled -DHCPv6StatelessMode Disabled -DNSServer $dnsserverv6 -DNSServerType $dnstype

Set-HPEiLOIPv6NetworkSetting -Connection $iLOHandle -InterfaceType Dedicated -DHCPv6StatefulMode Disabled -DHCPv6StatelessMode Disabled -DNSName $HostName -DNSServer $dnsserverv6 -DNSServerType $dnstype -DomainName $iloDomain
Set-HPEiLOIPv4NetworkSetting -Connection $iLOHandle -InterfaceType Dedicated -DHCPv4Enabled No -DNSName $HostName -DNSServer $dnsserver -DNSServerType $dnstype -DomainName $iLODomain -LinkSpeedMbps Automatic

# Set-HPEiLOIPv4NetworkSetting -Connection $iLOHandle -InterfaceType Dedicated -DHCPv4DNSServer Disabled -DHCPv4DomainName Disabled -DHCPv4Enabled No -DHCPv4Gateway Disabled -DHCPv4NTPServer Disabled -DHCPv4StaticRoute Disabled -DHCPv4WINSServer Disabled -DNSName $HostName -DNSServer $dnsserver -IPv4Address $iLOIP -IPv4Gateway $iLOGW -IPv4SubnetMask $iLONM -LinkSpeedMbps Automatic -NICEnabled Yes -DNSServerType $dnstype

Reset-HPEiLO -Connection $iLOHandle -Device iLO -Confirm -Force -ResetType ForceRestart

Disconnect-HPEiLO $iLOHandle


#  Set-HPEiLOServerPower -Connection $iLOHandle -Power ColdBoot -Force
#  Reset-HPEiLO -Connection $iLOHandle -Device Server -Confirm -Force -ResetType ForceRestart




#Configure HPESmartArray
import-module HPESmartArrayCmdlets
$SAHandle = Connect-HPESA -IP 10.177.250.183 -Password X6T8YRY5 -Username administrator -DisableCertificateAuthentication

$OSresult = New-HPESALogicalDrive -Connection $SAHandle -ControllerLocation "Slot 0" -LogicalDriveName LogicalDrive1 -Raid Raid1 -CapacityGiB 480 -DataDrive @(,@("2I:3:7","2I:3:8"))
$APPresult = New-HPESALogicalDrive -Connection $SAHandle -ControllerLocation "Slot 0" -LogicalDriveName LogicalDrive1 -Raid Raid1 -CapacityGiB 480 -DataDrive @(,@("2I:3:7","2I:3:8"))

Disconnect-HPESA $SAHandle

#Configure HPEBIOS
import-module HPEBIOSCmdlets

# Set one time boot from PXE
Set-HPEiLOOneTimeBootOption -Connection $BIOSHandle -BootSourceOverrideEnable Once -BootSourceOverrideTarget PXE -OutputType RawResponse

Enable-HPEBIOSLog -Verbose
$BIOSHandle = Connect-HPEBIOS -IP 10.10.10.10 -Credential (Get-Credential) -DisableCertificateAuthentication

Set-HPEBIOSWorkloadProfile -Connection $BIOSHandle -WorkloadProfile GeneralPowerEfficientCompute
Disconnect-HPEBIOS -Connection $BIOSHandle
Disable-HPEBIOSLog