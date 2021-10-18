Import-Module HpeIloCmdlets
Import-Module HPESmartArrayCmdlets
Import-Module HPEBIOSCmdlets
Import-Module Posh-SSH

$PXEuser = "root"
$PXEPass = "T3pxeGRIC"
$sPXEpass = ConvertTo-SecureString $PXEPass -AsPlainText -Force
$SCPCred = New-Object System.Management.Automation.PSCredential($PXEuser,$sPXEPass)

Get-SCPItem -Computername 192.169.71.2 -Credential $SCPCred -Path "/netboot/dnsmasq.leases" -PathType File -Destination ./ -Force

$todaysdate=Get-Date -Format "MM-dd-yyyy-HH"
$logfilepath = "./DeepField_"+$todaysdate+".log"

Start-Transcript -Path $logfilepath -append

# Static entries for DeepField

Write-Host "Setting Static variables"

    $iLO_adminilo_pw = "We2L0!Limbo"
    $iLO_apouser_pw = "APO2Limbo!"
    $dnsserver = ,@("71.10.216.1","71.10.216.2")
    $dnsserverv6 = ,@("2607:f428:ffff:ffff::1","2607:f428:ffff:ffff::2")
    $dnstype = ,@("Primary","Secondary")
    $iloDomain = "chrnc.xx"
    $iLOuser = "Administrator"

$Host_Updated = 0

Write-Host "Parsing dnsmasq.leases file"

$DHCP_Hosts = import-csv ./dnsmasq.leases -Header date,status,IP,MAC,hostname

ForEach ($D_Host in $DHCP_Hosts) {
Write-Host "Checking $($D_Host.hostname)"
    If ($D_Host.hostname.StartsWith("ILO")) {
        Write-Host "Found HPE host $($D_Host.hostname) on IP $($D_Host.IP)"

        $SN = $D_Host.hostname.Substring(3,10)

        $SNArray=import-csv ./DF_sysdata.txt
        Write-Host "Checking DF_sysdata for $($SN)"

        ForEach ($Serial in $SNArray) {
            If ($Serial.SerialNumber -eq $SN) {
                
                Write-Host "$($SN) confirmed... configuring..."
                Write-Host "Conecting to $($D_Host.hostname) - IP $($D_Host.IP) ..."

                $iLOConnection = Connect-HPEiLO -Address $D_Host.IP -Password $Serial.ILO_DEF_PASS -Username $Serial.ILO_User -DisableCertificateAuthentication

                If ( $iLOConnection -ne $null ) {

                    $PowerState = Get-HPEiLOServerPower -Connection $iLOConnection
                    $Post = Get-HPEiLOPostSetting -Connection $iLOConnection
                    If ( $PowerState.ServerPower -eq "Off" ) {
                        Write-host "Server is powered off" 
                        Write-host "Powering on server.  10 minute wait injected"
                        Set-HPEiLOServerPower -Connection $iLOConnection -Power On
                        Start-Sleep -s 600
                    } else {
                        Write-host "Server $($D_Host.hostname) is powered on" 
                    }
                        
                    If (( $Post.PostState -eq "FinishedPost" ) -or ( $Post.PostState -eq "InPostDiscoveryComplete" )){
                        Write-host "POST completed.  Starting configuration"
                    } else {
                        Write-host "Server has not finished POST.  Waiting ..."
                        $PostWait = 1
                        Do {
                            If ($PostWait -eq 10) {
                                Write-Host "Server $($D_Host.hostname) boot time excessive.  Failing install.  Review system $($D_Host.hostname)."
                                break
                            }
                            Start-Sleep -s 60
                            Write-Host "Waiting for server $($D_Host.hostname) to fnish post. "
                            $PostWait = $PostWait + 1
                        } While ( $Post.PostState -ne "FinishedPost" )
                    }
                    
#Configure HPEiLO

                    $iLOHostName = "NCE-DFCI-01-ILO" + $SN

                    #Set-HPEiLOLicense -Connection $iLOConnection -Key "332N6-VJMMM-MHTPD-L7XNR-29G8B"

                    Write-Host "Creating iLO users on $($SN)."
                    Add-HPEiLOUser -Connection $iLOConnection -LoginName adminilo -Password $iLO_adminilo_pw -Username adminilo -HostBIOSConfigPrivilege Yes -HostNICConfigPrivilege Yes -HostStorageConfigPrivilege Yes -iLOConfigPrivilege Yes -LoginPrivilege Yes  -RemoteConsolePrivilege Yes -SystemRecoveryConfigPrivilege Yes -UserConfigPrivilege Yes -VirtualMediaPrivilege Yes -VirtualPowerAndResetPrivilege Yes
                    Add-HPEiLOUser -Connection $iLOConnection -LoginName "APO Support Desk" -Password $iLO_apouser_pw -Username apouser -HostBIOSConfigPrivilege No -HostNICConfigPrivilege No -HostStorageConfigPrivilege No -iLOConfigPrivilege No -LoginPrivilege Yes  -RemoteConsolePrivilege No -ServiceAccount Yes -SystemRecoveryConfigPrivilege No -UserConfigPrivilege No -VirtualMediaPrivilege No
                    
                    Write-Host "Setting Security Banner and Authentication delay on $($SN)."
                    Set-HPEiLOLoginSecurityBanner -Connection $iLOConnection -SecurityMessageEnabled Yes
                    Set-HPEiLOAccessSetting -Connection $iLOConnection -AuthenticationFailuresBeforeDelay 0 -PasswordComplexityEnabled Yes -ServerFQDN $Serial.ILO_IPv4 -ServerName $Serial.Server_Name

                    Write-Host "Configuring SNMP alerting on $($SN)."
                    Set-HPEiLOSNMPSetting -Connection $iLOConnection -ReadCommunity1 SuD0CiERoStr -SystemContact "DL-OSS-Cont-Integ-Eng@charter.com" -SystemLocation CHRCNCTR
                    Set-HPEiLOSNMPAlertSetting -Connection $iLOConnection -AlertEnabled Yes -ColdStartTrapBroadcast Enabled -PeriodicHSATrapConfiguration Disabled -SNMPv1Enabled Disabled -TrapSourceIdentifier $iLOHostname
                    
                    Write-Host "Configuring mail alerting on $($SN)."
                    Set-HPEiLOAlertMailSetting -AlertMailEmail "DL-OSS-Cont-Integ-Eng@charter.com" -AlertMailEnabled Yes -AlertMailSenderDomain "charter.com" -AlertMailSMTPServer "nce.mail.chartercom.com" -Connection $iLOConnection -AlertMailSMTPAuthEnabled No -AlertMailSMTPSecureEnabled Yes

                    Write-Host "Configuring iLO IPv6 on $($SN)."
                    Set-HPEiLOIPv6NetworkSetting -Connection $iLOConnection -InterfaceType Dedicated -DHCPv6StatefulMode Disabled -DHCPv6StatelessMode Disabled -DNSName $iLOHostName -DNSServer $dnsserverv6 -DNSServerType $dnstype
                    
                    Reset-HPEiLO -Connection $iLOConnection -Device iLO -Force -ResetType ForceRestart -Confirm:$false

                    Write-Host "iLO for $($SN) configured.  Moving to SmartArray Config.  Waiting 90 seconds for iLO reset."
                    Start-Sleep 90

#Configure HPESmartArray

Write-Host Creating new drives

                    $iLOConnection = Connect-HPEiLO -Address $D_Host.IP -Password $Serial.ILO_DEF_PASS -Username $Serial.ILO_User -DisableCertificateAuthentication
                    $SAConnection = Connect-HPESA -IP $D_Host.IP -Password $Serial.ILO_DEF_PASS -Username $Serial.ILO_User -DisableCertificateAuthentication
                    $ControllerConfiguration= Get-HPESAConfigurationStatus -Connection $SAConnection
                	$SlotNumber= $ControllerConfiguration.ConfigurationStatus.ControllerLocation

                	$PhysicalDrives= Get-HPESAPhysicalDrive -Connection $SAConnection -ControllerLocation $SlotNumber
                	$PhysicalDrivesLocation= $PhysicalDrives.PhysicalDrive.Location

                    $Drive0= $PhysicalDrivesLocation[0]
                    $Drive1= $PhysicalDrivesLocation[1]
                    	$Drive2= $PhysicalDrivesLocation[2]
	                    $Drive3= $PhysicalDrivesLocation[3]
	                    $Drive4= $PhysicalDrivesLocation[4]
	                    $Drive5= $PhysicalDrivesLocation[5]
	                    $Drive6= $PhysicalDrivesLocation[6]
	                    $Drive7= $PhysicalDrivesLocation[7]
                    $Drive8= $PhysicalDrivesLocation[8]
	                $Drive9= $PhysicalDrivesLocation[9]
	                $Drive10= $PhysicalDrivesLocation[10]
	                $Drive11= $PhysicalDrivesLocation[11]
	                $Drive12= $PhysicalDrivesLocation[12]
	                $Drive13= $PhysicalDrivesLocation[13]
                    $Drive14= $PhysicalDrivesLocation[14]
	                $Drive15= $PhysicalDrivesLocation[15]
                    $Drive16= $PhysicalDrivesLocation[16]
	                $Drive17= $PhysicalDrivesLocation[17]
	                $Drive18= $PhysicalDrivesLocation[18]
	                $Drive19= $PhysicalDrivesLocation[19]
	                $Drive20= $PhysicalDrivesLocation[20]
	                $Drive21= $PhysicalDrivesLocation[21]
	                $Drive22= $PhysicalDrivesLocation[22]
	                $Drive23= $PhysicalDrivesLocation[23]
                    $Drive24= $PhysicalDrivesLocation[24]
	                $Drive25= $PhysicalDrivesLocation[25]
	                $Drive26= $PhysicalDrivesLocation[26]
                    $Drive27= $PhysicalDrivesLocation[27]

Write-Host Creating OS

                    If ($PhysicalDrivesSorted.Count -eq 8) {
                        $OSresult = New-HPESALogicalDrive -Connection $SAConnection -ControllerLocation $SlotNumber -DataDrive @(,@("$Drive0","$Drive1","$Drive2","$Drive3","$Drive4","$Drive5")) -Raid Raid10 -CapacityGiB -1 -LegacyBootPriority Primary -LogicalDriveName LogicalDrive1 -SpareDrive @(,@("$Drive6","$Drive7")) -SpareRebuildMode Dedicated
                    } else {
                        $OSresult = New-HPESALogicalDrive -Connection $SAConnection -ControllerLocation $SlotNumber -DataDrive @(,@("$Drive2","$Drive3","$Drive4","$Drive5","$Drive6","$Drive7")) -Raid Raid10 -CapacityGiB -1 -LegacyBootPriority Primary -LogicalDriveName LogicalDrive1 -SpareDrive @(,@("$Drive0","$Drive1","$Drive8","$Drive9","$Drive10","$Drive11","$Drive12","$Drive13","$Drive14","$Drive15","$Drive16","$Drive17","$Drive18","$Drive19","$Drive20","$Drive21","$Drive22","$Drive23","$Drive24","$Drive25","$Drive26","$Drive27")) -SpareRebuildMode Roaming
                    }

#Configure HPEBIOS
                    $iLOConnection = Connect-HPEiLO -Address $D_Host.IP -Password $Serial.ILO_DEF_PASS -Username $Serial.ILO_User -DisableCertificateAuthentication
                    $BIOSConnection = Connect-HPEBIOS -IP $D_Host.IP -Password $Serial.ILO_DEF_PASS -Username $Serial.ILO_User -DisableCertificateAuthentication

                    If ( $BIOSConnection -ne $null ) {

                        Write-Host "$($SN) connected for BIOS configuration."
                        Set-HPEiLOServerPower -Connection $iLOConnection -Power GracefulShutdown -Force
                        Start-Sleep 20
                        Set-HPEiLOAccessSetting -Connection $iLOConnection -AuthenticationFailuresBeforeDelay 0 -PasswordComplexityEnabled Yes -ServerFQDN $Serial.ILO_IPv4 -ServerName $Serial.Server_Name
                        Mount-HPEiLOVirtualMedia -Connection $iLOConnection  -Device DVD -ImageURL http://192.169.71.2/Nokia_Deep/deepfield-T3.iso
                        #Set-HPEiLOVirtualMediaStatus -Connection $iLOConnection -Device CD -VMBootOption BootOnNextReset
                        Set-HPEiLOOneTimeBootOption -Connection $iLOConnection -BootSourceOverrideEnable Once -BootSourceOverrideTarget CD
                        Set-HPEBIOSWorkloadProfile -Connection $BIOSConnection -WorkloadProfile GeneralPowerEfficientCompute
                        Set-HPEBIOSInternalSDCardSlot -Connection $BIOSConnection -InternalSDCardSlot Disabled

                        Set-HPEiLOServerPower -Connection $iLOConnection -Power On -Force
                        Write-Host "$($SN) waiting for BIOS workload profile configuration."
                        $Post = Get-HPEiLOPostSetting -Connection $iLOConnection
                        $PostWait = 0
                        Do {
                            If ($PostWait -eq 10) {
                                Write-Host "Server $($D_Host.hostname) boot time excessive.  Failing install.  Review system $($D_Host.hostname). - Final POST before ISO mount."
                                break
                            }
                            Write-Host "Waiting for server $($D_Host.hostname) to finish post."
                            Start-Sleep -s 30
                            $Post = Get-HPEiLOPostSetting -Connection $iLOConnection
                            $PostWait = $PostWait + 1
                            } While (( $Post.PostState -ne "FinishedPost" ) -and ( $Post.PostState -ne "InPostDiscoveryComplete" ))

                            #Mount-HPEiLOVirtualMedia -Connection $iLOConnection  -Device DVD -ImageURL http://10.177.250.84/Nokia_Deep/deepfield-T3.iso
                            #Set-HPEiLOServerPower -Connection $iLOConnection -Power Reset -Force
                    } else {
                        Write_Host "Connection to $($D_Host.hostname) failed."
                    }
                    
                    Write-Host "Configuring iLO IPv4 on $($SN)."
                    Set-HPEiLOIPv4NetworkSetting -Connection $iLOConnection -InterfaceType Dedicated -DHCPv4Enabled No -DNSName $iLOHostName -DNSServer $dnsserver -DNSServerType $dnstype -DomainName $iLODomain -LinkSpeedMbps Automatic

                }
            }
        }
    }
}

Disconnect-HPEiLO -Connection $iLOConnection
Disconnect-HPESA -Connection $SAConnection
Disconnect-HPEBIOS -Connection $BIOSConnection

Stop-Transcript