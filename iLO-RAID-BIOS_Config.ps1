Import-Module HpeIloCmdlets
Import-Module HPESmartArrayCmdlets
Import-Module HPEBIOSCmdlets

$todaysdate=Get-Date -Format "MM-dd-yyyy"
$logfilepath = "./DeepField_"+$todaysdate+".log"

Start-Transcript -Path $logfilepath -append

# Static entries for DeepField

Write-Host "Setting Static variables"

    $iLO_adminilo_pw = "Trace3_2021!"
    $iLO_apouser_pw = "Trace3_2021!"
    $dnsserver = ,@("71.10.216.1","71.10.216.2")
    $dnsserverv6 = ,@("2607:f428:ffff:ffff::1","2607:f428:ffff:ffff::2")
    $dnstype = ,@("Primary","Secondary")
    $iloDomain = "chrnc.xx"
    $iLOuser = "Administrator"

$Host_Updated = 0

Write-Host "Parsing dnsmasq.leases file"

$DHCP_Hosts = import-csv ../../dnsmasq.leases -Header date,status,IP,MAC,hostname

ForEach ($D_Host in $DHCP_Hosts) {

    If ($D_Host.hostname.StartsWith("ILO")) {
        Write-Host "Found HPE host $($D_Host.hostname) on IP $($D_Host.IP)"

        $Def_iLO_Pass = Read-Host "Please enter the systems default iLO Administrator password for $($D_Host.hostname) or hit enter to skip this iLO (8 alpha numeric characters)"
        If (( $Def_iLO_Pass -eq "" ) -and ( $D_Host.hostname -ne "ILO2M20340CLG" )) {
            Write-Host "Skipping $($D_Host.hostname)"
        }

        If ($D_Host.hostname.StartsWith("ILO2M20340CLG")) {
            Write-Host "Found test server iLO"
            $Def_iLO_Pass = "X6T8YRY5"
        }
    
        Write-Host "Conecting to $($D_Host.hostname) - IP $($D_Host.IP) ..."

        $iLOConnection = Connect-HPEiLO -Address $D_Host.IP -Password $Def_iLO_Pass -Username $iLOuser -DisableCertificateAuthentication

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


            $ChassisInfo = Get-HPEiLOChassisInfo -Connection $iLOConnection
            $SerialNumber = $ChassisInfo.SerialNumber
            $SNArray=import-csv ./DF_sysdata.txt
            Write-Host "Checking sysdata for $($SerialNumber)"

            ForEach ($Serial in $SNArray) {
                If ($Serial.SerialNumber -eq $SerialNumber) {

                    Write-Host "$($SerialNumber) validated... configuring..."
#Configure HPEiLO

                    $iLOHostName = "NCE-DFCI-01-ILO" + $SerialNumber

                    Set-HPEiLOLicense -Connection $iLOConnection -Key "332N6-VJMMM-MHTPD-L7XNR-29G8B"

                    Write-Host "Creating iLO users on $($SerialNumber)."
                    Add-HPEiLOUser -Connection $iLOConnection -LoginName adminilo -Password $iLO_adminilo_pw -Username adminilo -HostBIOSConfigPrivilege Yes -HostNICConfigPrivilege Yes -HostStorageConfigPrivilege Yes -iLOConfigPrivilege Yes -LoginPrivilege Yes  -RemoteConsolePrivilege Yes -SystemRecoveryConfigPrivilege Yes -UserConfigPrivilege Yes -VirtualMediaPrivilege Yes -VirtualPowerAndResetPrivilege Yes
                    Add-HPEiLOUser -Connection $iLOConnection -LoginName "APO Support Desk" -Password $iLO_apouser_pw -Username apouser -HostBIOSConfigPrivilege No -HostNICConfigPrivilege No -HostStorageConfigPrivilege No -iLOConfigPrivilege No -LoginPrivilege Yes  -RemoteConsolePrivilege No -ServiceAccount Yes -SystemRecoveryConfigPrivilege No -UserConfigPrivilege No -VirtualMediaPrivilege No
                    
                    Write-Host "Setting Security Banner and Authentication delay on $($SerialNumber)."
                    Set-HPEiLOLoginSecurityBanner -Connection $iLOConnection -SecurityMessageEnabled Yes
                    Set-HPEiLOAccessSetting -Connection $iLOConnection -AuthenticationFailuresBeforeDelay 0 -PasswordComplexityEnabled Yes -ServerFQDN $Serial.ILO_IPv4 -ServerName $Serial.Server_Name

                    Write-Host "Configuring SNMP alerting on $($SerialNumber)."
                    Set-HPEiLOSNMPSetting -Connection $iLOConnection -ReadCommunity1 ChangeMe -SystemContact "DL-OSS-Cont-Integ-Eng@charter.com" -SystemLocation CHRCNCTR
                    Set-HPEiLOSNMPAlertSetting -Connection $iLOConnection -AlertEnabled Yes -ColdStartTrapBroadcast Enabled -PeriodicHSATrapConfiguration Disabled -SNMPv1Enabled Disabled -TrapSourceIdentifier iLOHostname
                    
                    Write-Host "Configuring mail alerting on $($SerialNumber)."
                    Set-HPEiLOAlertMailSetting -AlertMailEmail "DL-OSS-Cont-Integ-Eng@charter.com" -AlertMailEnabled Yes -AlertMailSenderDomain "charter.com" -AlertMailSMTPServer "nce.mail.chartercom.com" -Connection $iLOConnection -AlertMailSMTPAuthEnabled No -AlertMailSMTPSecureEnabled Yes

                    Write-Host "Configuring iLO IPv6 on $($SerialNumber)."
                    Start-Sleep 9000

                    Set-HPEiLOIPv6NetworkSetting -Connection $iLOConnection -InterfaceType Dedicated -DHCPv6StatefulMode Disabled -DHCPv6StatelessMode Disabled -DNSName $iLOHostName -DNSServer $dnsserverv6 -DNSServerType $dnstype
                    
                    Write-Host "Configuring iLO IPv4 on $($SerialNumber)."
                    Set-HPEiLOIPv4NetworkSetting -Connection $iLOConnection -InterfaceType Dedicated -DHCPv4Enabled No -DNSName $iLOHostName -DNSServer $dnsserver -DNSServerType $dnstype -DomainName $iLODomain -LinkSpeedMbps Automatic

                    Reset-HPEiLO -Connection $iLOConnection -Device iLO -Force -ResetType ForceRestart -Confirm:$false

                    Write-Host "iLO for $($SerialNumber) configured.  Moving to SmartArray Config.  Waiting 3 minutes for iLO reset."
                    Start-Sleep 180

#Configure HPESmartArray

                    $SAConnection = Connect-HPESA -IP $D_Host.IP -Password $Def_iLO_Pass -Username $iLOuser -DisableCertificateAuthentication

                    If ( $SAConnection -ne $null ) {

                        Write-Host "$($SerialNumber) connected for SmartArray configuration."
                        $Physdrives = Get-HPESAPhysicalDrive -Connection $SAConnection -ControllerLocation "Slot 0"
                        $DataDriveVAR = @(,@($Physdrives.PhysicalDrive.Item(0).Location, $Physdrives.PhysicalDrive.Item(1).Location, $Physdrives.PhysicalDrive.Item(2).Location, $Physdrives.PhysicalDrive.Item(3).Location, $Physdrives.PhysicalDrive.Item(4).Location, $Physdrives.PhysicalDrive.Item(5).Location))

                        $OSresult = New-HPESALogicalDrive -Connection $SAConnection -ControllerLocation "Slot 0" -LogicalDriveName LogicalDrive1 -Raid Raid10 -CapacityGiB -1 -DataDrive $DataDriveVAR
                        $OSresult

                    } else {
                        Write-Host "Failed to connect to $($D_Host.hostname) for arry configuration."
                    }

#Configure HPEBIOS
                    $iLOConnection = Connect-HPEiLO -Address $D_Host.IP -Password $Def_iLO_Pass -Username $iLOuser -DisableCertificateAuthentication
                    $BIOSConnection = Connect-HPEBIOS -IP $D_Host.IP -Password $Def_iLO_Pass -Username $iLOuser -DisableCertificateAuthentication

                    If ( $BIOSConnection -ne $null ) {

                        Write-Host "$($SerialNumber) connected for BIOS configuration."
                        Set-HPEiLOServerPower -Connection $iLOConnection -Power GracefulShutdown -Force
                        Mount-HPEiLOVirtualMedia -Connection $iLOConnection  -Device DVD -ImageURL http://10.177.250.84/Nokia_Deep/deepfield-T3.iso
                        #Set-HPEiLOVirtualMediaStatus -Connection $iLOConnection -Device CD -VMBootOption BootOnNextReset
                        Set-HPEiLOOneTimeBootOption -Connection $iLOConnection -BootSourceOverrideEnable Once -BootSourceOverrideTarget CD
                        Set-HPEBIOSWorkloadProfile -Connection $BIOSConnection -WorkloadProfile GeneralPowerEfficientCompute

                        Set-HPEiLOServerPower -Connection $iLOConnection -Power On -Force
                        Write-Host "$($SerialNumber) waiting for BIOS workload profile configuration."
                        $Post = Get-HPEiLOPostSetting -Connection $iLOConnection
                        $PostWait = 1
                        Do {
                            If ($PostWait -eq 10) {
                                Write-Host "Server $($D_Host.hostname) boot time excessive.  Failing install.  Review system $($D_Host.hostname). - Final POST before ISO mount."
                                break
                            }
                            Start-Sleep -s 60
                            Write-Host "Waiting for server $($D_Host.hostname) to finish post. "
                            $PostWait = $PostWait + 1
                            } While (( $Post.PostState -ne "FinishedPost" ) -and ( $Post.PostState -ne "InPostDiscoveryComplete" ))
                            Mount-HPEiLOVirtualMedia -Connection $iLOConnection  -Device DVD -ImageURL http://10.177.250.84/Nokia_Deep/deepfield-T3.iso
                            Set-HPEiLOServerPower -Connection $iLOConnection -Power Reset -Force
                    } else {
                        Write_Host "Connection to $($D_Host.hostname) failed."
                    }
                    
                    $iLOConnection = Connect-HPEiLO -Address $D_Host.IP -Password $Def_iLO_Pass -Username $iLOuser -DisableCertificateAuthentication

                    
                    Reset-HPEiLO -Connection $iLOConnection -Device Server -Force -ResetType ForceRestart -Confirm:$false
                }
            }
        }
    }
}

Disconnect-HPEiLO -Connection $iLOConnection
Disconnect-HPESA -Connection $SAConnection
Disconnect-HPEBIOS -Connection $BIOSConnection

Stop-Transcript