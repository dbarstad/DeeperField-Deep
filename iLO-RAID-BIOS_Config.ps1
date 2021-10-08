Import-Module HpeIloCmdlets
Import-Module HPESmartArrayCmdlets
Import-Module HPEBIOSCmdlets

Start-Transcript -Path $logfilepath -append

$todaysdate=Get-Date -Format "MM-dd-yyyy"
$logfilepath = "./DeepField_"+$todaysdate+".log"

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

    $Def_iLO_Pass = Read-Host "Please enter the systems default iLO Administrator password for $($D_Host.hostname) or hit enter to skip this iLO (8 alpha numeric characters): "
    If ( $Def_iLO_Pass -eq "" ) {
        Write-Host "Skipping $($D_Host.hostname)"
    }

    If ($D_Host.hostname.StartsWith("ILO20340CLG")) {
        Write-Host "Found test server iLO"
        $Def_iLO_Pass = "X6T8YRY5"
    }

    Write-Host "Conecting to $($D_Host.hostname) @ IP $($D_Host.IP) ..."

    $iLOConection = Connect-HPEiLO -Address $D_Host.IP -Password $Def_iLO_Pass -Username $iLOuser -DisableCertificateAuthentication

    If ( $iLOConection -ne $null ) {

        $PowerState = Get-HPEiLOServerPower -Connection $iLOConection
        $Post = Get-HPEiLOPostSetting -Connection $iLOConnection
        If ( $PowerState.ServerPower -eq "Off" ) {
            Write-host "Server is powered off" 
            Write-host "Powering on server.  10 minute wait injected"
            Set-HPEiLOServerPower -Connection $iLOConnection -Power On
            Start-Sleep -s 600
            } else {
            Write-host "Server $D_Host.hostname is powered on" 
        }
        If ( $Post.PostState -eq "FinishedPost" ) {
            Write-host "POST completed.  Starting configuration"
            } else {
            Write-host "Server has not finished POST.  Waiting ..."
            $PostWait = 1
                Do {
                    If ($PostWait -eq 10) {
                        Write-Host "Server $D_Host.hostname boot time excessive.  Failing install.  Review system $D_Host.hostname."
                        break
                    }
                    Start-Sleep -s 60
                    Write-Host "Waiting for server $D_Host.hostname to fnish post. "
                    $PostWait = $PostWait + 1
                } While ( $Post.PostState -ne "FinishedPost" )
            }
        }

$ChassisInfo = Get-HPEiLOChassisInfo -Connection $iLOConection
$SerialNumber = $ChassisInfo.SerialNumber
$SNArray=import-csv ./DF_sysdata.txt
Write-Host "Checking sysdata for $($SerialNumber)"

ForEach ($Serial in $SNArray) {
    If ($Serial.SerialNumber -eq $SerialNumber) {

    Write-Host "$($SerialNumber) validated ... configuring..."
    #Configure HPEiLO

    $iLOHostName = "NCE-DFCI-01-ILO" + $SerialNumber

    # Set-HPEiLOLicense -Connection $iLOHandle -Key "332N6-VJMMM-MHTPD-L7XNR-29G8B"

    Add-HPEiLOUser -Connection $iLOConection -LoginName adminilo -Password $iLO_adminilo_pw -Username adminilo -HostBIOSConfigPrivilege Yes -HostNICConfigPrivilege Yes -HostStorageConfigPrivilege Yes -iLOConfigPrivilege Yes -LoginPrivilege Yes  -RemoteConsolePrivilege Yes -SystemRecoveryConfigPrivilege Yes -UserConfigPrivilege Yes -VirtualMediaPrivilege Yes -VirtualPowerAndResetPrivilege Yes
    Add-HPEiLOUser -Connection $iLOConection -LoginName "APO Support Desk" -Password $iLO_apouser_pw -Username apouser -HostBIOSConfigPrivilege No -HostNICConfigPrivilege No -HostStorageConfigPrivilege No -iLOConfigPrivilege No -LoginPrivilege Yes  -RemoteConsolePrivilege No -ServiceAccount Yes -SystemRecoveryConfigPrivilege No -UserConfigPrivilege No -VirtualMediaPrivilege No
    Set-HPEiLOLoginSecurityBanner -Connection $iLOConection -SecurityMessageEnabled Yes
    Set-HPEiLOAccessSetting -Connection $iLOConection -AuthenticationFailuresBeforeDelay 0 -PasswordComplexityEnabled Yes -ServerFQDN $Serial.ILO_IPv4 -ServerName $Serial.Server_Name

    Set-HPEiLOSNMPSetting -Connection $iLOConection -ReadCommunity1 ChangeMe -SystemContact "DL-OSS-Cont-Integ-Eng@charter.com" -SystemLocation CHRCNCTR
    Set-HPEiLOSNMPAlertSetting -Connection $iLOConection -AlertEnabled Yes -ColdStartTrapBroadcast Enabled -PeriodicHSATrapConfiguration Disabled -SNMPv1Enabled Disabled -TrapSourceIdentifier iLOHostname
    Set-HPEiLOAlertMailSetting -AlertMailEmail DL-OSS-Cont-Integ-Eng@charter.com -AlertMailEnabled Yes -AlertMailSenderDomain charter.com -AlertMailSMTPServer nce.mail.chartercom.com -Connection $iLOConection -AlertMailSMTPAuthEnabled No -AlertMailSMTPSecureEnabled Yes

    Set-HPEiLOIPv6NetworkSetting -Connection $iLOConection -InterfaceType Dedicated -DHCPv6StatefulMode Disabled -DHCPv6StatelessMode Disabled -DNSName $iLOHostName -DNSServer $dnsserverv6 -DNSServerType $dnstype -DomainName $iloDomain
    Set-HPEiLOIPv4NetworkSetting -Connection $iLOConection -InterfaceType Dedicated -DHCPv4Enabled No -DNSName $iLOHostName -DNSServer $dnsserver -DNSServerType $dnstype -DomainName $iLODomain -LinkSpeedMbps Automatic

    Reset-HPEiLO -Connection $iLOConection -Device iLO -Force -ResetType ForceRestart

    Write-Host "iLO for $($SerialNumber) configured.  Moving to SmartArray Config."
    Start-Sleep 180

    
    #  Set-HPEiLOServerPower -Connection $iLOConection -Power ColdBoot -Force
    #  Reset-HPEiLO -Connection $iLOConection -Device Server -Confirm -Force -ResetType ForceRestart


    #Configure HPESmartArray

    $SAConnection = Connect-HPESA -IP $D_Host.IP -Password X6T8YRY5 -Username $iLOuser -DisableCertificateAuthentication

    If ( $SAConnection -ne $null ) {

        Write-Host "$($SerialNumber) connected for SmartArray configuration."
        $Physdrives = Get-HPESAPhysicalDrive -Connection $SAConnection -ControllerLocation "Slot 0"
        $DataDriveVAR = @(,@($Physdrives.PhysicalDrive.Item(0).Location, $Physdrives.PhysicalDrive.Item(1).Location, $Physdrives.PhysicalDrive.Item(2).Location, $Physdrives.PhysicalDrive.Item(3).Location, $Physdrives.PhysicalDrive.Item(4).Location, $Physdrives.PhysicalDrive.Item(5).Location))

        $OSresult = New-HPESALogicalDrive -Connection $SAConnection -ControllerLocation "Slot 0" -LogicalDriveName LogicalDrive1 -Raid Raid10 -CapacityGiB -1 -DataDrive $DataDriveVAR

        #$PhysDriveNum = 6
        #Do {
        #$PhysDriveIter = @(,@($Physdrives.PhysicalDrive.Item($PhysDriveNum).Location))
        #$LDN = "LogicalDrive" + ($PhysDriveNum -4).ToString()
        #$APPresult = New-HPESALogicalDrive -Connection $SAConnection -ControllerLocation "Slot 0" -LogicalDriveName $LDN -Raid Raid0 -CapacityGiB -1 -DataDrive $PhysDriveIter
        #$PhysDriveNum = $PhysDriveNum + 1
        #}
        #while ($APPresult -eq $true)
    } else {
        Write-Host "Failed to connect to $($D_Host.hostname) for arry configuration."
    }

    #Configure HPEBIOS
    
    $BIOSConnection = Connect-HPEBIOS -IP $D_Host.IP) -Password $Def_iLO_Pass -Username $iLOuser -DisableCertificateAuthentication

    If ( $BIOSConnection -ne $null ) {

        Write-Host "$($SerialNumber) connected for SmartArray configuration."  
        Set-HPEiLOVirtualMediaStatus -Connection $iLOConnection -Device DVD -VMBootOption BootOnNextReset
        Set-HPEiLOOneTimeBootOption -Connection $iLOConnection -BootSourceOverrideEnable Once -BootSourceOverrideTarget DVD 

        Set-HPEBIOSWorkloadProfile -Connection $BIOSHandle -WorkloadProfile GeneralPowerEfficientCompute
        Disconnect-HPEBIOS -Connection $BIOSHandle
        Disable-HPEBIOSLog
    } else {
        Write_Host "Connection to $($D_Host.hostname) failed."
    }


$iLOConection = Connect-HPEiLO -Address 10.177.250.183 -Password $Def_iLO_Pass -Username $iLOuser -DisableCertificateAuthentication

Mount-HPEiLOVirtualMedia -Connection $iLOConnection  -Device CD -ImageURL http://10.177.250.84/Nokia_Deep/deepfield-T3.iso

Disconnect-HPEiLO -Connection $iLOConnection
	Disconnect-HPESA -Connection $SAConnection

Disconnect-HPEiLO $iLOHandle
$SAHandle = Connect-HPESA -IP 10.177.250.183 -Password X6T8YRY5 -Username $iLOuser -DisableCertificateAuthentication