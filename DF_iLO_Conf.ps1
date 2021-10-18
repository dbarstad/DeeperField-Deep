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
                    
#Configure HPEiLO

                    $iLOHostName = "NCE-DFCI-01-ILO" + $SN

                    Write-Host "Configuring iLO IPv6 on $($SN)."
                    Set-HPEiLOIPv6NetworkSetting -Connection $iLOConnection -InterfaceType Dedicated -DHCPv6StatefulMode Disabled -DHCPv6StatelessMode Disabled -DNSName $iLOHostName -DNSServer $dnsserverv6 -DNSServerType $dnstype
                    
                    Set-HPEiLOAccessSetting -Connection $iLOConnection  -ServerFQDN $Serial.eno1_IPv4 -ServerName $Serial.Server_Name

                    Write-Host "Configuring iLO IPv4 on $($SN)."
                    Set-HPEiLOIPv4NetworkSetting -Connection $iLOConnection -InterfaceType Dedicated -DHCPv4Enabled No -DNSName $iLOHostName -DNSServer $dnsserver -DNSServerType $dnstype -DomainName $iLODomain -LinkSpeedMbps Automatic -IPv4Address $Serial.ILO_IPv4 -IPv4Gateway $Serial.ILO_IPv4_GW -IPv4SubnetMask $Serial.ILO_IPv4_NM
                }
            }
        }
    }
}

Disconnect-HPEiLO -Connection $iLOConnection


Stop-Transcript