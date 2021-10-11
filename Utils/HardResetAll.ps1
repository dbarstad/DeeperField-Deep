Import-Module HpeIloCmdlets
Import-Module HPESmartArrayCmdlets
Import-Module HPEBIOSCmdlets

$D_Host = "10.177.250.183"
$Def_iLO_Pass = "X6T8YRY5"
$iLOuser = "Administrator"

$SAConnectionR = Connect-HPESA -IP $D_Host -Password $Def_iLO_Pass -Username $iLOuser -DisableCertificateAuthentication
$iLOConnectionR = Connect-HPEiLO -Address $D_Host -Password $Def_iLO_Pass -Username $iLOuser -DisableCertificateAuthentication


    Reset-HPESAController -Connection $SAConnectionR -ControllerLocation "Slot 0" -FactoryReset
    Reset-HPEiLOSystemManufacturingDefault -Connection $iLOConnectionR -Confirm:$false -Force
    Set-HPEiLOFactoryDefault -Connection $iLOConnectionR -Confirm:$false

Disconnect-HPEiLO -Connection $iLOConnection
Disconnect-HPESA -Connection $SAConnection