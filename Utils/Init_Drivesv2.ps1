import-module HPESmartArrayCmdlets
import-module HpeIloCmdlets

$SAConnection = Connect-HPESA -IP 10.177.250.183 -Password X6T8YRY5 -Username administrator -DisableCertificateAuthentication
$iLOConnection= Connect-HPEiLO -Address 10.177.250.183 -Password X6T8YRY5 -Username administrator -DisableCertificateAuthentication

$ControllerConfiguration= Get-HPESAConfigurationStatus -Connection $SAConnection
$SlotNumber= $ControllerConfiguration.ConfigurationStatus.ControllerLocation

#Create new OS Drive
Write-Host Creating new drives
	$PhysicalDrives= Get-HPESAPhysicalDrive -Connection $SAConnection -ControllerLocation $SlotNumber
	$PhysicalDrivesSorted= $PhysicalDrives.PhysicalDrive.Location | Sort-Object
$Drive0= $PhysicalDrivesSorted[0]
	$Drive1= $PhysicalDrivesSorted[1]
	$Drive2= $PhysicalDrivesSorted[2]
	$Drive3= $PhysicalDrivesSorted[3]
	$Drive4= $PhysicalDrivesSorted[4]
	$Drive5= $PhysicalDrivesSorted[5]
	$Drive6= $PhysicalDrivesSorted[6]
	$Drive7= $PhysicalDrivesSorted[7]
$Drive8= $PhysicalDrivesSorted[8]
	$Drive9= $PhysicalDrivesSorted[9]
	$Drive10= $PhysicalDrivesSorted[10]
	$Drive11= $PhysicalDrivesSorted[11]
	$Drive12= $PhysicalDrivesSorted[12]
	$Drive13= $PhysicalDrivesSorted[13]
	$Drive14= $PhysicalDrivesSorted[14]
	$Drive15= $PhysicalDrivesSorted[15]
$Drive16= $PhysicalDrivesSorted[16]
	$Drive17= $PhysicalDrivesSorted[17]
	$Drive18= $PhysicalDrivesSorted[18]
	$Drive19= $PhysicalDrivesSorted[19]
	$Drive20= $PhysicalDrivesSorted[20]
	$Drive21= $PhysicalDrivesSorted[21]
	$Drive22= $PhysicalDrivesSorted[22]
	$Drive23= $PhysicalDrivesSorted[23]
$Drive24= $PhysicalDrivesSorted[24]
	$Drive25= $PhysicalDrivesSorted[25]
	$Drive26= $PhysicalDrivesSorted[26]
	$Drive27= $PhysicalDrivesSorted[27]

Write-Host Creating OS
#	New-HPESALogicalDrive -Connection $SAConnection -ControllerLocation $SlotNumber -LogicalDriveName LogicalDrive1 -Raid Raid10 -DataDrive @(,@("$Drive0","$Drive1","$Drive2","$Drive3","$Drive4","$Drive5")) -SpareDrive @(,@("$Drive6","$Drive7")) -CapacityGiB -1
New-HPESALogicalDrive -Connection $SAConnection -ControllerLocation $SlotNumber -DataDrive @(,@("$Drive0","$Drive1","$Drive2","$Drive3","$Drive4","$Drive5")) -Raid Raid10 -CapacityGiB -1 -LegacyBootPriority Primary -LogicalDriveName LogicalDrive1 -SpareDrive @(,@("$Drive6","$Drive7")) -SpareRebuildMode Dedicated

#New-HPESALogicalDrive -Connection $SAConnection -ControllerLocation $SlotNumber -DataDrive @(,@("$Drive0","$Drive1","$Drive2","$Drive3","$Drive4","$Drive5")) -Raid Raid10 -CapacityGiB -1 -LegacyBootPriority Primary -LogicalDriveName LogicalDrive1 -SpareDrive @(,@("$Drive6","$Drive7")) -SpareRebuildMode Roaming

#Write-Host Creating R0-1
#	New-HPESALogicalDrive -Connection $SAConnection -ControllerLocation $SlotNumber -LogicalDriveName LogicalDrive2 -Raid Raid0 -DataDrive @(,@("$Drive6","$Drive7")) -CapacityGiB -1


Write-Host Resetting server with new Logical Drives
	$HostPower= Get-HPEiLoServerPower -Connection $iLOConnection
	If ($HostPower.Power -eq "Off")
	{
		Set-HPEiLoServerPower -Connection $iLOConnection -Power on
	}
	Else
	{
		Reset-HPEiLO -Connection $iLOConnection -Device Server -Confirm:$false
	}

Write-Host "Configuration complete.  Closing connections."
	Disconnect-HPEiLO -Connection $iLOConnection
	Disconnect-HPESA -Connection $SAConnection
Write-Host End of Script