import-module HPESmartArrayCmdlets
import-module HpeIloCmdlets

$SAConnection = Connect-HPESA -IP 10.177.250.183 -Password X6T8YRY5 -Username administrator -DisableCertificateAuthentication
$iLOConnection= Connect-HPEiLO -Address 10.177.250.183 -Password X6T8YRY5 -Username administrator -DisableCertificateAuthentication

# Remove existing drives
Write-Host Setting server to correct power state
	$HostPower= Get-HPEiLoServerPower -Connection $iLOConnection
	If ($HostPower.Power -eq "Off")
	{
		Set-HPEiLoServerPower -Connection $iLOConnection -Power on
	}
	Else
	{
		Reset-HPEiLO -Connection $iLOConnection -Device Server -Confirm:$false
	}
Write-Host Sleeping 120
	Start-Sleep -s 120
Write-Host Collecting existing array config
	$ControllerConfiguration= Get-HPESAConfigurationStatus -Connection $SAConnection
	$SlotNumber= $ControllerConfiguration.ConfigurationStatus.ControllerLocation
	$LogicalDrive= Get-HPESALogicalDrive -Connection $SAConnection
	$RemoveLogicalDrives= $LogicalDrive.LogicalDrive.VolumeUniqueIdentifier

    Write-Host Removing $RemoveLogicalDrives
	ForEach ($RemoveLogicalDrive in $RemoveLogicalDrives)
	{    
		Remove-HPESALogicalDrive -Connection $SAConnection -ControllerLocation $SlotNumber -VolumeUniqueIdentifier $RemoveLogicalDrive
	}
Write-Host Resetting power to remove HPSSA config
	Start-Sleep -s 5
	$HostPower= Get-HPEiLoServerPower -Connection $iLOConnection
	If ($HostPower.Power -eq "Off")
	{
		Set-HPEiLoServerPower -Connection $iLOConnection -Power on
	}
	Else
	{
		Reset-HPEiLO -Connection $iLOConnection -Device Server -Confirm:$false
	}
Write-Host Sleeping 120
	Start-Sleep -s 120


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
Write-Host Creating OS
#	New-HPESALogicalDrive -Connection $SAConnection -ControllerLocation $SlotNumber -LogicalDriveName LogicalDrive1 -Raid Raid10 -DataDrive @(,@("$Drive0","$Drive1","$Drive2","$Drive3","$Drive4","$Drive5")) -SpareDrive @(,@("$Drive6","$Drive7")) -CapacityGiB -1
New-HPESALogicalDrive -Connection $SAConnection -ControllerLocation $SlotNumber -DataDrive @(,@("$Drive0","$Drive1","$Drive2","$Drive3","$Drive4","$Drive5")) -Raid Raid10 -CapacityGiB -1 -LegacyBootPriority Primary -LogicalDriveName LogicalDrive1 -SpareDrive @(,@("$Drive6","$Drive7")) -SpareRebuildMode Roaming


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