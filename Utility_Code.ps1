Reset-HPEiLOSystemManufacturingDefault -Connection $iLOHandle -Force

Reset-HPEiLO -Connection $iLOHandle -Device iLO -Force -ResetType ForceRestart

Reset-HPEiLO -Connection $iLOHandle -Device iLO -Force -ResetType ForceRestart

Reset-HPEiLO -Connection $iLOHandle -Device Server -Force -ResetType ForceRestart

Set-HPEiLOServerPower -Connection v -Power ColdBoot

Mount-HPEiLOVirtualMedia -Connection $iLOConnection  -Device CD -ImageURL http://10.177.250.84/Nokia_Deep/deepfield-T3.iso

Dismount-HPEiLOVirtualMedia -Connection $iLOConnection -Device CD

http://10.177.250.84/Nokia_Deep/Deep_Init.sh



        #$PhysDriveNum = 6
        #Do {
        #$PhysDriveIter = @(,@($Physdrives.PhysicalDrive.Item($PhysDriveNum).Location))
        #$LDN = "LogicalDrive" + ($PhysDriveNum -4).ToString()
        #$APPresult = New-HPESALogicalDrive -Connection $SAConnection -ControllerLocation "Slot 0" -LogicalDriveName $LDN -Raid Raid0 -CapacityGiB -1 -DataDrive $PhysDriveIter
        #$PhysDriveNum = $PhysDriveNum + 1
        #}
        #while ($APPresult -eq $true)
