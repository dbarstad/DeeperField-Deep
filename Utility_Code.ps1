Reset-HPEiLOSystemManufacturingDefault -Connection $iLOHandle -Force

Reset-HPEiLO -Connection $iLOHandle -Device iLO -Force -ResetType ForceRestart

Reset-HPEiLO -Connection $iLOHandle -Device iLO -Confirm -Force -ResetType ForceRestart

Reset-HPEiLO -Connection $iLOHandle -Device Server -Confirm -Force -ResetType ForceRestart

