
<#
	.SYNOPSIS
		List installed software.

	.DESCRIPTION
		A detailed description of the function.

	.EXAMPLE
		PS C:\> Get-InstalledSoftware

	.OUTPUTS
		System.String

	.NOTES
		Created by:   	luj

#>

function Get-InstalledSoftware {
	try {
        # Check if its 64 or 32 Bit Computer
        if ((gwmi win32_operatingsystem).osarchitecture -eq "64-bit") {
        	$Reg32 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        }
        $Reg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"

        if ($Reg32) {
        	Write-Host "64-Bit:"
        }
        foreach ($key in ls $Reg) {
        	(Get-ItemProperty $key.PSPath).DisplayName
        }

        if ($Reg32) {
        	Write-Host "32-Bit:"
        	foreach ($key in ls $Reg32) {
        		(Get-ItemProperty $key.PSPath).DisplayName
        	}
        }
	}
	catch {
		throw
	}
}