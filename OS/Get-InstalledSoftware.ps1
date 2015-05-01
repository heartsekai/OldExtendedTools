
function Get-InstalledSoftware {
	<#
		.SYNOPSIS
			List installed software.

		.DESCRIPTION
			A detailed description of the function.

		.PARAMETER  ParameterA
			The description of the ParameterA parameter.

		.PARAMETER  ParameterB
			The description of the ParameterB parameter.

		.EXAMPLE
			PS C:\> Get-Something -ParameterA 'One value' -ParameterB 32

		.EXAMPLE
			PS C:\> Get-Something 'One value' 32

		.INPUTS
			System.String,System.Int32

		.OUTPUTS
			System.String

		.NOTES
			Additional information about the function go here.

		.LINK
			about_functions_advanced

		.LINK
			about_comment_based_help

	#>
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