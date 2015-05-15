<#
	.SYNOPSIS
		Remove Profiles
	
	.DESCRIPTION
		It will make a massage to your feed and bring you a coffee. Meanwile will delete
		the Profile in the specified user in the specified computer.
	
	.PARAMETER ComputerName
		Name from the Computer where will run the script
	
	.PARAMETER UserName
		Username from the User, without domain

	.EXAMPLE
		Remove-Profile C060004 t88
	
	.NOTES
		Created by:   	luj


#>
function Remove-Profile {
	[CmdletBinding()]
	param (
		[Parameter(Position=0,Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[System.String]
		$ComputerName,
		[Parameter(Position=1,Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[System.String]
		$UserName
	)
	foreach($Computer in $ComputerName) {
		Write-Debug "Working on $Computer"
		if(Test-Connection -ComputerName $Computer -Count 1 -ea 0) {
			$Profiles = Get-WmiObject -Class Win32_UserProfile -Computer $Computer -ea 0
			
			$profilefound=$false
			foreach ($profile in $profiles) {
				$objSID = New-Object System.Security.Principal.SecurityIdentifier($profile.sid)
				try {
					$objuser = $objsid.Translate([System.Security.Principal.NTAccount])
					$profilename = $objuser.value.split("\")[1]
					
					Write-Debug "Found profilname: $profilename"
				
					if($profilename -eq $UserName) {
						$profilefound = $true
						try {
							$profile.delete()
							Write-Host "$UserName profile deleted successfully on $Computer"
						} catch {
							Write-Host "Failed to delete the profile, $UserName on $Computer"
						}
					}	
				}catch {
					
				}
				
				
		
			}
			if(!$profilefound) {
				write-Host "No profiles found on $Computer with Name $UserName"
			}		
		}
		else {
			write-Host "$Computer Not reachable"
		}
		Write-Debug "Finished working on $Computer"
	}
}