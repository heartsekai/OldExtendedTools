<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2015 v4.2.83
	 Created on:   	02.05.2015 09:48
	 Created by:   	luj
	 Organization: 	
	 Filename:     	
	===========================================================================
	.DESCRIPTION
		A description of the file.
#>





<#
	.SYNOPSIS
		Creates new local User.
	
	.DESCRIPTION
		Creates new local User on the specified computer.
	
	.PARAMETER UserName
		Username of the new User to be created
	
	.PARAMETER ComputerName
		Specifies where to create the User, per Default is the localmachine.
	
	.PARAMETER DisplayName
		A description of the DisplayName parameter.
	
	.PARAMETER Description
		A description of the Description parameter.
	
	.PARAMETER Password
		A description of the Password parameter.
	
	.PARAMETER ChangePasswordAtNextLogon
		A description of the ChangePasswordAtNextLogon parameter.
	
	.PARAMETER CannotChangePassword
		A description of the CannotChangePassword parameter.
	
	.PARAMETER IsDisabled
		A description of the IsDisabled parameter.
	
	.PARAMETER PasswordNeverExpires
		A description of the PasswordNeverExpires parameter.
	
	.PARAMETER FullName
		Full name of the new User.
	
	.EXAMPLE
		PS C:\> New-LocalUser -UserName luj -Password "12345" -ComputerName C12345678
	
	.NOTES
		Additional information about the function.
#>
function New-LocalUser {
	param
		(
		[Parameter(Mandatory = $true,
				   HelpMessage = 'UserName to be created')]
		[ValidateLength(3, 10)]
		[ValidatePattern('^[aA-zZ]{1,}\d*[aA-zZ]*')]
		[string]$UserName,
		
		[ValidatePattern('^[aA-zZ]{1,}\d*[aA-zZ]*')]
		[string]$ComputerName = $env:COMPUTERNAME,
		
		[ValidatePattern('^[aA-zZ ]{1,}$')]
		[string]$DisplayName,
		
		[string]$Description,
		
		[Parameter(Mandatory = $true)]
		[ValidateLength(4, 20)]
		[string]$Password,
		
		[switch]$ChangePasswordAtNextLogon,
		
		[switch]$CannotChangePassword,
		
		[switch]$IsDisabled,
		
		[switch]$PasswordNeverExpires
	)
	
	begin {
		try {
			Add-Type -AssemblyName System.DirectoryServices.AccountManagement
		}
		catch {
			Write-Verbose "Error ocurred!"
			Write-Error $_.Exception.Message
		}
	}
	process {
		try {
			# if computer is offline we don't need to continue
			Write-Verbose "Trying to Ping $ComputerName"
			Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction 'Stop'
			
			# get the context where to create the user
			$context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine, $ComputerName)
			
			# create user in specified Context
			$user = New-Object System.DirectoryServices.AccountManagement.UserPrincipal($context)
			Write-Verbose "Creating User on $ComputerName"
			
			$user.SamAccountName = $UserName
			Write-Verbose "User Name: $UserName"
			
			$user.SetPassword($Password)
			Write-Verbose "Password: $Password"
			if ($DisplayName) {
				$user.DisplayName = $DisplayName
			}
			
			if ($Description) {
				$user.Description = $Description
			}
			
			if ($ChangePasswordAtNextLogon) {
				$user.ExpirePasswordNow()
			}
			
			$user.UserCannotChangePassword = $CannotChangePassword
			
			$user.Enabled = !$IsDisabled
			
			$user.PasswordNeverExpires = $PasswordNeverExpires
			
			# Saving if we get enought rights (crossing fingers)
			$user.Save()
		}
		# Catch all other exceptions thrown by one of those commands
		catch [System.DirectoryServices.AccountManagement.PasswordException] {
			Write-Output "You need a better Password"
			Write-Output $_.Exception.Message
		}
		catch {
			if ($_.Exception.Message.ToLower().Contains("access is denied")) {
				Write-Output "You don't have rights to do that, Access denied"
			}
			Write-Output $_.Exception.Message
		}
		
	}
	end {
	}
}


