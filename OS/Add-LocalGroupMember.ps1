
<#
	.SYNOPSIS
		Adds one or more members to an Computer group.
	
	.DESCRIPTION
		A detailed description of the Add-LocalGroupMember function.
	
	.PARAMETER UserName
		UserName in the domain.
	
	.PARAMETER ComputerName
		The description of a the ComputerName parameter.
	
	.PARAMETER GroupName
		A description of the GroupName parameter.
	
	.EXAMPLE
		PS C:\> Add-LocalGroupMember -UserName 'luj' -ComputerName C12345678
		"luj added in Remote Desktop Users at C12345678."
		This example shows how to call the Add-LocalGroupMember function with named parameters.
	
	.EXAMPLE
		PS C:\> Add-LocalGroupMember -UserName joan -Verbose -GroupName "Administrators"
		'joan added in Administrators at $env:COMPUTERNAME'
		This example shows how to call the Add-LocalGroupMember function with positional parameters.
	
	.NOTES
		Created on:   	01.05.2015 20:27
		Created by:   	luj

	.INPUTS
		System.String,System.String
#>
function Add-LocalGroupMember {
	[CmdletBinding()]
	param
		(
		[Parameter(Mandatory = $true,
				   Position = 0)]
		[string]$UserName,
		
		[Parameter(Position = 1)]
		[string]$GroupName = "Remote Desktop Users",
		
		[Parameter(Position = 2)]
		[String]$ComputerName = $env:COMPUTERNAME
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
			# First we get the Group
			# if computer is offline we don't need to continue
			Write-Verbose "Trying to Ping $ComputerName"
			
			Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction 'Stop' | Out-Null
			
			$GroupContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine, $ComputerName)
			
			$group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($GroupContext, $GroupName)
			
			if (!$group) {
				throw "$group not found in $($GroupContext.ContextType) on $ComputerName"
			}
			
			# time to get the user
			$UserContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain)
			
			$user = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($UserContext, $UserName)
			
			if (!$user) {
				throw "$user not found in $($UserContext.ConnectedServer)."
			}
			
			# we add the user in the group
			$group.Members.add($user)
			
			$group.Save()
			
			Write-Verbose "$UserName added in $GroupName at $ComputerName."
		}
		catch {
			Write-Verbose "Error ocurred!"
			Write-Error $_.Exception.Message
		}
	}
	end {
		Write-Verbose "Ended"
	}
}


