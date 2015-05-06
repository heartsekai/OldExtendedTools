
<#
	.SYNOPSIS
		Adds one or more members to an Computer group.
	
	.DESCRIPTION
		A detailed description of the Add-GroupMember function.
	
	.PARAMETER UserName
		UserName in the domain.
	
	.PARAMETER ComputerName
		The description of a the ComputerName parameter.
	
	.PARAMETER GroupName
		A description of the GroupName parameter.
	
	.EXAMPLE 1
		PS C:\> Add-GroupMember -UserName 'luj' -ComputerName C12345678
		"luj added in Administrators at C12345678."
		This example shows how to call the Add-GroupMember function with named parameters.
	
	.EXAMPLE 2
		PS C:\> Add-GroupMember -UserName joan -Verbose -GroupName "Remote Desktop Users"
		'joan added in Remote Desktop Users at $env:COMPUTERNAME'
		This example shows how to call the Add-GroupMember function with positional parameters.
	
	.OUTPUTS
		System.String
	
	.NOTES
		===========================================================================
		Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2015 v4.2.83
		Created on:   	01.05.2015 20:27
		Created by:   	luj
		Organization:
		Filename:
		===========================================================================

	.INPUTS
		System.String,System.String
#>
function Add-GroupMember {
	[CmdletBinding()]
	param
		(
		[Parameter(Mandatory = $true,
				   Position = 0)]
		[string]$UserName,
		
		[Parameter(Position = 1)]
		[String]$ComputerName = $env:COMPUTERNAME,
		
		[Parameter(Position = 2)]
		[string]$GroupName = "Administrators"
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
			
			Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction 'Stop'
			
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


