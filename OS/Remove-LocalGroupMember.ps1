<#
	.SYNOPSIS
		Remove a member from a Computer group.
	
	.DESCRIPTION
		A detailed description of the Remove-LocalGroupMember function.
	
	.PARAMETER UserName
		UserName in the domain.
	
	.PARAMETER ComputerName
		Computer Name where it will be applied. If no ComputerName is given, local Computer will take instead.
	
	.PARAMETER GroupName
		Group name of the group where the user need to be removed.
	
	.EXAMPLE
		PS C:\> Remove-LocalGroupMember -UserName 'luj' -ComputerName C12345678
		"luj deleted in Remote Desktop Users at C12345678."
		This example shows how to call the Remove-LocalGroupMember function with named parameters.
	
	.EXAMPLE
		PS C:\> Remove-LocalGroupMember joan "Administrators"
		'joan added in Administrators at $env:COMPUTERNAME'
		This example shows how to call the Remove-LocalGroupMember function with positional parameters.
	
	.NOTES
		Created on:   	12.05.2015 15:34
		Created by:   	luj

	.INPUTS
		System.String,System.String
#>
function Remove-LocalGroupMember {
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
		} catch {
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
			$group.Members.Remove($user)
			
			$group.Save()
			
			Write-Verbose "$UserName deleted in $GroupName at $ComputerName."
		} catch {
			Write-Verbose "Error ocurred!"
			Write-Error $_.Exception.Message
		}
	}
	end {
		Write-Verbose "Ended"
	}
}


