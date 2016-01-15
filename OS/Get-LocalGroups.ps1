
<#
	.SYNOPSIS
		Adds one or more members to an Computer group.
	
	.DESCRIPTION
		A detailed description of the Get-LocalGroupMember function.
	
	.PARAMETER ComputerName
		The description of a the ComputerName parameter.
	
	.PARAMETER GroupName
		A description of the GroupName parameter.
	
	.EXAMPLE
		PS C:\> Get-LocalGroupMember "Remote Desktop Users" C12345678
		
		This example shows a list of Users in the "Remote Desktop Users" Group on C12345678 computer.
	
	.EXAMPLE
		PS C:\> Get-LocalGroupMember "Administrators"
		
		This example shows a list of Users in the Administrators Group on the local computer.
	
	.NOTES
		Created on:   	28.07.2015 11:48
		Created by:   	luj

	.INPUTS
		System.String,System.String
#>
function Get-LocalGroups {
	[CmdletBinding()]
	param
	(
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
			
			# http://stackoverflow.com/questions/9487517/how-to-query-active-directory-for-all-groups-and-group-members
			$GroupContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine, $ComputerName)
			
			$group = New-Object System.DirectoryServices.AccountManagement.GroupPrincipal($GroupContext)
			
			$search = New-Object System.DirectoryServices.AccountManagement.PrincipalSearcher($group)
			
			foreach ($group in $search.FindAll()) {
				$group.SamAccountName
			}
			# $group.Members | Format-Wide Name -Column 1
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

