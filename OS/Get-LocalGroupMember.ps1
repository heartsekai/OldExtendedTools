
<#
	.SYNOPSIS
		Get a list of groups where the member.
	
	.DESCRIPTION
		Get-LocalGroupMember list all the local groups from a given computer where the user belongs.
	
	.PARAMETER ComputerName
		The ComputerName where the command will be done, if no ComputerName is given the current computer will be taken instead.
	
	.PARAMETER UserName
		A description of the GroupName parameter.
	
	.EXAMPLE
		PS C:\> Get-LocalGroupMember "Remote Desktop Users" C12345678
		
		This example shows a list of Users in the "Remote Desktop Users" Group on C12345678 computer.
	
	.EXAMPLE
		PS C:\> Get-LocalGroupMember "Administrators"
		
		This example shows a list of Users in the Administrators Group on the local computer.
	
	.NOTES
		Created on:   	12.05.2015 12:50
		Created by:   	luj

	.INPUTS
		System.String,System.String
#>
function Get-LocalGroupMember {
	[CmdletBinding()]
	param
	(
		[Parameter(Position = 0)]
		[String]$ComputerName = $env:COMPUTERNAME,
		[String]$UserName,
		[String]$GroupName
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
			
			# check a specific group or all the groups.
			if (![String]::IsNullOrEmpty($GroupName)) {
				$group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($GroupContext, $GroupName)
				
				if (!$group) {
					throw "$group not found in $($GroupContext.ContextType) on $ComputerName"
				}
			}
			else {
				$group = New-Object System.DirectoryServices.AccountManagement.GroupPrincipal($GroupContext)
			}
			
			
			$search = New-Object System.DirectoryServices.AccountManagement.PrincipalSearcher($group)
			# chech if a specified user is selected
			if (![String]::IsNullOrEmpty($UserName)) {
				foreach ($group in $search.FindAll()) {
					if ($group.GetMembers() | % { $_.SamAccountName -eq $UserName }) {
						$group.SamAccountName
					}
				}
			}
			else {
				foreach ($group in $search.FindAll()) {
					"*" + $group.SamAccountName
					$group.Members | Format-Wide Name -Column 1
				}
				
			}
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

