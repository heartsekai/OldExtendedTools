<#	
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2015 v4.2.99
	 Created on:   	03.02.2016 08:09
	 Created by:   	 
	 Organization: 	 
	 Filename:     	ExtendedTools.psm1
	-------------------------------------------------------------------------
	 Module Name: ExtendedTools
	===========================================================================
#>

function Remove-LocalProfile {
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
		PS C:\> Add-LocalGroupMember joan -GroupName "Administrators"
		'joan added in Administrators at $env:COMPUTERNAME'
		This example shows how to call the Add-LocalGroupMember function with positional parameters.
	
	.EXAMPLE
		PS C:\> Add-LocalGroupMember joan c012345 "Administrators"
		'joan added in Administrators at c012345'
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
		[String]$ComputerName = $env:COMPUTERNAME,
	
		[Parameter(Position = 2)]
		[string]$GroupName = "Remote Desktop Users"
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
	 	Created on:   	02.05.2015 09:48
	 	Created by:   	luj
#>
function Add-LocalUser {
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

<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2015 v4.2.99
	 Created on:   	28.01.2016 08:28
	 Created by:   	 
	 Organization: 	 
	 Filename:     	Get-ComputerUptime.ps1
	===========================================================================
	.DESCRIPTION
		A description of the file.
#>
function Get-ComputerUptime {
	param (
		[String]$ComputerName = $env:COMPUTERNAME
	)
	
	Get-WmiObject Win32_OperatingSystem -cn $ComputerName |
	Select __SERVER,
		   @{ N = 'UpTime'; E = { (Get-Date) - $_.ConvertToDateTime($_.LastBootUpTime) } }
	
}

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

<#
	.SYNOPSIS
		Adds one or more members to an Computer group.
	
	.DESCRIPTION
		A detailed description of the Get-LocalGroup function.
	
	.PARAMETER ComputerName
		The description of a the ComputerName parameter.
	
	.PARAMETER GroupName
		A description of the GroupName parameter.
	
	.EXAMPLE
		PS C:\> Get-LocalGroup "Remote Desktop Users" C12345678
		
		This example shows a list of Users in the "Remote Desktop Users" Group on C12345678 computer.
	
	.EXAMPLE
		PS C:\> Get-LocalGroup "Administrators"
		
		This example shows a list of Users in the Administrators Group on the local computer.
	
	.NOTES
		Created on:   	12.05.2015 12:50
		Created by:   	luj

	.INPUTS
		System.String,System.String
#>
function Get-LocalGroup {
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true, Position = 0)]
		[string]$GroupName,
		[Parameter(Position = 1)]
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
			
			$group.Members | Format-Wide Name -Column 1
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

function Get-LoggedOnUser {
	#Require -Version 2.0 and Running as local admin.           
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true,
				   Position = 0,
				   ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true)]
		[String[]]$ComputerName
	)#End Param
	
	Begin {
		Write-Verbose "`n Checking Users . . . "
		$i = 0
	}#Begin          
	Process {
		$ComputerName | Foreach-object {
			$Computer = $_
			try {
				$processinfo = @(Get-WmiObject -class win32_process -ComputerName $Computer -EA "Stop")
				if ($processinfo) {
					$processinfo | Foreach-Object { $_.GetOwner().User } |
					Where-Object { $_ -ne "NETWORK SERVICE" -and $_ -ne "LOCAL SERVICE" -and $_ -ne "SYSTEM" } |
					Sort-Object -Unique |
					ForEach-Object { New-Object psobject -Property @{ Computer = $Computer; LoggedOn = $_ } } |
					Select-Object Computer, LoggedOn
				}#If
			} catch {
				"Cannot find any processes running on $computer" | Out-Host
			}
		}#Forech-object(Comptuters)       
		
	}#Process
	End {
		
	}#End
	
}

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
		Group name of the group where the user need to be removed. If no GroupName is given "Remote Desktop Users" will be taken.
	
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

<#
	.SYNOPSIS
		Change Background
	
	.DESCRIPTION
		Change Background from the specified computer or the current one.
	
	.PARAMETER SourceImage
		A description of the SourceImage parameter.
	
	.PARAMETER ComputerName
		A description of the ComputerName parameter.
	
	.PARAMETER UserName
		A description of the UserName parameter.
	
	.PARAMETER DestinationFolder
		A description of the DestinationFolder parameter.
	
	.NOTES
		Created by:   	luj
	
	.EXAMPLE
		Set-BackgroundDesktop -SourceImage C:\temp\legolotr.jpg -UserName h3d -ComputerName C020794
#>
function Set-BackgroundDesktop {
	[CmdletBinding()]
	param
		(
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Test-Path $_ -PathType Leaf })]
		[String]$SourceImage,
		
		[ValidateScript({ Test-Connection $_ -Count 1 -Quiet })]
		[String]$ComputerName = "localhost",
		
		[Parameter(Mandatory = $true)]
		[String]$UserName,
		
		[String]$DestinationFolder = "C:\Users\$UserName\AppData\Roaming\Microsoft\Windows\Themes"
	)
	
	$ErrorActionPreference = 'Stop'
	
	$PSMount = ($DestinationFolder.ToLower()).Replace("c:", "\\$ComputerName\c$")
	$PSMount = $PSMount.Replace("d:", "\\$ComputerName\d$")
	
	# find unused letter for mounting (from F to Z)
	# we will use a random unused PSDrive
	# http://blogs.technet.com/b/heyscriptingguy/archive/2011/06/20/top-ten-favorite-powershell-tricks-part-3-working-with-ranges-dates-and-other-cool-powershell-tricks.aspx
	$PSDriveList = (70..90 | % { [char]$_ })
	$usedPSDrive = Get-PSDrive | ForEach-Object { $_.Name }
	$freePSDrive = $PSDriveList | where { $usedPSDrive -notcontains $_ }
	$PSDrive = Get-Random $freePSDrive
	
	try {
		# Nested try/catch
		# http://stackoverflow.com/questions/4799758/are-nested-try-catch-blocks-a-bad-idea
		# Mounting the RemoteFolder
		if (!(Test-Path ${PSDrive}:)) {
			Write-Verbose "Mounting ${PSDrive}: at $PSMount"
			New-PSDrive -Name $PSDrive -PSProvider FileSystem -Root $PSMount | Out-Null
			
			# Check for Writting rights
			"TestFile" | Out-File ${PSDrive}:\test.txt
			Remove-Item ${PSDrive}:\test.txt
		}
		
		try {
			
			# Save the new Background
			Copy-Item $SourceImage -destination "${PSDrive}:\$(Split-Path $SourceImage -Leaf)"
			
			Write-Verbose "Writing the key"
			
			# Using .NET to get username and userid (no LDAP)
			# http://blogs.technet.com/b/heyscriptingguy/archive/2009/10/08/hey-scripting-guy-october-8-2009.aspx
			# http://www.codeproject.com/Articles/38344/Using-System-DirectoryServices-AccountManagement
			Add-Type -AssemblyName System.DirectoryServices.AccountManagement
			# Powershell v.1 [reflection.assembly]::loadwithpartialname("System.DirectoryServices.AccountManagement")
			
			# creating an instance of a PrincipalContext object
			# it will allow us connecting to an Active Directory
			$ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain)
			
			# Creating the Object
			#	$user =  "System.DirectoryServices.AccountManagement.userPrincipal" -as [Type]
			#	$user::FindByIdentity($ctx,"luj")
			#	($user::FindByIdentity($ctx,"luj")).sid.value
			
			# FindByIdentity is an Static Method, so we cann use it directly
			$user = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($ctx, $UserName)
			$userSid = $user.Sid.Value
			
			$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', $ComputerName)
			$regkey = $reg.OpenSubKey("$userSid\Control Panel\Desktop", $true)
			$regkey.SetValue("Wallpaper", "$DestinationFolder\$(Split-Path $SourceImage -Leaf)", [Microsoft.Win32.RegistryValueKind]::String)
		} catch {
			Write-Verbose "Error ocurred copying the Background or Setting the Key."
			Write-Error $_.Exception.Message
		}
		
	} catch {
		Write-Verbose "Error Ocurred."
		Write-Error $_.Exception.Message
	} finally {
		if (Get-PSDrive -Name $PSDrive) {
			Write-Verbose "Dismounting PSDrive."
			Remove-PSDrive -Name $PSDrive
		}
	}
}

<#
	.SYNOPSIS
		Change the Logon Background.
	
	.DESCRIPTION
		Change the Logon Background from a Computer. If no Computer is defined it will change the current computer Logon Background
	
	.PARAMETER SourceImage
		A description of the SourceImage parameter.
	
	.PARAMETER ComputerName
		A description of the ComputerName parameter.

	.EXAMPLE
		PS C:\> Set-BackgroundLogon -SourceImage c:\temp\legolotr1.jpg -ComputerName C020794 -Verbose

	.NOTES
		Additional information about the function.
#>
function Set-BackgroundLogon {
	[CmdletBinding()]
	param
		(
		[Parameter(Mandatory = $true)]
		[ValidateScript({ (Test-Path $_ -PathType Leaf) -and ((Get-Item $_).Length -le 256kb) })]
		[String]$SourceImage,
		
		[ValidateScript({ Test-Connection $_ -Count 1 -Quiet })]
		[String]$ComputerName = $env:COMPUTERNAME
	)
	
	$ErrorActionPreference = 'Stop'
	
	# Default Filename defined by Microsoft
	$Filename = "BackgroundDefault.jpg"
	
	Write-Verbose "SourceImage = $SourceImage"
	Write-Verbose "ComputerName = $ComputerName"
	Write-Verbose "Filename =  $Filename"
	
	
	if ($ComputerName -ne $env:COMPUTERNAME) {
		$destinationFolder = "\\$ComputerName\C$\Windows\System32\oobe\info\backgrounds"
	} else {
		$destinationFolder = "C:\Windows\System32\oobe\info\backgrounds"
	}
	
	# find unused letter for mounting (from F to Z)
	# we will use a random unused PSDrive
	# http://blogs.technet.com/b/heyscriptingguy/archive/2011/06/20/top-ten-favorite-powershell-tricks-part-3-working-with-ranges-dates-and-other-cool-powershell-tricks.aspx
	$PSDriveList = (70..90 | % { [char]$_ })
	$usedPSDrive = Get-PSDrive | ForEach-Object { $_.Name }
	$freePSDrive = $PSDriveList | where { $usedPSDrive -notcontains $_ }
	$PSDrive = Get-Random $freePSDrive
	
	try {
		# Nested try/catch
		# http://stackoverflow.com/questions/4799758/are-nested-try-catch-blocks-a-bad-idea
		# Mounting the RemoteFolder
		if (!(Test-Path ${PSDrive}:)) {
			Write-Verbose "Mounting ${PSDrive}: at $destinationFolder"
			New-PSDrive -Name $PSDrive -PSProvider FileSystem -Root $destinationFolder | Out-Null
			
			# Check for Writting rights
			"TestFile" | Out-File ${PSDrive}:\test.txt
			Remove-Item ${PSDrive}:\test.txt
		}
		
		$destinationFolder = "${PSDrive}:"
		Write-Verbose "destinationFolder = $destinationFolder"
		
		# Save the old background
		$oldBackground = "$(get-date -format 'yyyyMMddHHmm').jpg"
		try {
			# If we get an error here its probalby because the $Filename doesn't exist
			Move-Item "$destinationFolder\$Filename" "$destinationFolder\$oldBackground" -ErrorAction SilentlyContinue
			
			# Save the new Background
			Copy-Item $SourceImage -destination "$destinationFolder\$Filename"
			
			Write-Verbose "Writing the key"
			
			#set the Key to enable customiyed Background
			$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
			$regkey = $reg.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Background", $true)
			$regkey.SetValue("OEMBackground", 1, [Microsoft.Win32.RegistryValueKind]::DWord)
		} catch {
			Write-Verbose "Error ocurred copying the Background or Setting the Key."
			Write-Error $_.Exception.Message
		}
		
	} catch {
		Write-Verbose "Error Ocurred."
		Write-Error $_.Exception.Message
	} finally {
		if (Get-PSDrive -Name $PSDrive) {
			Write-Verbose "Dismounting PSDrive."
			Remove-PSDrive -Name $PSDrive
		}
	}
}

<#
	.SYNOPSIS
		Modify the Size of an Image
	
	.DESCRIPTION
		If you have an image and want just change his JPEG Compression till it reaches a Maximum size. It was designed to fit the needs of
		the Logon Background for Windows 7.
	
	.PARAMETER Image
		Image to change
	
	.PARAMETER MaxSize
		Default will be the size of Logon background default 250Kb.
	
	.PARAMETER Output
		Where to save the Image
	
	.EXAMPLE
		PS C:\>  Set-ImageFilter -Image c:\temp\image.jpg -Output "C:\temp\imageSmall.jpg"

	.EXAMPLE
		PS C:\> foreach ($image in (Get-ChildItem $source)) { Set-ImageFilter -Image $image.FullName -Output "$destination\$($image.Name)"}

	.NOTES
		# 
		# https://msdn.microsoft.com/en-us/library/bb882583(v=vs.110).aspx
#>
function Set-ImageFilter {
	param
		(
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Test-Path $_ -PathType Leaf })]
		[string]$Image,
		
		[string]$MaxSize = 250Kb,
		
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Test-Path $_ -PathType Leaf -IsValid })]
		[string]$Output
	)
	
	Add-Type -AssemblyName System.Drawing
	
	$tmpOutput = [io.path]::GetTempFileName()
	
	# Load the Image
	$imageLoad = New-Object System.Drawing.Bitmap($Image)
	
	$jpgEncoder = [System.Drawing.Imaging.ImageCodecInfo]::GetImageDecoders() | Where-Object { $_.FormatID -eq [System.Drawing.Imaging.ImageFormat]::JPEG.Guid.Guid }
	
	# Create an Encoder object based on the GUID for the Quality parameter category.
	$myEncoder = [System.Drawing.Imaging.Encoder]::Quality
	
	$myEncoderParameters = New-Object System.Drawing.Imaging.EncoderParameters(1)
	
	$quality = 100
	do {
		$myEncoderParameter = New-Object System.Drawing.Imaging.EncoderParameter($myEncoder, $quality)
		$myEncoderParameters.Param[0] = $myEncoderParameter
		
		$imageLoad.Save($tmpOutput, $jpgEncoder, $myEncoderParameters)
		$quality--
	} while (((Get-Item $tmpOutput).Length -gt $MaxSize) -or $quality -eq 0)
	Remove-Item $tmpOutput
	
	Write-Host "Quality: $quality"
	$imageLoad.Save($Output, $jpgEncoder, $myEncoderParameters)
}


Export-ModuleMember Remove-LocalProfile,
					Add-LocalGroupMember,
					Add-LocalUser,
					Get-ComputerUptime,
					Get-InstalledSoftware,
					Get-LocalGroup,
					Get-LocalGroupMember,
					Get-LocalGroups,
					Get-LoggedOnUser,
					Remove-LocalGroupMember,
					Set-BackgroundDesktop,
					Set-BackgroundLogon,
					Set-ImageFilter