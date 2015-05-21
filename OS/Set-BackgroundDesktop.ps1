
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

