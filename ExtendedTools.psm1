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
#  .EXTERNALHELP ExtendedTools.psm1-Help.xml
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

#  .EXTERNALHELP ExtendedTools.psm1-Help.xml
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

#  .EXTERNALHELP ExtendedTools.psm1-Help.xml
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

#  .EXTERNALHELP ExtendedTools.psm1-Help.xml
function Convert-XamlToPowershell {
    param(
        [String]$Path,
        [String]$DestinationPath
    )

    $XamlFile = Get-Content $Path -Raw

    # Get all Click Events
    $ClickEvents = @{}
    $regex = new-object System.Text.RegularExpressions.Regex ('.+Name="(\S+)".+Click="(\S+)".*', [System.Text.RegularExpressions.RegexOptions]::MultiLine)
    $match = $regex.Matches($XamlFile)
    foreach ($click in $match){
        $ClickEvents.Add($click.Groups[1].Value,$click.Groups[2].Value)
    }

    # Get all FormObjects
    [System.Collections.ArrayList]$FormObjects = @()
    $regex = new-object System.Text.RegularExpressions.Regex ('.+Name="(\S+)".+', [System.Text.RegularExpressions.RegexOptions]::MultiLine)
    $match = $regex.Matches($XamlFile)
    foreach ($FormObject in $match){
        $FormObjects.Add("`$$($FormObject.Groups[1].Value)")
    }

    # Remove unneeded Code
    $XamlFile = $XamlFile -replace 'x:Class="\S+"'
    $XamlFile = $XamlFile -replace 'Class="\S+"'
    $XamlFile = $XamlFile -replace 'mc:Ignorable="d"'
    $XamlFile = $XamlFile -replace 'x:(?<name>Name="\S+")', "`${name}"
    $XamlFile = $XamlFile -replace '(Click="\S+")'

    $Document = "`n#region XAMLoutput`n"
    $Document += '$xamlstring = @"' +"`n$XamlFile`n" + '"@'
    $Document += "`n#endregion"

    $Document += @"
    `n
    #region AutoGenerated
    [void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
    [xml]`$xaml = `$xamlstring
    `$reader=(New-Object System.Xml.XmlNodeReader `$xaml)
    try {
        `$Window = [Windows.Markup.XamlReader]::Load(`$reader)
    }
    catch {
        Write-Host "Unable to load Windows.Markup.XamlReader. Some possible causes for this problem include: .NET Framework is missing PowerShell must be launched with PowerShell -sta, invalid XAML code was encountered."
        exit
    }

    #===========================================================================
    # Store Window Objects In PowerShell
    #===========================================================================

    `$xaml.SelectNodes("//*[@Name]") | %{Set-Variable -Name (`$_.Name) -Value `$Window.FindName(`$_.Name)}

"@

    $Document += @"

    #===========================================================================
    # Add Events
    #===========================================================================

"@

    foreach ($element in $ClickEvents.GetEnumerator()){
        $Document += "`$$($element.Key).Add_Click(`$$($element.Value))`n"
    }
    $Document += "`n#endregion"

    $Document += @"

    #List of Availible FormObjects
    #$FormObjects

    #===========================================================================
    # Here goes your Code
    #===========================================================================


"@
    foreach ($element in $ClickEvents.GetEnumerator()){
        $Document += "`$$($element.Value)={`n`t#TODO: Place custom script here`n}`n`n"
    }

    $Document += @"


    #===========================================================================
    #===========================================================================

"@


    #Adding Ending
    $Document += @"

    #region ShowDialog
    #===========================================================================
    # Shows the Window
    #===========================================================================
    `Window.ShowDialog() | out-null
    #endregion
"@

    # Save the File
    $Document > $DestinationPath
}

#  .EXTERNALHELP ExtendedTools.psm1-Help.xml
function Get-ComputerUptime {
	param (
		[String]$ComputerName = $env:COMPUTERNAME
	)
	
	Get-WmiObject Win32_OperatingSystem -cn $ComputerName |
	Select __SERVER,
		   @{ N = 'UpTime'; E = { (Get-Date) - $_.ConvertToDateTime($_.LastBootUpTime) } }
	
}


#  .EXTERNALHELP ExtendedTools.psm1-Help.xml
function Get-AppSenseLogsToCmTrace {
	[CmdletBinding()]
    param(
		[String]$ComputerName = $env:COMPUTERNAME,
		[String]$LogFile = $ComputerName + "_Output.log"
	)
	
	#Obtain UTC offset 
    $DateTime = New-Object -ComObject WbemScripting.SWbemDateTime  
    $DateTime.SetVarDate($(Get-Date)) 
    $UtcValue = $DateTime.Value 
    $UtcOffset = $UtcValue.Substring(21, $UtcValue.Length - 21)

    $regex = "(?<Start>^Logon \(\D*\) )(?<Time>Time:.*)(?<Node>Node Name:.*)(?<Action>Action:.*)(?<Start>Start Time:.*)(?<Duration>Duration: .*)ms(?( ) (?<Error>Error Code:.*)*|\.)"

	# if computer is offline we don't need to continue
	Write-Verbose "Pinging $ComputerName"
	if (!(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction 'Stop')){
		Write-Host "$ComputerName is Offline."
		exit
	}
	Write-Verbose "$ComputerName is Online."

	try {
		#Get the Events
		Write-Verbose "Exporting Events from $ComputerName"
		$stadistics = Measure-Command {$EventList = Get-EventLog -LogName AppSense -ComputerName $ComputerName}
		Write-Verbose "$($EventList.Count) Events Exported in $($stadistics.TotalSeconds) Seconds."
		
		#for progressbar
		$i = 0

		foreach ($item in $EventList){
			Write-Progress -Activity "Converting to CmTrace" -status "Converting Event $($i+1) from $($EventList.Count)" -percentComplete ($i/$EventList.Count*100)
			$i++
			# EventLog give the Error type in text, CmTrace accepts only numbers
			# we do first this check, coz later it can be changed depending the message. (Appsense mark Errors as Info)
			switch ($item.EntryType) {
				"Warning" { $type = 2 }
				"Error" { $type = 3 }
				default { $type = 1 }
			}

			# We put the message in a readable way
			if ($item.Message -match $regex) {
				$message = "$($matches.Start)`n$($matches.Time)`n$($matches.Node)`n$($matches.Action)`n$($matches.Start)`n$($matches.Duration)"
				if (![String]::IsNullOrEmpty($matches.Error)) {
				    $message += "`n$($matches.Error)"
				    #we set an Error
				    $type = 3
				}
			}
			else {
				$message = $item.Message
			}
		

			 $logline = `
			"<![LOG[$message]LOG]!>" +`
			"<time=`"$(Get-Date $item.TimeGenerated -Format HH:mm:ss.fff)$($UtcOffset)`" " +`
			"date=`"$(Get-Date $item.TimeGenerated -Format M-d-yyyy)`" " +`
			"component=`"$($item.Source)`" " +`
			"context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " +`
			"type=`"$type`" " +`
			"thread=`"$($item.EventID)`" " +`
			"file=`"$($item.MachineName)`">";
			$logline | Out-File -Append -Encoding utf8 -FilePath $Logfile;
		}
	}
	catch{
		Write-Error "Something went terribly wrong.`n$($_.Exception.Message)"
	}
	Write-Verbose "Done. Logfile = $Logfile"
}

#  .EXTERNALHELP ExtendedTools.psm1-Help.xml
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

#  .EXTERNALHELP ExtendedTools.psm1-Help.xml
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

#  .EXTERNALHELP ExtendedTools.psm1-Help.xml
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

#  .EXTERNALHELP ExtendedTools.psm1-Help.xml
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

#  .EXTERNALHELP ExtendedTools.psm1-Help.xml
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
		Search for a Project in the defined $ProjectDefault.
	
	.DESCRIPTION
		A detailed description of the push-project function.
	
	.PARAMETER ProjectName
		Name of the Project.
	
	.PARAMETER Path
		Paths where the Projects are.
	
	.EXAMPLE
		PS C:\> Push-Project win C:\PortableApps C:\Temp\Library1 C:\Temp\Library2
        1 - PortableApps / WinDirStatPortable
        2 - PortableApps / WinMergePortable
        3 - Library1 / WinDirStatPortable
        4 - Library1 / WinMergePortable
        0 - Exit
        Select one Project> : 3

        PS C:\Temp\Library1\WinDirStatPortable>
	.NOTES
		Additional information about the function.
#>
function Push-Project
{
    [CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true, Position = 1)]
		[String]$ProjectName,
		[Parameter(ValueFromRemainingArguments=$true)]
		[String[]]$Path = $PushProjectPath
	)
	
    Write-Verbose "Finding all the matches."
    $ProjectPathList = ls $Path -Filter "*$ProjectName*" -Directory
    Write-Verbose "Got $($ProjectPath.Length) matches."

    if ($ProjectPathList.Length -gt 1)
    {
        # build a menulist with the options
        $i = 1
        foreach ($item in $ProjectPathList)
        {
            Write-Host "$i - $($item.Parent.Name) / $($item.Name)"
            $i++
        }
        Write-Host "0 - Exit"
        
        $check = 0
        do
        {
            $option = Read-Host "Select one Project> "
            if (![Int32]::TryParse($option, [ref]$check))
            {
                Write-Host "Only integer please."
                # reset $option
                $option = -1
            }
        }
        while (([int]$option -lt 0) -or ([int]$option -gt $ProjectPathList.Length + 1))
        
        switch ($option)
        {
            0 { return }
            default
            {
                $ProjectPath = $ProjectPathList[$option -1]
            }
        }
    }

    if ($ProjectPath) {
        Write-Verbose "Pushd to $($ProjectPath.FullName)"
       Pushd $ProjectPath.FullName 
    }
    else {
        "No matches found." | Out-String 
    }
}


#  .EXTERNALHELP ExtendedTools.psm1-Help.xml
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

#  .EXTERNALHELP ExtendedTools.psm1-Help.xml
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

#  .EXTERNALHELP ExtendedTools.psm1-Help.xml
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

#  .EXTERNALHELP ExtendedTools.psm1-Help.xml
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


#  .EXTERNALHELP ExtendedTools.psm1-Help.xml
function Write-CMTraceLog{
     #Define and validate parameters 
    [CmdletBinding()] 
    Param( 
 
        #Path to the log file 
        [parameter(Mandatory=$False)]      
        [String]$Logfile = "$Env:Temp\ExtendedTools-cmtrace.log",
         
        #The information to log 
        [parameter(Mandatory=$True)] 
        $Message,
 
        #The severity (Error, Warning, Verbose, Debug, Information)
        [parameter(Mandatory=$True)]
        [ValidateSet('Warning','Error','Verbose','Debug', 'Information')] 
        [String]$Type,
 
        #Write back to the console or just to the log file. By default it will write back to the host.
        [parameter(Mandatory=$False)]
        [switch]$WriteBackToHost = $false
 
    )#Param
    
    #Get the info about the calling script, function etc
    $callinginfo = (Get-PSCallStack)[1]
 
    #Set Source Information
    $Source = (Get-PSCallStack)[1].Location
 
    #Set Component Information
    $Component = (Get-Process -Id $PID).ProcessName
 
    #Set PID Information
    $ProcessID = $PID
 
    #Obtain UTC offset 
    $DateTime = New-Object -ComObject WbemScripting.SWbemDateTime  
    $DateTime.SetVarDate($(Get-Date)) 
    $UtcValue = $DateTime.Value 
    $UtcOffset = $UtcValue.Substring(21, $UtcValue.Length - 21)
 
    #Set the order 
    switch($Type){
           'Warning' {$Severity = 2}#Warning
             'Error' {$Severity = 3}#Error
           'Verbose' {$Severity = 4}#Verbose
             'Debug' {$Severity = 5}#Debug
       'Information' {$Severity = 6}#Information
    }#Switch
 
    #Switch statement to write out to the log and/or back to the host.
    switch ($severity){
        2{
            #Warning
            
            #Write the log entry in the CMTrace Format.
             $logline = `
            "<![LOG[$($($Type.ToUpper()) + ": " +  $message)]LOG]!>" +`
            "<time=`"$(Get-Date -Format HH:mm:ss.fff)$($UtcOffset)`" " +`
            "date=`"$(Get-Date -Format M-d-yyyy)`" " +`
            "component=`"$Component`" " +`
            "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " +`
            "type=`"$Severity`" " +`
            "thread=`"$ProcessID`" " +`
            "file=`"$Source`">";
            $logline | Out-File -Append -Encoding utf8 -FilePath $Logfile;
            
            #Write back to the host if $Writebacktohost is true.
            if(($WriteBackToHost) -and ($Type -eq 'Warning')){
                Switch($PSCmdlet.GetVariableValue('WarningPreference')){
                    'Continue' {$WarningPreference = 'Continue';Write-Warning -Message "$Message";$WarningPreference=''}
                    'Stop' {$WarningPreference = 'Stop';Write-Warning -Message "$Message";$WarningPreference=''}
                    'Inquire' {$WarningPreference ='Inquire';Write-Warning -Message "$Message";$WarningPreference=''}
                    'SilentlyContinue' {}
                }
                Write-Warning -Message "$Message"
            }
 
        }#Warning
        3{  
            #Error
 
            #This if statement is to catch the two different types of errors that may come through. A normal terminating exception will have all the information that is needed, if it's a user generated error by using Write-Error,
            #then the else statment will setup all the information we would like to log.   
            if($Message.exception.Message){                
                if(($WriteBackToHost)-and($Type -eq 'Error')){                                        
                    #Write the log entry in the CMTrace Format.
                    $logline = `
                    "<![LOG[$($($Type.ToUpper()) + ": " +  "$([String]$Message.exception.message)`r`r" + `
                    "`nCommand: $($Message.InvocationInfo.MyCommand)" + `
                    "`nScriptName: $($Message.InvocationInfo.Scriptname)" + `
                    "`nLine Number: $($Message.InvocationInfo.ScriptLineNumber)" + `
                    "`nColumn Number: $($Message.InvocationInfo.OffsetInLine)" + `
                    "`nLine: $($Message.InvocationInfo.Line)")]LOG]!>" +`
                    "<time=`"$(Get-Date -Format HH:mm:ss.fff)$($UtcOffset)`" " +`
                    "date=`"$(Get-Date -Format M-d-yyyy)`" " +`
                    "component=`"$Component`" " +`
                    "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " +`
                    "type=`"$Severity`" " +`
                    "thread=`"$ProcessID`" " +`
                    "file=`"$Source`">"
                    $logline | Out-File -Append -Encoding utf8 -FilePath $Logfile;
                    #Write back to Host
                    Switch($PSCmdlet.GetVariableValue('ErrorActionPreference')){
                        'Stop'{$ErrorActionPreference = 'Stop';$Host.Ui.WriteErrorLine("ERROR: $([String]$Message.Exception.Message)");Write-Error $Message -ErrorAction 'Stop';$ErrorActionPreference=''}
                        'Inquire'{$ErrorActionPreference = 'Inquire';$Host.Ui.WriteErrorLine("ERROR: $([String]$Message.Exception.Message)");Write-Error $Message -ErrorAction 'Inquire';$ErrorActionPreference=''}
                        'Continue'{$ErrorActionPreference = 'Continue';$Host.Ui.WriteErrorLine("ERROR: $([String]$Message.Exception.Message)");$ErrorActionPreference=''}
                        'Suspend'{$ErrorActionPreference = 'Suspend';$Host.Ui.WriteErrorLine("ERROR: $([String]$Message.Exception.Message)");Write-Error $Message -ErrorAction 'Suspend';$ErrorActionPreference=''}
                        'SilentlyContinue'{}
                    }
 
                }
                else{                   
                    #Write the log entry in the CMTrace Format.
                    $logline = `
                    "<![LOG[$($($Type.ToUpper()) + ": " +  "$([String]$Message.exception.message)`r`r" + `
                    "`nCommand: $($Message.InvocationInfo.MyCommand)" + `
                    "`nScriptName: $($Message.InvocationInfo.Scriptname)" + `
                    "`nLine Number: $($Message.InvocationInfo.ScriptLineNumber)" + `
                    "`nColumn Number: $($Message.InvocationInfo.OffsetInLine)" + `
                    "`nLine: $($Message.InvocationInfo.Line)")]LOG]!>" +`
                    "<time=`"$(Get-Date -Format HH:mm:ss.fff)$($UtcOffset)`" " +`
                    "date=`"$(Get-Date -Format M-d-yyyy)`" " +`
                    "component=`"$Component`" " +`
                    "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " +`
                    "type=`"$Severity`" " +`
                    "thread=`"$ProcessID`" " +`
                    "file=`"$Source`">"
                    $logline | Out-File -Append -Encoding utf8 -FilePath $Logfile;
                }
            }
            else{
                if(($WriteBackToHost)-and($type -eq 'Error')){
                    [System.Exception]$Exception = $Message
                    [String]$ErrorID = 'Custom Error'
                    [System.Management.Automation.ErrorCategory]$ErrorCategory = [Management.Automation.ErrorCategory]::WriteError
                    #[System.Object]$Message
                    $ErrorRecord = New-Object Management.automation.errorrecord ($Exception,$ErrorID,$ErrorCategory,$Message)
                    $Message = $ErrorRecord
                    #Write the log entry
                    $logline = `
                        "<![LOG[$($($Type.ToUpper()) + ": " +  "$([String]$Message.exception.message)`r`r" + `
                        "`nFunction: $($Callinginfo.FunctionName)" + `
                        "`nScriptName: $($Callinginfo.Scriptname)" + `
                        "`nLine Number: $($Callinginfo.ScriptLineNumber)" + `
                        "`nColumn Number: $($callinginfo.Position.StartColumnNumber)" + `
                        "`nLine: $($Callinginfo.Position.StartScriptPosition.Line)")]LOG]!>" +`
                        "<time=`"$(Get-Date -Format HH:mm:ss.fff)$($UtcOffset)`" " +`
                        "date=`"$(Get-Date -Format M-d-yyyy)`" " +`
                        "component=`"$Component`" " +`
                        "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " +`
                        "type=`"$Severity`" " +`
                        "thread=`"$ProcessID`" " +`
                        "file=`"$Source`">"
                        $logline | Out-File -Append -Encoding utf8 -FilePath $Logfile;
                    #Write back to Host.
                    Switch($PSCmdlet.GetVariableValue('ErrorActionPreference')){
                            'Stop'{$ErrorActionPreference = 'Stop';$Host.Ui.WriteErrorLine("ERROR: $([String]$Message.Exception.Message)");Write-Error $Message -ErrorAction 'Stop';$ErrorActionPreference=''}
                            'Inquire'{$ErrorActionPreference = 'Inquire';$Host.Ui.WriteErrorLine("ERROR: $([String]$Message.Exception.Message)");Write-Error $Message -ErrorAction 'Inquire';$ErrorActionPreference=''}
                            'Continue'{$ErrorActionPreference = 'Continue';$Host.Ui.WriteErrorLine("ERROR: $([String]$Message.Exception.Message)");Write-Error $Message 2>&1 > $null;$ErrorActionPreference=''}
                            'Suspend'{$ErrorActionPreference = 'Suspend';$Host.Ui.WriteErrorLine("ERROR: $([String]$Message.Exception.Message)");Write-Error $Message -ErrorAction 'Suspend';$ErrorActionPreference=''}
                            'SilentlyContinue'{}
                        }
                    $Host.Ui.WriteErrorLine("ERROR: $([String]$Message.Exception.Message)")
                    Write-Error $Message 2>&1 > $null
                }
                else{
                    #Write the Log Entry
                    [System.Exception]$Exception = $Message
                    [String]$ErrorID = 'Custom Error'
                    [System.Management.Automation.ErrorCategory]$ErrorCategory = [Management.Automation.ErrorCategory]::WriteError
                    #[System.Object]$Message
                    $ErrorRecord = New-Object Management.automation.errorrecord ($Exception,$ErrorID,$ErrorCategory,$Message)
                    $Message = $ErrorRecord
                    #Write the log entry
                    $logline = `
                        "<![LOG[$($($Type.ToUpper())+ ": " +  "$([String]$Message.exception.message)`r`r" + `
                        "`nFunction: $($Callinginfo.FunctionName)" + `
                        "`nScriptName: $($Callinginfo.Scriptname)" + `
                        "`nLine Number: $($Callinginfo.ScriptLineNumber)" + `
                        "`nColumn Number: $($Callinginfo.Position.StartColumnNumber)" + `
                        "`nLine: $($Callinginfo.Position.StartScriptPosition.Line)")]LOG]!>" +`
                        "<time=`"$(Get-Date -Format HH:mm:ss.fff)$($UtcOffset)`" " +`
                        "date=`"$(Get-Date -Format M-d-yyyy)`" " +`
                        "component=`"$Component`" " +`
                        "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " +`
                        "type=`"$Severity`" " +`
                        "thread=`"$ProcessID`" " +`
                        "file=`"$Source`">"
                        $logline | Out-File -Append -Encoding utf8 -FilePath $Logfile;
                }                
            }   
        }#Error
        4{  
            #Verbose
            
            #Write the Log Entry
            
            $logline = `
            "<![LOG[$($($Type.ToUpper()) + ": " +  $message)]LOG]!>" +`
            "<time=`"$(Get-Date -Format HH:mm:ss.fff)$($UtcOffset)`" " +`
            "date=`"$(Get-Date -Format M-d-yyyy)`" " +`
            "component=`"$Component`" " +`
            "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " +`
            "type=`"$severity`" " +`
            "thread=`"$processid`" " +`
            "file=`"$source`">";
            $logline | Out-File -Append -Encoding utf8 -FilePath $Logfile; 
            
            #Write Back to Host
                
            if(($WriteBackToHost) -and ($Type -eq 'Verbose')){
                Switch ($PSCmdlet.GetVariableValue('VerbosePreference')) {
                    'Continue' {$VerbosePreference = 'Continue'; Write-Verbose -Message "$Message";$VerbosePreference = ''}
                    'Inquire' {$VerbosePreference = 'Inquire'; Write-Verbose -Message "$Message";$VerbosePreference = ''}
                    'Stop' {$VerbosePreference = 'Stop'; Write-Verbose -Message "$Message";$VerbosePreference = ''}
                }
            }              
       
        }#Verbose
        5{  
            #Debug
 
            #Write the Log Entry
            
            $logline = `
            "<![LOG[$($($Type.ToUpper()) + ": " +  $message)]LOG]!>" +`
            "<time=`"$(Get-Date -Format HH:mm:ss.fff)$($UtcOffset)`" " +`
            "date=`"$(Get-Date -Format M-d-yyyy)`" " +`
            "component=`"$Component`" " +`
            "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " +`
            "type=`"$severity`" " +`
            "thread=`"$processid`" " +`
            "file=`"$source`">";
            $logline | Out-File -Append -Encoding utf8 -FilePath $Logfile;  
 
            #Write Back to the Host.                              
 
            if(($WriteBackToHost) -and ($Type -eq 'Debug')){
                Switch ($PSCmdlet.GetVariableValue('DebugPreference')){
                    'Continue' {$DebugPreference = 'Continue'; Write-Debug -Message "$Message";$DebugPreference = ''}
                    'Inquire' {$DebugPreference = 'Inquire'; Write-Debug -Message "$Message";$DebugPreference = ''}
                    'Stop' {$DebugPreference = 'Stop'; Write-Debug -Message "$Message";$DebugPreference = ''}
                }
            } 
                      
        }#Debug
        6{  
            #Information
 
            #Write entry to the logfile.
 
            $logline = `
            "<![LOG[$($($Type.ToUpper()) + ": " + $message)]LOG]!>" +`
            "<time=`"$(Get-Date -Format HH:mm:ss.fff)$($UtcOffset)`" " +`
            "date=`"$(Get-Date -Format M-d-yyyy)`" " +`
            "component=`"$Component`" " +`
            "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " +`
            "type=`"$severity`" " +`
            "thread=`"$processid`" " +`
            "file=`"$source`">";            
            $logline | Out-File -Append -Encoding utf8 -FilePath $Logfile;
 
            #Write back to the host.
 
            if(($WriteBackToHost) -and ($Type -eq 'Information')){
                Switch ($PSCmdlet.GetVariableValue('InformationPreference')){
                    'Continue' {$InformationPreference = 'Continue'; Write-Information -Message "INFORMATION: $Message";$InformationPreference = ''}
                    'Inquire' {$InformationPreference = 'Inquire'; Write-Information -Message "INFORMATION: $Message";$InformationPreference = ''}
                    'Stop' {$InformationPreference = 'Stop'; Write-Information -Message "INFORMATION: $Message";$InformationPreference = ''}
                    'Suspend' {$InformationPreference = 'Suspend';Write-Information -Message "INFORMATION: $Message";$InformationPreference = ''}
                }
            }
        }#Information
    }#Switch
}#Function v1.3 - 23-12-2015



Export-ModuleMember Remove-LocalProfile,
					Add-LocalGroupMember,
					Add-LocalUser,
					Convert-XamlToPowershell,
					Get-ComputerUptime,
					Get-AppSenseLogsToCmTrace,
					Get-InstalledSoftware,
					Get-LocalGroup,
					Get-LocalGroupMember,
					Get-LocalGroups,
					Get-LoggedOnUser,
					Push-Project,
					Remove-LocalGroupMember,
					Set-BackgroundDesktop,
					Set-BackgroundLogon,
					Set-ImageFilter,
					Write-CMTraceLog