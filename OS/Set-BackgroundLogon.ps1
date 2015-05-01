#
# Set_LogonBackground.ps1
#
function Set-BackgroundLogon {
	[CmdletBinding()]
	param (
	[Parameter(Mandatory=$true)]
    [ValidateScript({(Test-Path $_ -PathType Leaf ) -and ((Get-Item $_).Length -le 256kb)})] 
	[String]$SourceImage,

    [ValidateScript({Test-Connection $_ -Count 1 -Quiet})]
	[String]$ComputerName = "localhost"
	)

	$ErrorActionPreference = 'Stop'

	# Default Filename defined by Microsoft
	$Filename = "BackgroundDefault.jpg"

	Write-Verbose "SourceImage = $SourceImage"
	Write-Verbose "ComputerName = $ComputerName"
	Write-Verbose "Filename =  $Filename"
	
	
	if ($ComputerName -ne "localhost"){
		$destinationFolder = "\\$ComputerName\C$\Windows\System32\oobe\info\backgrounds"
	}
	else {
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
			$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$ComputerName)
			$regkey = $reg.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Background",$true)
			$regkey.SetValue("OEMBackground",1,[Microsoft.Win32.RegistryValueKind]::DWord)
		}
		catch {
			Write-Verbose "Error ocurred copying the Background or Setting the Key."
			Write-Error $_.Exception.Message
		}

	}
	catch {
		Write-Verbose "Error Ocurred."
		Write-Error $_.Exception.Message
	}
	finally {
		if (Get-PSDrive -Name $PSDrive) {
			Write-Verbose "Dismounting PSDrive."
			Remove-PSDrive -Name $PSDrive
		}
	}
}

#Set-BackgroundLogon -SourceImage c:\temp\legolotr1.jpg -ComputerName C020794 -Verbose