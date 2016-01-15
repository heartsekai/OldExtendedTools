
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

