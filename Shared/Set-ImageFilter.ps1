#
# Set_ImageFilter.ps1
#
# https://msdn.microsoft.com/en-us/library/bb882583(v=vs.110).aspx
function Set-ImageFilter {
	param (
		[Parameter(Mandatory=$true)]
		$Image,
		$MaxSize = 250Kb,
		[Parameter(Mandatory=$true)]
		$Output
	)
	Add-Type -AssemblyName System.Drawing

	$tmpOutput = [io.path]::GetTempFileName()
	
	# Load the Image
	$imageLoad = New-Object System.Drawing.Bitmap($Image)

	$jpgEncoder = [System.Drawing.Imaging.ImageCodecInfo]::GetImageDecoders() | Where-Object {$_.FormatID -eq [System.Drawing.Imaging.ImageFormat]::JPEG.Guid.Guid }

	# Create an Encoder object based on the GUID for the Quality parameter category.
	$myEncoder = [System.Drawing.Imaging.Encoder]::Quality

	$myEncoderParameters = New-Object System.Drawing.Imaging.EncoderParameters(1)

	$quality = 100
	do {
		$myEncoderParameter = New-Object System.Drawing.Imaging.EncoderParameter($myEncoder,$quality)
		$myEncoderParameters.Param[0] = $myEncoderParameter

		$imageLoad.Save($tmpOutput,$jpgEncoder,$myEncoderParameters)
		$quality--
	}while (((Get-Item $tmpOutput).Length -gt $MaxSize) -or $quality -eq 0)
	Remove-Item $tmpOutput

	Write-Host "Quality: $quality"
	$imageLoad.Save($Output,$jpgEncoder,$myEncoderParameters)
}

# foreach ($image in (Get-ChildItem "G:\IFS\PERSONEN\luj\H3D")) { Set-ImageFilter -Image $image.FullName -Output "G:\IFS\PERSONEN\luj\Background\$($image.Name)"}