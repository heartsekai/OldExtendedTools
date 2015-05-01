#
# Get_LoggedOnUser.ps1
#
# https://gallery.technet.microsoft.com/scriptcenter/d46b1f3b-36a4-4a56-951b-e37815a2df0c
function Get-LoggedOnUser {
#Require -Version 2.0 and Running as local admin.           
[CmdletBinding()]            
 Param             
   (                       
    [Parameter(Mandatory=$true,
               Position=0,                          
               ValueFromPipeline=$true,            
               ValueFromPipelineByPropertyName=$true)]            
    [String[]]$ComputerName
   )#End Param

Begin            
{            
 Write-Verbose "`n Checking Users . . . "
 $i = 0            
}#Begin          
Process            
{
    $ComputerName | Foreach-object {
    $Computer = $_
    try
        {
            $processinfo = @(Get-WmiObject -class win32_process -ComputerName $Computer -EA "Stop")
                if ($processinfo)
                {    
                    $processinfo | Foreach-Object {$_.GetOwner().User} | 
                    Where-Object {$_ -ne "NETWORK SERVICE" -and $_ -ne "LOCAL SERVICE" -and $_ -ne "SYSTEM"} |
                    Sort-Object -Unique |
                    ForEach-Object { New-Object psobject -Property @{Computer=$Computer;LoggedOn=$_} } | 
                    Select-Object Computer,LoggedOn
                }#If
        }
    catch
        {
            "Cannot find any processes running on $computer" | Out-Host
        }
     }#Forech-object(Comptuters)       
            
}#Process
End
{

}#End

}#Get-LoggedOnUser
