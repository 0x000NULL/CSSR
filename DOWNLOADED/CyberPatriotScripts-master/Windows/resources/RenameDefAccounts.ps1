#Self elevate
if(-NOT([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){   
	$arguments="& '"+$myinvocation.mycommand.definition+"'"
	Start-Process powershell -Verb runAs -ArgumentList $arguments
	Break
}
Write-host 'Renaming Administrator account to "Dude"'
$adminAccount =Get-WMIObject Win32_UserAccount -Filter "Name='Administrator'"
$result =$adminAccount.Rename("Dude")
if($result.ReturnValue -eq 0){
	Write-host "Changed Administrator account to Dude"
}else{
	Write-host "Failed renaming administrator, please manually rename it"
	Start-Process C:\Windows\System32\lusrmgr.msc -Wait
}
Write-host 'Renaming Guest account to "LameDude"'
$guestAccount =Get-WMIObject Win32_UserAccount -Filter "Name='Guest'"
$result =$guestAccount.Rename("LameDude")
if($result.ReturnValue -eq 0){
	Write-host "Changed Administrator account to LameDude"
}else{
	Write-host "Failed renaming administrator, please manually rename it"
	Start-Process C:\Windows\System32\lusrmgr.msc -Wait
}