$path=Split-Path -parent $MyInvocation.MyCommand.Definition
$path2=Get-content $path/path.txt
$accounts = Get-Wmiobject Win32_UserAccount -filter 'LocalAccount=TRUE' | select-object -expandproperty Name
Clear-content "$path2\users.txt"
foreach($l in $accounts){
	$l >> "$path2\users.txt"
}