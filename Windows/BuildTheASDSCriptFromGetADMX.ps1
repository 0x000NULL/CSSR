#Author: David Cottingham
#Uses Content From MidnightFreddie https://gist.github.com/midnightfreddie/69d25ddf5ed784d75c1180f12bee84a6
#This script is a little insane, it was made to create another powershell script to check registry settings, based on data pulled from getadmx.com

Function Get-RandomAlphanumericString {
	
	[CmdletBinding()]
	Param (
        [int] $length = 8
	)

	Begin{
	}

	Process{
        Write-Output ( -join ((0x30..0x39) + ( 0x41..0x5A) + ( 0x61..0x7A) | Get-Random -Count $length  | % {[char]$_}) )
	}	
}

$browser = New-Object System.Net.WebClient
$browser.Proxy.Credentials =[System.Net.CredentialCache]::DefaultNetworkCredentials 
$Uri = Read-Host 'Please paste a Valid Control URL from getadmx.com'

$InfoPage = Invoke-Webrequest -Uri $Uri

$title = $InfoPage.ParsedHtml.getElementsByTagName("h1") | Select-Object innerText

$InfoPage.ParsedHtml.getElementsByTagName("tbody") | ForEach-Object {

    $Headers = @("Type", "Value")
    $n=0
    $_.getElementsByTagName("tr") | ForEach-Object {
        $OutputRow = $_.getElementsByTagName("td") | Select-Object -ExpandProperty InnerText
        if ($Headers) {
            $OutputHash = [ordered]@{}
            for($i=0;$i -lt $OutputRow.Count;$i++) {
                $OutputHash[$Headers[$i]] = $OutputRow[$i]
            }
            New-Object psobject -Property $OutputHash
        } else {
            $Headers = $OutputRow

        }
        $n++
        New-Variable -Name "Row$n" -Value $OutputHash.Value
    }
}

$Random = (Get-RandomAlphanumericString -length 15 | Tee-Object -variable teeTime )
New-Variable -Name $Random -Value $null

$pagetitle = $title.innerText
write-host "The Control Name is $pagetitle" -ForegroundColor Green
write-host "The Registry Hive is $Row1" -ForegroundColor Green
write-host "The Registry Path is $Row2" -ForegroundColor Green
write-host "The Registry Value is $Row3" -ForegroundColor Green
write-host "The Enabled Value is $Row5" -ForegroundColor Green
write-host "The Disabled Value is $Row6" -ForegroundColor Green


$variablelm = '$LM'+$Random
$variableup = '$UP'+$Random
$variablestd = '$'+$Random
$enabled = ''''+$row5+''''
$disabled = ''''+$row6+''''

$ASDRecommended = Read-Host 'What is the ASD Recommended Setting for' $pagetitle '(e for Enabled or d for Disabled)'

write-host "`r`n####################### START #######################`r`n"

if ($ASDRecommended -eq 'e')
{

if ($Row1 -eq 'HKEY_LOCAL_MACHINE or HKEY_CURRENT_USER')
{

write-host $variablelm '= Get-ItemProperty -Path' ''"'Registry::HKLM\$Row2\'"'-Name' $Row3 '-ErrorAction SilentlyContinue|Select-Object -ExpandProperty' $Row3
write-host $variableup '= Get-ItemProperty -Path' ''"'Registry::HKCU\$Row2\'"'-Name' $Row3 '-ErrorAction SilentlyContinue|Select-Object -ExpandProperty' $Row3
write-host 'if ('$variablelm '-eq $null -and '$variableup '-eq $null)'
write-host '{'
write-host 'write-host "'$pagetitle 'is not configured" -ForegroundColor Yellow'
write-host '}'
write-host 'if ('$variablelm ' -eq' $enabled ')'
write-host '{'
write-host     'write-host "'$pagetitle 'is enabled in Local Machine GP" -ForegroundColor Green'
write-host '}'
write-host 'if ('$variablelm ' -eq' $disabled ')'
write-host '{'
write-host     'write-host "'$pagetitle 'is disabled in Local Machine GP" -ForegroundColor Red' 
write-host '}'
write-host 'if ('$variableup ' -eq ' $enabled ')'
write-host '{'
write-host     'write-host "'$pagetitle 'is enabled in User GP" -ForegroundColor Green'
write-host '}'
write-host 'if ('$variableup ' -eq ' $disabled ')'
write-host '{'
write-host     'write-host "'$pagetitle 'is disabled in User GP" -ForegroundColor Red'
write-host '}'
}
else
{
write-host $variablestd '= Get-ItemProperty -Path' ''"'Registry::$Row1\$Row2\'"' -Name' $Row3 '-ErrorAction SilentlyContinue|Select-Object -ExpandProperty' $Row3

write-host 'if ('$variablestd '-eq $null)'
write-host '{'
write-host 'write-host "'$pagetitle 'is not configured" -ForegroundColor Yellow'
write-host '}'
write-host '   elseif ('$variablestd ' -eq '$enabled ')'
write-host '{'
write-host     'write-host "'$pagetitle 'is enabled" -ForegroundColor Green'
write-host '}'
write-host  '  elseif ('$variablestd ' -eq '$disabled ')'
write-host '{'
write-host     'write-host "'$pagetitle 'is disabled" -ForegroundColor Red'
write-host '}'
write-host  '  else'
write-host '{'
write-host     'write-host "'$pagetitle 'is set to an unknown setting" -ForegroundColor Red'
write-host '}'
}

}

if ($ASDRecommended -eq 'd')
{

if ($Row1 -eq 'HKEY_LOCAL_MACHINE or HKEY_CURRENT_USER')
{

write-host $variablelm '= Get-ItemProperty -Path' ''"'Registry::HKLM\$Row2\'"' -Name' $Row3 '-ErrorAction SilentlyContinue|Select-Object -ExpandProperty' $Row3
write-host $variableup '= Get-ItemProperty -Path' ''"'Registry::HKCU\$Row2\'"' -Name' $Row3 '-ErrorAction SilentlyContinue|Select-Object -ExpandProperty' $Row3
write-host 'if ('$variablelm '-eq $null -and '$variableup '-eq $null)'
write-host '{'
write-host 'write-host "'$pagetitle 'is not configured" -ForegroundColor Yellow'
write-host '}'
write-host 'if ('$variablelm ' -eq' $enabled ')'
write-host '{'
write-host     'write-host "'$pagetitle 'is enabled in Local Machine GP" -ForegroundColor Red'
write-host '}'
write-host 'if ('$variablelm ' -eq' $disabled ')'
write-host '{'
write-host     'write-host "'$pagetitle 'is disabled in Local Machine GP" -ForegroundColor Green'
write-host '}'
write-host 'if ('$variableup ' -eq ' $enabled ')'
write-host '{'
write-host     'write-host "'$pagetitle 'is enabled in User GP" -ForegroundColor Red'
write-host '}'
write-host 'if ('$variableup ' -eq ' $disabled ')'
write-host '{'
write-host     'write-host "'$pagetitle 'is disabled in User GP" -ForegroundColor Green'
write-host '}'
}
else
{
write-host $variablestd '= Get-ItemProperty -Path' ''"'Registry::$Row1\$Row2\'"' -Name' $Row3 '-ErrorAction SilentlyContinue|Select-Object -ExpandProperty' $Row3

write-host 'if ('$variablestd '-eq $null)'
write-host '{'
write-host 'write-host "'$pagetitle 'is not configured" -ForegroundColor Yellow'
write-host '}'
write-host '   elseif ('$variablestd ' -eq '$disabled ')'
write-host '{'
write-host     'write-host "'$pagetitle 'is disabled" -ForegroundColor Green'
write-host '}'
write-host  '  elseif ('$variablestd ' -eq '$enabled ')'
write-host '{'
write-host     'write-host "'$pagetitle 'is enabled" -ForegroundColor Red'
write-host '}'
write-host  '  else'
write-host '{'
write-host     'write-host "'$pagetitle 'is set to an unknown setting" -ForegroundColor Red'
write-host '}'
}

}
write-host "`r`n####################### END #######################`r`n"

Get-Variable -Exclude PWD,*Preference | Remove-Variable -EA 0