#Authors: David Cottingham & Huda Minhaj
#Purpose: This script checks for compliance with the ASD Office 2016 hardening guide by checking registry keys on the local machine. Where checks are unable to be performed in this manner, either other methods of scanning are used or the user is prompted for manual checking.
#This script is designed to be used as a simple spot check of a endpoint to ensure the correct settings are applied, regardless of how complex an organisations group policy may be.
#The ASD hardening guide for Office 2016 can be downloaded here: https://www.asd.gov.au/publications/protect/Hardening_MS_Office_2016.pdf


[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [string[]]$ComputerName = $env:COMPUTERNAME,
    [switch]$ShowAllInstalledProducts,
    [System.Management.Automation.PSCredential]$Credentials
)

Function Get-OfficeVersion {
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true, Position=0)]
    [string[]]$ComputerName = $env:COMPUTERNAME,
    [switch]$ShowAllInstalledProducts,
    [System.Management.Automation.PSCredential]$Credentials
)

begin {
    $HKLM = [UInt32] "0x80000002"
    $HKCR = [UInt32] "0x80000000"

    $excelKeyPath = "Excel\DefaultIcon"
    $wordKeyPath = "Word\DefaultIcon"
   
    $installKeys = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                   'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'

    $officeKeys = 'SOFTWARE\Microsoft\Office',
                  'SOFTWARE\Wow6432Node\Microsoft\Office'

    $defaultDisplaySet = 'DisplayName','Version', 'ComputerName'

    $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet',[string[]]$defaultDisplaySet)
    $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)
}

process {

 $results = new-object PSObject[] 0;
 $MSexceptionList = "mui","visio","project","proofing","visual"

 foreach ($computer in $ComputerName) {
    if ($Credentials) {
       $os=Get-WMIObject win32_operatingsystem -computername $computer -Credential $Credentials
    } else {
       $os=Get-WMIObject win32_operatingsystem -computername $computer
    }

    $osArchitecture = $os.OSArchitecture

    if ($Credentials) {
       $regProv = Get-Wmiobject -list "StdRegProv" -namespace root\default -computername $computer -Credential $Credentials
    } else {
       $regProv = Get-Wmiobject -list "StdRegProv" -namespace root\default -computername $computer
    }

    [System.Collections.ArrayList]$VersionList = New-Object -TypeName System.Collections.ArrayList
    [System.Collections.ArrayList]$PathList = New-Object -TypeName System.Collections.ArrayList
    [System.Collections.ArrayList]$PackageList = New-Object -TypeName System.Collections.ArrayList
    [System.Collections.ArrayList]$ClickToRunPathList = New-Object -TypeName System.Collections.ArrayList
    [System.Collections.ArrayList]$ConfigItemList = New-Object -TypeName  System.Collections.ArrayList
    $ClickToRunList = new-object PSObject[] 0;

    foreach ($regKey in $officeKeys) {
       $officeVersion = $regProv.EnumKey($HKLM, $regKey)
       foreach ($key in $officeVersion.sNames) {
          if ($key -match "\d{2}\.\d") {
            if (!$VersionList.Contains($key)) {
              $AddItem = $VersionList.Add($key)
            }

            $path = join-path $regKey $key

            $configPath = join-path $path "Common\Config"
            $configItems = $regProv.EnumKey($HKLM, $configPath)
            if ($configItems) {
               foreach ($configId in $configItems.sNames) {
                 if ($configId) {
                    $Add = $ConfigItemList.Add($configId.ToUpper())
                 }
               }
            }

            $cltr = New-Object -TypeName PSObject
            $cltr | Add-Member -MemberType NoteProperty -Name InstallPath -Value ""
            $cltr | Add-Member -MemberType NoteProperty -Name UpdatesEnabled -Value $false
            $cltr | Add-Member -MemberType NoteProperty -Name UpdateUrl -Value ""
            $cltr | Add-Member -MemberType NoteProperty -Name StreamingFinished -Value $false
            $cltr | Add-Member -MemberType NoteProperty -Name Platform -Value ""
            $cltr | Add-Member -MemberType NoteProperty -Name ClientCulture -Value ""
            
            $packagePath = join-path $path "Common\InstalledPackages"
            $clickToRunPath = join-path $path "ClickToRun\Configuration"
            $virtualInstallPath = $regProv.GetStringValue($HKLM, $clickToRunPath, "InstallationPath").sValue

            [string]$officeLangResourcePath = join-path  $path "Common\LanguageResources"
            $mainLangId = $regProv.GetDWORDValue($HKLM, $officeLangResourcePath, "SKULanguage").uValue
            if ($mainLangId) {
                $mainlangCulture = [globalization.cultureinfo]::GetCultures("allCultures") | where {$_.LCID -eq $mainLangId}
                if ($mainlangCulture) {
                    $cltr.ClientCulture = $mainlangCulture.Name
                }
            }

            [string]$officeLangPath = join-path  $path "Common\LanguageResources\InstalledUIs"
            $langValues = $regProv.EnumValues($HKLM, $officeLangPath);
            if ($langValues) {
               foreach ($langValue in $langValues) {
                  $langCulture = [globalization.cultureinfo]::GetCultures("allCultures") | where {$_.LCID -eq $langValue}
               } 
            }

            if ($virtualInstallPath) {

            } else {
              $clickToRunPath = join-path $regKey "ClickToRun\Configuration"
              $virtualInstallPath = $regProv.GetStringValue($HKLM, $clickToRunPath, "InstallationPath").sValue
            }

            if ($virtualInstallPath) {
               if (!$ClickToRunPathList.Contains($virtualInstallPath.ToUpper())) {
                  $AddItem = $ClickToRunPathList.Add($virtualInstallPath.ToUpper())
               }

               $cltr.InstallPath = $virtualInstallPath
               $cltr.StreamingFinished = $regProv.GetStringValue($HKLM, $clickToRunPath, "StreamingFinished").sValue
               $cltr.UpdatesEnabled = $regProv.GetStringValue($HKLM, $clickToRunPath, "UpdatesEnabled").sValue
               $cltr.UpdateUrl = $regProv.GetStringValue($HKLM, $clickToRunPath, "UpdateUrl").sValue
               $cltr.Platform = $regProv.GetStringValue($HKLM, $clickToRunPath, "Platform").sValue
               $cltr.ClientCulture = $regProv.GetStringValue($HKLM, $clickToRunPath, "ClientCulture").sValue
               $ClickToRunList += $cltr
            }

            $packageItems = $regProv.EnumKey($HKLM, $packagePath)
            $officeItems = $regProv.EnumKey($HKLM, $path)

            foreach ($itemKey in $officeItems.sNames) {
              $itemPath = join-path $path $itemKey
              $installRootPath = join-path $itemPath "InstallRoot"

              $filePath = $regProv.GetStringValue($HKLM, $installRootPath, "Path").sValue
              if (!$PathList.Contains($filePath)) {
                  $AddItem = $PathList.Add($filePath)
              }
            }

            foreach ($packageGuid in $packageItems.sNames) {
              $packageItemPath = join-path $packagePath $packageGuid
              $packageName = $regProv.GetStringValue($HKLM, $packageItemPath, "").sValue
            
              if (!$PackageList.Contains($packageName)) {
                if ($packageName) {
                   $AddItem = $PackageList.Add($packageName.Replace(' ', '').ToLower())
                }
              }
            }

          }
       }
    }

    foreach ($regKey in $installKeys) {
        $keyList = new-object System.Collections.ArrayList
        $keys = $regProv.EnumKey($HKLM, $regKey)

        foreach ($key in $keys.sNames) {
           $path = join-path $regKey $key
           $installPath = $regProv.GetStringValue($HKLM, $path, "InstallLocation").sValue
           if (!($installPath)) { continue }
           if ($installPath.Length -eq 0) { continue }

           $buildType = "64-Bit"
           if ($osArchitecture -eq "32-bit") {
              $buildType = "32-Bit"
           }

           if ($regKey.ToUpper().Contains("Wow6432Node".ToUpper())) {
              $buildType = "32-Bit"
           }

           if ($key -match "{.{8}-.{4}-.{4}-1000-0000000FF1CE}") {
              $buildType = "64-Bit" 
           }

           if ($key -match "{.{8}-.{4}-.{4}-0000-0000000FF1CE}") {
              $buildType = "32-Bit" 
           }

           if ($modifyPath) {
               if ($modifyPath.ToLower().Contains("platform=x86")) {
                  $buildType = "32-Bit"
               }

               if ($modifyPath.ToLower().Contains("platform=x64")) {
                  $buildType = "64-Bit"
               }
           }

           $primaryOfficeProduct = $false
           $officeProduct = $false
           foreach ($officeInstallPath in $PathList) {
             if ($officeInstallPath) {
                try{
                $installReg = "^" + $installPath.Replace('\', '\\')
                $installReg = $installReg.Replace('(', '\(')
                $installReg = $installReg.Replace(')', '\)')
                if ($officeInstallPath -match $installReg) { $officeProduct = $true }
                } catch {}
             }
           }

           if (!$officeProduct) { continue };
           
           $name = $regProv.GetStringValue($HKLM, $path, "DisplayName").sValue          

           $primaryOfficeProduct = $true
           if ($ConfigItemList.Contains($key.ToUpper()) -and $name.ToUpper().Contains("MICROSOFT OFFICE")) {
              foreach($exception in $MSexceptionList){
                 if($name.ToLower() -match $exception.ToLower()){
                    $primaryOfficeProduct = $false
                 }
              }
           } else {
              $primaryOfficeProduct = $false
           }

           $clickToRunComponent = $regProv.GetDWORDValue($HKLM, $path, "ClickToRunComponent").uValue
           $uninstallString = $regProv.GetStringValue($HKLM, $path, "UninstallString").sValue
           if (!($clickToRunComponent)) {
              if ($uninstallString) {
                 if ($uninstallString.Contains("OfficeClickToRun")) {
                     $clickToRunComponent = $true
                 }
              }
           }

           $modifyPath = $regProv.GetStringValue($HKLM, $path, "ModifyPath").sValue 
           $version = $regProv.GetStringValue($HKLM, $path, "DisplayVersion").sValue

           $cltrUpdatedEnabled = $NULL
           $cltrUpdateUrl = $NULL
           $clientCulture = $NULL;

           [string]$clickToRun = $false

           if ($clickToRunComponent) {
               $clickToRun = $true
               if ($name.ToUpper().Contains("MICROSOFT OFFICE")) {
                  $primaryOfficeProduct = $true
               }

               foreach ($cltr in $ClickToRunList) {
                 if ($cltr.InstallPath) {
                   if ($cltr.InstallPath.ToUpper() -eq $installPath.ToUpper()) {
                       $cltrUpdatedEnabled = $cltr.UpdatesEnabled
                       $cltrUpdateUrl = $cltr.UpdateUrl
                       if ($cltr.Platform -eq 'x64') {
                           $buildType = "64-Bit" 
                       }
                       if ($cltr.Platform -eq 'x86') {
                           $buildType = "32-Bit" 
                       }
                       $clientCulture = $cltr.ClientCulture
                   }
                 }
               }
           }
           
           if (!$primaryOfficeProduct) {
              if (!$ShowAllInstalledProducts) {
                  continue
              }
           }

           $object = New-Object PSObject -Property @{DisplayName = $name; Version = $version; InstallPath = $installPath; ClickToRun = $clickToRun; 
                     Bitness=$buildType; ComputerName=$computer; ClickToRunUpdatesEnabled=$cltrUpdatedEnabled; ClickToRunUpdateUrl=$cltrUpdateUrl;
                     ClientCulture=$clientCulture }
           $object | Add-Member MemberSet PSStandardMembers $PSStandardMembers
           $results += $object

        }
    }
  }


  $results = Get-Unique -InputObject $results 

  return $results;
}

}

$officetemp = Get-OfficeVersion | select -ExpandProperty version
$officeversion = $officetemp.Substring(0,4)


$officeuserhive = Get-ChildItem -Path "Registry::HKCU\Software\Policies\Microsoft\Office\$officeversion\" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name 
$officelocalhive = Get-ChildItem -Path "Registry::HKLM\Software\Policies\Microsoft\Office\$officeversion\" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name 

if ($officeuserhive -eq $null -and $officelocalhive -eq $null)
{
write-host "No Microsoft Office group policies were detected, this script will now exit" -ForegroundColor Yellow
pause
break
}

write-host "`r`n####################### ATTACK SURFACE REDUCTION #######################`r`n"

#This section could be improved to check sub settings for each exploitguard rule to ensure the configured rules are set to block

$ExploitGuard_ASR_Rules = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -Name ExploitGuard_ASR_Rules -ErrorAction SilentlyContinue|Select-Object -ExpandProperty ExploitGuard_ASR_Rules

if ($ExploitGuard_ASR_Rules -eq $null)
{
    write-host "Configure Attack Surface Reduction rules is not configured or disabled" -ForegroundColor Yellow
}
elseif ($ExploitGuard_ASR_Rules -eq '1')
{
    write-host "Configure Attack Surface Reduction rules is Enabled" -ForegroundColor Green

    Get-ChildItem -Path "Registry::HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\" | Select-Object -ExpandProperty Property | ForEach-Object{

    if ($_ -contains "3b576869-a4ec-4529-8536-b80a7769e899")
    {
        write-host "Block Office applications from creating executable content is set" -ForegroundColor Green
        $blockofficeapps = 1
    }

    if ($_ -contains "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550")
    {
        write-host "Block executable content from email client and webmail is set" -ForegroundColor Green
        $blockexecutablecontent = 1
    }

    if ($_ -contains "D4F940AB-401B-4EFC-AADC-AD5F3C50688A")
    {
        write-host "Block Office applications from creating child processes is set" -ForegroundColor Green
        $blockofficechildprocess = 1
    }

    if ($_ -contains "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84")
    {
        write-host "Block Office applications from injecting code into other processes is set" -ForegroundColor Green
        $blockcodeinjection = 1
    }

    if ($_ -contains "D3E037E1-3EB8-44C8-A917-57927947596D")
    {
        write-host "Block JavaScript and VBScript from launching downloaded executable content is set" -ForegroundColor Green
        $blockjavavbscript = 1
    }

    if ($_ -contains "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC")
    {
        write-host "Block execution of potentially obfuscated scripts is set" -ForegroundColor Green
        $blockobfuscated = 1
    }

    if ($_ -contains "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B")
    {
        write-host "Block Win32 API calls from Office macro is set" -ForegroundColor Green
        $blockwin32api = 1
    }
}
    if ($blockofficeapps -ne '1')
    {
        write-host "Block Office applications from creating executable content is not set" -ForegroundColor Red
    }
    if ($blockexecutablecontent -ne '1')
    {
        write-host "Block executable content from email client and webmail is not set" -ForegroundColor Red
    }
    if ($blockofficechildprocess -ne '1')
    {
        write-host "Block Office applications from creating child processes is not set" -ForegroundColor Red
    }
    if ($blockcodeinjection -ne '1')
    {
        write-host "Block Office applications from injecting code into other processes is not set" -ForegroundColor Red
    }
    if ($blockjavavbscript -ne '1')
    {
        write-host "Block JavaScript and VBScript from launching downloaded executable content is not set" -ForegroundColor Red
    }
    if ($blockobfuscated -ne '1')
    {
        write-host "Block execution of potentially obfuscated scripts is not set" -ForegroundColor Red
    }
    if ($blockwin32api -ne '1')
    {
        write-host "Block Win32 API calls from Office macro is not set" -ForegroundColor Red
    }
}
else
{
    write-host "Configure Attack Surface Reduction rules is configured with a setting of $_" -ForegroundColor Red
}


write-host "`r`n####################### MACROS #######################`r`n"

Get-ChildItem -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\$officeversion\" | Select-Object -ExpandProperty Name | ForEach-Object{
$officename = ($_).Split('\')[6]
if ($officename.Contains("outlook") -or $officename.Contains("common") -or $officename.Contains("firstrun") -or $officename.Contains("onenote") -or $officename.Contains("Registration"))
{
    #donothing
}
else
{
    $appsetting = Get-ItemProperty -Path Registry::$_\Security -ErrorAction SilentlyContinue| Select-Object -ExpandProperty VBAWarnings -ErrorAction SilentlyContinue

If ($appsetting -eq $null)
{
    write-host "Macro settings have not been configured in $officename" -ForegroundColor Yellow
}
    elseif ($appsetting -eq "4")
    {
        write-host "Macros are disabled in $officename" -ForegroundColor Green
    }
    elseif ($appsetting -eq "1")
      {
            Write-Host "Macros are not disabled in $officename, set to Enable all Macros ($appsetting)" -ForegroundColor Red
      }
      elseif ($appsetting -eq "2")
      {
            Write-Host "Macros are not disabled in $officename, Disable all Macros with notification ($appsetting)" -ForegroundColor Red
      }
      elseif ($appsetting -eq "3")
      {
            Write-Host "Macros are not disabled in $officename, Disable all Macros except those digitally signed ($appsetting)" -ForegroundColor Red
      }
      else 
      {
            Write-Host "Macros are not disabled in $officename, value is unknown and set to $appsetting" -ForegroundColor Red
      }

$apptoscan = $_

$tldisable = Get-ItemProperty -Path "Registry::$apptoscan\Security\Trusted Locations" -Name alllocationsdisabled -ErrorAction SilentlyContinue|Select-Object -ExpandProperty alllocationsdisabled

if ($tldisable -eq '1')
{
write-host "Trusted Locations for $officename are disabled" -ForegroundColor Green
}
else
{

write-host "Trusted Locations For $officename are enabled" -ForegroundColor Yellow
foreach($_ in 1..50)
{
    $i++
    $trustedlocation = Get-ItemProperty -Path "Registry::$apptoscan\Security\Trusted Locations\location$_" -Name path -ErrorAction SilentlyContinue|Select-Object -ExpandProperty path
    If ($trustedlocation -ne $null)
    {
        write-host "$trustedlocation" -ForegroundColor Magenta
    }
}
}
}
}


#Outlook has unique macro settings so we check them separately here
$macrooutlook = Get-ItemProperty -Path Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\$officeversion\outlook\Security -ErrorAction SilentlyContinue| Select-Object -ExpandProperty level -ErrorAction SilentlyContinue

If ($macrooutlook -eq $null)
{
write-host "Macro settings have not been configured in Microsoft Outlook" -ForegroundColor Yellow
}
elseif ($macrooutlook -eq "4"){
    write-host "Macros are disabled in Microsoft Outlook" -ForegroundColor Green
    }
    elseif ($macrooutlook -eq"1")
      {Write-Host "Macros are not disabled in Microsoft Outlook, set to Enable all Macros" -ForegroundColor Red}
      elseif ($macrooutlook -eq"2")
      {Write-Host "Macros are not disabled in Microsoft Outlook, set to Notifications for All Macros" -ForegroundColor Red}
      elseif ($macrooutlook -eq"3")
      {Write-Host "Macros are not disabled in Microsoft Outlook, set to Disable all Macros except those digitally signed" -ForegroundColor Red}
      else {Write-host "Macros are not disabled in Microsoft Outlook, value is unknown and set to $macrooutlook" -ForegroundColor Red}

#MS Outlook

$tldisable = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\$officeversion\Security\Trusted Locations" -Name alllocationsdisabled -ErrorAction SilentlyContinue|Select-Object -ExpandProperty alllocationsdisabled

if ($tldisable -eq '1')
{
write-host "Trusted Locations for Outlook are disabled" -ForegroundColor Green
}
else
{

write-host "Trusted Locations For Outlook are enabled" -ForegroundColor Yellow
foreach($_ in 1..50)
{
    $i++
    $trustedlocation = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\$officeversion\Outlook\Security\Trusted Locations\location$_" -Name path -ErrorAction SilentlyContinue|Select-Object -ExpandProperty path
    If ($trustedlocation -ne $null)
    {
        write-host "$trustedlocation" -ForegroundColor Magenta
    }
}
}

write-host "`r`n####################### PATCHING #######################`r`n"

write-host "Unable to check patch levels reliably yet, please check the latest office patch manually to ensure patches are up to date" -ForegroundColor Cyan
#Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where {$_.DisplayName -like "*Office*"} | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize

write-host "`r`n####################### ACTIVE-X #######################`r`n"

$disableallactivex = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\common\security" -Name disableallactivex -ErrorAction SilentlyContinue|Select-Object -ExpandProperty disableallactivex

if ($disableallactivex -eq $null)
{
write-host "Disable All ActiveX is not configured" -ForegroundColor Yellow
}

elseif ($disableallactivex -eq '1')
{
write-host "Disable All ActiveX is enabled" -ForegroundColor Green
}
elseif ($disableallactivex -eq '0')
{
write-host "Disable All ActiveX is disabled" -ForegroundColor Red
}
else
{
write-host "Disable All ActiveX is configured to an unknown setting" -ForegroundColor Red
}


write-host "`r`n####################### ADD-INS #######################`r`n"

#Allow mix of policy and user locations
$trustedlocationsmix = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\common\security\trusted locations" -Name 'allow user locations' -ErrorAction SilentlyContinue|Select-Object -ExpandProperty 'allow user locations'

if ($trustedlocationsmix -eq $null)
{
write-host "Allow mix of policy and user locations is not configured" -ForegroundColor Yellow
}
elseif ($trustedlocationsmix -eq '0')
{
write-host "Allow mix of policy and user locations is disabled" -ForegroundColor Green
}
elseif ($trustedlocationsmix -eq '1')
{
write-host "Allow mix of policy and user locations is enabled" -ForegroundColor Red
}
else
{
write-host "Allow mix of policy and user locations is set to an unknown setting" -ForegroundColor Red
}


#Disable all applications add-ins in Excel
$disablealladdinsexcel = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\excel\security" -Name disablealladdins -ErrorAction SilentlyContinue|Select-Object -ExpandProperty disablealladdins

if ($disablealladdinsexcel -eq $null)
{
write-host "Disable all applications add-ins in Excel is not configured" -ForegroundColor Yellow
}
elseif ($disablealladdinsexcel -eq '1')
{
write-host "Disable all applications add-ins in Excel is enabled" -ForegroundColor Green

    #Allow Trusted Locations on the network
    $allowtrustedlocationsexcel2 = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\excel\security\trusted locations" -Name allownetworklocations -ErrorAction SilentlyContinue|Select-Object -ExpandProperty allownetworklocations

    if ($allowtrustedlocationsexcel2 -eq $null)
    {
    write-host "Allow Trusted Locations on the network in Excel is not configured" -ForegroundColor Yellow
    }
    elseif ($allowtrustedlocationsexcel2 -eq '0')
    {
    write-host "Allow Trusted Locations on the network in Excel is disabled" -ForegroundColor Green
    }
    elseif ($allowtrustedlocationsexcel2 -eq '1')
    {
    write-host "Allow Trusted Locations on the network in Excel is enabled" -ForegroundColor Red
    }

    #Disable all trusted locations
    $alllocationsdisabledexcel2 = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\excel\security\trusted locations" -Name alllocationsdisabled -ErrorAction SilentlyContinue|Select-Object -ExpandProperty alllocationsdisabled

    if ($alllocationsdisabledexcel2 -eq $null)
    {
    write-host "Disable all trusted locations in Excel is not configured" -ForegroundColor Yellow
    }
    elseif ($alllocationsdisabledexcel2 -eq '0')
    {
    write-host "Disable all trusted locations in Excel is disabled" -ForegroundColor Red
    }
    elseif ($alllocationsdisabledexcel2 -eq '1')
    {
    write-host "Disable all trusted locations in Excel is enabled" -ForegroundColor Green
    }


}
elseif ($disablealladdinsexcel -eq '0')
{
write-host "Disable all applications add-ins in Excel is disabled, this setting is compliant if you explicitly need add-ins" -ForegroundColor Green

    #Disable Trust Bar Notification for unsigned application add-ins and block them
    $disabletrustbarexcel = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\excel\security" -Name notbpromptunsignedaddin -ErrorAction SilentlyContinue|Select-Object -ExpandProperty notbpromptunsignedaddin

    if ($disabletrustbarexcel -eq $null)
    {
    write-host "Disable Trust Bar Notification for unsigned application add-ins and block them in Excel is not configured" -ForegroundColor Yellow
    }
    elseif ($disabletrustbarexcel -eq '0')
    {
    write-host "Disable Trust Bar Notification for unsigned application add-ins and block them in Excel is disabled" -ForegroundColor Red
    }
    elseif ($disabletrustbarexcel -eq '1')
    {
    write-host "Disable Trust Bar Notification for unsigned application add-ins and block them in Excel is enabled" -ForegroundColor Green
    }

    #Require that application add-ins are signed by Trusted Publisher
    $requireaddinsigexcel = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\excel\security" -Name requireaddinsig -ErrorAction SilentlyContinue|Select-Object -ExpandProperty requireaddinsig

    if ($requireaddinsigexcel -eq $null)
    {
    write-host "Require that application add-ins are signed by Trusted Publisher in Excel is not configured" -ForegroundColor Yellow
    }
    elseif ($requireaddinsigexcel -eq '0')
    {
    write-host "Require that application add-ins are signed by Trusted Publisher in Excel is disabled" -ForegroundColor Red
    }
    elseif ($requireaddinsigexcel -eq '1')
    {
    write-host "Require that application add-ins are signed by Trusted Publisher in Excel is enabled" -ForegroundColor Green
    }

    #Allow Trusted Locations on the network
    $allowtrustedlocationsexcel1 = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\excel\security\trusted locations" -Name allownetworklocations -ErrorAction SilentlyContinue|Select-Object -ExpandProperty allownetworklocations

    if ($allowtrustedlocationsexcel1 -eq $null)
    {
    write-host "Allow Trusted Locations on the network in Excel is not configured" -ForegroundColor Yellow
    }
    elseif ($allowtrustedlocationsexcel1 -eq '0')
    {
    write-host "Allow Trusted Locations on the network in Excel is disabled" -ForegroundColor Red
    }
    elseif ($allowtrustedlocationsexcel1 -eq '1')
    {
    write-host "Allow Trusted Locations on the network in Excel is enabled" -ForegroundColor Green
    }

    #Disable all trusted locations
    $alllocationsdisabledexcel1 = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\excel\security\trusted locations" -Name alllocationsdisabled -ErrorAction SilentlyContinue|Select-Object -ExpandProperty alllocationsdisabled

    if ($alllocationsdisabledexcel1 -eq $null)
    {
    write-host "Disable all trusted locations in Excel is not configured" -ForegroundColor Yellow
    }
    elseif ($alllocationsdisabledexcel1 -eq '0')
    {
    write-host "Disable all trusted locations in Excel is disabled" -ForegroundColor Green
    }
    elseif ($alllocationsdisabledexcel1 -eq '1')
    {
    write-host "Disable all trusted locations in Excel is enabled" -ForegroundColor Red
    }

}
else
{
write-host "Disable all applications add-ins in Excel is set to an unknown setting" -ForegroundColor Red
}


#Disable all applications add-ins in Powerpoint
$disablealladdinspowerpoint = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\powerpoint\security" -Name disablealladdins -ErrorAction SilentlyContinue|Select-Object -ExpandProperty disablealladdins

if ($disablealladdinspowerpoint -eq $null)
{
write-host "Disable all applications add-ins in powerpoint is not configured" -ForegroundColor Yellow
}
elseif ($disablealladdinspowerpoint -eq '1')
{
write-host "Disable all applications add-ins in powerpoint is enabled" -ForegroundColor Green

    #Allow Trusted Locations on the network
    $allowtrustedlocationspowerpoint2 = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\powerpoint\security\trusted locations" -Name allownetworklocations -ErrorAction SilentlyContinue|Select-Object -ExpandProperty allownetworklocations

    if ($allowtrustedlocationspowerpoint2 -eq $null)
    {
    write-host "Allow Trusted Locations on the network in powerpoint is not configured" -ForegroundColor Yellow
    }
    elseif ($allowtrustedlocationspowerpoint2 -eq '0')
    {
    write-host "Allow Trusted Locations on the network in powerpoint is disabled" -ForegroundColor Green
    }
    elseif ($allowtrustedlocationspowerpoint2 -eq '1')
    {
    write-host "Allow Trusted Locations on the network in powerpoint is enabled" -ForegroundColor Red
    }

    #Disable all trusted locations
    $alllocationsdisabledpowerpoint2 = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\powerpoint\security\trusted locations" -Name alllocationsdisabled -ErrorAction SilentlyContinue|Select-Object -ExpandProperty alllocationsdisabled

    if ($alllocationsdisabledpowerpoint2 -eq $null)
    {
    write-host "Disable all trusted locations in powerpoint is not configured" -ForegroundColor Yellow
    }
    elseif ($alllocationsdisabledpowerpoint2 -eq '0')
    {
    write-host "Disable all trusted locations in powerpoint is disabled" -ForegroundColor Red
    }
    elseif ($alllocationsdisabledpowerpoint2 -eq '1')
    {
    write-host "Disable all trusted locations in powerpoint is enabled" -ForegroundColor Green
    }

}
elseif ($disablealladdinspowerpoint -eq '0')
{
write-host "Disable all applications add-ins in powerpoint is disabled, this setting is compliant if you explicitly need add-ins" -ForegroundColor Green

    #Disable Trust Bar Notification for unsigned application add-ins and block them
    $disabletrustbarpowerpoint = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\powerpoint\security" -Name notbpromptunsignedaddin -ErrorAction SilentlyContinue|Select-Object -ExpandProperty notbpromptunsignedaddin

    if ($disabletrustbarpowerpoint -eq $null)
    {
    write-host "Disable Trust Bar Notification for unsigned application add-ins and block them in powerpoint is not configured" -ForegroundColor Yellow
    }
    elseif ($disabletrustbarpowerpoint -eq '0')
    {
    write-host "Disable Trust Bar Notification for unsigned application add-ins and block them in powerpoint is disabled" -ForegroundColor Red
    }
    elseif ($disabletrustbarpowerpoint -eq '1')
    {
    write-host "Disable Trust Bar Notification for unsigned application add-ins and block them in powerpoint is enabled" -ForegroundColor Green
    }

    #Require that application add-ins are signed by Trusted Publisher
    $requireaddinsigpowerpoint = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\powerpoint\security" -Name requireaddinsig -ErrorAction SilentlyContinue|Select-Object -ExpandProperty requireaddinsig

    if ($requireaddinsigpowerpoint -eq $null)
    {
    write-host "Require that application add-ins are signed by Trusted Publisher in powerpoint is not configured" -ForegroundColor Yellow
    }
    elseif ($requireaddinsigpowerpoint -eq '0')
    {
    write-host "Require that application add-ins are signed by Trusted Publisher in powerpoint is disabled" -ForegroundColor Red
    }
    elseif ($requireaddinsigpowerpoint -eq '1')
    {
    write-host "Require that application add-ins are signed by Trusted Publisher in powerpoint is enabled" -ForegroundColor Green
    }

    #Allow Trusted Locations on the network
    $allowtrustedlocationspowerpoint1 = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\powerpoint\security\trusted locations" -Name allownetworklocations -ErrorAction SilentlyContinue|Select-Object -ExpandProperty allownetworklocations

    if ($allowtrustedlocationspowerpoint1 -eq $null)
    {
    write-host "Allow Trusted Locations on the network in powerpoint is not configured" -ForegroundColor Yellow
    }
    elseif ($allowtrustedlocationspowerpoint1 -eq '0')
    {
    write-host "Allow Trusted Locations on the network in powerpoint is disabled" -ForegroundColor Red
    }
    elseif ($allowtrustedlocationspowerpoint1 -eq '1')
    {
    write-host "Allow Trusted Locations on the network in powerpoint is enabled" -ForegroundColor Green
    }

    #Disable all trusted locations
    $alllocationsdisabledpowerpoint1 = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\powerpoint\security\trusted locations" -Name alllocationsdisabled -ErrorAction SilentlyContinue|Select-Object -ExpandProperty alllocationsdisabled

    if ($alllocationsdisabledpowerpoint1 -eq $null)
    {
    write-host "Disable all trusted locations in powerpoint is not configured" -ForegroundColor Yellow
    }
    elseif ($alllocationsdisabledpowerpoint1 -eq '0')
    {
    write-host "Disable all trusted locations in powerpoint is disabled" -ForegroundColor Green
    }
    elseif ($alllocationsdisabledpowerpoint1 -eq '1')
    {
    write-host "Disable all trusted locations in powerpoint is enabled" -ForegroundColor Red
    }

}
else
{
write-host "Disable all applications add-ins in powerpoint is set to an unknown setting" -ForegroundColor Red
}

#Disable all applications add-ins in Word
$disablealladdinsWord = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\Word\security" -Name disablealladdins -ErrorAction SilentlyContinue|Select-Object -ExpandProperty disablealladdins

if ($disablealladdinsWord -eq $null)
{
write-host "Disable all applications add-ins in Word is not configured" -ForegroundColor Yellow
}
elseif ($disablealladdinsWord -eq '1')
{
write-host "Disable all applications add-ins in Word is enabled" -ForegroundColor Green

    #Allow Trusted Locations on the network
    $allowtrustedlocationsWord2 = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\Word\security\trusted locations" -Name allownetworklocations -ErrorAction SilentlyContinue|Select-Object -ExpandProperty allownetworklocations

    if ($allowtrustedlocationsWord2 -eq $null)
    {
    write-host "Allow Trusted Locations on the network in Word is not configured" -ForegroundColor Yellow
    }
    elseif ($allowtrustedlocationsWord2 -eq '0')
    {
    write-host "Allow Trusted Locations on the network in Word is disabled" -ForegroundColor Green
    }
    elseif ($allowtrustedlocationsWord2 -eq '1')
    {
    write-host "Allow Trusted Locations on the network in Word is enabled" -ForegroundColor Red
    }

    #Disable all trusted locations
    $alllocationsdisabledWord2 = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\Word\security\trusted locations" -Name alllocationsdisabled -ErrorAction SilentlyContinue|Select-Object -ExpandProperty alllocationsdisabled

    if ($alllocationsdisabledWord2 -eq $null)
    {
    write-host "Disable all trusted locations in Word is not configured" -ForegroundColor Yellow
    }
    elseif ($alllocationsdisabledWord2 -eq '0')
    {
    write-host "Disable all trusted locations in Word is disabled" -ForegroundColor Red
    }
    elseif ($alllocationsdisabledWord2 -eq '1')
    {
    write-host "Disable all trusted locations in Word is enabled" -ForegroundColor Green
    }

}
elseif ($disablealladdinsWord -eq '0')
{
write-host "Disable all applications add-ins in Word is disabled, this setting is compliant if you explicitly need add-ins" -ForegroundColor Green

    #Disable Trust Bar Notification for unsigned application add-ins and block them
    $disabletrustbarWord = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\Word\security" -Name notbpromptunsignedaddin -ErrorAction SilentlyContinue|Select-Object -ExpandProperty notbpromptunsignedaddin

    if ($disabletrustbarWord -eq $null)
    {
    write-host "Disable Trust Bar Notification for unsigned application add-ins and block them in Word is not configured" -ForegroundColor Yellow
    }
    elseif ($disabletrustbarWord -eq '0')
    {
    write-host "Disable Trust Bar Notification for unsigned application add-ins and block them in Word is disabled" -ForegroundColor Red
    }
    elseif ($disabletrustbarWord -eq '1')
    {
    write-host "Disable Trust Bar Notification for unsigned application add-ins and block them in Word is enabled" -ForegroundColor Green
    }

    #Require that application add-ins are signed by Trusted Publisher
    $requireaddinsigWord = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\Word\security" -Name requireaddinsig -ErrorAction SilentlyContinue|Select-Object -ExpandProperty requireaddinsig

    if ($requireaddinsigWord -eq $null)
    {
    write-host "Require that application add-ins are signed by Trusted Publisher in Word is not configured" -ForegroundColor Yellow
    }
    elseif ($requireaddinsigWord -eq '0')
    {
    write-host "Require that application add-ins are signed by Trusted Publisher in Word is disabled" -ForegroundColor Red
    }
    elseif ($requireaddinsigWord -eq '1')
    {
    write-host "Require that application add-ins are signed by Trusted Publisher in Word is enabled" -ForegroundColor Green
    }

    #Allow Trusted Locations on the network
    $allowtrustedlocationsWord1 = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\Word\security\trusted locations" -Name allownetworklocations -ErrorAction SilentlyContinue|Select-Object -ExpandProperty allownetworklocations

    if ($allowtrustedlocationsWord1 -eq $null)
    {
    write-host "Allow Trusted Locations on the network in Word is not configured" -ForegroundColor Yellow
    }
    elseif ($allowtrustedlocationsWord1 -eq '0')
    {
    write-host "Allow Trusted Locations on the network in Word is disabled" -ForegroundColor Red
    }
    elseif ($allowtrustedlocationsWord1 -eq '1')
    {
    write-host "Allow Trusted Locations on the network in Word is enabled" -ForegroundColor Green
    }

    #Disable all trusted locations
    $alllocationsdisabledWord1 = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\Word\security\trusted locations" -Name alllocationsdisabled -ErrorAction SilentlyContinue|Select-Object -ExpandProperty alllocationsdisabled

    if ($alllocationsdisabledWord1 -eq $null)
    {
    write-host "Disable all trusted locations in Word is not configured" -ForegroundColor Yellow
    }
    elseif ($alllocationsdisabledWord1 -eq '0')
    {
    write-host "Disable all trusted locations in Word is disabled" -ForegroundColor Green
    }
    elseif ($alllocationsdisabledWord1 -eq '1')
    {
    write-host "Disable all trusted locations in Word is enabled" -ForegroundColor Red
    }

}
else
{
write-host "Disable all applications add-ins in Word is set to an unknown setting" -ForegroundColor Red
}

write-host "`r`n####################### EXTENSION HARDENING #######################`r`n"

$extensionhardening = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\excel\security" -Name extensionhardening -ErrorAction SilentlyContinue|Select-Object -ExpandProperty extensionhardening

if ($extensionhardening -eq $null)
{
write-host "Make hidden markup visible for Powerpoint is not configured" -ForegroundColor Yellow
}
elseif ($extensionhardening -eq '0')
{
write-host "Extension hardening for Excel is enabled, however it is set to Allow Different which is a non-compliant setting. The compliant setting is always match file type" -ForegroundColor Red
}
elseif ($extensionhardening -eq '1')
{
write-host "Extension hardening for Excel is enabled, however it is set to Allow Different, but warn which is a non-compliant setting. The compliant setting is always match file type" -ForegroundColor Red
}
elseif ($extensionhardening -eq '2')
{
write-host "Extension hardening for Excel is enabled and set to Always match file type" -ForegroundColor Green
}
else
{
write-host "Extension hardening for Excel is set to an unknown setting" -ForegroundColor Red
}


write-host "`r`n####################### FILE TYPE BLOCKING #######################`r`n"

$dbasefiles = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\excel\security\fileblock" -Name dbasefiles -ErrorAction SilentlyContinue|Select-Object -ExpandProperty dbasefiles

if ($dbasefiles -eq $null)
{
write-host "File Type Blocking for dBase III / IV files in Excel is not configured" -ForegroundColor Yellow
}
elseif ($dbasefiles -eq '0')
{
write-host "Do not block for dBase III / IV files in Excel is set to 'do not block'" -ForegroundColor Red
}
elseif ($dbasefiles -eq '2')
{
write-host "Do not block for dBase III / IV files in Excel is set to 'Open/Save blocked, use open policy'" -ForegroundColor Red
}
else
{
write-host "Do not block for dBase III / IV files in Excel is set to an unknown setting" -ForegroundColor Red
}

$difandsylkfiles = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\excel\security\fileblock" -Name difandsylkfiles -ErrorAction SilentlyContinue|Select-Object -ExpandProperty difandsylkfiles

if ($difandsylkfiles -eq $null)
{
write-host "File Type Blocking for Dif and Sylk files in Excel is not configured" -ForegroundColor Yellow
}
elseif ($difandsylkfiles -eq '0')
{
write-host "File Type Blocking for Dif and Sylk files in Excel is set to 'do not block'" -ForegroundColor Red
}
elseif ($difandsylkfiles -eq '1')
{
write-host "File Type Blocking for Dif and Sylk files in Excel is set to 'Save Blocked''" -ForegroundColor Red
}
elseif ($difandsylkfiles -eq '2')
{
write-host "File Type Blocking for Dif and Sylk files in Excel is set to 'Open/Save blocked, use open policy'" -ForegroundColor Red
}
else
{
write-host "File Type Blocking for Dif and Sylk files in Excel is set to an unknown setting" -ForegroundColor Red
}

$xl2macros = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\excel\security\fileblock" -Name xl2macros -ErrorAction SilentlyContinue|Select-Object -ExpandProperty xl2macros

if ($xl2macros -eq $null)
{
write-host "File Type Blocking for Excel 2 macrosheets and add-in files is not configured" -ForegroundColor Yellow
}
elseif ($xl2macros -eq '0')
{
write-host "File Type Blocking for Excel 2 macrosheets and add-in files is set to 'do not block'" -ForegroundColor Red
}
elseif ($xl2macros -eq '1')
{
write-host "File Type Blocking for Excel 2 macrosheets and add-in files is set to 'Save Blocked''" -ForegroundColor Red
}
elseif ($xl2macros -eq '2')
{
write-host "File Type Blocking for Excel 2 macrosheets and add-in files is set to 'Open/Save blocked, use open policy'" -ForegroundColor Red
}
elseif ($xl2macros -eq '3')
{
write-host "File Type Blocking for Excel 2 macrosheets and add-in files is set to 'Block'" -ForegroundColor Green
}
elseif ($xl2macros -eq '4')
{
write-host "File Type Blocking for Excel 2 macrosheets and add-in files is set to 'Open in Protected View'" -ForegroundColor Red
}
elseif ($xl2macros -eq '5')
{
write-host "File Type Blocking for Excel 2 macrosheets and add-in files is set to 'Allow editing and open in Protected View'" -ForegroundColor Red
}
else
{
write-host "File Type Blocking for Excel 2 macrosheets and add-in files is set to an unknown setting" -ForegroundColor Red
}

$xl2worksheets = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\excel\security\fileblock" -Name xl2worksheets -ErrorAction SilentlyContinue|Select-Object -ExpandProperty xl2worksheets

if ($xl2worksheets -eq $null)
{
write-host "File Type Blocking for Excel 2 worksheets in Excel is not configured" -ForegroundColor Yellow
}
elseif ($xl2worksheets -eq '0')
{
write-host "File Type Blocking for Excel 2 worksheets is set to 'do not block'" -ForegroundColor Red
}
elseif ($xl2worksheets -eq '1')
{
write-host "File Type Blocking for Excel 2 worksheets is set to 'Save Blocked''" -ForegroundColor Red
}
elseif ($xl2worksheets -eq '2')
{
write-host "File Type Blocking for Excel 2 worksheets is set to 'Open/Save blocked, use open policy'" -ForegroundColor Red
}
elseif ($xl2worksheets -eq '3')
{
write-host "File Type Blocking for Excel 2 worksheets is set to 'Block'" -ForegroundColor Green
}
elseif ($xl2worksheets -eq '4')
{
write-host "File Type Blocking for Excel 2 worksheets is set to 'Open in Protected View'" -ForegroundColor Red
}
elseif ($xl2worksheets -eq '5')
{
write-host "File Type Blocking for Excel 2 worksheets is set to 'Allow editing and open in Protected View'" -ForegroundColor Red
}
else
{
write-host "File Type Blocking for Excel 2 worksheets is set to an unknown setting" -ForegroundColor Red
}

$xlamfiles = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\excel\security\fileblock" -Name xlamfiles -ErrorAction SilentlyContinue|Select-Object -ExpandProperty xlamfiles

if ($xlamfiles -eq $null)
{
write-host "File Type Blocking for Excel 2007 and later add-in files is not configured" -ForegroundColor Yellow
}
elseif ($xlamfiles -eq '0')
{
write-host "File Type Blocking for Excel 2007 and later add-in files is set to 'do not block'" -ForegroundColor Red
}
elseif ($xlamfiles -eq '1')
{
write-host "File Type Blocking for Excel 2007 and later add-in files is set to 'Save Blocked''" -ForegroundColor Red
}
elseif ($xlamfiles -eq '2')
{
write-host "File Type Blocking for Excel 2007 and later add-in files is set to 'Open/Save blocked, use open policy'" -ForegroundColor Red
}
else
{
write-host "File Type Blocking for Excel 2007 and later add-in files is set to an unknown setting" -ForegroundColor Red
}

$xlsbfiles = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\excel\security\fileblock" -Name xlsbfiles -ErrorAction SilentlyContinue|Select-Object -ExpandProperty xlsbfiles

if ($xlsbfiles -eq $null)
{
write-host "File Type Blocking for Excel 2007 and later binary workbooks is not configured" -ForegroundColor Yellow
}
elseif ($xlsbfiles -eq '0')
{
write-host "File Type Blocking for Excel 2007 and later binary workbooks is set to 'do not block'" -ForegroundColor Red
}
elseif ($xlsbfiles -eq '1')
{
write-host "File Type Blocking for Excel 2007 and later binary workbooks is set to 'Save Blocked''" -ForegroundColor Red
}
elseif ($xlsbfiles -eq '2')
{
write-host "File Type Blocking for Excel 2007 and later binary workbooks is set to 'Open/Save blocked, use open policy'" -ForegroundColor Red
}
elseif ($xlsbfiles -eq '3')
{
write-host "File Type Blocking for Excel 2007 and later binary workbooks is set to 'Block'" -ForegroundColor Green
}
elseif ($xlsbfiles -eq '4')
{
write-host "File Type Blocking for Excel 2007 and later binary workbooks is set to 'Open in Protected View'" -ForegroundColor Red
}
elseif ($xlsbfiles -eq '5')
{
write-host "File Type Blocking for Excel 2007 and later binary workbooks is set to 'Allow editing and open in Protected View'" -ForegroundColor Red
}
else
{
write-host "File Type Blocking for Excel 2007 and later binary workbooks is set to an unknown setting" -ForegroundColor Red
}

$xl3macros = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\excel\security\fileblock" -Name xl3macros -ErrorAction SilentlyContinue|Select-Object -ExpandProperty xl3macros

if ($xl3macros -eq $null)
{
write-host "File Type Blocking for Excel 3 macrosheets and add-in files workbooks in Excel is not configured" -ForegroundColor Yellow
}
elseif ($xl3macros -eq '0')
{
write-host "File Type Blocking for Excel 3 macrosheets and add-in files is set to 'do not block'" -ForegroundColor Red
}
elseif ($xl3macros -eq '1')
{
write-host "File Type Blocking for Excel 3 macrosheets and add-in files is set to 'Save Blocked''" -ForegroundColor Red
}
elseif ($xl3macros -eq '2')
{
write-host "File Type Blocking for Excel 3 macrosheets and add-in files is set to 'Open/Save blocked, use open policy'" -ForegroundColor Red
}
elseif ($xl3macros -eq '3')
{
write-host "File Type Blocking for Excel 3 macrosheets and add-in files is set to 'Block'" -ForegroundColor Green
}
elseif ($xl3macros -eq '4')
{
write-host "File Type Blocking for Excel 3 macrosheets and add-in files is set to 'Open in Protected View'" -ForegroundColor Red
}
elseif ($xl3macros -eq '5')
{
write-host "File Type Blocking for Excel 3 macrosheets and add-in files is set to 'Allow editing and open in Protected View'" -ForegroundColor Red
}
else
{
write-host "File Type Blocking for Excel 3 macrosheets and add-in files is set to an unknown setting" -ForegroundColor Red
}

$xl3worksheets = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\excel\security\fileblock" -Name xl3worksheets -ErrorAction SilentlyContinue|Select-Object -ExpandProperty xl3worksheets

if ($xl3worksheets -eq $null)
{
write-host "File Type Blocking for Excel 3 worksheets is not configured" -ForegroundColor Yellow
}
elseif ($xl3worksheets -eq '0')
{
write-host "File Type Blocking for Excel 3 worksheets is set to 'do not block'" -ForegroundColor Red
}
elseif ($xl3worksheets -eq '1')
{
write-host "File Type Blocking for Excel 3 worksheets is set to 'Save Blocked''" -ForegroundColor Red
}
elseif ($xl3worksheets -eq '2')
{
write-host "File Type Blocking for Excel 3 worksheets is set to 'Open/Save blocked, use open policy'" -ForegroundColor Red
}
elseif ($xl3worksheets -eq '3')
{
write-host "File Type Blocking for Excel 3 worksheets is set to 'Block'" -ForegroundColor Green
}
elseif ($xl3worksheets -eq '4')
{
write-host "File Type Blocking for Excel 3 worksheets is set to 'Open in Protected View'" -ForegroundColor Red
}
elseif ($xl3worksheets -eq '5')
{
write-host "File Type Blocking for Excel 3 worksheets is set to 'Allow editing and open in Protected View'" -ForegroundColor Red
}
else
{
write-host "File Type Blocking for Excel 3 worksheets is set to an unknown setting" -ForegroundColor Red
}


$xl4macros = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\excel\security\fileblock" -Name xl4macros -ErrorAction SilentlyContinue|Select-Object -ExpandProperty xl4macros

if ($xl4macros -eq $null)
{
write-host "File Type Blocking for Excel 4 macrosheets and add-in files is not configured" -ForegroundColor Yellow
}
elseif ($xl4macros -eq '0')
{
write-host "File Type Blocking for Excel 4 macrosheets and add-in files is set to 'do not block'" -ForegroundColor Red
}
elseif ($xl4macros -eq '1')
{
write-host "File Type Blocking for Excel 4 macrosheets and add-in files is set to 'Save Blocked''" -ForegroundColor Red
}
elseif ($xl4macros -eq '2')
{
write-host "File Type Blocking for Excel 4 macrosheets and add-in files is set to 'Open/Save blocked, use open policy'" -ForegroundColor Red
}
elseif ($xl4macros -eq '3')
{
write-host "File Type Blocking for Excel 4 macrosheets and add-in files is set to 'Block'" -ForegroundColor Green
}
elseif ($xl4macros -eq '4')
{
write-host "File Type Blocking for Excel 4 macrosheets and add-in files is set to 'Open in Protected View'" -ForegroundColor Red
}
elseif ($xl4macros -eq '5')
{
write-host "File Type Blocking for Excel 4 macrosheets and add-in files is set to 'Allow editing and open in Protected View'" -ForegroundColor Red
}
else
{
write-host "File Type Blocking for Excel 4 macrosheets and add-in files is set to an unknown setting" -ForegroundColor Red
}

$xl4workbooks = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\excel\security\fileblock" -Name xl4workbooks -ErrorAction SilentlyContinue|Select-Object -ExpandProperty xl4workbooks

if ($xl4workbooks -eq $null)
{
write-host "File Type Blocking for Excel 4 workbooks is not configured" -ForegroundColor Yellow
}
elseif ($xl4workbooks -eq '0')
{
write-host "File Type Blocking for Excel 4 workbooks is set to 'do not block'" -ForegroundColor Red
}
elseif ($xl4workbooks -eq '1')
{
write-host "File Type Blocking for Excel 4 workbooks is set to 'Save Blocked''" -ForegroundColor Red
}
elseif ($xl4workbooks -eq '2')
{
write-host "File Type Blocking for Excel 4 workbooks is set to 'Open/Save blocked, use open policy'" -ForegroundColor Red
}
elseif ($xl4workbooks -eq '3')
{
write-host "File Type Blocking for Excel 4 workbooks is set to 'Block'" -ForegroundColor Green
}
elseif ($xl4workbooks -eq '4')
{
write-host "File Type Blocking for Excel 4 workbooks is set to 'Open in Protected View'" -ForegroundColor Red
}
elseif ($xl4workbooks -eq '5')
{
write-host "File Type Blocking for Excel 4 workbooks is set to 'Allow editing and open in Protected View'" -ForegroundColor Red
}
else
{
write-host "File Type Blocking for Excel 4 workbooks is set to an unknown setting" -ForegroundColor Red
}

$xl4worksheets = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\excel\security\fileblock" -Name xl4worksheets -ErrorAction SilentlyContinue|Select-Object -ExpandProperty xl4worksheets

if ($xl4worksheets -eq $null)
{
write-host "File Type Blocking for Excel 4 worksheets is not configured" -ForegroundColor Yellow
}
elseif ($xl4worksheets -eq '0')
{
write-host "File Type Blocking for Excel 4 worksheets is set to 'do not block'" -ForegroundColor Red
}
elseif ($xl4worksheets -eq '1')
{
write-host "File Type Blocking for Excel 4 worksheets is set to 'Save Blocked''" -ForegroundColor Red
}
elseif ($xl4worksheets -eq '2')
{
write-host "File Type Blocking for Excel 4 worksheets is set to 'Open/Save blocked, use open policy'" -ForegroundColor Red
}
elseif ($xl4worksheets -eq '3')
{
write-host "File Type Blocking for Excel 4 worksheets is set to 'Block'" -ForegroundColor Green
}
elseif ($xl4worksheets -eq '4')
{
write-host "File Type Blocking for Excel 4 worksheets is set to 'Open in Protected View'" -ForegroundColor Red
}
elseif ($xl4worksheets -eq '5')
{
write-host "File Type Blocking for Excel 4 worksheets is set to 'Allow editing and open in Protected View'" -ForegroundColor Red
}
else
{
write-host "File Type Blocking for Excel 4 workbooks is set to an unknown setting" -ForegroundColor Red
}

#Excel 95 workbooks

$xl95workbooks = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\excel\security\fileblock" -Name xl95workbooks -ErrorAction SilentlyContinue|Select-Object -ExpandProperty xl95workbooks

if ($xl95workbooks -eq $null)
{
write-host "File Type Blocking for Excel 95 workbooks is not configured" -ForegroundColor Yellow
}
elseif ($xl95workbooks -eq '0')
{
write-host "File Type Blocking for Excel 95 workbooks is set to 'do not block'" -ForegroundColor Red
}
elseif ($xl95workbooks -eq '1')
{
write-host "File Type Blocking for Excel 95 workbooks is set to 'Save Blocked''" -ForegroundColor Red
}
elseif ($xl95workbooks -eq '2')
{
write-host "File Type Blocking for Excel 95 workbooks is set to 'Open/Save blocked, use open policy'" -ForegroundColor Red
}
elseif ($xl95workbooks -eq '3')
{
write-host "File Type Blocking for Excel 95 workbooks is set to 'Block'" -ForegroundColor Green
}
elseif ($xl95workbooks -eq '4')
{
write-host "File Type Blocking for Excel 95 workbooks is set to 'Open in Protected View'" -ForegroundColor Red
}
elseif ($xl95workbooks -eq '5')
{
write-host "File Type Blocking for Excel 95 workbooks is set to 'Allow editing and open in Protected View'" -ForegroundColor Red
}
else
{
write-host "File Type Blocking for Excel 95 workbooks is set to an unknown setting" -ForegroundColor Red
}



#Excel 95-97 workbooks and templates

$xl9597workbooksandtemplates = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\excel\security\fileblock" -Name xl9597workbooksandtemplates -ErrorAction SilentlyContinue|Select-Object -ExpandProperty xl9597workbooksandtemplates

if ($xl9597workbooksandtemplates -eq $null)
{
write-host "File Type Blocking for Excel 95-97 workbooks and templates is not configured" -ForegroundColor Yellow
}
elseif ($xl9597workbooksandtemplates -eq '0')
{
write-host "File Type Blocking for Excel 95-97 workbooks and templates is set to 'do not block'" -ForegroundColor Red
}
elseif ($xl9597workbooksandtemplates -eq '2')
{
write-host "File Type Blocking for Excel 95-97 workbooks and templates is set to 'Open/Save blocked, use open policy'" -ForegroundColor Red
}
elseif ($xl9597workbooksandtemplates -eq '3')
{
write-host "File Type Blocking for Excel 95-97 workbooks and templates is set to 'Block'" -ForegroundColor Green
}
elseif ($xl9597workbooksandtemplates -eq '4')
{
write-host "File Type Blocking for Excel 95-97 workbooks and templates is set to 'Open in Protected View'" -ForegroundColor Red
}
elseif ($xl9597workbooksandtemplates -eq '5')
{
write-host "File Type Blocking for Excel 95-97 workbooks and templates is set to 'Allow editing and open in Protected View'" -ForegroundColor Red
}
else
{
write-host "File Type Blocking for Excel 95-97 workbooks and templates is set to an unknown setting" -ForegroundColor Red
}




#Excel 97-2003 add-in files

$xl97addins = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\excel\security\fileblock" -Name xl97addins -ErrorAction SilentlyContinue|Select-Object -ExpandProperty xl97addins

if ($xl97addins -eq $null)
{
write-host "File Type Blocking for Excel 97-2003 add-in files is not configured" -ForegroundColor Yellow
}
elseif ($xl97addins -eq '0')
{
write-host "File Type Blocking for Excel 97-2003 add-in files is set to 'do not block'" -ForegroundColor Red
}
elseif ($xl97addins -eq '1')
{
write-host "File Type Blocking for Excel 97-2003 add-in files is set to 'Save Blocked''" -ForegroundColor Red
}
elseif ($xl97addins -eq '2')
{
write-host "File Type Blocking for Excel 97-2003 add-in files is set to 'Open/Save blocked, use open policy'" -ForegroundColor Red
}
else
{
write-host "File Type Blocking for Excel 97-2003 add-in files is set to an unknown setting" -ForegroundColor Red
}




#Excel 97-2003 workbooks and templates

$xl97workbooksandtemplates = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\excel\security\fileblock" -Name xl97workbooksandtemplates -ErrorAction SilentlyContinue|Select-Object -ExpandProperty xl97workbooksandtemplates

if ($xl97workbooksandtemplates -eq $null)
{
write-host "File Type Blocking for Excel 97-2003 workbooks and templates is not configured" -ForegroundColor Yellow
}
elseif ($xl97workbooksandtemplates -eq '0')
{
write-host "File Type Blocking for Excel 97-2003 workbooks and templates is set to 'do not block'" -ForegroundColor Red
}
elseif ($xl97workbooksandtemplates -eq '1')
{
write-host "File Type Blocking for Excel 97-2003 workbooks and templates is set to 'Save Blocked''" -ForegroundColor Red
}
elseif ($xl97workbooksandtemplates -eq '2')
{
write-host "File Type Blocking for Excel 97-2003 workbooks and templates is set to 'Open/Save blocked, use open policy'" -ForegroundColor Red
}
elseif ($xl97workbooksandtemplates -eq '3')
{
write-host "File Type Blocking for Excel 97-2003 workbooks and templates is set to 'Block'" -ForegroundColor Green
}
elseif ($xl97workbooksandtemplates -eq '4')
{
write-host "File Type Blocking for Excel 97-2003 workbooks and templates is set to 'Open in Protected View'" -ForegroundColor Red
}
elseif ($xl97workbooksandtemplates -eq '5')
{
write-host "File Type Blocking for Excel 97-2003 workbooks and templates is set to 'Allow editing and open in Protected View'" -ForegroundColor Red
}
else
{
write-host "File Type Blocking for Excel 97-2003 workbooks and templates is set to an unknown setting" -ForegroundColor Red
}




#Set default file block behavior

$openinprotectedview = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\excel\security\fileblock" -Name openinprotectedview -ErrorAction SilentlyContinue|Select-Object -ExpandProperty openinprotectedview

if ($openinprotectedview -eq $null)
{
write-host "File Type Blocking for Set default file block behaviour is not configured" -ForegroundColor Yellow
}
elseif ($openinprotectedview -eq '0')
{
write-host "File Type Blocking for Set default file block behaviour is set to 'Blocked files are not opened'" -ForegroundColor Green
}
elseif ($openinprotectedview -eq '1')
{
write-host "File Type Blocking for Set default file block behaviour is set to 'Blocked files open in Protected View and can not be edited''" -ForegroundColor Red
}
elseif ($openinprotectedview -eq '2')
{
write-host "File Type Blocking for Set default file block behaviour is set to 'Blocked files open in Protected View and can be edited'" -ForegroundColor Red
}
else
{
write-host "File Type Blocking for Set default file block behaviour is set to an unknown setting" -ForegroundColor Red
}


#PowerPoint 97-2003 presentations, shows, templates and add-in files

$binaryfiles = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\powerpoint\security\fileblock" -Name binaryfiles -ErrorAction SilentlyContinue|Select-Object -ExpandProperty binaryfiles

if ($binaryfiles -eq $null)
{
write-host "PowerPoint 97-2003 presentations, shows, templates and add-in files is not configured" -ForegroundColor Yellow
}
elseif ($binaryfiles -eq '0')
{
write-host "PowerPoint 97-2003 presentations, shows, templates and add-in files is set to 'do not block'" -ForegroundColor Red
}
elseif ($binaryfiles -eq '1')
{
write-host "PowerPoint 97-2003 presentations, shows, templates and add-in files is set to 'Save Blocked''" -ForegroundColor Red
}
elseif ($binaryfiles -eq '2')
{
write-host "PowerPoint 97-2003 presentations, shows, templates and add-in files is set to 'Open/Save blocked, use open policy'" -ForegroundColor Red
}
elseif ($binaryfiles -eq '3')
{
write-host "PowerPoint 97-2003 presentations, shows, templates and add-in files is set to 'Block'" -ForegroundColor Green
}
elseif ($binaryfiles -eq '4')
{
write-host "PowerPoint 97-2003 presentations, shows, templates and add-in files is set to 'Open in Protected View'" -ForegroundColor Red
}
elseif ($binaryfiles -eq '5')
{
write-host "PowerPoint 97-2003 presentations, shows, templates and add-in files is set to 'Allow editing and open in Protected View'" -ForegroundColor Red
}
else
{
write-host "PowerPoint 97-2003 presentations, shows, templates and add-in files is set to an unknown setting" -ForegroundColor Red
}


#PowerPoint beta files

$powerpoint12betafiles = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\powerpoint\security\fileblock" -Name powerpoint12betafiles -ErrorAction SilentlyContinue|Select-Object -ExpandProperty powerpoint12betafiles

if ($powerpoint12betafiles -eq $null)
{
write-host "PowerPoint beta files is not configured" -ForegroundColor Yellow
}
elseif ($powerpoint12betafiles -eq '0')
{
write-host "PowerPoint beta files is set to 'do not block'" -ForegroundColor Red
}
elseif ($powerpoint12betafiles -eq '1')
{
write-host "PowerPoint beta files is set to 'Save Blocked''" -ForegroundColor Red
}
elseif ($powerpoint12betafiles -eq '2')
{
write-host "PowerPoint beta files is set to 'Open/Save blocked, use open policy'" -ForegroundColor Red
}
elseif ($powerpoint12betafiles -eq '3')
{
write-host "PowerPoint beta files is set to 'Block'" -ForegroundColor Green
}
elseif ($powerpoint12betafiles -eq '4')
{
write-host "PowerPoint beta files is set to 'Open in Protected View'" -ForegroundColor Red
}
elseif ($powerpoint12betafiles -eq '5')
{
write-host "PowerPoint beta files is set to 'Allow editing and open in Protected View'" -ForegroundColor Red
}
else
{
write-host "PowerPoint beta files is set to an unknown setting" -ForegroundColor Red
}

#Set default file block behavior - powerpoint

$openinprotectedviewBFppt = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\powerpoint\security\fileblock" -Name openinprotectedview -ErrorAction SilentlyContinue|Select-Object -ExpandProperty openinprotectedview

if ($openinprotectedviewBFppt -eq $null)
{
write-host "Set default file block behavior is not configured in powerpoint" -ForegroundColor Yellow
}
elseif ($openinprotectedviewBFppt -eq '0')
{
write-host "Set default file block behavior is set to 'Blocked files are not opened'in powerpoint" -ForegroundColor Green
}
elseif ($openinprotectedviewBFppt -eq '1')
{
write-host "Set default file block behavior is set to 'Blocked files open in Protected View and can not be edited'in powerpoint" -ForegroundColor Red
}
elseif ($openinprotectedviewBFppt -eq '2')
{
write-host "Set default file block behavior is set to 'Blocked files open in Protected View and can be edited'in powerpoint" -ForegroundColor Red
}
else
{
write-host "Set default file block behavior is set to an unknown setting in powerpoint" -ForegroundColor Red
}




#word
#Set default file block behavior - word

$openinprotectedviewBFword = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\word\security\fileblock" -Name openinprotectedview -ErrorAction SilentlyContinue|Select-Object -ExpandProperty openinprotectedview

if ($openinprotectedviewBFword -eq $null)
{
write-host "Set default file block behavior is not configured in Word" -ForegroundColor Yellow
}
elseif ($openinprotectedviewBFword -eq '0')
{
write-host "Set default file block behavior is set to 'Blocked files are not opened'in Word" -ForegroundColor Green
}
elseif ($openinprotectedviewBFword -eq '1')
{
write-host "Set default file block behavior is set to 'Blocked files open in Protected View and can not be edited'in Word" -ForegroundColor Red
}
elseif ($openinprotectedviewBFword -eq '2')
{
write-host "Set default file block behavior is set to 'Blocked files open in Protected View and can be edited'in Word" -ForegroundColor Red
}
else
{
write-host "Set default file block behavior is set to an unknown setting in Word" -ForegroundColor Red
}



#Word 2 and earlier binary documents and templates

$word2files = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\word\security\fileblock" -Name word2files -ErrorAction SilentlyContinue|Select-Object -ExpandProperty word2files

if ($word2files -eq $null)
{
write-host "Word 2 and earlier binary documents and templates is not configured" -ForegroundColor Yellow
}
elseif ($word2files -eq '0')
{
write-host "Word 2 and earlier binary documents and templates is set to 'do not block'" -ForegroundColor Red
}
elseif ($word2files -eq '2')
{
write-host "Word 2 and earlier binary documents and templates is set to 'Open/Save blocked, use open policy'" -ForegroundColor Red
}
elseif ($word2files -eq '3')
{
write-host "Word 2 and earlier binary documents and templates is set to 'Block'" -ForegroundColor Green
}
elseif ($word2files -eq '4')
{
write-host "Word 2 and earlier binary documents and templates is set to 'Open in Protected View'" -ForegroundColor Red
}
elseif ($word2files -eq '5')
{
write-host "Word 2 and earlier binary documents and templates is set to 'Allow editing and open in Protected View'" -ForegroundColor Red
}
else
{
write-host "Word 2 and earlier binary documents and templates is set to an unknown setting" -ForegroundColor Red
}


#Word 2000 binary documents and templates

$word2000files = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\word\security\fileblock" -Name word2000files -ErrorAction SilentlyContinue|Select-Object -ExpandProperty word2000files

if ($word2000files -eq $null)
{
write-host "word 2000 and earlier binary documents and templates is not configured" -ForegroundColor Yellow
}
elseif ($word2000files -eq '0')
{
write-host "word 2000 and earlier binary documents and templates is set to 'do not block'" -ForegroundColor Red
}
elseif ($word2000files -eq '2')
{
write-host "word 2000 and earlier binary documents and templates is set to 'Open/Save blocked, use open policy'" -ForegroundColor Red
}
elseif ($word2000files -eq '3')
{
write-host "word 2000 and earlier binary documents and templates is set to 'Block'" -ForegroundColor Green
}
elseif ($word2000files -eq '4')
{
write-host "word 2000 and earlier binary documents and templates is set to 'Open in Protected View'" -ForegroundColor Red
}
elseif ($word2000files -eq '5')
{
write-host "word 2000 and earlier binary documents and templates is set to 'Allow editing and open in Protected View'" -ForegroundColor Red
}
else
{
write-host "word 2000 and earlier binary documents and templates is set to an unknown setting" -ForegroundColor Red
}


#Word 2003 binary documents and templates
$word2003files = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\word\security\fileblock" -Name word2003files -ErrorAction SilentlyContinue|Select-Object -ExpandProperty word2003files

if ($word2003files -eq $null)
{
write-host "word 2003 and earlier binary documents and templates is not configured" -ForegroundColor Yellow
}
elseif ($word2003files -eq '0')
{
write-host "word 2003 and earlier binary documents and templates is set to 'do not block'" -ForegroundColor Red
}
elseif ($word2003files -eq '2')
{
write-host "word 2003 and earlier binary documents and templates is set to 'Open/Save blocked, use open policy'" -ForegroundColor Red
}
elseif ($word2003files -eq '3')
{
write-host "word 2003 and earlier binary documents and templates is set to 'Block'" -ForegroundColor Green
}
elseif ($word2003files -eq '4')
{
write-host "word 2003 and earlier binary documents and templates is set to 'Open in Protected View'" -ForegroundColor Red
}
elseif ($word2003files -eq '5')
{
write-host "word 2003 and earlier binary documents and templates is set to 'Allow editing and open in Protected View'" -ForegroundColor Red
}
else
{
write-host "word 2003 and earlier binary documents and templates is set to an unknown setting" -ForegroundColor Red
}


#Word 2007 and later binary documents and templates
$word2007files = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\word\security\fileblock" -Name word2007files -ErrorAction SilentlyContinue|Select-Object -ExpandProperty word2007files

if ($word2007files -eq $null)
{
write-host "word 2007 and later binary documents and templates is not configured" -ForegroundColor Yellow
}
elseif ($word2007files -eq '0')
{
write-host "word 2007 and later binary documents and templates is set to 'do not block'" -ForegroundColor Red
}
elseif ($word2007files -eq '1')
{
write-host "word 2007 and later binary documents and templates is set to 'Save blocked'" -ForegroundColor Red
}
elseif ($word2007files -eq '2')
{
write-host "word 2007 and later binary documents and templates is set to 'Open/Save blocked, use open policy'" -ForegroundColor Red
}
elseif ($word2007files -eq '3')
{
write-host "word 2007 and later binary documents and templates is set to 'Block'" -ForegroundColor Green
}
elseif ($word2007files -eq '4')
{
write-host "word 2007 and later binary documents and templates is set to 'Open in Protected View'" -ForegroundColor Red
}
elseif ($word2007files -eq '5')
{
write-host "word 2007 and later binary documents and templates is set to 'Allow editing and open in Protected View'" -ForegroundColor Red
}
else
{
write-host "word 2007 and later binary documents and templates is set to an unknown setting" -ForegroundColor Red
}

#Word 6.0 binary documents and templates
$word60files = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\word\security\fileblock" -Name word60files -ErrorAction SilentlyContinue|Select-Object -ExpandProperty word60files

if ($word60files -eq $null)
{
write-host "Word 6.0 binary documents and templates is not configured" -ForegroundColor Yellow
}
elseif ($word60files -eq '0')
{
write-host "Word 6.0 binary documents and templates is set to 'do not block'" -ForegroundColor Red
}
elseif ($word60files -eq '2')
{
write-host "Word 6.0 binary documents and templates is set to 'Open/Save blocked, use open policy'" -ForegroundColor Red
}
elseif ($word60files -eq '3')
{
write-host "Word 6.0 binary documents and templates is set to 'Block'" -ForegroundColor Green
}
elseif ($word60files -eq '4')
{
write-host "Word 6.0 binary documents and templates is set to 'Open in Protected View'" -ForegroundColor Red
}
elseif ($word60files -eq '5')
{
write-host "Word 6.0 binary documents and templates is set to 'Allow editing and open in Protected View'" -ForegroundColor Red
}
else
{
write-host "word 2007 and later binary documents and templates is set to an unknown setting" -ForegroundColor Red
}

#Word 95 binary documents and templates
$word95files = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\word\security\fileblock" -Name word95files -ErrorAction SilentlyContinue|Select-Object -ExpandProperty word95files

if ($word95files -eq $null)
{
write-host "Word 95 binary documents and templates is not configured" -ForegroundColor Yellow
}
elseif ($word95files -eq '0')
{
write-host "Word 95 binary documents and templates is set to 'do not block'" -ForegroundColor Red
}
elseif ($word95files -eq '2')
{
write-host "Word 95 binary documents and templates is set to 'Open/Save blocked, use open policy'" -ForegroundColor Red
}
elseif ($word95files -eq '3')
{
write-host "Word 95 binary documents and templates is set to 'Block'" -ForegroundColor Green
}
elseif ($word95files -eq '4')
{
write-host "Word 95 binary documents and templates is set to 'Open in Protected View'" -ForegroundColor Red
}
elseif ($word95files -eq '5')
{
write-host "Word 95 binary documents and templates is set to 'Allow editing and open in Protected View'" -ForegroundColor Red
}
else
{
write-host "Word 95 binary documents and templates is set to an unknown setting" -ForegroundColor Red
}

#Word 97 binary documents and templates
$word97files = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\word\security\fileblock" -Name word97files -ErrorAction SilentlyContinue|Select-Object -ExpandProperty word97files

if ($word97files -eq $null)
{
write-host "Word 97 binary documents and templates is not configured" -ForegroundColor Yellow
}
elseif ($word97files -eq '0')
{
write-host "Word 97 binary documents and templates is set to 'do not block'" -ForegroundColor Red
}
elseif ($word97files -eq '2')
{
write-host "Word 97 binary documents and templates is set to 'Open/Save blocked, use open policy'" -ForegroundColor Red
}
elseif ($word97files -eq '3')
{
write-host "Word 97 binary documents and templates is set to 'Block'" -ForegroundColor Green
}
elseif ($word97files -eq '4')
{
write-host "Word 97 binary documents and templates is set to 'Open in Protected View'" -ForegroundColor Red
}
elseif ($word97files -eq '5')
{
write-host "Word 97 binary documents and templates is set to 'Allow editing and open in Protected View'" -ForegroundColor Red
}
else
{
write-host "Word 97 binary documents and templates is set to an unknown setting" -ForegroundColor Red
}

#Word 2000 binary documents and templates
$word2000files = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\word\security\fileblock" -Name word2000files -ErrorAction SilentlyContinue|Select-Object -ExpandProperty word2000files

if ($word2000files -eq $null)
{
write-host "Word 2000 binary documents and templates is not configured" -ForegroundColor Yellow
}
elseif ($word2000files -eq '0')
{
write-host "Word 2000 binary documents and templates is set to 'do not block'" -ForegroundColor Red
}
elseif ($word2000files -eq '2')
{
write-host "Word 2000 binary documents and templates is set to 'Open/Save blocked, use open policy'" -ForegroundColor Red
}
elseif ($word2000files -eq '3')
{
write-host "Word 2000 binary documents and templates is set to 'Block'" -ForegroundColor Green
}
elseif ($word2000files -eq '4')
{
write-host "Word 2000 binary documents and templates is set to 'Open in Protected View'" -ForegroundColor Red
}
elseif ($word2000files -eq '5')
{
write-host "Word 2000 binary documents and templates is set to 'Allow editing and open in Protected View'" -ForegroundColor Red
}
else
{
write-host "Word 2000 binary documents and templates is set to an unknown setting" -ForegroundColor Red
}

#Word XP binary documents and templates
$wordXPfiles = Get-ItemProperty -Path "Registry::HKCU\software\policies\microsoft\office\$officeversion\word\security\fileblock" -Name wordXPfiles -ErrorAction SilentlyContinue|Select-Object -ExpandProperty wordXPfiles

if ($wordXPfiles -eq $null)
{
write-host "Word XP binary documents and templates is not configured" -ForegroundColor Yellow
}
elseif ($wordXPfiles -eq '0')
{
write-host "Word XP binary documents and templates is set to 'do not block'" -ForegroundColor Red
}
elseif ($wordXPfiles -eq '2')
{
write-host "Word XP binary documents and templates is set to 'Open/Save blocked, use open policy'" -ForegroundColor Red
}
elseif ($wordXPfiles -eq '3')
{
write-host "Word XP binary documents and templates is set to 'Block'" -ForegroundColor Green
}
elseif ($wordXPfiles -eq '4')
{
write-host "Word XP binary documents and templates is set to 'Open in Protected View'" -ForegroundColor Red
}
elseif ($wordXPfiles -eq '5')
{
write-host "Word XP binary documents and templates is set to 'Allow editing and open in Protected View'" -ForegroundColor Red
}
else
{
write-host "Word XP binary documents and templates is set to an unknown setting" -ForegroundColor Red
}



write-host "`r`n####################### HIDDEN MARKUP #######################`r`n"

#Powerpoint - Make Hidden Markup Visible

$hiddenmarkupppt = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\powerpoint\options" -Name markupopensave -ErrorAction SilentlyContinue|Select-Object -ExpandProperty markupopensave

if ($hiddenmarkupppt -eq $null)
{
write-host "Make hidden markup visible for Powerpoint is not configured" -ForegroundColor Yellow
}

elseif ($hiddenmarkupppt -eq '1')
{
write-host "Make hidden markup visible for Powerpoint is enabled" -ForegroundColor Green
}
else
{
write-host "Make hidden markup visible for Powerpoint is disabled" -ForegroundColor Red
}


#Word - Make Hidden Markup Visible

$hiddenmarkupword = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\word\options" -Name showmarkupopensave -ErrorAction SilentlyContinue|Select-Object -ExpandProperty showmarkupopensave

if ($hiddenmarkupword -eq $null)
{
write-host "Make hidden markup visible for Word is not configured" -ForegroundColor Yellow
}

elseif ($hiddenmarkupword -eq '1')
{
write-host "Make hidden markup visible for Word is enabled" -ForegroundColor Green
}
else
{
write-host "Make hidden markup visible for Word is disabled" -ForegroundColor Red
}


write-host "`r`n####################### OFFICE FILE VALIDATION #######################`r`n"

#Turn off error reporting for files that fail file validation

$disablereporting = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\common\security\filevalidation" -Name disablereporting -ErrorAction SilentlyContinue|Select-Object -ExpandProperty disablereporting

if ($disablereporting -eq $null)
{
write-host "Turn off error reporting for files that fail file validation is not configured" -ForegroundColor Yellow
}

elseif ($disablereporting -eq '1')
{
write-host "Turn off error reporting for files that fail file validation is enabled" -ForegroundColor Green
}
else
{
write-host "Turn off error reporting for files that fail file validation is disabled" -ForegroundColor Red
}


#Turn off file validation - excel

$filevalidationexcel = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\excel\security\filevalidation" -Name enableonload -ErrorAction SilentlyContinue|Select-Object -ExpandProperty enableonload

if ($filevalidationexcel -eq $null)
{
write-host "Turn off file validation is not configured in Excel" -ForegroundColor Yellow
}

elseif ($filevalidationexcel -eq '1')
{
write-host "Turn off file validation is disabled in Excel" -ForegroundColor Green
}
else
{
write-host "Turn off file validation is enabled in Excel" -ForegroundColor Red
}


#Turn off file validation - Powerpoint

$filevalidationppt = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\powerpoint\security\filevalidation" -Name enableonload -ErrorAction SilentlyContinue|Select-Object -ExpandProperty enableonload

if ($filevalidationppt -eq $null)
{
write-host "Turn off file validation is not configured in Powepoint" -ForegroundColor Yellow
}

elseif ($filevalidationppt -eq '1')
{
write-host "Turn off file validation is disabled in Powepoint" -ForegroundColor Green
}
else
{
write-host "Turn off file validation is enabled in Powepoint" -ForegroundColor Red
}

#Turn off file validation - Word

$filevalidationword = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\word\security\filevalidation" -Name enableonload -ErrorAction SilentlyContinue|Select-Object -ExpandProperty enableonload

if ($filevalidationword -eq $null)
{
write-host "Turn off file validation is not configured in Word" -ForegroundColor Yellow
}

elseif ($filevalidationppt -eq '1')
{
write-host "Turn off file validation is disabled in Word" -ForegroundColor Green
}
else
{
write-host "Turn off file validation is enabled in Word" -ForegroundColor Red
}


write-host "`r`n####################### PROTECTED VIEW #######################`r`n"

#Do not open files from the Internet zone in Protected View - Excel

$disableifexcel = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\excel\security\protectedview" -Name disableinternetfilesinpv -ErrorAction SilentlyContinue|Select-Object -ExpandProperty disableinternetfilesinpv

if ($disableifexcel -eq $null)
{
write-host "Do not open files from the Internet zone in Protected View is not configured in Excel" -ForegroundColor Yellow
}

elseif ($disableifexcel -eq '0')
{
write-host "Do not open files from the Internet zone in Protected View is disabled in Excel" -ForegroundColor Green
}
elseif ($disableifexcel -eq '1')
{
write-host "Do not open files from the Internet zone in Protected View is enabled in Excel" -ForegroundColor Red
}
else
{
write-host "Do not open files from the Internet zone in Protected View is set to an unknown configuration in Excel" -ForegroundColor Red
}



#Do not open files in unsafe locations in Protected View - Excel

$disableifulexcel = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\excel\security\protectedview" -Name disableunsafelocationsinpv -ErrorAction SilentlyContinue|Select-Object -ExpandProperty disableunsafelocationsinpv

if ($disableifulexcel -eq $null)
{
write-host "Do not open files in unsafe locations in Protected View is not configured in Excel" -ForegroundColor Yellow
}

elseif ($disableifulexcel -eq '0')
{
write-host "Do not open files in unsafe locations in Protected View is disabled in Excel" -ForegroundColor Green
}
elseif ($disableifulexcel -eq '1')
{
write-host "Do not open files in unsafe locations in Protected View is enabled in Excel" -ForegroundColor Red
}
else
{
write-host "Do not open files in unsafe locations in Protected View is set to an unknown configuration in Excel" -ForegroundColor Red
}




#Set document behaviour if file validation fails - Excel

$openinprotectedviewexcel = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\excel\security\filevalidation" -Name openinprotectedview -ErrorAction SilentlyContinue|Select-Object -ExpandProperty openinprotectedview

if ($openinprotectedviewexcel -eq $null)
{
write-host "Set document behaviour if file validation fails is not configured in Excel" -ForegroundColor Yellow
}

elseif ($openinprotectedviewexcel -eq '0')
{
write-host "Set document behaviour if file validation fails is set to 'Block files' in Excel" -ForegroundColor Green
}
elseif ($openinprotectedviewexcel -eq '1')
{
write-host "Set document behaviour if file validation fails is set to 'Open in Protected View' in Excel" -ForegroundColor Red
}
else
{
write-host "Set document behaviour if file validation fails is set to an unknown configuration in Excel" -ForegroundColor Red
}






#Turn off Protected View for attachments opened from Outlook - Excel

$disableattachmentsexcel = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\excel\security\protectedview" -Name disableattachmentsinpv -ErrorAction SilentlyContinue|Select-Object -ExpandProperty disableattachmentsinpv

if ($disableattachmentsexcel -eq $null)
{
write-host "Turn off Protected View for attachments opened from Outlook is not configured in Excel" -ForegroundColor Yellow
}

elseif ($disableattachmentsexcel -eq '0')
{
write-host "Turn off Protected View for attachments opened from Outlook is disabled in Excel" -ForegroundColor Green
}
elseif ($disableattachmentsexcel -eq '1')
{
write-host "Turn off Protected View for attachments opened from Outlook is enabled in Excel" -ForegroundColor Red
}
else
{
write-host "Turn off Protected View for attachments opened from Outlook is set to an unknown configuration in Excel" -ForegroundColor Red
}




#Do not open files from the Internet zone in Protected View - Powerpoint

$disableifpowerpoint = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\powerpoint\security\protectedview" -Name disableinternetfilesinpv -ErrorAction SilentlyContinue|Select-Object -ExpandProperty disableinternetfilesinpv

if ($disableifpowerpoint -eq $null)
{
write-host "Do not open files from the Internet zone in Protected View is not configured in powerpoint" -ForegroundColor Yellow
}

elseif ($disableifpowerpoint -eq '0')
{
write-host "Do not open files from the Internet zone in Protected View is disabled in powerpoint" -ForegroundColor Green
}
elseif ($disableifpowerpoint -eq '1')
{
write-host "Do not open files from the Internet zone in Protected View is enabled in powerpoint" -ForegroundColor Red
}
else
{
write-host "Do not open files from the Internet zone in Protected View is set to an unknown configuration in powerpoint" -ForegroundColor Red
}

#Do not open files in unsafe locations in Protected View - Powerpoint

$disableifulpowerpoint = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\powerpoint\security\protectedview" -Name disableunsafelocationsinpv -ErrorAction SilentlyContinue|Select-Object -ExpandProperty disableunsafelocationsinpv

if ($disableifulpowerpoint -eq $null)
{
write-host "Do not open files in unsafe locations in Protected View is not configured in powerpoint" -ForegroundColor Yellow
}

elseif ($disableifulpowerpoint -eq '0')
{
write-host "Do not open files in unsafe locations in Protected View is disabled in powerpoint" -ForegroundColor Green
}
elseif ($disableifulpowerpoint -eq '1')
{
write-host "Do not open files in unsafe locations in Protected View is enabled in powerpoint" -ForegroundColor Red
}
else
{
write-host "Do not open files in unsafe locations in Protected View is set to an unknown configuration in powerpoint" -ForegroundColor Red
}



#Set document behaviour if file validation fails - Powerpoint

$openinprotectedviewpowerpoint = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\powerpoint\security\filevalidation" -Name openinprotectedview -ErrorAction SilentlyContinue|Select-Object -ExpandProperty openinprotectedview

if ($openinprotectedviewpowerpoint -eq $null)
{
write-host "Set document behaviour if file validation fails is not configured in powerpoint" -ForegroundColor Yellow
}

elseif ($openinprotectedviewpowerpoint -eq '0')
{
write-host "Set document behaviour if file validation fails is set to 'Block files' in powerpoint" -ForegroundColor Green
}
elseif ($openinprotectedviewpowerpoint -eq '1')
{
write-host "Set document behaviour if file validation fails is set to 'Open in Protected View' in powerpoint" -ForegroundColor Red
}
else
{
write-host "Set document behaviour if file validation fails is set to an unknown configuration in powerpoint" -ForegroundColor Red
}



#Turn off Protected View for attachments opened from Outlook - Powerpoint

$disableattachmentspowerpoint = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\powerpoint\security\protectedview" -Name disableattachmentsinpv -ErrorAction SilentlyContinue|Select-Object -ExpandProperty disableattachmentsinpv

if ($disableattachmentspowerpoint -eq $null)
{
write-host "Turn off Protected View for attachments opened from Outlook is not configured in powerpoint" -ForegroundColor Yellow
}

elseif ($disableattachmentspowerpoint -eq '0')
{
write-host "Turn off Protected View for attachments opened from Outlook is disabled in powerpoint" -ForegroundColor Green
}
elseif ($disableattachmentspowerpoint -eq '1')
{
write-host "Turn off Protected View for attachments opened from Outlook is enabled in powerpoint" -ForegroundColor Red
}
else
{
write-host "Turn off Protected View for attachments opened from Outlook is set to an unknown configuration in powerpoint" -ForegroundColor Red
}



#Do not open files from the Internet zone in Protected View - word

$disableifword = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\word\security\protectedview" -Name disableinternetfilesinpv -ErrorAction SilentlyContinue|Select-Object -ExpandProperty disableinternetfilesinpv

if ($disableifword -eq $null)
{
write-host "Do not open files from the Internet zone in Protected View is not configured in word" -ForegroundColor Yellow
}

elseif ($disableifword -eq '0')
{
write-host "Do not open files from the Internet zone in Protected View is disabled in word" -ForegroundColor Green
}
elseif ($disableifword -eq '1')
{
write-host "Do not open files from the Internet zone in Protected View is enabled in word" -ForegroundColor Red
}
else
{
write-host "Do not open files from the Internet zone in Protected View is set to an unknown configuration in word" -ForegroundColor Red
}



#Do not open files in unsafe locations in Protected View - word

$disableifulword = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\word\security\protectedview" -Name disableunsafelocationsinpv -ErrorAction SilentlyContinue|Select-Object -ExpandProperty disableunsafelocationsinpv

if ($disableifulword -eq $null)
{
write-host "Do not open files in unsafe locations in Protected View is not configured in word" -ForegroundColor Yellow
}

elseif ($disableifulword -eq '0')
{
write-host "Do not open files in unsafe locations in Protected View is disabled in word" -ForegroundColor Green
}
elseif ($disableifulword -eq '1')
{
write-host "Do not open files in unsafe locations in Protected View is enabled in word" -ForegroundColor Red
}
else
{
write-host "Do not open files in unsafe locations in Protected View is set to an unknown configuration in word" -ForegroundColor Red
}



#Set document behaviour if file validation fails - word

$openinprotectedviewword = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\word\security\filevalidation" -Name openinprotectedview -ErrorAction SilentlyContinue|Select-Object -ExpandProperty openinprotectedview

if ($openinprotectedviewword -eq $null)
{
write-host "Set document behaviour if file validation fails is not configured in word" -ForegroundColor Yellow
}

elseif ($openinprotectedviewword -eq '0')
{
write-host "Set document behaviour if file validation fails is set to 'Block files' in word" -ForegroundColor Green
}
elseif ($openinprotectedviewword -eq '1')
{
write-host "Set document behaviour if file validation fails is set to 'Open in Protected View' in word" -ForegroundColor Red
}
else
{
write-host "Set document behaviour if file validation fails is set to an unknown configuration in word" -ForegroundColor Red
}



#Turn off Protected View for attachments opened from Outlook - word

$disableattachmentsword = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\word\security\protectedview" -Name disableattachmentsinpv -ErrorAction SilentlyContinue|Select-Object -ExpandProperty disableattachmentsinpv

if ($disableattachmentsword -eq $null)
{
write-host "Turn off Protected View for attachments opened from Outlook is not configured in word" -ForegroundColor Yellow
}

elseif ($disableattachmentsword -eq '0')
{
write-host "Turn off Protected View for attachments opened from Outlook is disabled in word" -ForegroundColor Green
}
elseif ($disableattachmentsword -eq '1')
{
write-host "Turn off Protected View for attachments opened from Outlook is enabled in word" -ForegroundColor Red
}
else
{
write-host "Turn off Protected View for attachments opened from Outlook is set to an unknown configuration in word" -ForegroundColor Red
}


write-host "`r`n####################### TRUSTED DOCUMENTS #######################`r`n"

#Turn off trusted documents - Excel

$trusteddocsexcel = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\excel\security\trusted documents" -Name disabletrusteddocuments -ErrorAction SilentlyContinue|Select-Object -ExpandProperty disabletrusteddocuments

if ($trusteddocsexcel -eq $null)
{
write-host "Turn off trusted documents is not configured in Excel" -ForegroundColor Yellow
}

elseif ($trusteddocsexcel -eq '1')
{
write-host "Turn off trusted documents is enabled in Excel" -ForegroundColor Green
}
elseif ($trusteddocsexcel -eq '0')
{
write-host "Turn off trusted documents is disabled in Excel" -ForegroundColor Red
}
else
{
write-host "Turn off trusted documents is set to an unknown configuration in Excel" -ForegroundColor Red
}



#Turn off Trusted Documents on the network - Excel

$trusteddocsnetworkexcel = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\excel\security\trusted documents" -Name disablenetworktrusteddocuments -ErrorAction SilentlyContinue|Select-Object -ExpandProperty disablenetworktrusteddocuments

if ($trusteddocsnetworkexcel -eq $null)
{
write-host "Turn off Trusted Documents on the network is not configured in Excel" -ForegroundColor Yellow
}

elseif ($trusteddocsnetworkexcel -eq '1')
{
write-host "Turn off Trusted Documents on the network is enabled in Excel" -ForegroundColor Green
}
elseif ($trusteddocsnetworkexcel -eq '0')
{
write-host "Turn off Trusted Documents on the network is disabled in Excel" -ForegroundColor Red
}
else
{
write-host "Turn off Trusted Documents on the network is set to an unknown configuration in Excel" -ForegroundColor Red
}



#Turn off trusted documents - Powerpoint

$trusteddocspowerpoint = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\powerpoint\security\trusted documents" -Name disabletrusteddocuments -ErrorAction SilentlyContinue|Select-Object -ExpandProperty disabletrusteddocuments

if ($trusteddocspowerpoint -eq $null)
{
write-host "Turn off trusted documents is not configured in powerpoint" -ForegroundColor Yellow
}

elseif ($trusteddocspowerpoint -eq '1')
{
write-host "Turn off trusted documents is enabled in powerpoint" -ForegroundColor Green
}
elseif ($trusteddocspowerpoint -eq '0')
{
write-host "Turn off trusted documents is disabled in powerpoint" -ForegroundColor Red
}
else
{
write-host "Turn off trusted documents is set to an unknown configuration in powerpoint" -ForegroundColor Red
}


#Turn off Trusted Documents on the network - Powerpoint

$trusteddocsnetworkpowerpoint = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\powerpoint\security\trusted documents" -Name disablenetworktrusteddocuments -ErrorAction SilentlyContinue|Select-Object -ExpandProperty disablenetworktrusteddocuments

if ($trusteddocsnetworkpowerpoint -eq $null)
{
write-host "Turn off Trusted Documents on the network is not configured in powerpoint" -ForegroundColor Yellow
}

elseif ($trusteddocsnetworkpowerpoint -eq '1')
{
write-host "Turn off Trusted Documents on the network is enabled in powerpoint" -ForegroundColor Green
}
elseif ($trusteddocsnetworkpowerpoint -eq '0')
{
write-host "Turn off Trusted Documents on the network is disabled in powerpoint" -ForegroundColor Red
}
else
{
write-host "Turn off Trusted Documents on the network is set to an unknown configuration in powerpoint" -ForegroundColor Red
}



#Turn off trusted documents - word

$trusteddocsword = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\word\security\trusted documents" -Name disabletrusteddocuments -ErrorAction SilentlyContinue|Select-Object -ExpandProperty disabletrusteddocuments

if ($trusteddocsword -eq $null)
{
write-host "Turn off trusted documents is not configured in word" -ForegroundColor Yellow
}

elseif ($trusteddocsword -eq '1')
{
write-host "Turn off trusted documents is enabled in word" -ForegroundColor Green
}
elseif ($trusteddocsword -eq '0')
{
write-host "Turn off trusted documents is disabled in word" -ForegroundColor Red
}
else
{
write-host "Turn off trusted documents is set to an unknown configuration in word" -ForegroundColor Red
}

#Turn off Trusted Documents on the network - word

$trusteddocsnetworkword = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\word\security\trusted documents" -Name disablenetworktrusteddocuments -ErrorAction SilentlyContinue|Select-Object -ExpandProperty disablenetworktrusteddocuments

if ($trusteddocsnetworkword -eq $null)
{
write-host "Turn off Trusted Documents on the network is not configured in word" -ForegroundColor Yellow
}

elseif ($trusteddocsnetworkword -eq '1')
{
write-host "Turn off Trusted Documents on the network is enabled in word" -ForegroundColor Green
}
elseif ($trusteddocsnetworkword -eq '0')
{
write-host "Turn off Trusted Documents on the network is disabled in word" -ForegroundColor Red
}
else
{
write-host "Turn off Trusted Documents on the network is set to an unknown configuration in word" -ForegroundColor Red
}

write-host "`r`n####################### REPORTING INFORMATION #######################`r`n"


#Allow including screenshot with Office Feedback

$includescreenshot = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\common\feedback" -Name includescreenshot -ErrorAction SilentlyContinue|Select-Object -ExpandProperty includescreenshot

if ($includescreenshot -eq $null)
{
write-host "Allow including screenshot with Office Feedback is not configured" -ForegroundColor Yellow
}

elseif ($includescreenshot -eq '0')
{
write-host "Allow including screenshot with Office Feedback is disabled" -ForegroundColor Green
}
elseif ($includescreenshot -eq '1')
{
write-host "Allow including screenshot with Office Feedback is enabled" -ForegroundColor Red
}
else
{
write-host "Allow including screenshot with Office Feedback is set to an unknown configuration" -ForegroundColor Red
}



#Automatically receive small updates to improve reliability

$updatereliabilitydata = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\common\" -Name updatereliabilitydata -ErrorAction SilentlyContinue|Select-Object -ExpandProperty updatereliabilitydata

if ($updatereliabilitydata -eq $null)
{
write-host "Automatically receive small updates to improve reliability is not configured" -ForegroundColor Yellow
}

elseif ($updatereliabilitydata -eq '0')
{
write-host "Automatically receive small updates to improve reliability is disabled" -ForegroundColor Green
}
elseif ($updatereliabilitydata -eq '1')
{
write-host "Automatically receive small updates to improve reliability is enabled" -ForegroundColor Red
}
else
{
write-host "Automatically receive small updates to improve reliability is set to an unknown configuration" -ForegroundColor Red
}


#Disable Opt-in Wizard on first run

$shownfirstrunoptin = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\common\general" -Name shownfirstrunoptin -ErrorAction SilentlyContinue|Select-Object -ExpandProperty shownfirstrunoptin

if ($shownfirstrunoptin -eq $null)
{
write-host "Disable Opt-in Wizard on first run is not configured" -ForegroundColor Yellow
}

elseif ($shownfirstrunoptin -eq '1')
{
write-host "Disable Opt-in Wizard on first run is enabled" -ForegroundColor Green
}
elseif ($shownfirstrunoptin -eq '0')
{
write-host "Disable Opt-in Wizard on first run is disabled" -ForegroundColor Red
}
else
{
write-host "Disable Opt-in Wizard on first run is set to an unknown configuration" -ForegroundColor Red
}



#Enable Customer Experience Improvement Program

$qmenable = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\common\" -Name qmenable -ErrorAction SilentlyContinue|Select-Object -ExpandProperty qmenable

if ($qmenable -eq $null)
{
write-host "Enable Customer Experience Improvement Program is not configured" -ForegroundColor Yellow
}

elseif ($qmenable -eq '0')
{
write-host "Enable Customer Experience Improvement Program is disabled" -ForegroundColor Green
}
elseif ($qmenable -eq '1')
{
write-host "Enable Customer Experience Improvement Program is enabled" -ForegroundColor Red
}
else
{
write-host "Enable Customer Experience Improvement Program is set to an unknown configuration" -ForegroundColor Red
}



#Send Office Feedback

$enabled = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\common\feedback" -Name enabled -ErrorAction SilentlyContinue|Select-Object -ExpandProperty enabled

if ($enabled -eq $null)
{
write-host "Send Office Feedback is not configured" -ForegroundColor Yellow
}

elseif ($enabled -eq '0')
{
write-host "Send Office Feedback is disabled" -ForegroundColor Green
}
elseif ($enabled -eq '1')
{
write-host "Send Office Feedback is enabled" -ForegroundColor Red
}
else
{
write-host "Send Office Feedback is set to an unknown configuration" -ForegroundColor Red
}



#Send personal information

$sendcustomerdata = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\$officeversion\common\" -Name sendcustomerdata -ErrorAction SilentlyContinue|Select-Object -ExpandProperty sendcustomerdata

if ($sendcustomerdata -eq $null)
{
write-host "Send personal information is not configured" -ForegroundColor Yellow
}

elseif ($sendcustomerdata -eq '0')
{
write-host "Send personal information is disabled" -ForegroundColor Green
}
elseif ($sendcustomerdata -eq '1')
{
write-host "Send personal information is enabled" -ForegroundColor Red
}
else
{
write-host "Send personal information is set to an unknown configuration" -ForegroundColor Red
}
