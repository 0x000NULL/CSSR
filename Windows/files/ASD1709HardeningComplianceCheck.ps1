#ASD Hardening Microsoft Windows 10, version 1709 Workstations compliance script. This script will check the applied settings in the current user context.
#This script is based on the settings recommended in the ASD Hardening Guide here: https://acsc.gov.au/publications/protect/Hardening_Win10.pdf
#Created by github.com/cottinghamd and github.com/huda008
#Incorporated Invoke-ElevatedCommand by TaoK https://gist.github.com/TaoK/1582185

If ($isDotSourced = $MyInvocation.InvocationName -eq '.' -or $MyInvocation.Line -eq '')
{
#donothingandcontinue
}
else
{
write-host "This script was not run 'dot sourced'. For this script to execute correctly, please ensure the script is dot sourced e.g. use . .\ASD1709HardeningComplianceCheck.ps1" -Foregroundcolor Red
write-host "This script will now exit" -Foregroundcolor Red
break
}

Function Invoke-ElevatedCommand {

	param
	(
		## The script block to invoke elevated. NOTE: to access the InputObject/pipeline data from the script block, use "$input"!
		[Parameter(Mandatory = $true)]
		[ScriptBlock] $Scriptblock,
	 
		## Any input to give the elevated process
		[Parameter(ValueFromPipeline = $true)]
		$InputObject,
	 
		## Switch to enable the user profile
		[switch] $EnableProfile,
	 
		## Switch to display the spawned window (as interactive)
		[switch] $DisplayWindow
	)
	 
	begin
	{
		Set-StrictMode -Version Latest
		$inputItems = New-Object System.Collections.ArrayList
	}
	 
	process
	{
		$null = $inputItems.Add($inputObject)
	}
	 
	end
	{

		## Create some temporary files for streaming input and output
		$outputFile = [IO.Path]::GetTempFileName()	
		$inputFile = [IO.Path]::GetTempFileName()
		$errorFile = [IO.Path]::GetTempFileName()

		## Stream the input into the input file
		$inputItems.ToArray() | Export-CliXml -Depth 1 $inputFile
	 
		## Start creating the command line for the elevated PowerShell session
		$commandLine = ""
		if(-not $EnableProfile) { $commandLine += "-NoProfile " }

		if(-not $DisplayWindow) { 
			$commandLine += "-Noninteractive " 
			$processWindowStyle = "Hidden" 
		}
		else {
			$processWindowStyle = "Normal" 
		}
	 
		## Convert the command into an encoded command for PowerShell
		$commandString = "Set-Location '$($pwd.Path)'; " +
			"`$output = Import-CliXml '$inputFile' | " +
			"& {" + $scriptblock.ToString() + "} 2>&1 ; " +
			"Out-File -filepath '$errorFile' -inputobject `$error;" +
			"Export-CliXml -Depth 1 -In `$output '$outputFile';"
	 
		$commandBytes = [System.Text.Encoding]::Unicode.GetBytes($commandString)
		$encodedCommand = [Convert]::ToBase64String($commandBytes)
		$commandLine += "-EncodedCommand $encodedCommand"

		## Start the new PowerShell process
		$process = Start-Process -FilePath (Get-Command powershell).Definition `
			-ArgumentList $commandLine `
			-Passthru `
			-Verb RunAs `
			-WindowStyle $processWindowStyle

		$process.WaitForExit()

		$errorMessage = $(gc $errorFile | Out-String)
		if($errorMessage) {
			Write-Error -Message $errorMessage
		}
		else {
			## Return the output to the user
			if((Get-Item $outputFile).Length -gt 0)
			{
				Import-CliXml $outputFile
			}
		}

		## Clean up
		Remove-Item $outputFile
		Remove-Item $inputFile
		Remove-Item $errorFile
	}
}

Function Get-MachineType 
{ 
    [CmdletBinding()] 
    [OutputType([int])] 
    Param 
    ( 
        # ComputerName 
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$true, 
                   ValueFromPipelineByPropertyName=$true, 
                   Position=0)] 
        [string[]]$ComputerName=$env:COMPUTERNAME, 
        $Credential = [System.Management.Automation.PSCredential]::Empty 
    ) 
 
    Begin 
    { 
    } 
    Process 
    { 
        foreach ($Computer in $ComputerName) { 
            Write-Verbose "Checking $Computer" 
            try { 
                $hostdns = [System.Net.DNS]::GetHostEntry($Computer) 
                $ComputerSystemInfo = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $Computer -ErrorAction Stop -Credential $Credential 
                 
                switch ($ComputerSystemInfo.Model) { 
                     
                    # Check for Hyper-V Machine Type 
                    "Virtual Machine" { 
                        $MachineType="VM" 
                        } 
 
                    # Check for VMware Machine Type 
                    "VMware Virtual Platform" { 
                        $MachineType="VM" 
                        } 
 
                    # Check for Oracle VM Machine Type 
                    "VirtualBox" { 
                        $MachineType="VM" 
                        } 
  
 
                    # Otherwise it is a physical Box 
                    default { 
                        $MachineType="Physical" 
                        } 
                    } 
                 
                # Building MachineTypeInfo Object 
                $MachineTypeInfo = New-Object -TypeName PSObject -Property ([ordered]@{ 
                    ComputerName=$ComputerSystemInfo.PSComputername 
                    Type=$MachineType 
                    Manufacturer=$ComputerSystemInfo.Manufacturer 
                    Model=$ComputerSystemInfo.Model 
                    }) 
                $MachineTypeInfo 
                } 
            catch [Exception] { 
                Write-Output "$Computer`: $($_.Exception.Message)" 
                } 
            } 
    } 
    End 
    { 
 
    } 
}


Function outputanswer($answer,$color)
{

if($global:displayconsole -eq 'y')
{
if ($color -eq 'White')
    {
    write-host "`r`n#######################" $answer "#######################`r`n" -ForegroundColor $color
    }
    else
    {
    write-host $answer -ForegroundColor $color
    }
}

    if ($color -eq 'Yellow')
    {
        $compliance = 'Non-Compliant (Due to Non-Configuration)'
    }
        elseif ($color -eq 'Green')
    {
        $compliance = 'Compliant'
    }
        elseif ($color -eq 'Red')
    {
        $compliance = 'Non-Compliant'
    }
        elseif ($color -eq 'White')
    {
        $global:chapter = $answer
        $answer = $null
    }
        elseif ($color -eq 'Cyan')
    {
        $compliance = 'Unknown'
    }
$global:report += New-Object psobject -Property @{Chapter=$chapter;Compliance=$compliance;Setting=$answer}
}

Write-Host "ASD Hardening Microsoft Windows 10, version 1709 Workstations compliance script" -ForegroundColor Green
Write-Host "This script is based on the settings recommended in the ASD Hardening Guide here: https://www.asd.gov.au/publications/protect/Hardening_Win10.pdf" -ForegroundColor Green
Write-Host "Created by github.com/cottinghamd and github.com/huda008" -ForegroundColor Green

If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    $adminprivs = Read-Host "`r`nAdministrative privileges have not been detected, do you want to elevate now and pre-check controls that require administrative privileges? (y/n)"
        If ($adminprivs -eq 'y')
        {
        $Checkelevateditems = 'y'
        }
    else
        {
        #donothing
        }
}
else
{
    $Checkelevateditems = 'y'
}

If ($Checkelevateditems -eq 'y')
{
#Get Current User Temp Directory For Writing Between Contexts
$userenvironmenttemp = ${env:TEMP}

#this statement is now ready to check multiple elevated controls
$secureboottemp = $userenvironmenttemp
Invoke-ElevatedCommand -InputObject $userenvironmenttemp {
$temppath = "$input"

#check secure boot Elevated
$secureboot = "$temppath" + '\secureboot.txt'
Confirm-SecureBootUEFI | Out-File $secureboot

#check Allow Anonymous SID / Name Translation Elevated
$lsaanonymousnamelookup = "$temppath" + '\lsaanonymousnamelookup.txt'
$null = secedit /export /cfg $temppath/secexport.cfg
$(gc $temppath/secexport.cfg | Select-String "LSAAnonymousNameLookup").ToString().Split('=')[1].Trim() | Out-File $lsaanonymousnamelookup
Remove-Item $temppath/secexport.cfg
}
}



$report = @()
$writetype = Read-Host "`r`nDo you want to output this scripts results to a file? (y for Yes or n for No)"

If ($writetype -eq 'y')
{
$tooutput = 'y'
$working = Get-Location
$workingdirok = Read-Host "`r`nThe output file will be output to the following location $working\results.csv, is this ok? (y for Yes or n for No)"

    If ($workingdirok -eq 'y')
    {
    $filepath = "$working\results.csv"
    }
    else
    {
    $filepath = Read-Host "`r`naPlease specify the full output file path here e.g. C:\logs\output.csv"
    }
}

$displayconsole = Read-Host "`r`nDo you want the output to also be displayed in the console? (y for Yes or n for No)"


outputanswer -answer "CREDENTIAL CACHING" -color White
outputanswer -answer "This script is unable to check Number of Previous Logons to cache, this is because the setting is in the security registry hive, please check the GPO located at Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive Logon" -color Cyan

#Check Network Access: Do not allow storage of passwords and credentials for network authentication
$networkaccess = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\" -Name disabledomaincreds -ErrorAction SilentlyContinue|Select-Object -ExpandProperty disabledomaincreds

if ($networkaccess -eq $null)
{
outputanswer -answer "Do not allow storage of passwords and credentials for network authentication is not configured" -color Yellow
}
    elseif ($networkaccess -eq '1')
    {
        outputanswer -answer "Do not allow storage of passwords and credentials for network authentication is enabled" -color Green
    }
    else
    {
        outputanswer -answer "Do not allow storage of passwords and credentials for network authentication is disabled" -color Red
    }

#Check WDigestAuthentication is disabled
$wdigest = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\" -Name uselogoncredential -ErrorAction SilentlyContinue|Select-Object -ExpandProperty uselogoncredential

if ($wdigest -eq $null)
{
outputanswer -answer "WDigest is not configured" -color Yellow
}
    elseif ($wdigest -eq '0')
    {
        outputanswer -answer "WDigest is disabled" -color Green
    }
    else
    {
        outputanswer -answer "WDigest is enabled" -color Red
    }

#Check Turn on Virtualisation Based Security
$vbsecurity = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\" -Name EnableVirtualizationBasedSecurity -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EnableVirtualizationBasedSecurity

if ($vbsecurity -eq $null)
{
outputanswer -answer "Virtualisation Based Security is not configured" -color Yellow
}
    elseif ($vbsecurity -eq '1')
    {
        outputanswer -answer "Virtualisation Based security is enabled" -color Green
    }
    else
    {
        outputanswer -answer "Virtualisation Based security is disabled" -color Red
    }

#Check Secure Boot and DMA Protection
$sbdmaprot = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name RequirePlatformSecurityFeatures -ErrorAction SilentlyContinue|Select-Object -ExpandProperty RequirePlatformSecurityFeatures

if ($sbdmaprot -eq $null)
{
outputanswer -answer "Secure Boot and DMA Protection is not configured" -color Yellow
}
    elseif ($sbdmaprot -eq '3')
    {
        outputanswer -answer "Secure Boot and DMA Protection is enabled" -color Green
    }
    else
    {
        outputanswer -answer "Secure Boot and DMA Protection is set to something non compliant" -color Red
    }

#Check UEFI Lock is enabled for device guard
$uefilock = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name LsaCfgFlags -ErrorAction SilentlyContinue|Select-Object -ExpandProperty LsaCfgFlags

if ($uefilock -eq $null)
{
outputanswer -answer "Virtualisation Based Protection of Code Integrity with UEFI lock is not configured" -color Yellow
}
    elseif ($uefilock -eq '1')
    {
        outputanswer -answer "Virtualisation Based Protection of Code Integrity with UEFI lock is enabled" -color Green
    }
    else
    {
        outputanswer -answer "Virtualisation Based Protection of Code Integrity with UEFI lock is set to something non compliant" -color Red
    }

outputanswer -answer "CONTROLLED FOLDER ACCESS" -color White

#Check Controlled Folder Access for Exploit Guard is Enabled
$cfaccess = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exploit Guard\Controlled Folder Access" -Name EnableControlledFolderAccess -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EnableControlledFolderAccess

if ($cfaccess -eq $null)
{
outputanswer -answer "Controlled Folder Access for Exploit Guard is not configured" -color Yellow
}
    elseif ($cfaccess -eq '1')
    {
        outputanswer -answer "Controlled Folder Access for Exploit Guard is enabled" -color Green
    }
    else
    {
        outputanswer -answer "Controlled Folder Access for Exploit Guard is disabled" -color Red
    }

outputanswer -answer "CREDENTIAL ENTRY" -color White

#Check Do not display network selection UI

$netselectui = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" -Name DontDisplayNetworkSelectionUI -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DontDisplayNetworkSelectionUI

if ($netselectui -eq $null)
{
outputanswer -answer "Do not display network selection UI is not configured" -color Yellow
}
    elseif ($netselectui -eq '1')
    {
        outputanswer -answer "Do not display network selection UI is enabled" -color Green
    }
    else
    {
        outputanswer -answer "Do not display network selection UI is disabled" -color Red
    }

#Check Enumerate local users on domain joined computers

$enumlocalusers = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" -Name EnumerateLocalUsers -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EnumerateLocalUsers

if ($enumlocalusers -eq $null)
{
outputanswer -answer "Enumerate local users on domain joined computers is not configured" -color Yellow
}
    elseif ($enumlocalusers -eq '0')
    {
        outputanswer -answer "Enumerate local users on domain joined computers is enabled" -color Green
    }
    else
    {
        outputanswer -answer "Enumerate local users on domain joined computers is disabled" -color Red
    }


#Check Do not display the password reveal button

$disablepassreveal = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI" -Name DisablePasswordReveal -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisablePasswordReveal

if ($disablepassreveal -eq $null)
{
outputanswer -answer "Do not display the password reveal button is not configured" -color Yellow
}
    elseif ($disablepassreveal -eq '1')
    {
        outputanswer -answer "Do not display the password reveal button is enabled" -color Green
    }
    else
    {
        outputanswer -answer "Do not display the password reveal button is disabled" -color Red
    }

#Check Enumerate administrator accounts on elevation

$enumerateadmins = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Name EnumerateAdministrators -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EnumerateAdministrators

if ($enumerateadmins -eq $null)
{
outputanswer -answer "Enumerate administrator accounts on elevation is not configured" -color Yellow
}
    elseif ($enumerateadmins -eq '0')
    {
        outputanswer -answer "Enumerate administrator accounts on elevation is disabled" -color Green
    }
    else
    {
        outputanswer -answer "Enumerate administrator accounts on elevation is enabled" -color Red
    }

#Check Require trusted path for credential entry 

$credentry = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI" -Name EnableSecureCredentialPrompting -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EnableSecureCredentialPrompting

if ($credentry -eq $null)
{
outputanswer -answer "Require trusted path for credential entry is not configured" -color Yellow
}
    elseif ($credentry -eq '1')
    {
        outputanswer -answer "Require trusted path for credential entry is enabled" -color Green
    }
    else
    {
        outputanswer -answer "Require trusted path for credential entry is disabled" -color Red
    }

#Check Disable or enable software Secure Attention Sequence  

$sasgeneration = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name SoftwareSASGeneration -ErrorAction SilentlyContinue|Select-Object -ExpandProperty SoftwareSASGeneration

if ($sasgeneration -eq $null)
{
outputanswer -answer "Disable or enable software Secure Attention Sequence is not configured or disabled" -color Green
}
    elseif ($sasgeneration -eq '0')
    {
        outputanswer -answer "Disable or enable software Secure Attention Sequence is disabled" -color Green
    }
    else
    {
        outputanswer -answer "Disable or enable software Secure Attention Sequence is enabled" -color Red
    }

#Check Sign-in last interactive user automatically after a system-initiated restart 

$systeminitiated = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name DisableAutomaticRestartSignOn -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableAutomaticRestartSignOn

if ($systeminitiated -eq $null)
{
outputanswer -answer "Sign-in last interactive user automatically after a system-initiated restart is not configured" -color Yellow
}
    elseif ($systeminitiated -eq '1')
    {
        outputanswer -answer "Sign-in last interactive user automatically after a system-initiated restart is disabled" -color Green
    }
    else
    {
        outputanswer -answer "Sign-in last interactive user automatically after a system-initiated restart is enabled" -color Red
    }

#Check Interactive logon: Do not require CTRL+ALT+DEL 

$ctrlaltdel = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name DisableCAD -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableCAD

if ($ctrlaltdel -eq $null)
{
outputanswer -answer "Interactive logon: Do not require CTRL+ALT+DEL  is not configured" -color Yellow
}
    elseif ($ctrlaltdel -eq '0')
    {
        outputanswer -answer "Interactive logon: Do not require CTRL+ALT+DEL is disabled" -color Green
    }
    else
    {
        outputanswer -answer "Interactive logon: Do not require CTRL+ALT+DEL is enabled" -color Red
    }

#Check Interactive logon: Don't display username at sign-in 

$dontdisplaylastuser = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name DontDisplayLastUserName -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DontDisplayLastUserName

if ($dontdisplaylastuser -eq $null)
{
outputanswer -answer "Interactive logon: Don't display username at sign-in is not configured" -color Yellow
}
    elseif ($dontdisplaylastuser -eq '1')
    {
        outputanswer -answer "Interactive logon: Don't display username at sign-in is enabled" -color Green
    }
    else
    {
        outputanswer -answer "Interactive logon: Don't display username at sign-in is disabled" -color Red
    }


outputanswer -answer "EARLY LAUNCH ANTI MALWARE" -color White

#Check ELAM Configuration

$elam = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Policies\EarlyLaunch" -Name DriverLoadPolicy -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DriverLoadPolicy

if ($elam -eq $null)
{
outputanswer -answer "ELAM Boot-Start Driver Initialization Policy is not configured" -color Yellow
}
    elseif ($elam -eq '8')
    {
        outputanswer -answer "ELAM Boot-Start Driver Initialization Policy is enabled and set to Good Only" -color Green
    }
    elseif ($elam -eq '2' -or $elam -eq '1')
    {
        outputanswer -answer "ELAM Boot-Start Driver Initialization Policy is enabled and set to Good and Unknown" -color Green
    }
    elseif ($elam -eq '3')
    {
        outputanswer -answer "ELAM Boot-Start Driver Initialization Policy is enabled, but set to Good, Unknown, Bad but critical" -color Red
    }
    elseif ($elam -eq '7')
    {
        outputanswer -answer "ELAM Boot-Start Driver Initialization Policy is enabled, but set allow All drivers" -color Red
    }
    else
    {
        outputanswer -answer "ELAM Boot-Start Driver Initialization Policy is disabled" -color Red
    }


outputanswer -answer "ELEVATING PRIVILEGES" -color White



#User Account Control: Admin Approval Mode for the Built-in Administrator account

$adminapprovalmode = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name FilterAdministratorToken -ErrorAction SilentlyContinue|Select-Object -ExpandProperty FilterAdministratorToken

if ($adminapprovalmode -eq $null)
{
outputanswer -answer "Admin Approval Mode for the Built-in Administrator account is not configured" -color Yellow
}
    elseif ($adminapprovalmode -eq '1')
    {
        outputanswer -answer "Admin Approval Mode for the Built-in Administrator account is enabled" -color Green
    }
    else
    {
        outputanswer -answer "Admin Approval Mode for the Built-in Administrator account is disabled" -color Red
    }

#User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop
$uiaccessapplications = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableUIADesktopToggle -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EnableUIADesktopToggle

if ($uiaccessapplications -eq $null)
{
outputanswer -answer "Allow UIAccess applications to prompt for elevation without using the secure desktop is not configured" -color Yellow
}
    elseif ($uiaccessapplications -eq '0')
    {
        outputanswer -answer "Allow UIAccess applications to prompt for elevation without using the secure desktop is disabled" -color Green
    }
    else
    {
        outputanswer -answer "Allow UIAccess applications to prompt for elevation without using the secure desktop is enabled" -color Red
    }

#User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode
$elevationprompt = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue|Select-Object -ExpandProperty ConsentPromptBehaviorAdmin

if ($elevationprompt -eq $null)
{
outputanswer -answer "Behavior of the elevation prompt for administrators in Admin Approval Mode is not configured" -color Yellow
}
    elseif ($elevationprompt -eq '0')
    {
        outputanswer -answer "Behavior of the elevation prompt for administrators in Admin Approval Mode is configured, but set to Elevate without prompting" -color Red
    }
        elseif ($elevationprompt -eq '1')
    {
        outputanswer -answer "Behavior of the elevation prompt for administrators in Admin Approval Mode is configured and set to Prompt for credentials on the secure desktop" -color Green
    }
        elseif ($elevationprompt -eq '2')
    {
        outputanswer -answer "Behavior of the elevation prompt for administrators in Admin Approval Mode is configured, but set to Prompt for consent on the secure desktop" -color Red
    }
        elseif ($elevationprompt -eq '3')
    {
        outputanswer -answer "Behavior of the elevation prompt for administrators in Admin Approval Mode is configured, but set to Prompt for credentials" -color Red
    }
        elseif ($elevationprompt -eq '4')
    {
        outputanswer -answer "Behavior of the elevation prompt for administrators in Admin Approval Mode is configured, but set to Prompt for consent" -color Red
    }
        elseif ($elevationprompt -eq '5')
    {
        outputanswer -answer "Behavior of the elevation prompt for administrators in Admin Approval Mode is configured, but set to Prompt for consent for non-Windows binaries" -color Red
    }
    else
    {
        outputanswer -answer "Behavior of the elevation prompt for administrators in Admin Approval Mode is not configured" -color Red
    }


#User Account Control: Behavior of the elevation prompt for standard users
$standardelevationprompt = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorUser -ErrorAction SilentlyContinue|Select-Object -ExpandProperty ConsentPromptBehaviorUser

if ($standardelevationprompt -eq $null)
{
outputanswer -answer "Behavior of the elevation prompt for standard users is not configured" -color Yellow
}
    elseif ($standardelevationprompt -eq '0')
    {
        outputanswer -answer "Behavior of the elevation prompt for standard users is configured, but set to Automatically deny elevation requests" -color Yellow
    }
        elseif ($standardelevationprompt -eq '1')
    {
        outputanswer -answer "Behavior of the elevation prompt for standard users is configured set to Prompt for credentials on the secure desktop" -color Green
    }
        elseif ($standardelevationprompt -eq '3')
    {
        outputanswer -answer "Behavior of the elevation prompt for standard users is configured, but set to Prompt for credentials" -color Red
    }
    else
    {
        outputanswer -answer "Behavior of the elevation prompt for administrators is not configured" -color Red
    }





#User Account Control: Detect application installations and prompt for elevation
$detectinstallelevate = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableInstallerDetection -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EnableInstallerDetection

if ($detectinstallelevate -eq $null)
{
outputanswer -answer "Detect application installations and prompt for elevation is not configured" -color Yellow
}
    elseif ($detectinstallelevate -eq '1')
    {
        outputanswer -answer "Detect application installations and prompt for elevation is enabled" -color Green
    }
    else
    {
        outputanswer -answer "Detect application installations and prompt for elevation is disabled" -color Red
    }



#User Account Control: Only elevate UIAccess applications that are installed in secure locations
$onlyelevateapps = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableSecureUIAPaths -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EnableSecureUIAPaths

if ($onlyelevateapps -eq $null)
{
outputanswer -answer "Only elevate UIAccess applications that are installed in secure locations is not configured" -color Yellow
}
    elseif ($onlyelevateapps -eq '1')
    {
        outputanswer -answer "Only elevate UIAccess applications that are installed in secure locations is enabled" -color Green
    }
    else
    {
        outputanswer -answer "Only elevate UIAccess applications that are installed in secure locations is disabled" -color Red
    }



#User Account Control: Run all administrators in Admin Approval Mode
$adminapprovalmode = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EnableLUA

if ($adminapprovalmode -eq $null)
{
outputanswer -answer "Run all administrators in Admin Approval Mode is not configured" -color Yellow
}
    elseif ($adminapprovalmode -eq '1')
    {
        outputanswer -answer "Run all administrators in Admin Approval Mode is enabled" -color Green
    }
    else
    {
        outputanswer -answer "Run all administrators in Admin Approval Mode is disabled" -color Red
    }

#User Account Control: Switch to the secure desktop when prompting for elevation
$promptonsecuredesktop = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name PromptOnSecureDesktop -ErrorAction SilentlyContinue|Select-Object -ExpandProperty PromptOnSecureDesktop

if ($promptonsecuredesktop -eq $null)
{
outputanswer -answer "Switch to the secure desktop when prompting for elevation is not configured" -color Yellow
}
    elseif ($promptonsecuredesktop -eq '1')
    {
        outputanswer -answer "Switch to the secure desktop when prompting for elevation is enabled" -color Green
    }
    else
    {
        outputanswer -answer "Switch to the secure desktop when prompting for elevation is disabled" -color Red
    }



# User Account Control: Virtualize file and registry write failures to per-user locations
$EnableVirtualization = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableVirtualization -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EnableVirtualization

if ($EnableVirtualization -eq $null)
{
outputanswer -answer "Virtualize file and registry write failures to per-user locations is not configured" -color Yellow
}
    elseif ($EnableVirtualization -eq '1')
    {
        outputanswer -answer "Virtualize file and registry write failures to per-user locations is enabled" -color Green
    }
    else
    {
        outputanswer -answer "Virtualize file and registry write failures to per-user locations is disabled" -color Red
    }


outputanswer -answer "EXPLOIT PROTECTION" -color White



# Use a common set of exploit protection settings (this has more settings need to research)
#$ExploitProtectionSettings = Get-ItemProperty -Path "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender ExploitGuard\Exploit Protection" -Name ExploitProtectionSettings -ErrorAction SilentlyContinue|Select-Object -ExpandProperty ExploitProtectionSettings

#if ($ExploitProtectionSettings -eq $null)
#{
#outputanswer -answer "Use a common set of exploit protection settings is not configured" -color Yellow
#}
#    elseif ($ExploitProtectionSettings -eq '1')
#    {
#        outputanswer -answer "Use a common set of exploit protection settings is enabled" -color Green
#    }
#    else
#    {
#        outputanswer -answer "Use a common set of exploit protection settings is disabled" -color Red
#    }

# Prevent users from modifying settings
$DisallowExploitProtectionOverride = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" -Name DisallowExploitProtectionOverride -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisallowExploitProtectionOverride

if ($DisallowExploitProtectionOverride -eq $null)
{
outputanswer -answer "Prevent users from modifying settings is not configured" -color Yellow
}
    elseif ($DisallowExploitProtectionOverride -eq '1')
    {
        outputanswer -answer "Prevent users from modifying settings is enabled" -color Green
    }
    else
    {
        outputanswer -answer "Prevent users from modifying settings is disabled" -color Red
    }

# Turn off Data Execution Prevention for Explorer
$NoDataExecutionPrevention = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\Explorer" -Name NoDataExecutionPrevention -ErrorAction SilentlyContinue|Select-Object -ExpandProperty NoDataExecutionPrevention

if ($NoDataExecutionPrevention -eq $null)
{
outputanswer -answer "Turn off Data Execution Prevention for Explorer is not configured" -color Yellow
}
    elseif ($NoDataExecutionPrevention -eq '0')
    {
        outputanswer -answer "Turn off Data Execution Prevention for Explorer is disabled" -color Green
    }
    else
    {
        outputanswer -answer "Turn off Data Execution Prevention for Explorer is enabled" -color Red
    }

# Enabled Structured Exception Handling Overwrite Protection (SEHOP)
$DisableExceptionChainValidation = Get-ItemProperty -Path "Registry::HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\" -Name DisableExceptionChainValidation -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableExceptionChainValidation

if ($DisableExceptionChainValidation -eq $null)
{
outputanswer -answer "Enabled Structured Exception Handling Overwrite Protection (SEHOP) is not configured" -color Yellow
}
    elseif ($DisableExceptionChainValidation -eq '0')
    {
        outputanswer -answer "Enabled Structured Exception Handling Overwrite Protection (SEHOP) is enabled" -color Green
    }
    else
    {
        outputanswer -answer "Enabled Structured Exception Handling Overwrite Protection (SEHOP) is disabled" -color Red
    }


outputanswer -answer "LOCAL ADMINISTRATOR ACCOUNTS" -color White

# Accounts: Administrator account status
# This is apparently not a registry key, need to implement a check using another method later


#Apply UAC restrictions to local accounts on network logons 

$LocalAccountTokenFilterPolicy = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue|Select-Object -ExpandProperty LocalAccountTokenFilterPolicy

if ($LocalAccountTokenFilterPolicy -eq $null)
{
outputanswer -answer "Apply UAC restrictions to local accounts on network logons is not configured" -color Yellow
}
    elseif ($LocalAccountTokenFilterPolicy -eq '0')
    {
        outputanswer -answer "Apply UAC restrictions to local accounts on network logons is enabled" -color Green
    }
    else
    {
        outputanswer -answer "Apply UAC restrictions to local accounts on network logons is disabled" -color Red
    }


outputanswer -answer "MICROSOFT EDGE" -color White


#Allow Adobe Flash 

$FlashPlayerEnabledLM = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\MicrosoftEdge\Addons\" -Name FlashPlayerEnabled -ErrorAction SilentlyContinue|Select-Object -ExpandProperty FlashPlayerEnabled
$FlashPlayerEnabledUP = Get-ItemProperty -Path "Registry::HKCU\Software\Policies\Microsoft\MicrosoftEdge\Addons\" -Name FlashPlayerEnabled -ErrorAction SilentlyContinue|Select-Object -ExpandProperty FlashPlayerEnabled

if ($FlashPlayerEnabledLM -eq $null -and $FlashPlayerEnabledUP -eq $null)
{
outputanswer -answer "Flash Player is Not Configured" -color Yellow
}

if ($FlashPlayerEnabledLM -eq '0')
    {
        outputanswer -answer "Flash Player is disabled in Local Machine GP" -color Green
    }
if ($FlashPlayerEnabledLM -eq '1')
    {
        outputanswer -answer "Flash Player is enabled in Local Machine GP" -color Red
    }   
if ($FlashPlayerEnabledUP -eq '0')
    {
        outputanswer -answer "Flash Player is disabled in User GP" -color Green
    }
if ($FlashPlayerEnabledUP -eq '1')
    {
        outputanswer -answer "Flash Player is enabled in User GP" -color Red
    }

#Allow Developer Tools

$AllowDeveloperToolsLM = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\MicrosoftEdge\F12\" -Name AllowDeveloperTools -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AllowDeveloperTools
$AllowDeveloperToolsUP = Get-ItemProperty -Path "Registry::HKCU\Software\Policies\Microsoft\MicrosoftEdge\F12\" -Name AllowDeveloperTools -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AllowDeveloperTools

if ($AllowDeveloperToolsLM -eq $null -and $AllowDeveloperToolsUP -eq $null)
{
outputanswer -answer "Edge Developer Tools are Not Configured" -color Yellow
}

if ($AllowDeveloperToolsLM -eq '0')
    {
        outputanswer -answer "Edge Developer Tools are disabled in Local Machine GP" -color Green
    }
if ($AllowDeveloperToolsLM -eq '1')
    {
        outputanswer -answer "Edge Developer Tools are enabled in Local Machine GP" -color Red
    }   
if ($AllowDeveloperToolsUP -eq '0')
    {
        outputanswer -answer "Edge Developer Tools are disabled in User GP" -color Green
    }
if ($AllowDeveloperToolsUP -eq '1')
    {
        outputanswer -answer "Edge Developer Tools are enabled in User GP" -color Red
    }


#Configure Do Not Track

$DoNotTrackLM = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main\" -Name DoNotTrack -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DoNotTrack
$DoNotTracksUP = Get-ItemProperty -Path "Registry::HKCU\Software\Policies\Microsoft\MicrosoftEdge\Main\" -Name DoNotTrack -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DoNotTrack

if ($DoNotTrackLM -eq $null -and $DoNotTrackUP -eq $null)
{
outputanswer -answer "Edge Do Not Track is Not Configured" -color Yellow
}

if ($AllowDeveloperToolsLM -eq '0')
    {
        outputanswer -answer "Edge Do Not Track is disabled in Local Machine GP" -color Red
    }
if ($AllowDeveloperToolsLM -eq '1')
    {
        outputanswer -answer "Edge Do Not Track is enabled in Local Machine GP" -color Green
    }   
if ($AllowDeveloperToolsUP -eq '0')
    {
        outputanswer -answer "Edge Do Not Track is disabled in User GP" -color Red
    }
if ($AllowDeveloperToolsUP -eq '1')
    {
        outputanswer -answer "Edge Do Not Track is enabled in User GP" -color Green
    }

#Configure Password Manager

$FormSuggestPasswordsLM = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main\" -Name 'FormSuggest Passwords' -ErrorAction SilentlyContinue|Select-Object -ExpandProperty 'FormSuggest Passwords'
$FormSuggestPasswordsUP = Get-ItemProperty -Path "Registry::HKCU\Software\Policies\Microsoft\MicrosoftEdge\Main\" -Name 'FormSuggest Passwords' -ErrorAction SilentlyContinue|Select-Object -ExpandProperty 'FormSuggest Passwords'

if ($FormSuggestPasswordsLM -eq $null -and $FormSuggestPasswordsUP -eq $null)
{
outputanswer -answer "Edge Password Manager is Not Configured" -color Yellow
}

if ($FormSuggestPasswordsLM -eq 'no')
    {
        outputanswer -answer "Edge Password Manager is disabled in Local Machine GP" -color Red
    }
if ($FormSuggestPasswordsLM -eq 'yes')
    {
        outputanswer -answer "Edge Password Manager is enabled in Local Machine GP" -color Green
    }   
if ($FormSuggestPasswordsUP -eq 'no')
    {
        outputanswer -answer "Edge Password Manager is disabled in User GP" -color Red
    }
if ($FormSuggestPasswordsUP -eq 'yes')
    {
        outputanswer -answer "Edge Password Manager is enabled in User GP" -color Green
    }

#Configure Pop-up Blocker

$AllowPopupsLM = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main\" -Name AllowPopups -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AllowPopups
$AllowPopupsUP = Get-ItemProperty -Path "Registry::HKCU\Software\Policies\Microsoft\MicrosoftEdge\Main\" -Name AllowPopups -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AllowPopups

if ($AllowPopupsLM -eq $null -and $AllowPopupsUP -eq $null)
{
outputanswer -answer "Edge Pop-up Blocker is Not Configured" -color Yellow
}

if ($AllowPopupsLM -eq 'no')
    {
        outputanswer -answer "Edge Pop-up Blocker is disabled in Local Machine GP" -color Red
    }
if ($AllowPopupsLM -eq 'yes')
    {
        outputanswer -answer "Edge Pop-up Blocker is enabled in Local Machine GP" -color Green
    }   
if ($AllowPopupsUP -eq 'no')
    {
        outputanswer -answer "Edge Pop-up Blocker is disabled in User GP" -color Red
    }
if ($AllowPopupsUP -eq 'yes')
    {
        outputanswer -answer "Edge Pop-up Blocker is enabled in User GP" -color Green
    }

$EnableSmartScreen = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System\ -Name EnableSmartScreen -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EnableSmartScreen
if ( $EnableSmartScreen -eq $null)
{
outputanswer -answer "Configure Windows Defender SmartScreen is not configured" -color Yellow
}
   elseif ( $EnableSmartScreen  -eq  '1' )
{
outputanswer -answer "Configure Windows Defender SmartScreen is enabled" -color Green
}
  elseif ( $EnableSmartScreen  -eq  '0' )
{
outputanswer -answer "Configure Windows Defender SmartScreen is disabled" -color Red
}
  else
{
outputanswer -answer "Configure Windows Defender SmartScreen is set to an unknown setting" -color Red
}

#Prevent access to the about:flags page in Microsoft Edge is disabled in User GP

$LMPreventAccessToAboutFlagsInMicrosoftEdge = Get-ItemProperty -Path Registry::HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main\ -Name PreventAccessToAboutFlagsInMicrosoftEdge -ErrorAction SilentlyContinue|Select-Object -ExpandProperty PreventAccessToAboutFlagsInMicrosoftEdge
$UPPreventAccessToAboutFlagsInMicrosoftEdge = Get-ItemProperty -Path Registry::HKCU\Software\Policies\Microsoft\MicrosoftEdge\Main\ -Name PreventAccessToAboutFlagsInMicrosoftEdge -ErrorAction SilentlyContinue|Select-Object -ExpandProperty PreventAccessToAboutFlagsInMicrosoftEdge
if ( $LMPreventAccessToAboutFlagsInMicrosoftEdge -eq $null -and  $UPPreventAccessToAboutFlagsInMicrosoftEdge -eq $null)
{
outputanswer -answer "Prevent access to the about:flags page in Microsoft Edge is not configured" -color Yellow
}
if ( $LMPreventAccessToAboutFlagsInMicrosoftEdge  -eq '1' )
{
outputanswer -answer "Prevent access to the about:flags page in Microsoft Edge is enabled in Local Machine GP" -color Green
}
if ( $LMPreventAccessToAboutFlagsInMicrosoftEdge  -eq '0' )
{
outputanswer -answer "Prevent access to the about:flags page in Microsoft Edge is disabled in Local Machine GP" -color Red
}
if ( $UPPreventAccessToAboutFlagsInMicrosoftEdge  -eq  '1' )
{
outputanswer -answer "Prevent access to the about:flags page in Microsoft Edge is enabled in User GP" -color Green
}
if ( $UPPreventAccessToAboutFlagsInMicrosoftEdge  -eq  '0' )
{
outputanswer -answer "Prevent access to the about:flags page in Microsoft Edge is disabled in User GP" -color Red
}



#Prevent bypassing Windows Defender SmartScreen prompts for sites is not configured
$LMPreventOverride = Get-ItemProperty -Path Registry::HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\ -Name PreventOverride -ErrorAction SilentlyContinue|Select-Object -ExpandProperty PreventOverride
$UPPreventOverride = Get-ItemProperty -Path Registry::HKCU\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\ -Name PreventOverride -ErrorAction SilentlyContinue|Select-Object -ExpandProperty PreventOverride
if ( $LMPreventOverride -eq $null -and  $UPPreventOverride -eq $null)
{
outputanswer -answer "Prevent bypassing Windows Defender SmartScreen prompts for sites is not configured" -color Yellow
}
if ( $LMPreventOverride  -eq '1' )
{
outputanswer -answer "Prevent bypassing Windows Defender SmartScreen prompts for sites is enabled in Local Machine GP" -color Green
}
if ( $LMPreventOverride  -eq '0' )
{
outputanswer -answer "Prevent bypassing Windows Defender SmartScreen prompts for sites is disabled in Local Machine GP" -color Red
}
if ( $UPPreventOverride  -eq  '1' )
{
outputanswer -answer "Prevent bypassing Windows Defender SmartScreen prompts for sites is enabled in User GP" -color Green
}
if ( $UPPreventOverride  -eq  '0' )
{
outputanswer -answer "Prevent bypassing Windows Defender SmartScreen prompts for sites is disabled in User GP" -color Red
}


#Prevent users and apps from accessing dangerous websites
$EnableNetworkProtection = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\' -Name EnableNetworkProtection -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EnableNetworkProtection
if ( $EnableNetworkProtection -eq $null)
{
outputanswer -answer "Prevent users and apps from accessing dangerous websites is not configured" -color Yellow
}
   elseif ( $EnableNetworkProtection  -eq  '1' )
{
outputanswer -answer "Prevent users and apps from accessing dangerous websites is enabled" -color Green
}
  elseif ( $EnableNetworkProtection  -eq  '0' )
{
outputanswer -answer "Prevent users and apps from accessing dangerous websites is disabled" -color Red
}
  else
{
outputanswer -answer "Prevent users and apps from accessing dangerous websites is set to an unknown setting" -color Red
}



#Check Turn on Windows Defender Application Guard in Enterprise Mode
$AllowAppHVSI_ProviderSet = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\AppHVSI\ -Name AllowAppHVSI_ProviderSet -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AllowAppHVSI_ProviderSet
if ( $AllowAppHVSI_ProviderSet -eq $null)
{
outputanswer -answer "Turn on Windows Defender Application Guard in Enterprise Mode is not configured" -color Yellow
}
   elseif ( $AllowAppHVSI_ProviderSet  -eq  '1' )
{
outputanswer -answer "Turn on Windows Defender Application Guard in Enterprise Mode is enabled" -color Green
}
  elseif ( $AllowAppHVSI_ProviderSet  -eq  '0' )
{
outputanswer -answer "Turn on Windows Defender Application Guard in Enterprise Mode is disabled" -color Red
}
  else
{
outputanswer -answer "Turn on Windows Defender Application Guard in Enterprise Mode is set to an unknown setting" -color Red
}



#Check Windows Defender SmartScreen configuration
$LMEnabledV9 = Get-ItemProperty -Path Registry::HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\ -Name EnabledV9 -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EnabledV9
$UPEnabledV9 = Get-ItemProperty -Path Registry::HKCU\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\ -Name EnabledV9 -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EnabledV9
if ( $LMEnabledV9 -eq $null -and  $UPEnabledV9 -eq $null)
{
outputanswer -answer "Configure Windows Defender SmartScreen is not configured" -color Yellow
}
if ( $LMEnabledV9  -eq '1' )
{
outputanswer -answer "Configure Windows Defender SmartScreen is enabled in Local Machine GP" -color Green
}
if ( $LMEnabledV9  -eq '0' )
{
outputanswer -answer "Configure Windows Defender SmartScreen is disabled in Local Machine GP" -color Red
}
if ( $UPEnabledV9  -eq  '1' )
{
outputanswer -answer "Configure Windows Defender SmartScreen is enabled in User GP" -color Green
}
if ( $UPEnabledV9  -eq  '0' )
{
outputanswer -answer "Configure Windows Defender SmartScreen is disabled in User GP" -color Red
}



#Prevent bypassing Windows Defender SmartScreen prompts for sites
$LMPreventOverride = Get-ItemProperty -Path Registry::HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\ -Name PreventOverride -ErrorAction SilentlyContinue|Select-Object -ExpandProperty PreventOverride
$UPPreventOverride = Get-ItemProperty -Path Registry::HKCU\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\ -Name PreventOverride -ErrorAction SilentlyContinue|Select-Object -ExpandProperty PreventOverride
if ( $LMPreventOverride -eq $null -and  $UPPreventOverride -eq $null)
{
outputanswer -answer "Prevent bypassing Windows Defender SmartScreen prompts for sites is not configured" -color Yellow
}
if ( $LMPreventOverride  -eq '1' )
{
outputanswer -answer "Prevent bypassing Windows Defender SmartScreen prompts for sites is enabled in Local Machine GP" -color Green
}
if ( $LMPreventOverride  -eq '0' )
{
outputanswer -answer "Prevent bypassing Windows Defender SmartScreen prompts for sites is disabled in Local Machine GP" -color Red
}
if ( $UPPreventOverride  -eq  '1' )
{
outputanswer -answer "Prevent bypassing Windows Defender SmartScreen prompts for sites is enabled in User GP" -color Green
}
if ( $UPPreventOverride  -eq  '0' )
{
outputanswer -answer "Prevent bypassing Windows Defender SmartScreen prompts for sites is disabled in User GP" -color Red
}


outputanswer -answer "MULTI-FACTOR AUTHENTICATION" -color White

outputanswer -answer "There are no controls in this section that can be checked by a PowerShell script, this control requires manual auditing" -color Cyan



outputanswer -answer "OPERATING SYSTEM ARCHITECTURE" -color White

#Operating System Architecture
$architecture = $ENV:PROCESSOR_ARCHITECTURE
if ($architecture -Match '64')
{
outputanswer -answer "Operating System Architecture is 64-Bit" -color Green
}
elseif ($architecture -Match '32')
{
outputanswer -answer "Operating System Architecture is 32-Bit" -color Red
}
else
{
outputanswer -answer "Operating System Architecture was unable to be determined" -color Red
}


outputanswer -answer "OPERATING SYSTEM PATCHING" -color White



#Automatic Updates immediate installation
$AutoInstallMinorUpdates = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ -Name AutoInstallMinorUpdates -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AutoInstallMinorUpdates
if ( $AutoInstallMinorUpdates -eq $null)
{
outputanswer -answer "Allow Automatic Updates immediate installation is not configured" -color Yellow
}
   elseif ( $AutoInstallMinorUpdates  -eq  '1' )
{
outputanswer -answer "Allow Automatic Updates immediate installation is enabled" -color Green
}
  elseif ( $AutoInstallMinorUpdates  -eq  '0' )
{
outputanswer -answer "Allow Automatic Updates immediate installation is disabled" -color Red
}
  else
{
outputanswer -answer "Allow Automatic Updates immediate installation is set to an unknown setting" -color Red
}



#Check "Configure Automatic Updates"
$NoAutoUpdate = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ -Name NoAutoUpdate -ErrorAction SilentlyContinue|Select-Object -ExpandProperty NoAutoUpdate
if ( $NoAutoUpdate -eq $null)
{
outputanswer -answer "Configure Automatic Updates is not configured" -color Yellow
}
   elseif ( $NoAutoUpdate  -eq  '0' )
{
outputanswer -answer "Configure Automatic Updates is enabled" -color Green
}
  elseif ( $NoAutoUpdate  -eq  '1' )
{
outputanswer -answer "Configure Automatic Updates is disabled" -color Red
}
  else
{
outputanswer -answer "Configure Automatic Updates is set to an unknown setting" -color Red
}



#check Do not include drivers with Windows Updates
$ExcludeWUDriversInQualityUpdate = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\ -Name ExcludeWUDriversInQualityUpdate -ErrorAction SilentlyContinue|Select-Object -ExpandProperty ExcludeWUDriversInQualityUpdate
if ( $ExcludeWUDriversInQualityUpdate -eq $null)
{
outputanswer -answer "Do not include drivers with Windows Updates is not configured" -color Yellow
}
   elseif ( $ExcludeWUDriversInQualityUpdate  -eq  '0' )
{
outputanswer -answer "Do not include drivers with Windows Updates is disabled" -color Green
}
  elseif ( $ExcludeWUDriversInQualityUpdate  -eq  '1' )
{
outputanswer -answer "Do not include drivers with Windows Updates is enabled" -color Red
}
  else
{
outputanswer -answer "Do not include drivers with Windows Updates is set to an unknown setting" -color Red
}



#No auto-restart with logged on users for scheduled automatic updates installations
$NoAutoRebootWithLoggedOnUsers = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ -Name NoAutoRebootWithLoggedOnUsers -ErrorAction SilentlyContinue|Select-Object -ExpandProperty NoAutoRebootWithLoggedOnUsers
if ( $NoAutoRebootWithLoggedOnUsers -eq $null)
{
outputanswer -answer "No auto-restart with logged on users for scheduled automatic updates installations is not configured" -color Yellow
}
   elseif ( $NoAutoRebootWithLoggedOnUsers  -eq  '1' )
{
outputanswer -answer "No auto-restart with logged on users for scheduled automatic updates installations is enabled" -color Green
}
  elseif ( $NoAutoRebootWithLoggedOnUsers  -eq  '0' )
{
outputanswer -answer "No auto-restart with logged on users for scheduled automatic updates installations is disabled" -color Red
}
  else
{
outputanswer -answer "No auto-restart with logged on users for scheduled automatic updates installations is set to an unknown setting" -color Red
}



#Check configuration for Remove access to use all Windows Update features
$SetDisableUXWUAccess = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\ -Name SetDisableUXWUAccess -ErrorAction SilentlyContinue|Select-Object -ExpandProperty SetDisableUXWUAccess
if ( $SetDisableUXWUAccess -eq $null)
{
outputanswer -answer "Remove access to use all Windows Update features is not configured" -color Yellow
}
   elseif ( $SetDisableUXWUAccess  -eq  '0' )
{
outputanswer -answer "Remove access to use all Windows Update features is disabled" -color Green
}
  elseif ( $SetDisableUXWUAccess  -eq  '1' )
{
outputanswer -answer "Remove access to use all Windows Update features is enabled" -color Red
}
  else
{
outputanswer -answer "Remove access to use all Windows Update features is set to an unknown setting" -color Red
}




#Check configuration for Turn on recommended updates via Automatic Updates
$IncludeRecommendedUpdates = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ -Name IncludeRecommendedUpdates -ErrorAction SilentlyContinue|Select-Object -ExpandProperty IncludeRecommendedUpdates
if ( $IncludeRecommendedUpdates -eq $null)
{
outputanswer -answer "Turn on recommended updates via Automatic Updates is not configured" -color Yellow
}
   elseif ( $IncludeRecommendedUpdates  -eq  '1' )
{
outputanswer -answer "Turn on recommended updates via Automatic Updates is enabled" -color Green
}
  elseif ( $IncludeRecommendedUpdates  -eq  '0' )
{
outputanswer -answer "Turn on recommended updates via Automatic Updates is disabled" -color Red
}
  else
{
outputanswer -answer "Turn on recommended updates via Automatic Updates is set to an unknown setting" -color Red
}



#Check configuration: Specify intranet Microsoft update service location
$UseWUServer = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ -Name UseWUServer -ErrorAction SilentlyContinue|Select-Object -ExpandProperty UseWUServer
if ( $UseWUServer -eq $null)
{
outputanswer -answer "Specify intranet Microsoft update service location is not configured" -color Yellow
}
   elseif ( $UseWUServer  -eq  '1' )
{
outputanswer -answer "Specify intranet Microsoft update service location is enabled" -color Green
}
  elseif ( $UseWUServer  -eq  '0' )
{
outputanswer -answer "Specify intranet Microsoft update service location is disabled" -color Red
}
  else
{
outputanswer -answer "Specify intranet Microsoft update service location is set to an unknown setting" -color Red
}



outputanswer -answer "PASSWORD POLICY" -color White



#Check configuration: Turn off picture password sign-in
$BlockDomainPicturePassword = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System\ -Name BlockDomainPicturePassword -ErrorAction SilentlyContinue|Select-Object -ExpandProperty BlockDomainPicturePassword
if ( $BlockDomainPicturePassword -eq $null)
{
outputanswer -answer "Turn off picture password sign-in is not configured" -color Yellow
}
   elseif ( $BlockDomainPicturePassword  -eq  '1' )
{
outputanswer -answer "Turn off picture password sign-in is enabled" -color Green
}
  elseif ( $BlockDomainPicturePassword  -eq  '0' )
{
outputanswer -answer "Turn off picture password sign-in is disabled" -color Red
}
  else
{
outputanswer -answer "Turn off picture password sign-in is set to an unknown setting" -color Red
}


#Check: Turn on convenience PIN sign-in
$AllowDomainPINLogon = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System\ -Name AllowDomainPINLogon -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AllowDomainPINLogon
if ( $AllowDomainPINLogon -eq $null)
{
outputanswer -answer "Turn on convenience PIN sign-in is not configured" -color Yellow
}
   elseif ( $AllowDomainPINLogon  -eq  '0' )
{
outputanswer -answer "Turn on convenience PIN sign-in is disabled" -color Green
}
  elseif ( $AllowDomainPINLogon  -eq  '1' )
{
outputanswer -answer "Turn on convenience PIN sign-in is enabled" -color Red
}
  else
{
outputanswer -answer "Turn on convenience PIN sign-in is set to an unknown setting" -color Red
}

$accountSettings = net.exe accounts | ForEach-Object {ConvertFrom-String -InputObject $_ -Delimiter ": +" -PropertyNames Setting, Value}

if ( $accountSettings -eq $null)
{
#Enforce Password History
outputanswer -answer "Enforce Password History is unable to be checked due to an error calling net.exe" -color Cyan

#Maximum password age
outputanswer -answer "Maximum password age is unable to be checked due to an error calling net.exe" -color Cyan

#Minimum password age
outputanswer -answer "Minimum password age is unable to be checked due to an error calling net.exe" -color Cyan

#Minimum password length
outputanswer -answer "Minimum password length is unable to be checked due to an error calling net.exe" -color Cyan
}
else
{
$enforcehistory = $accountsettings.item(4).value
$maximumpasswordage = $accountsettings.item(2).value
$minimumpasswordage = $accountsettings.item(1).value
$minimumpasswordlength = $accountsettings.item(3).value

    if ($enforcehistory -le '8' -or $enforcehistory -eq 'None')
    {
    outputanswer -answer "Enforce Password History is set to $enforcehistory which is a compliant setting" -color Green
    }
    elseif ($enforcehistory -gt '8')
    {
    outputanswer -answer "Enforce Password History is set to $enforcehistory which is a non-compliant setting" -color Red
    }

    if ($maximumpasswordage -le '90')
    {
    outputanswer -answer "Maximum password age is set to $maximumpasswordage which is a compliant setting" -color Green
    }
    elseif ($maximumpasswordage -gt '90')
    {
    outputanswer -answer "Maximum password age is set to $maximumpasswordage which is a non-compliant setting" -color Red
    }

    if ($minimumpasswordage -le '1')
    {
    outputanswer -answer "Minimum password age is set to $minimumpasswordage which is a compliant setting" -color Green
    }
    elseif ($minimumpasswordage -gt '1')
    {
    outputanswer -answer "Minimum password age is set to $minimumpasswordage which is a non-compliant setting" -color Red
    }

    if ($minimumpasswordlength -ge '10')
    {
    outputanswer -answer "Minimum password length is set to $minimumpasswordlength which is a compliant setting" -color Green
    }
    elseif ($minimumpasswordlength -le '9')
    {
    outputanswer -answer "Minimum password length is set to $minimumpasswordlength which is a non-compliant setting" -color Red
    }
    
}
#Store passwords using reversible encryption
outputanswer -answer "Store passwords using reversible encryption is unable to be checked using PowerShell, as the setting is not a registry key. Please check Computer Configuration\Policies\Administrative Templates\System\Logon" -color Cyan


#Check: Limit local account use of blank passwords to console logon only
$LimitBlankPasswordUse = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\ -Name LimitBlankPasswordUse -ErrorAction SilentlyContinue|Select-Object -ExpandProperty LimitBlankPasswordUse
if ( $LimitBlankPasswordUse -eq $null)
{
outputanswer -answer "Limit local account use of blank passwords to console logon only is not configured" -color Yellow
}
   elseif ( $LimitBlankPasswordUse  -eq  '0' )
{
outputanswer -answer "Limit local account use of blank passwords to console logon only is disabled" -color Red
}
  elseif ( $LimitBlankPasswordUse  -eq  '1' )
{
outputanswer -answer "Limit local account use of blank passwords to console logon only is enabled" -color Green
}
  else
{
outputanswer -answer "Limit local account use of blank passwords to console logon only is set to an unknown setting" -color Red
}


outputanswer -answer "RESTRICTING PRIVILEGED ACCOUNTS" -color White

outputanswer -answer "There are no controls in this section that can be checked by a PowerShell script, this control requires manual auditing" -color Cyan



outputanswer -answer "SECURE BOOT" -color White


#Secure Boot status
If ($Checkelevateditems -eq $null)
{
    outputanswer -answer "Secure Boot status was unable to be checked due to no administrative privileges" -color Cyan
}
elseif ($Checkelevateditems -eq 'y')
{
$secureboottemp = "$userenvironmenttemp" + '\secureboot.txt'
$SecureBootStatus = Get-Content $secureboottemp
If ($SecureBootStatus -eq 'True')
    {
    outputanswer -answer "Secure Boot is Enabled On This Computer" -color Green
    }
elseIf($SecureBootStatus -eq 'False')
    {
    outputanswer -answer "Secure Boot status was unable to be determined" -color Red 
    }
Remove-Item $secureboottemp
}

outputanswer -answer "ACCOUNT LOCKOUT POLICIES" -color White

if ( $accountSettings -eq $null)
{
#Account Lockout Duration
outputanswer -answer "Account Lockout Duration is unable to be checked due to an error calling net.exe" -color Cyan

#Account Lockout Threshold
outputanswer -answer "Account Lockout Threshold is unable to be checked due to an error calling net.exe" -color Cyan

#Reset Account Lockout Counter
outputanswer -answer "Reset Account Lockout Counter After is unable to be checked due to an error calling net.exe" -color Cyan

}
else
{
$accountlockoutduration = $accountsettings.item(6).value
$accountlockoutthreshold = $accountsettings.item(5).value
$accountlockoutcounter = $accountsettings.item(7).value

    if ($accountlockoutduration -eq '0' -or $accountlockoutduration -eq 'Never')
    {
    outputanswer -answer "Account Lockout Duration is set to $accountlockoutduration which is a compliant setting" -color Green
    }
    else
    {
    outputanswer -answer "Account Lockout Duration is set to $accountlockoutduration which is a non-compliant setting" -color Red
    }

    if ($accountlockoutthreshold -le '5')
    {
    outputanswer -answer "Account Lockout Threshold is set to $accountlockoutthreshold which is a compliant setting" -color Green
    }
    else
    {
    outputanswer -answer "Account Lockout Threshold is set to $accountlockoutthreshold which is a non-compliant setting" -color Red
    }

    if ($accountlockoutcounter -ge '15')
    {
    outputanswer -answer "Account Lockout Threshold is set to $accountlockoutcounter minutes which is a compliant setting" -color Green
    }
    else
    {
    outputanswer -answer "Account Lockout Threshold is set to $accountlockoutcounter minutes which is a non-compliant setting" -color Red
    }

}



outputanswer -answer "ANONYMOUS CONNECTIONS" -color White


#Enable insecure guest logons
$AllowInsecureGuestAuth = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LanmanWorkstation\ -Name AllowInsecureGuestAuth -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AllowInsecureGuestAuth
if ( $AllowInsecureGuestAuth -eq $null)
{
outputanswer -answer "Enable insecure guest logons is not configured" -color Yellow
}
   elseif ( $AllowInsecureGuestAuth  -eq  '0' )
{
outputanswer -answer "Enable insecure guest logons is disabled" -color Green
}
  elseif ( $AllowInsecureGuestAuth  -eq  '1' )
{
outputanswer -answer "Enable insecure guest logons is enabled" -color Red
}
  else
{
outputanswer -answer "Enable insecure guest logons is set to an unknown setting" -color Red
}


#Network access: Allow anonymous SID/Name translation
If ($Checkelevateditems -eq $null)
{
    outputanswer -answer "Allow anonymous SID/Name translation was unable to be checked due to no administrative privileges" -color Cyan
}
elseif ($Checkelevateditems -eq 'y')
{
$lsaanonymousnamelookup = "$userenvironmenttemp" + '\lsaanonymousnamelookup.txt'
$lsaanonymousstatus = Get-Content $lsaanonymousnamelookup
If ($lsaanonymousstatus -eq '0')
    {
    outputanswer -answer "Allow anonymous SID/Name translation is disabled" -color Green
    }
elseIf($lsaanonymousstatus -eq '1')
    {
    outputanswer -answer "Allow anonymous SID/Name translation is enabled" -color Red 
    }
Remove-Item $lsaanonymousnamelookup

}


#Check configuration: Network access: Do not allow anonymous enumeration of SAM accounts
$RestrictAnonymousSAM = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\ -Name RestrictAnonymousSAM -ErrorAction SilentlyContinue|Select-Object -ExpandProperty RestrictAnonymousSAM
if ( $RestrictAnonymousSAM -eq $null)
{
outputanswer -answer "Network access: Do not allow anonymous enumeration of SAM accounts is not configured" -color Yellow
}
   elseif ( $RestrictAnonymousSAM  -eq  '1' )
{
outputanswer -answer "Network access: Do not allow anonymous enumeration of SAM accounts is enabled" -color Green
}
  elseif ( $RestrictAnonymousSAM  -eq  '0' )
{
outputanswer -answer "Network access: Do not allow anonymous enumeration of SAM accounts is disabled" -color Red
}
  else
{
outputanswer -answer "Network access: Do not allow anonymous enumeration of SAM accounts is set to an unknown setting" -color Red
}



#Check configuration: Network access: Do not allow anonymous enumeration of SAM accounts and shares
$RestrictAnonymous = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\ -Name restrictanonymous -ErrorAction SilentlyContinue|Select-Object -ExpandProperty RestrictAnonymous
if ( $RestrictAnonymous -eq $null)
{
outputanswer -answer "Network access: Do not allow anonymous enumeration of SAM accounts and shares is not configured" -color Yellow
}
   elseif ( $RestrictAnonymous  -eq  '1' )
{
outputanswer -answer "Network access: Do not allow anonymous enumeration of SAM accounts and shares is enabled" -color Green
}
  elseif ( $RestrictAnonymous  -eq  '0' )
{
outputanswer -answer "Network access: Do not allow anonymous enumeration of SAM accounts and shares is disabled" -color Red
}
  else
{
outputanswer -answer "Network access: Do not allow anonymous enumeration of SAM accounts and shares is set to an unknown setting" -color Red
}



#Check configuration: Network access: Let Everyone permissions apply to anonymous users
$EveryoneIncludesAnonymous = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\ -Name EveryoneIncludesAnonymous -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EveryoneIncludesAnonymous
if ( $EveryoneIncludesAnonymous -eq $null)
{
outputanswer -answer "Network access: Let Everyone permissions apply to anonymous users is not configured" -color Yellow
}
   elseif ( $EveryoneIncludesAnonymous  -eq  '0' )
{
outputanswer -answer "Network access: Let Everyone permissions apply to anonymous users is disabled" -color Green
}
  elseif ( $EveryoneIncludesAnonymous  -eq  '1' )
{
outputanswer -answer "Network access: Let Everyone permissions apply to anonymous users is enabled" -color Red
}
  else
{
outputanswer -answer "Network access: Let Everyone permissions apply to anonymous users is set to an unknown setting" -color Red
}



#Check configuration: Network access: Restrict anonymous access to Named Pipes and Shares
$RestrictNullSessAccess = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\ -Name RestrictNullSessAccess -ErrorAction SilentlyContinue|Select-Object -ExpandProperty RestrictNullSessAccess
if ( $RestrictNullSessAccess -eq $null)
{
outputanswer -answer "Network access: Restrict anonymous access to Named Pipes and Shares is not configured" -color Yellow
}
   elseif ( $RestrictNullSessAccess  -eq  '1' )
{
outputanswer -answer "Network access: Restrict anonymous access to Named Pipes and Shares is enabled" -color Green
}
 elseif ( $RestrictNullSessAccess  -eq  '0' )
{
outputanswer -answer "Network access: Restrict anonymous access to Named Pipes and Shares is disabled" -color Red
}
   else
{
outputanswer -answer "Network access: Restrict anonymous access to Named Pipes and Shares is set to an unknown setting " -color Red
}



#Check configuration: Network access: Do not allow anonymous enumeration of SAM accounts and shares
$RestrictRemoteSAM = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\ -Name RestrictRemoteSAM -ErrorAction SilentlyContinue|Select-Object -ExpandProperty RestrictRemoteSAM
if ( $RestrictRemoteSAM -eq $null)
{
outputanswer -answer "Network access: Do not allow anonymous enumeration of SAM accounts and shares is not configured" -color Yellow
}
   elseif ( $RestrictRemoteSAM  -eq  'O:BAG:BAD:(A;;RC;;;BA)' )
{
outputanswer -answer "Network access: Do not allow anonymous enumeration of SAM accounts and shares is configured correctly" -color Green
}
    else
{
outputanswer -answer "Network access: Do not allow anonymous enumeration of SAM accounts and shares is configured incorrectly." -color Red
}



#Check configuration: Network security: Allow Local System to use computer identity for NTLM
$UseMachineId = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\ -Name UseMachineId -ErrorAction SilentlyContinue|Select-Object -ExpandProperty UseMachineId
if ( $UseMachineId -eq $null)
{
outputanswer -answer "Network security: Allow Local System to use computer identity for NTLM is not configured" -color Yellow
}
   elseif ( $UseMachineId  -eq  '1' )
{
outputanswer -answer "Network security: Allow Local System to use computer identity for NTLM is enabled" -color Green
}
  elseif ( $UseMachineId  -eq  '1' )
{
outputanswer -answer "Network security: Allow Local System to use computer identity for NTLM is disabled" -color Red
}
  else
{
outputanswer -answer "Network security: Allow Local System to use computer identity for NTLM is set to an unknown setting" -color Red
}



#Check configuration: Allow LocalSystem NULL session fallback is not configured
$allownullsessionfallback = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\ -Name allownullsessionfallback -ErrorAction SilentlyContinue|Select-Object -ExpandProperty allownullsessionfallback
if ( $allownullsessionfallback -eq $null)
{
outputanswer -answer "Network security: Allow LocalSystem NULL session fallback is not configured" -color Yellow
}
   elseif ( $allownullsessionfallback  -eq  '0' )
{
outputanswer -answer "Network security: Allow LocalSystem NULL session fallback is disabled" -color Green
}
  elseif ( $allownullsessionfallback  -eq  '1' )
{
outputanswer -answer "Network security: Allow LocalSystem NULL session fallback is enabled" -color Red
}
  else
{
outputanswer -answer "Network security: Allow LocalSystem NULL session fallback is set to an unknown setting" -color Red
}


#Access this computer from the network
outputanswer -answer "Access this computer from the network is unable to be checked using PowerShell, as the setting is not a registry key. Please check Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\. ASD Recommendation is to only have 'Administrators & Remote Desktop Users' present" -color Cyan


#Deny Access to this computer from the network
outputanswer -answer "Deny Access to this computer from the network is unable to be checked using PowerShell, as the setting is not a registry key. Please check Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\. ASD Recommendation is to only have 'Guests & NT AUTHORITY\Local Account' present" -color Cyan


outputanswer -answer "ANTI-VIRUS SOFTWARE" -color White



#Check configuration: Turn off Windows Defender Antivirus
$DisableAntiSpyware = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\" -Name DisableAntiSpyware -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableAntiSpyware
if ( $DisableAntiSpyware -eq $null)
{
outputanswer -answer "Turn off Windows Defender Antivirus is not configured" -color Yellow
}
   elseif ( $DisableAntiSpyware  -eq  '0' )
{
outputanswer -answer "Turn off Windows Defender Antivirus is disabled" -color Green
}
  elseif ( $DisableAntiSpyware  -eq  '1' )
{
outputanswer -answer "Turn off Windows Defender Antivirus is enabled" -color Red
}
  else
{
outputanswer -answer "Turn off Windows Defender Antivirus is set to an unknown setting" -color Red
}



#Check configuration: Configure local setting override for reporting to Microsoft Active Protection Service (MAPS)
$LocalSettingOverrideSpyNetReporting = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\SpyNet\' -Name LocalSettingOverrideSpyNetReporting -ErrorAction SilentlyContinue|Select-Object -ExpandProperty LocalSettingOverrideSpyNetReporting
if ( $LocalSettingOverrideSpyNetReporting -eq $null)
{
outputanswer -answer "Configure local setting override for reporting to Microsoft Active Protection Service (MAPS). is not configured" -color Yellow
}
   elseif ( $LocalSettingOverrideSpyNetReporting  -eq  '0' )
{
outputanswer -answer "Configure local setting override for reporting to Microsoft Active Protection Service (MAPS). is disabled" -color Green
}
  elseif ( $LocalSettingOverrideSpyNetReporting  -eq  '1' )
{
outputanswer -answer "Configure local setting override for reporting to Microsoft Active Protection Service (MAPS). is enabled" -color Red
}
  else
{
outputanswer -answer "Configure local setting override for reporting to Microsoft Active Protection Service (MAPS). is set to an unknown setting" -color Red
}



#Check configuration: Configure the 'Block at First Sight' feature
$DisableBlockAtFirstSeen = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Spynet\' -Name DisableBlockAtFirstSeen -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableBlockAtFirstSeen
if ( $DisableBlockAtFirstSeen -eq $null)
{
outputanswer -answer "Configure the 'Block at First Sight' feature is not configured" -color Yellow
}
   elseif ( $DisableBlockAtFirstSeen  -eq  '0' )
{
outputanswer -answer "Configure the 'Block at First Sight' feature is enabled" -color Green
}
  elseif ( $DisableBlockAtFirstSeen  -eq  '1' )
{
outputanswer -answer "Configure the 'Block at First Sight' feature is disabled" -color Red
}
  else
{
outputanswer -answer "Configure the 'Block at First Sight' feature is set to an unknown setting" -color Red
}




#Check configuration: Join Microsoft Active Protection Service (MAPS)
$SpyNetReporting = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\SpyNet\' -Name SpyNetReporting -ErrorAction SilentlyContinue|Select-Object -ExpandProperty SpyNetReporting
if ( $SpyNetReporting -eq $null)
{
outputanswer -answer "Join Microsoft Active Protection Service (MAPS). is not configured" -color Yellow
}
   elseif ( $SpyNetReporting  -eq  '1' )
{
outputanswer -answer "Join Microsoft Active Protection Service (MAPS). is enabled" -color Green
}
  elseif ( $SpyNetReporting  -eq  '0' )
{
outputanswer -answer "Join Microsoft Active Protection Service (MAPS). is disabled" -color Red
}
  else
{
outputanswer -answer "Join Microsoft Active Protection Service (MAPS). is set to an unknown setting" -color Red
}



#Check configuration: Send file samples when further analysis is required
$SubmitSamplesConsent = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Spynet\' -Name SubmitSamplesConsent -ErrorAction SilentlyContinue|Select-Object -ExpandProperty SubmitSamplesConsent
if ( $SubmitSamplesConsent -eq $null)
{
outputanswer -answer "Send file samples when further analysis is required is not configured" -color Yellow
}
   elseif ( $SubmitSamplesConsent  -eq  '1' )
{
outputanswer -answer "Send file samples when further analysis is required is enabled" -color Green
}
  elseif ( $SubmitSamplesConsent  -eq  '0' )
{
outputanswer -answer "Send file samples when further analysis is required is disabled" -color Red
}
  else
{
outputanswer -answer "Send file samples when further analysis is required is set to an unknown setting" -color Red
}



#Check configuration: Configure extended cloud check
$MpBafsExtendedTimeout = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\MpEngine\' -Name MpBafsExtendedTimeout -ErrorAction SilentlyContinue|Select-Object -ExpandProperty MpBafsExtendedTimeout
if ( $MpBafsExtendedTimeout -eq $null)
{
outputanswer -answer "Configure extended cloud check is not configured" -color Yellow
}
   elseif ( $MpBafsExtendedTimeout  -eq  '1' )
{
outputanswer -answer "Configure extended cloud check is enabled" -color Green
}
  elseif ( $MpBafsExtendedTimeout  -eq  '0' )
{
outputanswer -answer "Configure extended cloud check is disabled" -color Red
}
  else
{
outputanswer -answer "Configure extended cloud check is set to an unknown setting" -color Red
}



#Check configuration: Select cloud protection level
$MpCloudBlockLevel = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\MpEngine\' -Name MpCloudBlockLevel -ErrorAction SilentlyContinue|Select-Object -ExpandProperty MpCloudBlockLevel
if ( $MpCloudBlockLevel -eq $null)
{
outputanswer -answer "Select cloud protection level is not configured" -color Yellow
}
   elseif ( $MpCloudBlockLevel  -eq  '1' )
{
outputanswer -answer "Select cloud protection level is enabled" -color Green
}
  elseif ( $MpCloudBlockLevel  -eq  '0' )
{
outputanswer -answer "Select cloud protection level is disabled" -color Red
}
  else
{
outputanswer -answer "Select cloud protection level is set to an unknown setting" -color Red
}



#Check configuration: Configure local setting override for scanning all downloaded files and attachments
$LocalSettingOverrideDisableIOAVProtection = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\' -Name LocalSettingOverrideDisableIOAVProtection -ErrorAction SilentlyContinue|Select-Object -ExpandProperty LocalSettingOverrideDisableIOAVProtection
if ( $LocalSettingOverrideDisableIOAVProtection -eq $null)
{
outputanswer -answer "Configure local setting override for scanning all downloaded files and attachments is not configured" -color Yellow
}
   elseif ( $LocalSettingOverrideDisableIOAVProtection  -eq  '1' )
{
outputanswer -answer "Configure local setting override for scanning all downloaded files and attachments is enabled" -color Green
}
  elseif ( $LocalSettingOverrideDisableIOAVProtection  -eq  '0' )
{
outputanswer -answer "Configure local setting override for scanning all downloaded files and attachments is disabled" -color Red
}
  else
{
outputanswer -answer "Configure local setting override for scanning all downloaded files and attachments is set to an unknown setting" -color Red
}




#Check configuration: Turn off real-time protection
$DisableRealtimeMonitoring = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\' -Name DisableRealtimeMonitoring -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableRealtimeMonitoring
if ( $DisableRealtimeMonitoring -eq $null)
{
outputanswer -answer "Turn off real-time protection is not configured" -color Yellow
}
   elseif ( $DisableRealtimeMonitoring  -eq  '0' )
{
outputanswer -answer "Turn off real-time protection is disabled" -color Green
}
  elseif ( $DisableRealtimeMonitoring  -eq  '1' )
{
outputanswer -answer "Turn off real-time protection is enabled" -color Red
}
  else
{
outputanswer -answer "Turn off real-time protection is set to an unknown setting" -color Red
}



#Check configuration: Turn on behavior monitoring
$DisableBehaviorMonitoring = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\' -Name DisableBehaviorMonitoring -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableBehaviorMonitoring
if ( $DisableBehaviorMonitoring -eq $null)
{
outputanswer -answer "Turn on behavior monitoring is not configured" -color Yellow
}
   elseif ( $DisableBehaviorMonitoring  -eq  '0' )
{
outputanswer -answer "Turn on behavior monitoring is enabled" -color Green
}
  elseif ( $DisableBehaviorMonitoring  -eq  '1' )
{
outputanswer -answer "Turn on behavior monitoring is disabled" -color Red
}
  else
{
outputanswer -answer "Turn on behavior monitoring is set to an unknown setting" -color Red
}



#Check configuration: Turn on process scanning whenever real-time protection
$DisableScanOnRealtimeEnable = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\' -Name DisableScanOnRealtimeEnable -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableScanOnRealtimeEnable
if ( $DisableScanOnRealtimeEnable -eq $null)
{
outputanswer -answer "Turn on process scanning whenever real-time protection is enabled is not configured" -color Yellow
}
   elseif ( $DisableScanOnRealtimeEnable  -eq  '0' )
{
outputanswer -answer "Turn on process scanning whenever real-time protection is enabled is enabled" -color Green
}
  elseif ( $DisableScanOnRealtimeEnable  -eq  '1' )
{
outputanswer -answer "Turn on process scanning whenever real-time protection is enabled is disabled" -color Red
}
  else
{
outputanswer -answer "Turn on process scanning whenever real-time protection is enabled is set to an unknown setting" -color Red
}



#Check configuration: Configure removal of items from Quarantine folder
$PurgeItemsAfterDelay = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Quarantine\' -Name PurgeItemsAfterDelay -ErrorAction SilentlyContinue|Select-Object -ExpandProperty PurgeItemsAfterDelay
if ( $PurgeItemsAfterDelay -eq $null)
{
outputanswer -answer "Configure removal of items from Quarantine folder is not configured" -color Yellow
}
   elseif ( $PurgeItemsAfterDelay  -eq  '0' )
{
outputanswer -answer "Configure removal of items from Quarantine folder is disabled" -color Green
}
  elseif ( $PurgeItemsAfterDelay  -eq  '1' )
{
outputanswer -answer "Configure removal of items from Quarantine folder is enabled" -color Red
}
  else
{
outputanswer -answer "Configure removal of items from Quarantine folder is set to an unknown setting" -color Red
}



#Check configuration: Allow users to pause scan
$AllowPause = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\Scan\' -Name AllowPause -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AllowPause
if ( $AllowPause -eq $null)
{
outputanswer -answer "Allow users to pause scan is not configured" -color Yellow
}
   elseif ( $AllowPause  -eq  '0' )
{
outputanswer -answer "Allow users to pause scan is disabled" -color Green
}
  elseif ( $AllowPause  -eq  '1' )
{
outputanswer -answer "Allow users to pause scan is enabled" -color Red
}
  else
{
outputanswer -answer "Allow users to pause scan is set to an unknown setting" -color Red
}




#Check configuration: Check for the latest virus and spyware definitions before running a scheduled scan
$CheckForSignaturesBeforeRunningScan = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\Scan\' -Name CheckForSignaturesBeforeRunningScan -ErrorAction SilentlyContinue|Select-Object -ExpandProperty CheckForSignaturesBeforeRunningScan
if ( $CheckForSignaturesBeforeRunningScan -eq $null)
{
outputanswer -answer "Check for the latest virus and spyware definitions before running a scheduled scan is not configured" -color Yellow
}
   elseif ( $CheckForSignaturesBeforeRunningScan  -eq  '1' )
{
outputanswer -answer "Check for the latest virus and spyware definitions before running a scheduled scan is enabled" -color Green
}
  elseif ( $CheckForSignaturesBeforeRunningScan  -eq  '0' )
{
outputanswer -answer "Check for the latest virus and spyware definitions before running a scheduled scan is disabled" -color Red
}
  else
{
outputanswer -answer "Check for the latest virus and spyware definitions before running a scheduled scan is set to an unknown setting" -color Red
}



#Check configuration: Scan archive files
$DisableArchiveScanning = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\Scan\' -Name DisableArchiveScanning -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableArchiveScanning
if ( $DisableArchiveScanning -eq $null)
{
outputanswer -answer "Scan archive files is not configured" -color Yellow
}
   elseif ( $DisableArchiveScanning  -eq  '0' )
{
outputanswer -answer "Scan archive files is enabled" -color Green
}
  elseif ( $DisableArchiveScanning  -eq  '1' )
{
outputanswer -answer "Scan archive files is disabled" -color Red
}
  else
{
outputanswer -answer "Scan archive files is set to an unknown setting" -color Red
}



#Check configuration: Scan packed executables
$DisablePackedExeScanning = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\Scan\' -Name DisablePackedExeScanning -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisablePackedExeScanning
if ( $DisablePackedExeScanning -eq $null)
{
outputanswer -answer "Scan packed executables is not configured" -color Yellow
}
   elseif ( $DisablePackedExeScanning  -eq  '0' )
{
outputanswer -answer "Scan packed executables is enabled" -color Green
}
  elseif ( $DisablePackedExeScanning  -eq  '1' )
{
outputanswer -answer "Scan packed executables is disabled" -color Red
}
  else
{
outputanswer -answer "Scan packed executables is set to an unknown setting" -color Red
}



#Check configuration: Scan removable drives
$DisableRemovableDriveScanning = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\Scan\' -Name DisableRemovableDriveScanning -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableRemovableDriveScanning
if ( $DisableRemovableDriveScanning -eq $null)
{
outputanswer -answer "Scan removable drives is not configured" -color Yellow
}
   elseif ( $DisableRemovableDriveScanning  -eq  '0' )
{
outputanswer -answer "Scan removable drives is enabled" -color Green
}
  elseif ( $DisableRemovableDriveScanning  -eq  '1' )
{
outputanswer -answer "Scan removable drives is disabled" -color Red
}
  else
{
outputanswer -answer "Scan removable drives is set to an unknown setting" -color Red
}



#Check configuration: Turn on e-mail scanning
$DisableEmailScanning = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\Scan\' -Name DisableEmailScanning -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableEmailScanning
if ( $DisableEmailScanning -eq $null)
{
outputanswer -answer "Turn on e-mail scanning is not configured" -color Yellow
}
   elseif ( $DisableEmailScanning  -eq  '0' )
{
outputanswer -answer "Turn on e-mail scanning is enabled" -color Green
}
  elseif ( $DisableEmailScanning  -eq  '1' )
{
outputanswer -answer "Turn on e-mail scanning is disabled" -color Red
}
  else
{
outputanswer -answer "Turn on e-mail scanning is set to an unknown setting" -color Red
}



#Check configuration: Turn on heuristics
$DisableHeuristics = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\Scan\' -Name DisableHeuristics -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableHeuristics
if ( $DisableHeuristics -eq $null)
{
outputanswer -answer "Turn on heuristics is not configured" -color Yellow
}
   elseif ( $DisableHeuristics  -eq  '0' )
{
outputanswer -answer "Turn on heuristics is enabled" -color Green
}
  elseif ( $DisableHeuristics  -eq  '1' )
{
outputanswer -answer "Turn on heuristics is disabled" -color Red
}
  else
{
outputanswer -answer "Turn on heuristics is set to an unknown setting" -color Red
}


outputanswer -answer "ATTACHMENT MANAGER" -color White

$SaveZoneInformation = Get-ItemProperty -Path Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\ -Name SaveZoneInformation -ErrorAction SilentlyContinue|Select-Object -ExpandProperty SaveZoneInformation
if ( $SaveZoneInformation -eq $null)
{
outputanswer -answer "Do not preserve zone information in file attachments is not configured" -color Yellow
}
   elseif ( $SaveZoneInformation  -eq  '2' )
{
outputanswer -answer "Do not preserve zone information in file attachments is disabled" -color Green
}
  elseif ( $SaveZoneInformation  -eq  '1' )
{
outputanswer -answer "Do not preserve zone information in file attachments is enabled" -color Red
}
  else
{
outputanswer -answer "Do not preserve zone information in file attachments is set to an unknown setting" -color Red
}

$HideZoneInfoOnProperties = Get-ItemProperty -Path Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\ -Name HideZoneInfoOnProperties -ErrorAction SilentlyContinue|Select-Object -ExpandProperty HideZoneInfoOnProperties
if ( $HideZoneInfoOnProperties -eq $null)
{
outputanswer -answer "Hide mechanisms to remove zone information is not configured" -color Yellow
}
   elseif ( $HideZoneInfoOnProperties  -eq  '1' )
{
outputanswer -answer "Hide mechanisms to remove zone information is enabled" -color Green
}
  elseif ( $HideZoneInfoOnProperties  -eq  '0' )
{
outputanswer -answer "Hide mechanisms to remove zone information is disabled" -color Red
}
  else
{
outputanswer -answer "Hide mechanisms to remove zone information is set to an unknown setting" -color Red
}

outputanswer -answer "AUDIT EVENT MANAGEMENT" -color White

$ProcessCreationIncludeCmdLine_Enabled = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\'  -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue|Select-Object -ExpandProperty ProcessCreationIncludeCmdLine_Enabled
if ( $ProcessCreationIncludeCmdLine_Enabled -eq $null)
{
outputanswer -answer "Include command line in process creation events is not configured" -color Yellow
}
   elseif ( $ProcessCreationIncludeCmdLine_Enabled  -eq  '1' )
{
outputanswer -answer "Include command line in process creation events is enabled" -color Green
}
  elseif ( $ProcessCreationIncludeCmdLine_Enabled  -eq  '0' )
{
outputanswer -answer "Include command line in process creation events is disabled" -color Red
}
  else
{
outputanswer -answer "Include command line in process creation events is set to an unknown setting" -color Red
}


$1AW2CfpSKiewv0 = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application\'  -Name MaxSize -ErrorAction SilentlyContinue|Select-Object -ExpandProperty MaxSize
if ( $1AW2CfpSKiewv0 -eq $null)
{
outputanswer -answer "Specify the maximum log file size (KB) for the Application Log is not configured" -color Yellow
}
   elseif ( $1AW2CfpSKiewv0  -eq  '65536' )
{
outputanswer -answer "Specify the maximum log file size (KB) for the Application Log is set to a compliant setting" -color Green
}
  elseif ( $1AW2CfpSKiewv0  -lt  '65536' )
{
outputanswer -answer "Specify the maximum log file size (KB) for the Application Log is set to $1AW2CfpSKiewv0 which is a lower value than 65536 required for compliance" -color Red
}
  elseif ( $1AW2CfpSKiewv0  -gt  '65536' )
{
outputanswer -answer "Specify the maximum log file size (KB) for the Application Log is set to $1AW2CfpSKiewv0 which is a higher value than 65536 required for compliance" -color Green
}
  else
{
outputanswer -answer "Specify the maximum log file size (KB) for the Application Log is set to an unknown setting" -color Red
}

$1AW2CfpSKiewv = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security\'  -Name MaxSize -ErrorAction SilentlyContinue|Select-Object -ExpandProperty MaxSize
if ( $1AW2CfpSKiewv -eq $null)
{
outputanswer -answer "Specify the maximum log file size (KB) for the Security Log is not configured" -color Yellow
}
   elseif ( $1AW2CfpSKiewv  -eq  '65536' )
{
outputanswer -answer "Specify the maximum log file size (KB) for the Security Log is set to a compliant setting" -color Green
}
  elseif ( $1AW2CfpSKiewv  -lt  '65536' )
{
outputanswer -answer "Specify the maximum log file size (KB) for the Security Log is set to $1AW2CfpSKiewv which is a lower value than 65536 required for compliance" -color Red
}
  elseif ( $1AW2CfpSKiewv  -gt  '65536' )
{
outputanswer -answer "Specify the maximum log file size (KB) for the Security Log is set to $1AW2CfpSKiewv which is a higher value than 65536 required for compliance" -color Green
}
  else
{
outputanswer -answer "Specify the maximum log file size (KB) for the Security Log is set to an unknown setting" -color Red
}

$1AW2CfpSKiew = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\System\'  -Name MaxSize -ErrorAction SilentlyContinue|Select-Object -ExpandProperty MaxSize
if ( $1AW2CfpSKiew -eq $null)
{
outputanswer -answer "Specify the maximum log file size (KB) for the System Log is not configured" -color Yellow
}
   elseif ( $1AW2CfpSKiew  -eq  '65536' )
{
outputanswer -answer "Specify the maximum log file size (KB) for the System Log is set to a compliant setting" -color Green
}
  elseif ( $1AW2CfpSKiew  -lt  '65536' )
{
outputanswer -answer "Specify the maximum log file size (KB) for the System Log is set to $1AW2CfpSKiew which is a lower value than 65536 required for compliance" -color Red
}
  elseif ( $1AW2CfpSKiew  -gt  '65536' )
{
outputanswer -answer "Specify the maximum log file size (KB) for the System Log is set to $1AW2CfpSKiew which is a higher value than 65536 required for compliance" -color Green
}
  else
{
outputanswer -answer "Specify the maximum log file size (KB) for the System Log is set to an unknown setting" -color Red
}

$1AW2CfpSKiewv0n = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Setup\'  -Name MaxSize -ErrorAction SilentlyContinue|Select-Object -ExpandProperty MaxSize
if ( $1AW2CfpSKiewv0n -eq $null)
{
outputanswer -answer "Specify the maximum log file size (KB) for the Setup Log is not configured" -color Yellow
}
   elseif ( $1AW2CfpSKiewv0n  -eq  '65536' )
{
outputanswer -answer "Specify the maximum log file size (KB) for the Setup Log is set to a compliant setting" -color Green
}
  elseif ( $1AW2CfpSKiewv0n  -lt  '65536' )
{
outputanswer -answer "Specify the maximum log file size (KB) for the Setup Log is set to $1AW2CfpSKiewv0n which is a lower value than 65536 required for compliance" -color Red
}
  elseif ( $1AW2CfpSKiewv0n  -gt  '65536' )
{
outputanswer -answer "Specify the maximum log file size (KB) for the Setup Log is set to $1AW2CfpSKiewv0n which is a higher value than 65536 required for compliance" -color Green
}
  else
{
outputanswer -answer "Specify the maximum log file size (KB) for the Setup Log is set to an unknown setting" -color Red
}

outputanswer -answer "Manage Auditing and Security Log is unable to be checked using PowerShell, as the setting is not a registry key. Please check Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment. ASD Recommendation is to only have 'Administrators' present" -color Cyan

outputanswer -answer "Audit Credential Validation is unable to be checked using PowerShell, as the setting is not a registry key. Please check Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Account Logon. ASD Recommendation is to have 'Success and Failure' Present" -color Cyan

outputanswer -answer "Audit Computer Account Management is unable to be checked using PowerShell, as the setting is not a registry key. ASD Recommendation is to have 'Success and Failure' Present" -color Cyan

outputanswer -answer "Audit Other Account Management Events is unable to be checked using PowerShell, as the setting is not a registry key. ASD Recommendation is to have 'Success and Failure' Present" -color Cyan

outputanswer -answer "Audit Security Group Management is unable to be checked using PowerShell, as the setting is not a registry key. ASD Recommendation is to have 'Success and Failure' Present" -color Cyan

outputanswer -answer "Audit User Account Management is unable to be checked using PowerShell, as the setting is not a registry key. ASD Recommendation is to have 'Success and Failure' Present" -color Cyan

outputanswer -answer "Audit PNP Activity is unable to be checked using PowerShell, as the setting is not a registry key. ASD Recommendation is to have 'Success' Present" -color Cyan

outputanswer -answer "Audit Process Creation is unable to be checked using PowerShell, as the setting is not a registry key. ASD Recommendation is to have 'Success' Present" -color Cyan

outputanswer -answer "Audit Process Termination is unable to be checked using PowerShell, as the setting is not a registry key. ASD Recommendation is to have 'Success' Present" -color Cyan

outputanswer -answer "Audit Account Lockout is unable to be checked using PowerShell, as the setting is not a registry key. Please check. ASD Recommendation is to have 'Success and Failure' Present" -color Cyan

outputanswer -answer "Audit Group Membership is unable to be checked using PowerShell, as the setting is not a registry key. ASD Recommendation is to have 'Success' Present" -color Cyan

outputanswer -answer "Audit Logoff is unable to be checked using PowerShell, as the setting is not a registry key. ASD Recommendation is to have 'Success' Present" -color Cyan

outputanswer -answer "Audit Logon is unable to be checked using PowerShell, as the setting is not a registry key. ASD Recommendation is to have 'Success and Failure' Present" -color Cyan

outputanswer -answer "Audit Other Logon/Logoff Events is unable to be checked using PowerShell, as the setting is not a registry key. ASD Recommendation is to have 'Success and Failure' Present" -color Cyan

outputanswer -answer "Audit Audit Special Logon is unable to be checked using PowerShell, as the setting is not a registry key. ASD Recommendation is to have 'Success and Failure' Present" -color Cyan

outputanswer -answer "Audit File Share is unable to be checked using PowerShell, as the setting is not a registry key. ASD Recommendation is to have 'Success and Failure' Present" -color Cyan

outputanswer -answer "Audit Kernel Object is unable to be checked using PowerShell, as the setting is not a registry key. ASD Recommendation is to have 'Success and Failure' Present" -color Cyan

outputanswer -answer "Audit Other Object Access Events is unable to be checked using PowerShell, as the setting is not a registry key. ASD Recommendation is to have 'Success and Failure' Present" -color Cyan

outputanswer -answer "Audit Removable Storage is unable to be checked using PowerShell, as the setting is not a registry key ASD Recommendation is to have 'Success and Failure' Present" -color Cyan

outputanswer -answer "Audit Audit Policy Change is unable to be checked using PowerShell, as the setting is not a registry key. ASD Recommendation is to have 'Success and Failure' Present" -color Cyan

outputanswer -answer "Audit Authentication Policy Change is unable to be checked using PowerShell, as the setting is not a registry key. ASD Recommendation is to have 'Success' Present" -color Cyan

outputanswer -answer "Audit Authorization Policy Change is unable to be checked using PowerShell, as the setting is not a registry key. ASD Recommendation is to have 'Success' Present" -color Cyan

outputanswer -answer "Audit Sensitive Privilege Use is unable to be checked using PowerShell, as the setting is not a registry key. Please check Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Privilege Use. ASD Recommendation is to have 'Success and Failure' Present" -color Cyan

outputanswer -answer "Audit IPsec Driver is unable to be checked using PowerShell, as the setting is not a registry key. ASD Recommendation is to have 'Success and Failure' Present" -color Cyan

outputanswer -answer "Audit Other System Events is unable to be checked using PowerShell, as the setting is not a registry key. ASD Recommendation is to have 'Success and Failure' Present" -color Cyan

outputanswer -answer "Audit Security State Change is unable to be checked using PowerShell, as the setting is not a registry key. ASD Recommendation is to have 'Success' Present" -color Cyan

outputanswer -answer "Audit Security System Extension is unable to be checked using PowerShell, as the setting is not a registry key. ASD Recommendation is to have 'Success and Failure' Present" -color Cyan

outputanswer -answer "Audit System Integrity is unable to be checked using PowerShell, as the setting is not a registry key. ASD Recommendation is to have 'Success and Failure' Present" -color Cyan

$SCENoApplyLegacyAuditPolicy = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\'  -Name SCENoApplyLegacyAuditPolicy -ErrorAction SilentlyContinue|Select-Object -ExpandProperty SCENoApplyLegacyAuditPolicy
if ( $SCENoApplyLegacyAuditPolicy -eq $null)
{
outputanswer -answer "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings is not configured" -color Yellow
}
   elseif ( $SCENoApplyLegacyAuditPolicy -eq  '1' )
{
outputanswer -answer "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings is enabled" -color Green
}
  elseif ( $SCENoApplyLegacyAuditPolicy  -eq  '0' )
{
outputanswer -answer "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings is disabled" -color Red
}
  else
{
outputanswer -answer "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings is set to an unknown setting" -color Red
}

outputanswer -answer "AUTOPLAY AND AUTORUN" -color White

$LMNoAutoplayfornonVolume = Get-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\Explorer\' -Name NoAutoplayfornonVolume -ErrorAction SilentlyContinue|Select-Object -ExpandProperty NoAutoplayfornonVolume
$UPNoAutoplayfornonVolume = Get-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\Explorer\' -Name NoAutoplayfornonVolume -ErrorAction SilentlyContinue|Select-Object -ExpandProperty NoAutoplayfornonVolume
if ( $LMNoAutoplayfornonVolume -eq $null -and  $UPNoAutoplayfornonVolume -eq $null)
{
outputanswer -answer "Disallow Autoplay for non-volume devices is not configured" -color Yellow
}
if ( $LMNoAutoplayfornonVolume  -eq '1' )
{
outputanswer -answer "Disallow Autoplay for non-volume devices is enabled in Local Machine GP" -color Green
}
if ( $LMNoAutoplayfornonVolume  -eq '0' )
{
outputanswer -answer "Disallow Autoplay for non-volume devices is disabled in Local Machine GP" -color Red
}
if ( $UPNoAutoplayfornonVolume  -eq  '1' )
{
outputanswer -answer "Disallow Autoplay for non-volume devices is enabled in User GP" -color Green
}
if ( $UPNoAutoplayfornonVolume  -eq  '0' )
{
outputanswer -answer "Disallow Autoplay for non-volume devices is disabled in User GP" -color Red
}

$LMNoAutorun = Get-ItemProperty -Path  'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\' -Name NoAutorun -ErrorAction SilentlyContinue|Select-Object -ExpandProperty NoAutorun
$UPNoAutorun = Get-ItemProperty -Path  'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\' -Name NoAutorun -ErrorAction SilentlyContinue|Select-Object -ExpandProperty NoAutorun
if ( $LMNoAutorun -eq $null -and  $UPNoAutorun -eq $null)
{
outputanswer -answer "Set the default behavior for AutoRun is not configured" -color Yellow
}
if ( $LMNoAutorun  -eq '1' )
{
outputanswer -answer "Set the default behavior for AutoRun is enabled in Local Machine GP" -color Green
}
if ( $LMNoAutorun  -eq '2' )
{
outputanswer -answer "Set the default behavior for AutoRun is disabled in Local Machine GP" -color Red
}
if ( $UPNoAutorun  -eq  '1' )
{
outputanswer -answer "Set the default behavior for AutoRun is enabled in User GP" -color Green
}
if ( $UPNoAutorun  -eq  '2' )
{
outputanswer -answer "Set the default behavior for AutoRun is disabled in User GP" -color Red
}

$LMNoDriveTypeAutoRun = Get-ItemProperty -Path  'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\' -Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue|Select-Object -ExpandProperty NoDriveTypeAutoRun
$UPNoDriveTypeAutoRun = Get-ItemProperty -Path  'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\' -Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue|Select-Object -ExpandProperty NoDriveTypeAutoRun
if ( $LMNoDriveTypeAutoRun -eq $null -and  $UPNoDriveTypeAutoRun -eq $null)
{
outputanswer -answer "Turn off Autoplay is not configured" -color Yellow
}
if ( $LMNoDriveTypeAutoRun  -eq '255' )
{
outputanswer -answer "Turn off Autoplay is enabled in Local Machine GP" -color Green
}
if ( $LMNoDriveTypeAutoRun  -eq '181' )
{
outputanswer -answer "Turn off Autoplay is disabled in Local Machine GP" -color Red
}
if ( $UPNoDriveTypeAutoRun  -eq  '255' )
{
outputanswer -answer "Turn off Autoplay is enabled in User GP" -color Green
}
if ( $UPNoDriveTypeAutoRun  -eq  '181' )
{
outputanswer -answer "Turn off Autoplay is disabled in User GP" -color Red
}

outputanswer -answer "BIOS AND UEFI PASSWORDS" -color White

outputanswer -answer "Unable to confirm that a BIOS password is set via PowerShell. Please manually check if a BIOS password is set (if applicable)" -color Cyan

outputanswer -answer "BOOT DEVICES" -color White

outputanswer -answer "Unable to confirm the BIOS device boot order. Please manually check to ensure that the hard disk of this device is the primary boot device and the machine is unable to be booted off removable media (if applicable)" -color Cyan

outputanswer -answer "BRIDGING NETWORKS" -color White

$NC_AllowNetBridge_NLA = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections\'  -Name NC_AllowNetBridge_NLA -ErrorAction SilentlyContinue|Select-Object -ExpandProperty NC_AllowNetBridge_NLA
if ( $NC_AllowNetBridge_NLA -eq $null)
{
outputanswer -answer "Prohibit installation and configuration of Network Bridge on your DNS domain network is not configured" -color Yellow
}
   elseif ( $NC_AllowNetBridge_NLA  -eq  '0' )
{
outputanswer -answer "Prohibit installation and configuration of Network Bridge on your DNS domain network is enabled" -color Green
}
  elseif ( $NC_AllowNetBridge_NLA  -eq  '1' )
{
outputanswer -answer "Prohibit installation and configuration of Network Bridge on your DNS domain network is disabled" -color Red
}
  else
{
outputanswer -answer "Prohibit installation and configuration of Network Bridge on your DNS domain network is set to an unknown setting" -color Red
}

$Force_Tunneling = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\'  -Name Force_Tunneling -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Force_Tunneling
if ( $Force_Tunneling -eq $null)
{
outputanswer -answer "Route all traffic through the internal network is not configured" -color Yellow
}
   elseif ( $Force_Tunneling  -eq  'Enabled' )
{
outputanswer -answer "Route all traffic through the internal network is enabled" -color Green
}
  elseif ( $Force_Tunneling  -eq  'Disabled' )
{
outputanswer -answer "Route all traffic through the internal network is disabled" -color Red
}
  else
{
outputanswer -answer "Route all traffic through the internal network is set to an unknown setting" -color Red
}

$fBlockNonDomain = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\'  -Name fBlockNonDomain -ErrorAction SilentlyContinue|Select-Object -ExpandProperty fBlockNonDomain
if ( $fBlockNonDomain -eq $null)
{
outputanswer -answer "Prohibit connection to non-domain networks when connected to domain authenticated network is not configured" -color Yellow
}
   elseif ( $fBlockNonDomain  -eq  '1' )
{
outputanswer -answer "Prohibit connection to non-domain networks when connected to domain authenticated network is enabled" -color Green
}
  elseif ( $fBlockNonDomain  -eq  '0' )
{
outputanswer -answer "Prohibit connection to non-domain networks when connected to domain authenticated network is disabled" -color Red
}
  else
{
outputanswer -answer "Prohibit connection to non-domain networks when connected to domain authenticated network is set to an unknown setting" -color Red
}


outputanswer -answer "BUILT-IN GUEST ACCOUNTS" -color White


$accounts = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='$true'"|Select-Object Name,Disabled|Select-String 'Guest'
if ($accounts -like"@{Name=Guest; Disabled=True}")
{
outputanswer -answer "The local guest account is disabled" -color Green
}
elseif ($accounts -like "@{Name=Guest; Disabled=False}")
{
outputanswer -answer "The local guest account is enabled" -color Red
}
else
{
outputanswer -answer "The local guest account status was unable to be determined or has been renamed" -color Red
}



outputanswer -answer "Deny Logon Locally is unable to be checked realiably using PowerShell. Please check Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment. ASD Recommendation is to have 'Guests' present." -color Cyan

outputanswer -answer "CASE LOCKS" -color White

outputanswer -answer "Unable to check if this computer has a physical case lock with a PowerShell script! Ensure the physical workstation is secured to prevent tampering, such as adding / removing hardware or removing CMOS battery." -color Cyan


outputanswer -answer "CD BURNER ACCESS" -color White

$NoCDBurning = Get-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'  -Name NoCDBurning -ErrorAction SilentlyContinue|Select-Object -ExpandProperty NoCDBurning
if ( $NoCDBurning -eq $null)
{
outputanswer -answer "Remove CD Burning features is not configured" -color Yellow
}
   elseif ( $NoCDBurning  -eq  '1' )
{
outputanswer -answer "Remove CD Burning features is enabled" -color Green
}
  elseif ( $NoCDBurning  -eq  '0' )
{
outputanswer -answer "Remove CD Burning features is disabled" -color Red
}
  else
{
outputanswer -answer "Remove CD Burning features is set to an unknown setting" -color Red
}

outputanswer -answer "CENTRALISED AUDIT EVENT LOGGING" -color White

outputanswer -answer "Centralised Audit Event Logging is unable to be checked with PowerShell. Ensure the organisation is using Centralised Event Logging, please confirm events from endpoint computers are being sent to a central location." -color Cyan

outputanswer -answer "COMMAND PROMPT" -color White

$DisableCMD = Get-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\System\'  -Name DisableCMD -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableCMD
if ( $DisableCMD -eq $null)
{
outputanswer -answer "Prevent access to the command prompt is not configured" -color Yellow
}
   elseif ( $DisableCMD  -eq  '1' )
{
outputanswer -answer "Prevent access to the command prompt is enabled" -color Green
}
  elseif ( $DisableCMD  -eq  '2' )
{
outputanswer -answer "Prevent access to the command prompt is disabled" -color Red
}
  else
{
outputanswer -answer "Prevent access to the command prompt is set to an unknown setting" -color Red
}

outputanswer -answer "DIRECT MEMORY ACCESS" -color White

$deviceidbanlol = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\'  -Name DenyDeviceIDs -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DenyDeviceIDs
if ( $deviceidbanlol -eq $null)
{
outputanswer -answer "Prevent installation of devices that match any of these device IDs is not configured" -color Yellow
}
   elseif ( $deviceidbanlol  -eq  '1' )
{
outputanswer -answer "Prevent installation of devices that match any of these device IDs is enabled" -color Green
}
  elseif ( $deviceidbanlol  -eq  '0' )
{
outputanswer -answer "Prevent installation of devices that match any of these device IDs is disabled" -color Red
}
  else
{
outputanswer -answer "Prevent installation of devices that match any of these device IDs is set to an unknown setting" -color Red
}

$deviceidbanlol1 = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\'  -Name DenyDeviceIDsRetroactive -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DenyDeviceIDsRetroactive
if ( $deviceidbanlol1 -eq $null)
{
outputanswer -answer "Prevent installation of devices that match any of these device IDs (retroactively) is not configured" -color Yellow
}
   elseif ( $deviceidbanlol1  -eq  '1' )
{
outputanswer -answer "Prevent installation of devices that match any of these device IDs (retroactively) is enabled" -color Green
}
  elseif ( $deviceidbanlol1  -eq  '0' )
{
outputanswer -answer "Prevent installation of devices that match any of these device IDs (retroactively) is disabled" -color Red
}
  else
{
outputanswer -answer "Prevent installation of devices that match any of these device IDs (retroactively) is set to an unknown setting" -color Red
}

foreach($_ in 1..50)
{
    $i++
    $banneddevice = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs\" -Name $_ -ErrorAction SilentlyContinue|Select-Object -ExpandProperty $_
    If ($banneddevice -ne $null)
    {
	If ($banneddevice -eq 'PCI\CC_0C0A')
		{
		outputanswer -answer "PCI\CC_0C0A is included on the banned device list to prevent DMA installations" -color Green
		}
	else
	{
	outputanswer -answer "PCI\CC_0C0A is not included on the banned device list to prevent DMA installations." -color Red
	}
    }
}

$deviceidbanlol3 = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\'  -Name DenyDeviceClasses -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DenyDeviceClasses
if ( $deviceidbanlol3 -eq $null)
{
outputanswer -answer "Prevent installation of devices using drivers that match these device setup classes is not configured" -color Yellow
}
   elseif ( $deviceidbanlol3  -eq  '1' )
{
outputanswer -answer "Prevent installation of devices using drivers that match these device setup classes is enabled" -color Green
}
  elseif ( $deviceidbanlol3  -eq  '0' )
{
outputanswer -answer "Prevent installation of devices using drivers that match these device setup classes is disabled" -color Red
}
  else
{
outputanswer -answer "Prevent installation of devices using drivers that match these device setup classes is set to an unknown setting" -color Red
}

$deviceidbanlol4 = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\'  -Name DenyDeviceClassesRetroactive -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DenyDeviceClassesRetroactive
if ( $deviceidbanlol4 -eq $null)
{
outputanswer -answer "Prevent installation of devices using drivers that match these device setup classes (retroactively) is not configured" -color Yellow
}
   elseif ( $deviceidbanlol4  -eq  '1' )
{
outputanswer -answer "Prevent installation of devices using drivers that match these device setup classes (retroactively) is enabled" -color Green
}
  elseif ( $deviceidbanlol4  -eq  '0' )
{
outputanswer -answer "Prevent installation of devices using drivers that match these device setup classes (retroactively) is disabled" -color Red
}
  else
{
outputanswer -answer "Prevent installation of devices using drivers that match these device setup classes (retroactively) is set to an unknown setting" -color Red
}

foreach($_ in 1..50)
{
    $i++
    $banneddevice2 = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses\" -Name $_ -ErrorAction SilentlyContinue|Select-Object -ExpandProperty $_
    If ($banneddevice2 -ne $null)
    {
	If ($banneddevice2 -eq '{d48179be-ec20-11d1-b6b8-00c04fa372a7}')
		{
		outputanswer -answer "{d48179be-ec20-11d1-b6b8-00c04fa372a7} is included on the banned device list to prevent DMA installations" -color Green
		}
	else
	{
	outputanswer -answer "{d48179be-ec20-11d1-b6b8-00c04fa372a7} is not included on the banned device list to prevent DMA installations." -color Red
	}
    }
}


outputanswer -answer "ENDPOINT DEVICE CONTROL" -color White


$Deny_All = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\'  -Name Deny_All -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_All
if ( $Deny_All -eq $null)
{
outputanswer -answer "All Removable Storage classes: Deny all access is not configured in local machine group policy" -color Yellow
}
   elseif ( $Deny_All  -eq  '1' )
{
outputanswer -answer "All Removable Storage classes: Deny all access is enabled in local machine group policy" -color Green
}
  elseif ( $Deny_All  -eq  '0' )
{
outputanswer -answer "All Removable Storage classes: Deny all access is disabled in local machine group policy" -color Red
}
  else
{
outputanswer -answer "All Removable Storage classes: Deny all access is set to an unknown setting in local machine group policy" -color Red
}

$Deny_All2 = Get-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\RemovableStorageDevices\'  -Name Deny_All -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_All
if ( $Deny_All2 -eq $null)
{
outputanswer -answer "All Removable Storage classes: Deny all access is not configured in user group policy" -color Yellow
}
   elseif ( $Deny_All2  -eq  '1' )
{
outputanswer -answer "All Removable Storage classes: Deny all access is enabled in user group policy" -color Green
}
  elseif ( $Deny_All2  -eq  '0' )
{
outputanswer -answer "All Removable Storage classes: Deny all access is disabled in user group policy" -color Red
}
  else
{
outputanswer -answer "All Removable Storage classes: Deny all access is set to an unknown setting in user group policy" -color Red
}

$Deny_Execute = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56308-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Execute -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Execute
if ( $Deny_Execute -eq $null)
{
outputanswer -answer "CD and DVD: Deny execute access is not configured in local machine group policy" -color Yellow
}
   elseif ( $Deny_Execute  -eq  '1' )
{
outputanswer -answer "CD and DVD: Deny execute access is enabled in local machine group policy" -color Green
}
  elseif ( $Deny_Execute  -eq  '0' )
{
outputanswer -answer "CD and DVD: Deny execute access is disabled in local machine group policy" -color Red
}
  else
{
outputanswer -answer "CD and DVD: Deny execute access is set to an unknown setting in local machine group policy" -color Red
}


$Deny_Read = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56308-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Read -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Read
if ( $Deny_Read -eq $null)
{
outputanswer -answer "CD and DVD: Deny read access is not configured in local machine group policy" -color Yellow
}
   elseif ( $Deny_Read  -eq  '0' )
{
outputanswer -answer "CD and DVD: Deny read access is disabled in local machine group policy" -color Green
}
  elseif ( $Deny_Read  -eq  '1' )
{
outputanswer -answer "CD and DVD: Deny read access is enabled in local machine group policy" -color Red
}
  else
{
outputanswer -answer "CD and DVD: Deny read access is set to an unknown setting in local machine group policy" -color Red
}

$Deny_Write = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56308-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Write -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Write
if ( $Deny_Write -eq $null)
{
outputanswer -answer "CD and DVD: Deny write access is not configured in local machine group policy" -color Yellow
}
   elseif ( $Deny_Write  -eq  '1' )
{
outputanswer -answer "CD and DVD: Deny write access is enabled in local machine group policy" -color Green
}
  elseif ( $Deny_Write  -eq  '0' )
{
outputanswer -answer "CD and DVD: Deny write access is disabled in local machine group policy" -color Red
}
  else
{
outputanswer -answer "CD and DVD: Deny write access is set to an unknown setting in local machine group policy" -color Red
}

$Deny_Read99 = Get-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56308-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Read -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Read
if ( $Deny_Read99 -eq $null)
{
outputanswer -answer "CD and DVD: Deny read access is not configured in user group policy" -color Yellow
}
   elseif ( $Deny_Read99  -eq  '0' )
{
outputanswer -answer "CD and DVD: Deny read access is disabled in user group policy" -color Green
}
  elseif ( $Deny_Read99  -eq  '1' )
{
outputanswer -answer "CD and DVD: Deny read access is enabled in user group policy" -color Red
}
  else
{
outputanswer -answer "CD and DVD: Deny read access is set to an unknown setting in user group policy" -color Red
}

$Deny_Write99 = Get-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56308-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Write -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Write
if ( $Deny_Write99 -eq $null)
{
outputanswer -answer "CD and DVD: Deny write access is not configured in user group policy" -color Yellow
}
   elseif ( $Deny_Write99  -eq  '1' )
{
outputanswer -answer "CD and DVD: Deny write access is enabled in user group policy" -color Green
}
  elseif ( $Deny_Write99  -eq  '0' )
{
outputanswer -answer "CD and DVD: Deny write access is disabled in user group policy" -color Red
}
  else
{
outputanswer -answer "CD and DVD: Deny write access is set to an unknown setting in user group policy" -color Red
}

$Deny_Read98 = Get-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\Custom\Deny_Read\'  -Name Deny_Read -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Read
if ( $Deny_Read98 -eq $null)
{
outputanswer -answer "Custom Classes: Deny read access is not configured in local machine group policy" -color Yellow
}
   elseif ( $Deny_Read98  -eq  '0' )
{
outputanswer -answer "Custom Classes: Deny read access is disabled in local machine group policy" -color Green
}
  elseif ( $Deny_Read98  -eq  '1' )
{
outputanswer -answer "Custom Classes: Deny read access is enabled in local machine group policy" -color Red
}
  else
{
outputanswer -answer "Custom Classes: Deny read access is set to an unknown setting in local machine group policy" -color Red
}

$Deny_Write98 = Get-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\Custom\Deny_Write\'  -Name Deny_Write -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Write
if ( $Deny_Write98 -eq $null)
{
outputanswer -answer "Custom Classes: Deny write access is not configured in local machine group policy" -color Yellow
}
   elseif ( $Deny_Write98  -eq  '1' )
{
outputanswer -answer "Custom Classes: Deny write access is enabled in local machine group policy" -color Green
}
  elseif ( $Deny_Write98  -eq  '0' )
{
outputanswer -answer "Custom Classes: Deny write access is disabled in local machine group policy" -color Red
}
  else
{
outputanswer -answer "Custom Classes: Deny write access is set to an unknown setting in local machine group policy" -color Red
}


$Deny_Read2 = Get-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\RemovableStorageDevices\Custom\Deny_Read\'  -Name Deny_Read -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Read
if ( $Deny_Read2 -eq $null)
{
outputanswer -answer "Custom Classes: Deny read access is not configured in user group policy" -color Yellow
}
   elseif ( $Deny_Read2  -eq  '0' )
{
outputanswer -answer "Custom Classes: Deny read access is disabled in user group policy" -color Green
}
  elseif ( $Deny_Read2  -eq  '1' )
{
outputanswer -answer "Custom Classes: Deny read access is enabled in user group policy" -color Red
}
  else
{
outputanswer -answer "Custom Classes: Deny read access is set to an unknown setting in user group policy" -color Red
}

$Deny_Write2 = Get-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\RemovableStorageDevices\Custom\Deny_Write\'  -Name Deny_Write -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Write
if ( $Deny_Write2 -eq $null)
{
outputanswer -answer "Custom Classes: Deny write access is not configured in user group policy" -color Yellow
}
   elseif ( $Deny_Write2  -eq  '1' )
{
outputanswer -answer "Custom Classes: Deny write access is enabled in user group policy" -color Green
}
  elseif ( $Deny_Write2  -eq  '0' )
{
outputanswer -answer "Custom Classes: Deny write access is disabled in user group policy" -color Red
}
  else
{
outputanswer -answer "Custom Classes: Deny write access is set to an unknown setting in user group policy" -color Red
}

$Deny_Execute3 = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56311-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Execute -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Execute
if ( $Deny_Execute3 -eq $null)
{
outputanswer -answer "Floppy Drives: Deny execute access is not configured in local machine group policy" -color Yellow
}
   elseif ( $Deny_Execute3  -eq  '1' )
{
outputanswer -answer "Floppy Drives: Deny execute access is enabled in local machine group policy" -color Green
}
  elseif ( $Deny_Execute3  -eq  '0' )
{
outputanswer -answer "Floppy Drives: Deny execute access is disabled in local machine group policy" -color Red
}
  else
{
outputanswer -answer "Floppy Drives: Deny execute access is set to an unknown setting in local machine" -color Red
}

$Deny_Read97 = Get-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56311-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Read -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Read
if ( $Deny_Read97 -eq $null)
{
outputanswer -answer "Floppy Drives: Deny read access is not configured in local machine group policy" -color Yellow
}
   elseif ( $Deny_Read97  -eq  '0' )
{
outputanswer -answer "Floppy Drives: Deny read access is disabled in local machine group policy" -color Green
}
  elseif ( $Deny_Read97  -eq  '1' )
{
outputanswer -answer "Floppy Drives: Deny read access is enabled in local machine group policy" -color Red
}
  else
{
outputanswer -answer "Floppy Drives: Deny read access is set to an unknown setting in local machine group policy" -color Red
}

$Deny_Write97 = Get-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56311-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Write -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Write
if ( $Deny_Write97 -eq $null)
{
outputanswer -answer "Floppy Drives: Deny write access is not configured in local machine group policy" -color Yellow
}
   elseif ( $Deny_Write97  -eq  '1' )
{
outputanswer -answer "Floppy Drives: Deny write access is enabled in local machine group policy" -color Green
}
  elseif ( $Deny_Write97  -eq  '0' )
{
outputanswer -answer "Floppy Drives: Deny write access is disabled in local machine group policy" -color Red
}
  else
{
outputanswer -answer "Floppy Drives: Deny write access is set to an unknown setting in local machine group policy" -color Red
}

$Deny_Read3 = Get-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56311-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Read -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Read
if ( $Deny_Read3 -eq $null)
{
outputanswer -answer "Floppy Drives: Deny read access is not configured in user group policy" -color Yellow
}
   elseif ( $Deny_Read3  -eq  '0' )
{
outputanswer -answer "Floppy Drives: Deny read access is disabled in user group policy" -color Green
}
  elseif ( $Deny_Read3  -eq  '1' )
{
outputanswer -answer "Floppy Drives: Deny read access is enabled in user group policy" -color Red
}
  else
{
outputanswer -answer "Floppy Drives: Deny read access is set to an unknown setting in user group policy" -color Red
}

$Deny_Write3 = Get-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56311-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Write -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Write
if ( $Deny_Write3 -eq $null)
{
outputanswer -answer "Floppy Drives: Deny write access is not configured in user group policy" -color Yellow
}
   elseif ( $Deny_Write3  -eq  '1' )
{
outputanswer -answer "Floppy Drives: Deny write access is enabled in user group policy" -color Green
}
  elseif ( $Deny_Write3  -eq  '0' )
{
outputanswer -answer "Floppy Drives: Deny write access is disabled in user group policy" -color Red
}
  else
{
outputanswer -answer "Floppy Drives: Deny write access is set to an unknown setting in user group policy" -color Red
}

$Deny_Execute4 = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Execute -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Execute
if ( $Deny_Execute4 -eq $null)
{
outputanswer -answer "Removable Disks: Deny execute access is not configured in local machine group policy" -color Yellow
}
   elseif ( $Deny_Execute4  -eq  '1' )
{
outputanswer -answer "Removable Disks: Deny execute access is enabled in local machine group policy" -color Green
}
  elseif ( $Deny_Execute4  -eq  '0' )
{
outputanswer -answer "Removable Disks: Deny execute access is disabled in local machine group policy" -color Red
}
  else
{
outputanswer -answer "Removable Disks: Deny execute access is set to an unknown setting in local machine group policy" -color Red
}


$Deny_Read96 = Get-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Read -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Read
if ( $Deny_Read96 -eq $null)
{
outputanswer -answer "Removable Disks: Deny read access is not configured in local machine group policy" -color Yellow
}
   elseif ( $Deny_Read96  -eq  '0' )
{
outputanswer -answer "Removable Disks: Deny read access is disabled in local machine group policy" -color Green
}
  elseif ( $Deny_Read96  -eq  '1' )
{
outputanswer -answer "Removable Disks: Deny read access is enabled in local machine group policy" -color Red
}
  else
{
outputanswer -answer "Removable Disks: Deny read access is set to an unknown setting in local machine group policy" -color Red
}

$Deny_Write96 = Get-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Write -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Write
if ( $Deny_Write96 -eq $null)
{
outputanswer -answer "Removable Disks: Deny write access is not configured in local machine group policy" -color Yellow
}
   elseif ( $Deny_Write96  -eq  '1' )
{
outputanswer -answer "Removable Disks: Deny write access is enabled in local machine group policy" -color Green
}
  elseif ( $Deny_Write96  -eq  '0' )
{
outputanswer -answer "Removable Disks: Deny write access is disabled in local machine group policy" -color Red
}
  else
{
outputanswer -answer "Removable Disks: Deny write access is set to an unknown setting in local machine group policy" -color Red
}


$Deny_Read4 = Get-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Read -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Read
if ( $Deny_Read4 -eq $null)
{
outputanswer -answer "Removable Disks: Deny read access is not configured in user group policy" -color Yellow
}
   elseif ( $Deny_Read4  -eq  '0' )
{
outputanswer -answer "Removable Disks: Deny read access is disabled in user group policy" -color Green
}
  elseif ( $Deny_Read4  -eq  '1' )
{
outputanswer -answer "Removable Disks: Deny read access is enabled in user group policy" -color Red
}
  else
{
outputanswer -answer "Removable Disks: Deny read access is set to an unknown setting in user group policy" -color Red
}

$Deny_Write4 = Get-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Write -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Write
if ( $Deny_Write4 -eq $null)
{
outputanswer -answer "Removable Disks: Deny write access is not configured in user group policy" -color Yellow
}
   elseif ( $Deny_Write4  -eq  '1' )
{
outputanswer -answer "Removable Disks: Deny write access is enabled in user group policy" -color Green
}
  elseif ( $Deny_Write4  -eq  '0' )
{
outputanswer -answer "Removable Disks: Deny write access is disabled in user group policy" -color Red
}
  else
{
outputanswer -answer "Removable Disks: Deny write access is set to an unknown setting in user group policy" -color Red
}

$Deny_Execute5 = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630b-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Execute -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Execute
if ( $Deny_Execute5 -eq $null)
{
outputanswer -answer "Tape Drives: Deny execute access is not configured in local machine group policy" -color Yellow
}
   elseif ( $Deny_Execute5  -eq  '1' )
{
outputanswer -answer "Tape Drives: Deny execute access is enabled in local machine group policy" -color Green
}
  elseif ( $Deny_Execute5  -eq  '0' )
{
outputanswer -answer "Tape Drives: Deny execute access is disabled in local machine group policy" -color Red
}
  else
{
outputanswer -answer "Tape Drives: Deny execute access is set to an unknown setting in local machine group policy" -color Red
}

$Deny_Read5 = Get-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630b-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Read -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Read
if ( $Deny_Read5 -eq $null)
{
outputanswer -answer "Tape Drives: Deny read access is not configured in user group policy" -color Yellow
}
   elseif ( $Deny_Read5  -eq  '0' )
{
outputanswer -answer "Tape Drives: Deny read access is disabled in user group policy" -color Green
}
  elseif ( $Deny_Read5  -eq  '1' )
{
outputanswer -answer "Tape Drives: Deny read access is enabled in user group policy" -color Red
}
  else
{
outputanswer -answer "Tape Drives: Deny read access is set to an unknown setting  in user group policy" -color Red
}

$Deny_Write5 = Get-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630b-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Write -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Write
if ( $Deny_Write5 -eq $null)
{
outputanswer -answer "Tape Drives: Deny write access is not configured in user group policy" -color Yellow
}
   elseif ( $Deny_Write5  -eq  '1' )
{
outputanswer -answer "Tape Drives: Deny write access is enabled in user group policy" -color Green
}
  elseif ( $Deny_Write5  -eq  '0' )
{
outputanswer -answer "Tape Drives: Deny write access is disabled in user group policy" -color Red
}
  else
{
outputanswer -answer "Tape Drives: Deny write access is set to an unknown setting in user group policy" -color Red
}

$Deny_Read94 = Get-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630b-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Read -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Read
if ( $Deny_Read94 -eq $null)
{
outputanswer -answer "Tape Drives: Deny read access is not configured in local machine group policy" -color Yellow
}
   elseif ( $Deny_Read94  -eq  '0' )
{
outputanswer -answer "Tape Drives: Deny read access is disabled in local machine group policy" -color Green
}
  elseif ( $Deny_Read94  -eq  '1' )
{
outputanswer -answer "Tape Drives: Deny read access is enabled in local machine group policy" -color Red
}
  else
{
outputanswer -answer "Tape Drives: Deny read access is set to an unknown setting in local machine group policy" -color Red
}

$Deny_Write94 = Get-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630b-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Write -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Write
if ( $Deny_Write94 -eq $null)
{
outputanswer -answer "Tape Drives: Deny write access is not configured in local machine group policy" -color Yellow
}
   elseif ( $Deny_Write94  -eq  '1' )
{
outputanswer -answer "Tape Drives: Deny write access is enabled in local machine group policy" -color Green
}
  elseif ( $Deny_Write94  -eq  '0' )
{
outputanswer -answer "Tape Drives: Deny write access is disabled in local machine group policy" -color Red
}
  else
{
outputanswer -answer "Tape Drives: Deny write access is set to an unknown setting in local machine group policy" -color Red
}


$Deny_Read93 = Get-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{6AC27878-A6FA-4155-BA85-F98F491D4F33}\'  -Name Deny_Read -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Read
$Deny_Read92 = Get-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{F33FDC04-D1AC-4E8E-9A30-19BBD4B108AE}\'  -Name Deny_Read -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Read

if ( $Deny_Read93 -eq $null -and $Deny_Read92 -eq $null)
{
outputanswer -answer "WPD Devices: Deny read access is not configured in local machine group policy" -color Yellow
}
   elseif ( $Deny_Read93  -eq  '0' -and $Deny_Read92 -eq '0' )
{
outputanswer -answer "WPD Devices: Deny read access is disabled in local machine group policy" -color Green
}
  elseif ( $Deny_Read93  -eq  '1' -and $Deny_Read92 -eq '1' )
{
outputanswer -answer "WPD Devices: Deny read access is enabled in local machine group policy" -color Red
}
  else
{
outputanswer -answer "WPD Devices: Deny read access is set to an unknown setting in local machine group policy" -color Red
}

$Deny_Write93 = Get-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{6AC27878-A6FA-4155-BA85-F98F491D4F33}\'  -Name Deny_Write -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Write
$Deny_Write92 = Get-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{F33FDC04-D1AC-4E8E-9A30-19BBD4B108AE}\'  -Name Deny_Write -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Write

if ( $Deny_Write93 -eq $null -and $Deny_Write92 -eq $null)
{
outputanswer -answer "WPD Devices: Deny write access is not configured in local machine group policy" -color Yellow
}
   elseif ( $Deny_Write93  -eq  '1'  -and $Deny_Write92 -eq '1' )
{
outputanswer -answer "WPD Devices: Deny write access is enabled in local machine group policy" -color Green
}
  elseif ( $Deny_Write93  -eq  '0' -and $Deny_Write92 -eq '0' )
{
outputanswer -answer "WPD Devices: Deny write access is disabled in local machine group policy" -color Red
}
  else
{
outputanswer -answer "WPD Devices: Deny write access is set to an unknown setting in local machine group policy" -color Red
}

$Deny_Read91 = Get-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{6AC27878-A6FA-4155-BA85-F98F491D4F33}\'  -Name Deny_Read -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Read
$Deny_Read90 = Get-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{F33FDC04-D1AC-4E8E-9A30-19BBD4B108AE}\'  -Name Deny_Read -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Read

if ( $Deny_Read91 -eq $null -and $Deny_Read90 -eq $null)
{
outputanswer -answer "WPD Devices: Deny read access is not configured in user group policy" -color Yellow
}
   elseif ( $Deny_Read91  -eq  '0' -and $Deny_Read90 -eq '0' )
{
outputanswer -answer "WPD Devices: Deny read access is disabled in user group policy" -color Green
}
  elseif ( $Deny_Read91  -eq  '1' -and $Deny_Read90 -eq '1' )
{
outputanswer -answer "WPD Devices: Deny read access is enabled in user  group policy" -color Red
}
  else
{
outputanswer -answer "WPD Devices: Deny read access is set to an unknown setting in user  group policy" -color Red
}

$Deny_Write89 = Get-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{6AC27878-A6FA-4155-BA85-F98F491D4F33}\'  -Name Deny_Write -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Write
$Deny_Write88 = Get-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{F33FDC04-D1AC-4E8E-9A30-19BBD4B108AE}\'  -Name Deny_Write -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Deny_Write

if ( $Deny_Write89 -eq $null -and $Deny_Write88 -eq $null)
{
outputanswer -answer "WPD Devices: Deny write access is not configured in user group policy" -color Yellow
}
   elseif ( $Deny_Write89  -eq  '1'  -and $Deny_Write88 -eq '1' )
{
outputanswer -answer "WPD Devices: Deny write access is enabled in user  group policy" -color Green
}
  elseif ( $Deny_Write89  -eq  '0' -and $Deny_Write88 -eq '0' )
{
outputanswer -answer "WPD Devices: Deny write access is disabled in user  group policy" -color Red
}
  else
{
outputanswer -answer "WPD Devices: Deny write access is set to an unknown setting in user  group policy" -color Red
}


outputanswer -answer "FILE AND PRINT SHARING" -color White

$DisableHomeGroup = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\HomeGroup\'  -Name DisableHomeGroup -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableHomeGroup
if ( $DisableHomeGroup -eq $null)
{
outputanswer -answer "Prevent the computer from joining a homegroup is not configured" -color Yellow
}
   elseif ( $DisableHomeGroup  -eq  '1' )
{
outputanswer -answer "Prevent the computer from joining a homegroup is enabled" -color Green
}
  elseif ( $DisableHomeGroup  -eq  '0' )
{
outputanswer -answer "Prevent the computer from joining a homegroup is disabled" -color Red
}
  else
{
outputanswer -answer "Prevent the computer from joining a homegroup is set to an unknown setting" -color Red
}

$NoInplaceSharing = Get-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'  -Name NoInplaceSharing -ErrorAction SilentlyContinue|Select-Object -ExpandProperty NoInplaceSharing
if ( $NoInplaceSharing -eq $null)
{
outputanswer -answer "Prevent users from sharing files within their profile is not configured" -color Yellow
}
   elseif ( $NoInplaceSharing  -eq  '1' )
{
outputanswer -answer "Prevent users from sharing files within their profile is enabled" -color Green
}
  elseif ( $NoInplaceSharing  -eq  '0' )
{
outputanswer -answer "Prevent users from sharing files within their profile is disabled" -color Red
}
  else
{
outputanswer -answer "Prevent users from sharing files within their profile is set to an unknown setting" -color Red
}

outputanswer -answer "GROUP POLICY PROCESSING" -color White
$hardenedpaths = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -ErrorAction SilentlyContinue

if ($hardenedpaths -eq $null)
{
outputanswer -answer "Hardened UNC Paths are not configured, disabled or no paths are defined" -color Red
}
    else
{
outputanswer -answer "Hardened UNC Paths are defined" -color Green
}

$hardenedpaths = (Get-ItemProperty 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths')

$hardenedpaths.PSObject.Properties | ForEach-Object {
  If($_.Name -notlike 'PSP*' -and $_.Name -notlike 'PSChild*'){
    outputanswer -answer "Hardened UNC Path is configured with the location" $_.Name "and has a configuration value of" $_.Value -color Magenta
  }
}

$NoBackgroundPolicy = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\'  -Name NoGPOListChanges -ErrorAction SilentlyContinue|Select-Object -ExpandProperty NoGPOListChanges
if ( $NoBackgroundPolicy -eq $null)
{
outputanswer -answer "Configure registry policy processing is not configured" -color Yellow
}
   elseif ( $NoBackgroundPolicy  -eq  '0' )
{
outputanswer -answer "Configure registry policy processing is enabled" -color Green
}
  elseif ( $NoBackgroundPolicy  -eq  '1' )
{
outputanswer -answer "Configure registry policy processing is disabled" -color Red
}
  else
{
outputanswer -answer "Configure registry policy processing is set to an unknown setting" -color Red
}

$NoBackgroundPolicy2 = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}\'  -Name NoGPOListChanges -ErrorAction SilentlyContinue|Select-Object -ExpandProperty NoGPOListChanges
if ( $NoBackgroundPolicy2 -eq $null)
{
outputanswer -answer "Configure security policy processing is not configured" -color Yellow
}
   elseif ( $NoBackgroundPolicy2  -eq  '0' )
{
outputanswer -answer "Configure security policy processing is enabled" -color Green
}
  elseif ( $NoBackgroundPolicy2  -eq  '1' )
{
outputanswer -answer "Configure security policy processing is disabled" -color Red
}
  else
{
outputanswer -answer "Configure security policy processing is set to an unknown setting" -color Red
}

#THIS CONTROL HAS AN ISSUE, THE REGISTRY KEY DOESN'T ALWAYS EXIST
$DisableBkGndGroupPolicy = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\'  -Name DisableBkGndGroupPolicy -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableBkGndGroupPolicy
if ( $DisableBkGndGroupPolicy -eq $null)
{
outputanswer -answer "Turn off background refresh of Group Policy is not configured" -color Yellow
}
   elseif ( $DisableBkGndGroupPolicy  -eq  '0' )
{
outputanswer -answer "Turn off background refresh of Group Policy is disabled" -color Green
}
  elseif ( $DisableBkGndGroupPolicy  -eq  '1' )
{
outputanswer -answer "Turn off background refresh of Group Policy is enabled" -color Red
}
  else
{
outputanswer -answer "Turn off background refresh of Group Policy is set to an unknown setting" -color Red
}

$DisableLGPOProcessing = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System\'  -Name DisableLGPOProcessing -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableLGPOProcessing
if ( $DisableLGPOProcessing -eq $null)
{
outputanswer -answer "Turn off Local Group Policy Objects processing is not configured" -color Yellow
}
   elseif ( $DisableLGPOProcessing  -eq  '1' )
{
outputanswer -answer "Turn off Local Group Policy Objects processing is enabled" -color Green
}
  elseif ( $DisableLGPOProcessing  -eq  '0' )
{
outputanswer -answer "Turn off Local Group Policy Objects processing is disabled" -color Red
}
  else
{
outputanswer -answer "Turn off Local Group Policy Objects processing is set to an unknown setting" -color Red
}

outputanswer -answer "HARD DRIVE ENCRYPTION" -color White

$driveencryption = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE" -Name EncryptionMethodWithXtsOs -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EncryptionMethodWithXtsOs
$driveencryption3 = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE" -Name EncryptionMethodWithXtsFdv -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EncryptionMethodWithXtsFdv
$driveencryption4 = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE" -Name EncryptionMethodWithXtsRdv -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EncryptionMethodWithXtsRdv

if ($driveencryption -eq $null -and $driveencryption3 -eq $null -and $driveencryption4 -eq $null)
{
outputanswer -answer "Choose drive encryption method and cipher strength (Windows 10 [Version 1511] and later) is not configured or disabled" -color Red
}
    else
    {
        outputanswer -answer "Choose drive encryption method and cipher strength (Windows 10 [Version 1511] and later) is enabled" -color Green


if ($driveencryption2 -eq '7')
{
outputanswer -answer "The Operating System Drives Bitlocker encryption method is set to XTS-AES 256-bit" -color Green
}
    elseif ($driveencryption2 -eq '6')
    {
        outputanswer -answer "The Operating System Drives Bitlocker encryption method is set to XTS-AES 128-bit, the compliant setting is XES-AES 256-bit" -color Red
    }
    elseif ($driveencryption2 -eq '4')
    {
        outputanswer -answer "The Operating System Drives Bitlocker encryption method is set to AES-CBC 128-bit, the compliant setting is XES-AES 256-bit" -color Red
    }
    elseif ($driveencryption2 -eq '3')
    {
        outputanswer -answer "The Operating System Drives Bitlocker encryption method is set to AES-CBC 128-bit, the compliant setting is XES-AES 256-bit" -color Red
    }
    else
    {
        outputanswer -answer "The Operating System Drives encryption method is unable to be determined"
    }


if ($driveencryption3 -eq '7')
{
outputanswer -answer "The Fixed Drives Bitlocker encryption method is set to XTS-AES 256-bit" -color Green
}
    elseif ($driveencryption3 -eq '6')
    {
        outputanswer -answer "The Fixed Drives Bitlocker encryption method is set to XTS-AES 128-bit, the compliant setting is XES-AES 256-bit" -color Red
    }
    elseif ($driveencryption3 -eq '4')
    {
        outputanswer -answer "The Fixed Drives Bitlocker encryption method is set to AES-CBC 128-bit, the compliant setting is XES-AES 256-bit" -color Red
    }
    elseif ($driveencryption3 -eq '3')
    {
        outputanswer -answer "The Fixed Drives Bitlocker encryption method is set to AES-CBC 128-bit, the compliant setting is XES-AES 256-bit" -color Red
    }
        else
    {
        outputanswer -answer "The Fixed Drives encryption method is unable to be determined"
    }


if ($driveencryption4 -eq '7')
{
outputanswer -answer "The Removable Drives Bitlocker encryption method is set to XTS-AES 256-bit" -color Green
}
    elseif ($driveencryption4 -eq '6')
    {
        outputanswer -answer "The Removable Drives Bitlocker encryption method is set to XTS-AES 128-bit, the compliant setting is XES-AES 256-bit" -color Red
    }
    elseif ($driveencryption4 -eq '4')
    {
        outputanswer -answer "The Removable Drives Bitlocker encryption method is set to AES-CBC 128-bit, the compliant setting is XES-AES 256-bit" -color Red
    }
    elseif ($driveencryption4 -eq '3')
    {
        outputanswer -answer "The Removable Drives Bitlocker encryption method is set to AES-CBC 128-bit, the compliant setting is XES-AES 256-bit" -color Red
    }
        else
    {
        outputanswer -answer "The Removable Drives encryption method is unable to be determined"
    }
}

$DisableExternalDMAUnderLock = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\FVE\'  -Name DisableExternalDMAUnderLock -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableExternalDMAUnderLock
if ( $DisableExternalDMAUnderLock -eq $null)
{
outputanswer -answer "Disable new DMA devices when this computer is locked is not configured" -color Yellow
}
   elseif ( $DisableExternalDMAUnderLock  -eq  '1' )
{
outputanswer -answer "Disable new DMA devices when this computer is locked is enabled" -color Green
}
  elseif ( $DisableExternalDMAUnderLock  -eq  '0' )
{
outputanswer -answer "Disable new DMA devices when this computer is locked is disabled" -color Red
}
  else
{
outputanswer -answer "Disable new DMA devices when this computer is locked is set to an unknown setting" -color Red
}

$MorBehavior = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\FVE\'  -Name MorBehavior -ErrorAction SilentlyContinue|Select-Object -ExpandProperty MorBehavior
if ( $MorBehavior -eq $null)
{
outputanswer -answer "Prevent memory overwrite on restart is not configured" -color Yellow
}
   elseif ( $MorBehavior  -eq  '0' )
{
outputanswer -answer "Prevent memory overwrite on restart is disabled" -color Green
}
  elseif ( $MorBehavior  -eq  '1' )
{
outputanswer -answer "Prevent memory overwrite on restart is enabled" -color Red
}
  else
{
outputanswer -answer "Prevent memory overwrite on restart is set to an unknown setting" -color Red
}

#This check could be improved by printing out the possible configuration settings if choose how Bitlocker-protected fixed drives is configured
$bitlockerrecovery1 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name FDVRecovery -ErrorAction SilentlyContinue|Select-Object -ExpandProperty FDVRecovery
$bitlockerrecovery2 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name FDVRecoveryPassword -ErrorAction SilentlyContinue|Select-Object -ExpandProperty FDVRecoveryPassword
$bitlockerrecovery3 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name FDVRecoveryKey -ErrorAction SilentlyContinue|Select-Object -ExpandProperty FDVRecoveryKey
$bitlockerrecovery4 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name FDVManageDRA -ErrorAction SilentlyContinue|Select-Object -ExpandProperty FDVManageDRA
$bitlockerrecovery5 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name FDVHideRecoveryPage -ErrorAction SilentlyContinue|Select-Object -ExpandProperty FDVHideRecoveryPage
$bitlockerrecovery6 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name FDVActiveDirectoryBackup -ErrorAction SilentlyContinue|Select-Object -ExpandProperty FDVActiveDirectoryBackup
$bitlockerrecovery7 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name FDVActiveDirectoryInfoToStore -ErrorAction SilentlyContinue|Select-Object -ExpandProperty FDVActiveDirectoryInfoToStore

if ($bitlockerrecovery1 -eq $null -and $bitlockerrecovery2 -eq $null -and $bitlockerrecovery3 -eq $null -and $bitlockerrecovery4 -eq $null -and $bitlockerrecovery5 -eq $null -and $bitlockerrecovery6 -eq $null -and $bitlockerrecovery7 -eq $null)
{
outputanswer -answer "Choose how BitLocker-protected fixed drives can be recovered is not configured or disabled" -color Red
}
    else
{
outputanswer -answer "Choose how BitLocker-protected fixed  drives can be recovered has been configured" -color Green
}


$bitlockerpassuse1 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name FDVEnforcePassphrase -ErrorAction SilentlyContinue|Select-Object -ExpandProperty FDVEnforcePassphrase
$bitlockerpassuse2 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name FDVPassphrase -ErrorAction SilentlyContinue|Select-Object -ExpandProperty FDVPassphrase
$bitlockerpassuse3 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name FDVPassphraseComplexity -ErrorAction SilentlyContinue|Select-Object -ExpandProperty FDVPassphraseComplexity
$bitlockerpassuse4 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name FDVPassphraseLength -ErrorAction SilentlyContinue|Select-Object -ExpandProperty FDVPassphraseLength

if ($bitlockerpassuse1 -eq $null -and $bitlockerpassuse2 -eq $null -and $bitlockerpassuse3 -eq $null -and $bitlockerpassuse4 -eq $null)
{
outputanswer -answer "Configure use of passwords for fixed data drives is not configured or disabled" -color Red
}
    else
{
outputanswer -answer "Configure use of passwords for fixed data drives has been configured" -color Green

if ($bitlockerpassuse1 -eq '1')
{
outputanswer -answer "Passwords required for fixed data drives is enabled" -color Green
}
elseif ($bitlockerpassuse1 -eq '0')
{
outputanswer -answer "Passwords required for fixed data drives is disabled" -color Red
}

if ($bitlockerpassuse3 -eq '2')
{
outputanswer -answer "Password complexity for fixed data drives is set to Allow Passphrase Complexity, the compliant setting is Require Passphrase Complexity" -color Red
}
elseif ($bitlockerpassuse3 -eq '0')
{
outputanswer -answer "Password complexity for fixed data drives is set to Do Not Allow Passphrase Complexity, the compliant setting is Require Passphrase Complexity" -color Red
}
elseif ($bitlockerpassuse3 -eq '1')
{
outputanswer -answer "Password complexity for fixed data drives is set to Require Passphrase Complexity" -color Green
}

if ($bitlockerpassuse4 -le '9')
{
outputanswer -answer "Bitlocker Minimum passphrase length is set to $bitlockerpassuse4 which is less than the minimum requirement of 10 characters" -color Red
}
elseif ($bitlockerpassuse4 -gt '9')
{
outputanswer -answer "Bitlocker Minimum passphrase length is set to $bitlockerpassuse4 which is compliant" -color Green
}
else
{
outputanswer -answer "Bitlocker minimum passphrase length is set to an unknown setting"
}
}



$FDVDenyWriteAccess = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Policies\Microsoft\FVE\'  -Name FDVDenyWriteAccess -ErrorAction SilentlyContinue|Select-Object -ExpandProperty FDVDenyWriteAccess
if ( $FDVDenyWriteAccess -eq $null)
{
outputanswer -answer "Deny write access to fixed drives not protected by BitLocker is not configured" -color Yellow
}
   elseif ( $FDVDenyWriteAccess  -eq  '1' )
{
outputanswer -answer "Deny write access to fixed drives not protected by BitLocker is enabled" -color Green
}
  elseif ( $FDVDenyWriteAccess  -eq  '0' )
{
outputanswer -answer "Deny write access to fixed drives not protected by BitLocker is disabled" -color Red
}
  else
{
outputanswer -answer "Deny write access to fixed drives not protected by BitLocker is set to an unknown setting" -color Red
}

$fveencryptiontype = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name FDVEncryptionType -ErrorAction SilentlyContinue|Select-Object -ExpandProperty FDVEncryptionType

if ($fveencryptiontype -eq $null)
{
outputanswer -answer "Enforce drive encryption type on fixed data drive is not configured" -color Yellow
}
    elseif ($fveencryptiontype -eq '0')
{
outputanswer -answer "Enforce drive encryption type on fixed data drive is disabled or set to Allow User to Choose" -color Red
}
    elseif ($fveencryptiontype -eq '1')
{
outputanswer -answer "Enforce drive encryption type on fixed data drive is set to Full Encryption" -color Green
}
    elseif ($fveencryptiontype -eq '2')
{
outputanswer -answer "Enforce drive encryption type on fixed data drive is set to Used Space Only Encryption" -color Green
}


$OSEnablePreBootPinExceptionOnDECapableDevice = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\FVE\'  -Name OSEnablePreBootPinExceptionOnDECapableDevice -ErrorAction SilentlyContinue|Select-Object -ExpandProperty OSEnablePreBootPinExceptionOnDECapableDevice
if ( $OSEnablePreBootPinExceptionOnDECapableDevice -eq $null)
{
outputanswer -answer "Allow devices compliant with InstantGo or HSTI to opt out of pre-boot PIN is not configured" -color Yellow
}
   elseif ( $OSEnablePreBootPinExceptionOnDECapableDevice  -eq  '0' )
{
outputanswer -answer "Allow devices compliant with InstantGo or HSTI to opt out of pre-boot PIN is disabled" -color Green
}
  elseif ( $OSEnablePreBootPinExceptionOnDECapableDevice  -eq  '1' )
{
outputanswer -answer "Allow devices compliant with InstantGo or HSTI to opt out of pre-boot PIN. is enabled" -color Red
}
  else
{
outputanswer -answer "Allow devices compliant with InstantGo or HSTI to opt out of pre-boot PIN is set to an unknown setting" -color Red
}

$UseEnhancedPin = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\FVE\'  -Name UseEnhancedPin -ErrorAction SilentlyContinue|Select-Object -ExpandProperty UseEnhancedPin
if ( $UseEnhancedPin -eq $null)
{
outputanswer -answer "Allow enhanced PINs for startup is not configured" -color Yellow
}
   elseif ( $UseEnhancedPin  -eq  '1' )
{
outputanswer -answer "Allow enhanced PINs for startup is enabled" -color Green
}
  elseif ( $UseEnhancedPin  -eq  '0' )
{
outputanswer -answer "Allow enhanced PINs for startup is disabled" -color Red
}
  else
{
outputanswer -answer "Allow enhanced PINs for startup is set to an unknown setting" -color Red
}

$OSManageNKP = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE\'  -Name OSManageNKP -ErrorAction SilentlyContinue|Select-Object -ExpandProperty OSManageNKP
if ( $OSManageNKP -eq $null)
{
outputanswer -answer "Allow network unlock at startup is not configured" -color Yellow
}
   elseif ( $OSManageNKP  -eq  '1' )
{
outputanswer -answer "Allow network unlock at startup is enabled" -color Green
}
  elseif ( $OSManageNKP  -eq  '0' )
{
outputanswer -answer "Allow network unlock at startup is disabled" -color Red
}
  else
{
outputanswer -answer "Allow network unlock at startup is set to an unknown setting" -color Red
}

$OSAllowSecureBootForIntegrity = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\FVE\'  -Name OSAllowSecureBootForIntegrity -ErrorAction SilentlyContinue|Select-Object -ExpandProperty OSAllowSecureBootForIntegrity
if ( $OSAllowSecureBootForIntegrity -eq $null)
{
outputanswer -answer "Allow Secure Boot for integrity validation is not configured" -color Yellow
}
   elseif ( $OSAllowSecureBootForIntegrity  -eq  '1' )
{
outputanswer -answer "Allow Secure Boot for integrity validation is enabled" -color Green
}
  elseif ( $OSAllowSecureBootForIntegrity  -eq  '0' )
{
outputanswer -answer "Allow Secure Boot for integrity validation is disabled" -color Red
}
  else
{
outputanswer -answer "Allow Secure Boot for integrity validation is set to an unknown setting" -color Red
}

#This check could be improved by printing out the possible configuration settings if choose how Bitlocker-protected operating system drives is configured
$bitlockerosrecovery1 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name OSRecovery -ErrorAction SilentlyContinue|Select-Object -ExpandProperty OSRecovery
$bitlockerosrecovery2 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name OSRecoveryPassword -ErrorAction SilentlyContinue|Select-Object -ExpandProperty OSRecoveryPassword
$bitlockerosrecovery3 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name OSRecoveryKey -ErrorAction SilentlyContinue|Select-Object -ExpandProperty OSRecoveryKey
$bitlockerosrecovery4 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name OSManageDRA -ErrorAction SilentlyContinue|Select-Object -ExpandProperty OSManageDRA
$bitlockerosrecovery5 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name OSHideRecoveryPage -ErrorAction SilentlyContinue|Select-Object -ExpandProperty OSHideRecoveryPage
$bitlockerosrecovery6 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name OSActiveDirectoryBackup -ErrorAction SilentlyContinue|Select-Object -ExpandProperty OSActiveDirectoryBackup
$bitlockerosrecovery7 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name OSActiveDirectoryInfoToStore -ErrorAction SilentlyContinue|Select-Object -ExpandProperty OSActiveDirectoryInfoToStore

if ($bitlockerosrecovery1 -eq $null -and $bitlockerosrecovery2 -eq $null -and $bitlockerosrecovery3 -eq $null -and $bitlockerosrecovery4 -eq $null -and $bitlockerosrecovery5 -eq $null -and $bitlockerosrecovery6 -eq $null -and $bitlockerosrecovery7 -eq $null)
{
outputanswer -answer "Choose how BitLocker-protected operating system drives can be recovered is not configured or disabled" -color Red
}
    else
{
outputanswer -answer "Choose how BitLocker-protected operating system drives can be recovered has been configured" -color Green
}

$configureminimumpin = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name MinimumPin -ErrorAction SilentlyContinue|Select-Object -ExpandProperty MinimumPin

if ($configureminimumpin -eq $null)
{
outputanswer -answer "Configure minimum PIN length for startup is not configured" -color Yellow
}
elseif ($configureminimumpin -le '12')
{
outputanswer -answer "Configure minimum PIN length for startup is set to $configureminimumpin, which is less than the requirement of 13" -color Red
}
elseif ($configureminimumpin -gt '12')
{
outputanswer -answer "Configure minimum PIN length for startup is set to $configureminimumpin, which is more than the requirement of 13" -color Green
}


$bitlockerospassuse1 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name OSPassphraseASCIIOnly -ErrorAction SilentlyContinue|Select-Object -ExpandProperty OSPassphraseASCIIOnly
$bitlockerospassuse2 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name OSPassphrase -ErrorAction SilentlyContinue|Select-Object -ExpandProperty OSPassphrase
$bitlockerospassuse3 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name OSPassphraseComplexity -ErrorAction SilentlyContinue|Select-Object -ExpandProperty OSPassphraseComplexity
$bitlockerospassuse4 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name OSPassphraseLength -ErrorAction SilentlyContinue|Select-Object -ExpandProperty OSPassphraseLength

if ($bitlockerospassuse1 -eq $null -and $bitlockerospassuse2 -eq $null -and $bitlockerospassuse3 -eq $null -and $bitlockerospassuse4 -eq $null)
{
outputanswer -answer "Configure use of passwords for operating system drives is not configured or disabled" -color Red
}
    else
{
outputanswer -answer "Configure use of passwords for operating system drives has been configured" -color Green

if ($bitlockerospassuse1 -eq '1')
{
outputanswer -answer "Passwords required for operating system drives is enabled" -color Green
}
elseif ($bitlockerospassuse1 -eq '0')
{
outputanswer -answer "Passwords required for operating system drives is disabled" -color Red
}

if ($bitlockerospassuse3 -eq '2')
{
outputanswer -answer "Password complexity for operating system drives is set to Allow Passphrase Complexity, the compliant setting is Require Passphrase Complexity" -color Red
}
elseif ($bitlockerospassuse3 -eq '0')
{
outputanswer -answer "Password complexity for operating system drives is set to Do Not Allow Passphrase Complexity, the compliant setting is Require Passphrase Complexity" -color Red
}
elseif ($bitlockerospassuse3 -eq '1')
{
outputanswer -answer "Password complexity for operating system drives is set to Require Passphrase Complexity" -color Green
}

if ($bitlockerospassuse4 -le '9')
{
outputanswer -answer "Bitlocker Minimum passphrase length is set to $bitlockerospassuse4 which is less than the minimum requirement of 10 characters" -color Red
}
elseif ($bitlockerospassuse4 -gt '9')
{
outputanswer -answer "Bitlocker Minimum passphrase length is set to $bitlockerospassuse4 which is compliant" -color Green
}
else
{
outputanswer -answer "Bitlocker minimum passphrase length is set to an unknown setting"
}
}

$DisallowStandardUserPINReset = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\FVE\'  -Name DisallowStandardUserPINReset -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisallowStandardUserPINReset
if ( $DisallowStandardUserPINReset -eq $null)
{
outputanswer -answer "Disallow standard users from changing the PIN or password is not configured" -color Yellow
}
   elseif ( $DisallowStandardUserPINReset  -eq  '0' )
{
outputanswer -answer "Disallow standard users from changing the PIN or password is disabled" -color Green
}
  elseif ( $DisallowStandardUserPINReset  -eq  '1' )
{
outputanswer -answer "Disallow standard users from changing the PIN or password is enabled" -color Red
}
  else
{
outputanswer -answer "Disallow standard users from changing the PIN or password is set to an unknown setting" -color Red
}

$oseencryptiontype = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name OSEncryptionType -ErrorAction SilentlyContinue|Select-Object -ExpandProperty OSEncryptionType

if ($oseencryptiontype -eq $null)
{
outputanswer -answer "Enforce drive encryption type on operating system drive is not configured" -color Yellow
}
    elseif ($oseencryptiontype -eq '0')
{
outputanswer -answer "Enforce drive encryption type on operating system drive is disabled or set to Allow User to Choose" -color Red
}
    elseif ($oseencryptiontype -eq '1')
{
outputanswer -answer "Enforce drive encryption type on operating system drive is set to Full Encryption" -color Green
}
    elseif ($oseencryptiontype -eq '2')
{
outputanswer -answer "Enforce drive encryption type on operating system drive is set to Used Space Only Encryption" -color Green
}


$requireadditionalauth1 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name UseTPM -ErrorAction SilentlyContinue|Select-Object -ExpandProperty UseTPM
$requireadditionalauth2 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name UseTPMKey -ErrorAction SilentlyContinue|Select-Object -ExpandProperty UseTPMKey
$requireadditionalauth3 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name UseTPMKeyPIN -ErrorAction SilentlyContinue|Select-Object -ExpandProperty UseTPMKeyPIN
$requireadditionalauth4 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name UseTPMPIN -ErrorAction SilentlyContinue|Select-Object -ExpandProperty UseTPMPIN
$requireadditionalauth5 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name UseAdvancedStartup -ErrorAction SilentlyContinue|Select-Object -ExpandProperty UseAdvancedStartup 
$requireadditionalauth6 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name EnableBDEWithNoTPM -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EnableBDEWithNoTPM



if ($requireadditionalauth1 -eq $null -and $requireadditionalauth2 -eq $null -and $requireadditionalauth3 -eq $null -and $requireadditionalauth4 -eq $null  -and $requireadditionalauth5 -eq $null -and $requireadditionalauth6 -eq $null)
{
outputanswer -answer "Require additional authentication at startup is not configured" -color Yellow
}
else
{
    if ($requireadditionalauth1 -eq '0')
{
outputanswer -answer "Configure TPM Startup is set to Do Not Allow TPM" -color Green
}
else
{
outputanswer -answer "Configure TPM Startup is set to a non compliant setting" -color Red
}
    if ($requireadditionalauth2 -eq '2')
{
outputanswer -answer "Configure TPM Startup key is set to Allow Startup Key With TPM" -color Green
}
else
{
outputanswer -answer "Configure TPM Startup key is set to a non compliant setting" -color Red
}
    if ($requireadditionalauth3 -eq '2')
{
outputanswer -answer "Configure TPM Startup key and pin is set to Allow Startup Key and pin With TPM" -color Green
}
else
{
outputanswer -answer "Configure TPM Startup key is set to a non compliant setting" -color Red
}
    if ($requireadditionalauth4 -eq '2')
{
outputanswer -answer "Configure TPM Startup pin is set to Allow Startup pin With TPM" -color Green
}
else
{
outputanswer -answer "Configure TPM Startup key is set to a non compliant setting" -color Red
}
    if ($requireadditionalauth6 -eq '1')
{
outputanswer -answer "Allow Bitlocker without a compatible TPM (require key and pin) is enabled" -color Green
}
else
{
outputanswer -answer "Allow Bitlocker without a compatible TPM (require key and pin) is disabled" -color Red
}
}

$TPMAutoReseal = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\FVE\'  -Name TPMAutoReseal -ErrorAction SilentlyContinue|Select-Object -ExpandProperty TPMAutoReseal
if ( $TPMAutoReseal -eq $null)
{
outputanswer -answer "Reset platform validation data after BitLocker recovery is not configured" -color Yellow
}
   elseif ( $TPMAutoReseal  -eq  '1' )
{
outputanswer -answer "Reset platform validation data after BitLocker recovery is enabled" -color Green
}
  elseif ( $TPMAutoReseal  -eq  '0' )
{
outputanswer -answer "Reset platform validation data after BitLocker recovery is disabled" -color Red
}
  else
{
outputanswer -answer "Reset platform validation data after BitLocker recovery is set to an unknown setting" -color Red
}

#This check could be improved by printing out the possible configuration settings if choose how Bitlocker-protected removable drives is configured
$bitlockerrmrecovery1 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name RDVRecovery -ErrorAction SilentlyContinue|Select-Object -ExpandProperty RDVRecovery
$bitlockerrmrecovery2 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name RDVRecoveryPassword -ErrorAction SilentlyContinue|Select-Object -ExpandProperty RDVRecoveryPassword
$bitlockerrmrecovery3 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name RDVRecoveryKey -ErrorAction SilentlyContinue|Select-Object -ExpandProperty RDVRecoveryKey
$bitlockerrmrecovery4 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name RDVManageDRA -ErrorAction SilentlyContinue|Select-Object -ExpandProperty RDVManageDRA
$bitlockerrmrecovery5 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name RDVHideRecoveryPage -ErrorAction SilentlyContinue|Select-Object -ExpandProperty RDVHideRecoveryPage
$bitlockerrmrecovery6 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name RDVActiveDirectoryBackup -ErrorAction SilentlyContinue|Select-Object -ExpandProperty RDVActiveDirectoryBackup
$bitlockerrmrecovery7 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name RDVActiveDirectoryInfoToStore -ErrorAction SilentlyContinue|Select-Object -ExpandProperty RDVActiveDirectoryInfoToStore

if ($bitlockerrmrecovery1 -eq $null -and $bitlockerrmrecovery2 -eq $null -and $bitlockerrmrecovery3 -eq $null -and $bitlockerrmrecovery4 -eq $null -and $bitlockerrmrecovery5 -eq $null -and $bitlockerrmrecovery6 -eq $null -and $bitlockerrmrecovery7 -eq $null)
{
outputanswer -answer "Choose how BitLocker-protected removable drives can be recovered is not configured or disabled" -color Red
}
    else
{
outputanswer -answer "Choose how BitLocker-protected removable drives can be recovered has been configured" -color Green
}



$bitlockerrmpassuse1 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name RDVEnforcePassphrase -ErrorAction SilentlyContinue|Select-Object -ExpandProperty RDVEnforcePassphrase
$bitlockerrmpassuse2 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name RDVPassphrase -ErrorAction SilentlyContinue|Select-Object -ExpandProperty RDVPassphrase
$bitlockerrmpassuse3 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name RDVPassphraseComplexity -ErrorAction SilentlyContinue|Select-Object -ExpandProperty RDVPassphraseComplexity
$bitlockerrmpassuse4 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name RDVPassphraseLength -ErrorAction SilentlyContinue|Select-Object -ExpandProperty RDVPassphraseLength

if ($bitlockerrmpassuse1 -eq $null -and $bitlockerrmpassuse2 -eq $null -and $bitlockerrmpassuse3 -eq $null -and $bitlockerrmpassuse4 -eq $null)
{
outputanswer -answer "Configure use of passwords for removable drives is not configured or disabled" -color Red
}
    else
{
outputanswer -answer "Configure use of passwords for removable drives has been configured" -color Green

if ($bitlockerrmpassuse1 -eq '1')
{
outputanswer -answer "Passwords required for removable drives is enabled" -color Green
}
elseif ($bitlockerrmpassuse1 -eq '0')
{
outputanswer -answer "Passwords required for removable drives is disabled" -color Red
}

if ($bitlockerrmpassuse3 -eq '2')
{
outputanswer -answer "Password complexity for removable drives is set to Allow Passphrase Complexity, the compliant setting is Require Passphrase Complexity" -color Red
}
elseif ($bitlockerrmpassuse3 -eq '0')
{
outputanswer -answer "Password complexity for removable drives is set to Do Not Allow Passphrase Complexity, the compliant setting is Require Passphrase Complexity" -color Red
}
elseif ($bitlockerrmpassuse3 -eq '1')
{
outputanswer -answer "Password complexity for removable drives is set to Require Passphrase Complexity" -color Green
}

if ($bitlockerrmpassuse4 -le '9')
{
outputanswer -answer "Bitlocker Minimum passphrase length is set to $bitlockerrmpassuse4 which is less than the minimum requirement of 10 characters" -color Red
}
elseif ($bitlockerrmpassuse4 -gt '9')
{
outputanswer -answer "Bitlocker Minimum passphrase length is set to $bitlockerrmpassuse4 which is compliant" -color Green
}
else
{
outputanswer -answer "Bitlocker minimum passphrase length is set to an unknown setting"
}
}

$bitlockerrmconf1 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name RDVAllowBDE -ErrorAction SilentlyContinue|Select-Object -ExpandProperty RDVAllowBDE
$bitlockerrmconf2 = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE" -Name RDVConfigureBDE -ErrorAction SilentlyContinue|Select-Object -ExpandProperty RDVConfigureBDE

if ($bitlockerrmconf1 -eq $null -and $bitlockerrmconf2 -eq $null)
{
outputanswer -answer "Control use of bitlocker on removable drives is not configured" -color Yellow
}
    elseif ($bitlockerrmconf1 -eq '0' -and $bitlockerrmconf2 -eq '0')
{
outputanswer -answer "Control use of bitlocker on removable drives is disabled" -color Red
}
elseif ($bitlockerrmconf2 -eq '1')
{
outputanswer -answer "Control use of bitlocker on removable drives is enabled" -color Green



if ($bitlockerrmconf1 -eq '1')
{
outputanswer -answer "Allow users to apply bitlocker protection on removable data drives is enabled" -color Green
}
elseif ($bitlockerrmconf1 -eq '0')
{
outputanswer -answer "Allow users to apply bitlocker protection on removable data drives is disabled" -color Red
}
}

if ($bitlockerrmconf1 -eq '1')
{
outputanswer -answer "Passwords required for removable drives is enabled" -color Green
}
elseif ($bitlockerrmconf1 -eq '0')
{
outputanswer -answer "Passwords required for removable drives is disabled" -color Red
}

$RDVDenyWriteAccess = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Policies\Microsoft\FVE\'  -Name RDVDenyWriteAccess -ErrorAction SilentlyContinue|Select-Object -ExpandProperty RDVDenyWriteAccess
if ( $RDVDenyWriteAccess -eq $null)
{
outputanswer -answer "Deny write access to removable drives not protected by BitLocker is not configured" -color Yellow
}
   elseif ( $RDVDenyWriteAccess  -eq  '1' )
{
outputanswer -answer "Deny write access to removable drives not protected by BitLocker is enabled" -color Green
}
  elseif ( $RDVDenyWriteAccess  -eq  '0' )
{
outputanswer -answer "Deny write access to removable drives not protected by BitLocker is disabled" -color Red
}
  else
{
outputanswer -answer "Deny write access to removable drives not protected by BitLocker is set to an unknown setting" -color Red
}

$RDVEncryptionType = Get-ItemProperty -Path  'Registry::HKLM\SOFTWARE\Policies\Microsoft\FVE\RDVEncryptionType HKLM\SOFTWARE\Policies\Microsoft\FVE\'  -Name  RDVEncryptionType -ErrorAction SilentlyContinue|Select-Object -ExpandProperty RDVEncryptionType
if ( $RDVEncryptionType -eq $null)
{
outputanswer -answer "Enforce drive encryption type on removable data drive  is not configured" -color Yellow
}
   elseif ( $RDVEncryptionType  -eq  '1' )
{
outputanswer -answer "Enforce drive encryption type on removable data drive  is enabled with full encryption" -color Green
}
  elseif ( $RDVEncryptionType  -eq  '2' )
{
outputanswer -answer "Enforce drive encryption type on removable data drive  is enabled with Used Space Only encryption" -color Red
}
  else
{
outputanswer -answer "Enforce drive encryption type on removable data drive  is set to Allow user to choose" -color Red
}

outputanswer -answer "INSTALLING APPLICATIONS" -color White

$EnableSmartScreen = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System\'  -Name EnableSmartScreen -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EnableSmartScreen
if ( $EnableSmartScreen -eq $null)
{
outputanswer -answer "Configure Windows Defender SmartScreen is not configured" -color Yellow
}
   elseif ( $EnableSmartScreen  -eq  '1' )
{
outputanswer -answer "Configure Windows Defender SmartScreen is enabled" -color Green

$ShellSmartScreenLevel = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System\'  -Name ShellSmartScreenLevel -ErrorAction SilentlyContinue|Select-Object -ExpandProperty ShellSmartScreenLevel
if ( $ShellSmartScreenLevel -eq $null)
{
outputanswer -answer "SmartScreen is not configured" -color Yellow
}
   elseif ( $ShellSmartScreenLevel  -eq  'Block' )
{
outputanswer -answer "Windows Defender SmartScreen is set to Warn and Prevent Bypass" -color Green
}
  elseif ( $ShellSmartScreenLevel -eq  'Warn' )
{
outputanswer -answer "SmartScreen is set to Warn" -color Red
}
  else
{
outputanswer -answer "SmartScreen is set to an unknown setting" -color Red
}


}
  elseif ( $EnableSmartScreen  -eq  '0' )
{
outputanswer -answer "Configure Windows Defender SmartScreen is disabled" -color Red
}
  else
{
outputanswer -answer "Configure Windows Defender SmartScreen is set to an unknown setting" -color Red
}

$EnableUserControl = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer\'  -Name EnableUserControl -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EnableUserControl
if ( $EnableUserControl -eq $null)
{
outputanswer -answer "Allow user control over installs is not configured" -color Yellow
}
   elseif ( $EnableUserControl  -eq  '0' )
{
outputanswer -answer "Allow user control over installs is disabled" -color Green
}
  elseif ( $EnableUserControl  -eq  '1' )
{
outputanswer -answer "Allow user control over installs is enabled" -color Red
}
  else
{
outputanswer -answer "Allow user control over installs is set to an unknown setting" -color Red
}

$AlwaysInstallElevated = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer\'  -Name AlwaysInstallElevated -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AlwaysInstallElevated
if ( $AlwaysInstallElevated -eq $null)
{
outputanswer -answer "Always install with elevated privileges is not configured in local machine policy" -color Yellow
}
   elseif ( $AlwaysInstallElevated  -eq  '0' )
{
outputanswer -answer "Always install with elevated privileges is disabled in local machine policy" -color Green
}
  elseif ( $AlwaysInstallElevated  -eq  '1' )
{
outputanswer -answer "Always install with elevated privileges is enabled in local machine policy" -color Red
}
  else
{
outputanswer -answer "Always install with elevated privileges is set to an unknown setting in local machine policy" -color Red
}


$AlwaysInstallElevated1 = Get-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer\'  -Name AlwaysInstallElevated -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AlwaysInstallElevated
if ( $AlwaysInstallElevated1 -eq $null)
{
outputanswer -answer "Always install with elevated privileges is not configured in user policy" -color Yellow
}
   elseif ( $AlwaysInstallElevated1  -eq  '0' )
{
outputanswer -answer "Always install with elevated privileges is disabled in user policy" -color Green
}
  elseif ( $AlwaysInstallElevated1  -eq  '1' )
{
outputanswer -answer "Always install with elevated privileges is enabled in user policy" -color Red
}
  else
{
outputanswer -answer "Always install with elevated privileges is set to an unknown setting in user policy" -color Red
}

outputanswer -answer "INTERNET PRINTING" -color White

$DisableWebPnPDownload = Get-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Printers\'  -Name DisableWebPnPDownload -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableWebPnPDownload
if ( $DisableWebPnPDownload -eq $null)
{
outputanswer -answer "Turn off downloading of print drivers over HTTP is not configured" -color Yellow
}
   elseif ( $DisableWebPnPDownload  -eq  '1' )
{
outputanswer -answer "Turn off downloading of print drivers over HTTP is enabled" -color Green
}
  elseif ( $DisableWebPnPDownload  -eq  '0' )
{
outputanswer -answer "Turn off downloading of print drivers over HTTP is disabled" -color Red
}
  else
{
outputanswer -answer "Turn off downloading of print drivers over HTTP is set to an unknown setting" -color Red
}

$DisableHTTPPrinting = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\'  -Name DisableHTTPPrinting -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableHTTPPrinting
if ( $DisableHTTPPrinting -eq $null)
{
outputanswer -answer "Turn off printing over HTTP is not configured" -color Yellow
}
   elseif ( $DisableHTTPPrinting  -eq  '1' )
{
outputanswer -answer "Turn off printing over HTTP is enabled" -color Green
}
  elseif ( $DisableHTTPPrinting  -eq  '0' )
{
outputanswer -answer "Turn off printing over HTTP is disabled" -color Red
}
  else
{
outputanswer -answer "Turn off printing over HTTP is set to an unknown setting" -color Red
}

outputanswer -answer "LEGACY AND RUN ONCE LISTS" -color White

$UN6ehVpmakAXClE = Get-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'  -Name DisableCurrentUserRun -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableCurrentUserRun
if ( $UN6ehVpmakAXClE -eq $null)
{
outputanswer -answer "Do not process the legacy run list is not configured" -color Yellow
}
   elseif ( $UN6ehVpmakAXClE  -eq  '1' )
{
outputanswer -answer "Do not process the legacy run list is enabled" -color Green
}
  elseif ( $UN6ehVpmakAXClE  -eq  '0' )
{
outputanswer -answer "Do not process the legacy run list is disabled" -color Red
}
  else
{
outputanswer -answer "Do not process the legacy run list is set to an unknown setting" -color Red
}

$keAWhyT9w1aMjVE = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'  -Name DisableLocalMachineRunOnce -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableLocalMachineRunOnce
if ( $keAWhyT9w1aMjVE -eq $null)
{
outputanswer -answer "Do not process the run once list is not configured" -color Yellow
}
   elseif ( $keAWhyT9w1aMjVE  -eq  '1' )
{
outputanswer -answer "Do not process the run once list is enabled" -color Green
}
  elseif ( $keAWhyT9w1aMjVE  -eq  '0' )
{
outputanswer -answer "Do not process the run once list is disabled" -color Red
}
  else
{
outputanswer -answer "Do not process the run once list is set to an unknown setting" -color Red
}

foreach($_ in 1..50)
{
    $runkeys = Get-ItemProperty -Path "Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\" -Name $_ -ErrorAction SilentlyContinue|Select-Object -ExpandProperty $_
    If ($runkeys -ne $null)
    {
        outputanswer -answer "The following run key is set: $runkeys" -color Red

    }
}
foreach($_ in 1..50)
{
    $runkeys2 = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\" -Name $_ -ErrorAction SilentlyContinue|Select-Object -ExpandProperty $_
    If ($runkeys2 -ne $null)
    {
        outputanswer -answer "The following run key is set: $runkeys2" -color Red

    }
}
If ($runkeys -eq $null -and $runkeys2 -eq $runkeys2)
{

    outputanswer -answer "Run These Programs At User Logon is disabled, no run keys are set" -color Green
}



outputanswer -answer "MICROSOFT ACCOUNTS" -color White

$7u6bAiHSjEa1L9F = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\MicrosoftAccount\'  -Name DisableUserAuth -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableUserAuth
if ( $7u6bAiHSjEa1L9F -eq $null)
{
outputanswer -answer "Block all consumer Microsoft account user authentication is not configured" -color Yellow
}
   elseif ( $7u6bAiHSjEa1L9F  -eq  '1' )
{
outputanswer -answer "Block all consumer Microsoft account user authentication is enabled" -color Green
}
  elseif ( $7u6bAiHSjEa1L9F  -eq  '0' )
{
outputanswer -answer "Block all consumer Microsoft account user authentication is disabled" -color Red
}
  else
{
outputanswer -answer "Block all consumer Microsoft account user authentication is set to an unknown setting" -color Red
}

$q69ocA0RwE3KT7D = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\OneDrive\'  -Name DisableFileSyncNGSC -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableFileSyncNGSC
if ( $q69ocA0RwE3KT7D -eq $null)
{
outputanswer -answer "Prevent the usage of OneDrive for file storage is not configured" -color Yellow
}
   elseif ( $q69ocA0RwE3KT7D  -eq  '1' )
{
outputanswer -answer "Prevent the usage of OneDrive for file storage is enabled" -color Green
}
  elseif ( $q69ocA0RwE3KT7D  -eq  '0' )
{
outputanswer -answer "Prevent the usage of OneDrive for file storage is disabled" -color Red
}
  else
{
outputanswer -answer "Prevent the usage of OneDrive for file storage is set to an unknown setting" -color Red
}

outputanswer -answer "This setting is unable to be checked with PowerShell as it is a registry key, please manually check Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options" -color Cyan

outputanswer -answer "MSS SETTINGS" -color White

$fYg2RApMS8B3z4o = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\'  -Name DisableIPSourceRouting -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableIPSourceRouting
if ( $fYg2RApMS8B3z4o -eq $null)
{
outputanswer -answer "MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing) is not configured" -color Yellow
}
   elseif ( $fYg2RApMS8B3z4o  -eq  '2' )
{
outputanswer -answer "MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing) is set to Highest protection, source routing is completely disabled " -color Green
}
  elseif ( $fYg2RApMS8B3z4o  -eq  '0' -or $fYg2RApMS8B3z4o  -eq  '1' )
{
outputanswer -answer "MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing) is configured incorrectly" -color Red
}
  else
{
outputanswer -answer "MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing) is set to an unknown setting" -color Red
}

$Yd9tFn6Q4UEIR8a = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters\'  -Name DisableIPSourceRouting -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableIPSourceRouting
if ( $Yd9tFn6Q4UEIR8a -eq $null)
{
outputanswer -answer "MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing) is not configured" -color Yellow
}
   elseif ( $Yd9tFn6Q4UEIR8a  -eq  '2' )
{
outputanswer -answer "MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing) is set to Highest protection, source routing is completely disabled " -color Green
}
  elseif ( $Yd9tFn6Q4UEIR8a  -eq  '0' -or $Yd9tFn6Q4UEIR8a  -eq  '1' )
{
outputanswer -answer "MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing) is configured incorrectly" -color Red
}
  else
{
outputanswer -answer "MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing) is set to an unknown setting" -color Red
}

$ZqEKJnRyWQruTsH = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\'  -Name EnableICMPRedirect -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EnableICMPRedirect
if ( $ZqEKJnRyWQruTsH -eq $null)
{
outputanswer -answer "MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes is not configured" -color Yellow
}
   elseif ( $ZqEKJnRyWQruTsH  -eq  '0' )
{
outputanswer -answer "MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes is disabled" -color Green
}
  elseif ( $ZqEKJnRyWQruTsH  -eq  '1' )
{
outputanswer -answer "MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes is enabled" -color Red
}
  else
{
outputanswer -answer "MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes is set to an unknown setting" -color Red
}

$JKYyPoEx63dhjZr = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netbt\Parameters\'  -Name NoNameReleaseOnDemand -ErrorAction SilentlyContinue|Select-Object -ExpandProperty NoNameReleaseOnDemand
if ( $JKYyPoEx63dhjZr -eq $null)
{
outputanswer -answer "MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers is not configured" -color Yellow
}
   elseif ( $JKYyPoEx63dhjZr  -eq  '1' )
{
outputanswer -answer "MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers is enabled" -color Green
}
  elseif ( $JKYyPoEx63dhjZr  -eq  '0' )
{
outputanswer -answer "MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers is disabled" -color Red
}
  else
{
outputanswer -answer "MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers is set to an unknown setting" -color Red
}

outputanswer -answer "NETBIOS OVER TCP/IP" -color White

$servicenetbt = get-service netbt

if ($servicenetbt.Status -eq 'Running')
{
    outputanswer -answer "NetBIOS Over TCP/IP service is running, NetBIOS over TCP/IP is likely enabled" -color Red
}
elseif ($servicenetbt.Status -eq 'Disabled')
{
    outputanswer -answer "NetBIOS Over TCP/IP service is disabled, NetBIOS over TCP/IP is not running" -color Green
}
elseif ($servicenetbt.Status -eq 'Stopped')
{
    outputanswer -answer "NetBIOS Over TCP/IP service is stopped but not disabled" -color Red
}
else
{
    outputanswer -answer "NetBIOS Over TCP/IP service status was unable to be determined" -color Yellow
}



outputanswer -answer "NETWORK AUTHENTICATION" -color White

$encryptiontypeskerb = Get-ItemProperty -Path  'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\'  -Name SupportedEncryptionTypes -ErrorAction SilentlyContinue|Select-Object -ExpandProperty SupportedEncryptionTypes
if ( $encryptiontypeskerb -eq $null)
{
outputanswer -answer "Network security: Configure encryption types allowed for Kerberos is not configured" -color Yellow
}
   elseif ( $encryptiontypeskerb  -eq  '24' )
{
outputanswer -answer "Network security: Configure encryption types allowed for Kerberos is set to AES128_HMAC_SHA1 and AES256_HMAC_SHA1" -color Green
}
  else
{
outputanswer -answer "Network security: Configure encryption types allowed for Kerberos is configured with a non-compliant setting, it must be set to allow only AES128_HMAC_SHA1 and AES256_HMAC_SHA1" -color Red
}


$LMCompatibilityLevel = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\'  -Name LMCompatibilityLevel -ErrorAction SilentlyContinue|Select-Object -ExpandProperty LMCompatibilityLevel
if ( $LMCompatibilityLevel -eq $null)
{
outputanswer -answer "Network security: LAN Manager authentication level is not configured" -color Yellow
}
   elseif ( $LMCompatibilityLevel  -eq  '5' )
{
outputanswer -answer "Network security: LAN Manager authentication level is set to Send NTLMv2 response only & refuse LM & NTLM" -color Green
}
  else
{
outputanswer -answer "Network security: LAN Manager authentication level is configured with a non-compliant setting, it must be set to Send NTLMv2 response only & refuse LM & NTLM" -color Red
}

$minsesssecclient = Get-ItemProperty -Path  'Registry::HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\'  -Name NTLMMinClientSec -ErrorAction SilentlyContinue|Select-Object -ExpandProperty NTLMMinClientSec
if ( $minsesssecclient -eq $null)
{
outputanswer -answer "Network security: Minimum session security for NTLM SSP based (including secure RPC) clients is not configured" -color Yellow
}
   elseif ( $minsesssecclient  -eq  '537395200' )
{
outputanswer -answer "Network security: Minimum session security for NTLM SSP based (including secure RPC) clients is set to Require NTLMv2 session security & Require 128-bit encryption" -color Green
}
  else
{
outputanswer -answer "Network security: Minimum session security for NTLM SSP based (including secure RPC) clients is configured with a non-compliant setting, it must be set to Require NTLMv2 session security and Require 128-bit encryption" -color Red
}

$minsesssecserver = Get-ItemProperty -Path  'Registry::HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\'  -Name NTLMMinServerSec -ErrorAction SilentlyContinue|Select-Object -ExpandProperty NTLMMinServerSec
if ( $minsesssecserver -eq $null)
{
outputanswer -answer "Network security: Minimum session security for NTLM SSP based (including secure RPC) servers is not configured" -color Yellow
}
   elseif ( $minsesssecserver  -eq  '537395200' )
{
outputanswer -answer "Network security: Minimum session security for NTLM SSP based (including secure RPC) servers is set to Require NTLMv2 session security and Require 128-bit encryption" -color Green
}
  else
{
outputanswer -answer "Network security: Minimum session security for NTLM SSP based (including secure RPC) servers is configured with a non-compliant setting, it must be set to Require NTLMv2 session security and Require 128-bit encryption" -color Red
}

outputanswer -answer "NOLM HASH POLICY" -color White

$noLMhash = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\'  -Name noLMHash -ErrorAction SilentlyContinue|Select-Object -ExpandProperty noLMHash

if ( $noLMhash -eq $null)

{
outputanswer -answer "Network security: Do not store LAN Manager hash value on next password change is not configured" -color Yellow
}
   
elseif ( $noLMhash  -eq  '1' )

{
outputanswer -answer "Network security: Do not store LAN Manager hash value on next password change is enabled" -color Green
}
  
elseif ( $noLMhash  -eq  '0' )

{
outputanswer -answer "Network security: Do not store LAN Manager hash value on next password change is disabled" -color Red
}
  
else
{
outputanswer -answer "Network security: Do not store LAN Manager hash value on next password change is set to an unknown setting" -color Red
}



outputanswer -answer "OPERATING SYSTEM FUNCTIONALITY" -color White

$numberofservices = (Get-Service | Measure-Object).Count
$numberofdisabledservices = (Get-WmiObject Win32_Service | Where-Object {$_.StartMode -eq 'Disabled'}).count
If ($numberofdisabledservices -eq $null)
{
outputanswer -answer "The number of disabled services was unable to be determined" -color Yellow
}
elseif ($numberofdisabledservices -le '30')
{
outputanswer -answer "There are $numberofservices services present on this machine, however only $numberofdisabledservices have been disabled. This indicates that no functionality reduction, or a minimal level of functionality reduction has been applied to this machine." -color Red
}
elseif($numberofdisabledservices -gt '30')
{
outputanswer -answer "There are $numberofservices services present on this machine and $numberofdisabledservices have been disabled. This incidicates that reduction in operating system functionality has likely been performed." -color Green
}


outputanswer -answer "POWER MANAGEMENT" -color White

$p86A1e2VhcGQKas = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab\'  -Name DCSettingIndex -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DCSettingIndex
if ( $p86A1e2VhcGQKas -eq $null)
{
outputanswer -answer "Allow standby states (S1-S3) when sleeping (on battery) is not configured" -color Yellow
}
   elseif ( $p86A1e2VhcGQKas  -eq  '0' )
{
outputanswer -answer "Allow standby states (S1-S3) when sleeping (on battery) is disabled" -color Green
}
  elseif ( $p86A1e2VhcGQKas  -eq  '1' )
{
outputanswer -answer "Allow standby states (S1-S3) when sleeping (on battery) is enabled" -color Red
}
  else
{
outputanswer -answer "Allow standby states (S1-S3) when sleeping (on battery) is set to an unknown setting" -color Red
}

$w4PO3v6EaroqgUu = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab\'  -Name ACSettingIndex -ErrorAction SilentlyContinue|Select-Object -ExpandProperty ACSettingIndex
if ( $w4PO3v6EaroqgUu -eq $null)
{
outputanswer -answer "Allow standby states (S1-S3) when sleeping (plugged in) is not configured" -color Yellow
}
   elseif ( $w4PO3v6EaroqgUu  -eq  '0' )
{
outputanswer -answer "Allow standby states (S1-S3) when sleeping (plugged in) is disabled" -color Green
}
  elseif ( $w4PO3v6EaroqgUu  -eq  '1' )
{
outputanswer -answer "Allow standby states (S1-S3) when sleeping (plugged in) is enabled" -color Red
}
  else
{
outputanswer -answer "Allow standby states (S1-S3) when sleeping (plugged in) is set to an unknown setting" -color Red
}


$b9ePm1KdQUNf7tu = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\'  -Name DCSettingIndex -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DCSettingIndex
if ( $b9ePm1KdQUNf7tu -eq $null)
{
outputanswer -answer "Require a password when a computer wakes (on battery) is not configured" -color Yellow
}
   elseif ( $b9ePm1KdQUNf7tu  -eq  '1' )
{
outputanswer -answer "Require a password when a computer wakes (on battery) is enabled" -color Green
}
  elseif ( $b9ePm1KdQUNf7tu  -eq  '0' )
{
outputanswer -answer "Require a password when a computer wakes (on battery) is disabled" -color Red
}
  else
{
outputanswer -answer "Require a password when a computer wakes (on battery) is set to an unknown setting" -color Red
}

$GmlQKPgtw7i91Fx = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\'  -Name ACSettingIndex -ErrorAction SilentlyContinue|Select-Object -ExpandProperty ACSettingIndex
if ( $GmlQKPgtw7i91Fx -eq $null)
{
outputanswer -answer "Require a password when a computer wakes (plugged in) is not configured" -color Yellow
}
   elseif ( $GmlQKPgtw7i91Fx  -eq  '1' )
{
outputanswer -answer "Require a password when a computer wakes (plugged in) is enabled" -color Green
}
  elseif ( $GmlQKPgtw7i91Fx  -eq  '0' )
{
outputanswer -answer "Require a password when a computer wakes (plugged in) is disabled" -color Red
}
  else
{
outputanswer -answer "Require a password when a computer wakes (plugged in) is set to an unknown setting" -color Red
}

$IDxPlKksMyvH3Xd = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\9D7815A6-7EE4-497E-8888-515A05F02364\'  -Name DCSettingIndex -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DCSettingIndex
if ( $IDxPlKksMyvH3Xd -eq $null)
{
outputanswer -answer "Specify the system hibernate timeout (on battery) is not configured" -color Yellow
}
   elseif ( $IDxPlKksMyvH3Xd  -eq  '0' )
{
outputanswer -answer "Specify the system hibernate timeout (on battery) is enabled and set to 0 seconds" -color Green
}
   else
{
outputanswer -answer "Specify the system hibernate timeout (on battery) is set to an unknown setting" -color Red
}

$wqSbpksEI7retQd = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\9D7815A6-7EE4-497E-8888-515A05F02364\'  -Name ACSettingIndex -ErrorAction SilentlyContinue|Select-Object -ExpandProperty ACSettingIndex
if ( $wqSbpksEI7retQd -eq $null)
{
outputanswer -answer "Specify the system hibernate timeout (plugged in) is not configured" -color Yellow
}
   elseif ( $wqSbpksEI7retQd  -eq  '0' )
{
outputanswer -answer "Specify the system hibernate timeout (plugged in) is enabled and set to 0 seconds" -color Green
}
 
  else
{
outputanswer -answer "Specify the system hibernate timeout (plugged in) is set to an unknown setting" -color Red
}

$7QZf3kP5WXARGrt = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\29F6C1DB-86DA-48C5-9FDB-F2B67B1F44DA\'  -Name DCSettingIndex -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DCSettingIndex
if ( $7QZf3kP5WXARGrt -eq $null)
{
outputanswer -answer "Specify the system sleep timeout (on battery) is not configured" -color Yellow
}
   elseif ( $7QZf3kP5WXARGrt  -eq  '0' )
{
outputanswer -answer "Specify the system sleep timeout (on battery) is enabled and set to 0 seconds" -color Green
}
 
  else
{
outputanswer -answer "Specify the system sleep timeout (on battery) is set to an unknown setting" -color Red
}
$r5kh6s8qULHTAfD = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\29F6C1DB-86DA-48C5-9FDB-F2B67B1F44DA\'  -Name ACSettingIndex -ErrorAction SilentlyContinue|Select-Object -ExpandProperty ACSettingIndex
if ( $r5kh6s8qULHTAfD -eq $null)
{
outputanswer -answer "Specify the system sleep timeout (plugged in) is not configured" -color Yellow
}
   elseif ( $r5kh6s8qULHTAfD  -eq  '0' )
{
outputanswer -answer "Specify the system sleep timeout (plugged in) is enabled and set to 0 seconds" -color Green
}
  else
{
outputanswer -answer "Specify the system sleep timeout (plugged in) is set to an unknown setting" -color Red
}

$BMbAhC2V4J0SpLD = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0\'  -Name DCSettingIndex -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DCSettingIndex
if ( $BMbAhC2V4J0SpLD -eq $null)
{
outputanswer -answer "Specify the unattended sleep timeout (on battery) is not configured" -color Yellow
}
   elseif ( $BMbAhC2V4J0SpLD  -eq  '0' )
{
outputanswer -answer "Specify the unattended sleep timeout (on battery) is enabled and set to 0 seconds" -color Green
}
  else
{
outputanswer -answer "Specify the unattended sleep timeout (on battery) is set to an unknown setting" -color Red
}

$4lhpjTxyb92RsKJ = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0\'  -Name ACSettingIndex -ErrorAction SilentlyContinue|Select-Object -ExpandProperty ACSettingIndex
if ( $4lhpjTxyb92RsKJ -eq $null)
{
outputanswer -answer "Specify the unattended sleep timeout (plugged in) is not configured" -color Yellow
}
   elseif ( $4lhpjTxyb92RsKJ  -eq  '0' )
{
outputanswer -answer "Specify the unattended sleep timeout (plugged in) is enabled" -color Green
}
    else
{
outputanswer -answer "Specify the unattended sleep timeout (plugged in) is set to an unknown setting" -color Red
}

$bOEF2189wg3Dhzq = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\94ac6d29-73ce-41a6-809f-6363ba21b47e\'  -Name DCSettingIndex -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DCSettingIndex
if ( $bOEF2189wg3Dhzq -eq $null)
{
outputanswer -answer "Turn off hybrid sleep (on battery) is not configured" -color Yellow
}
   elseif ( $bOEF2189wg3Dhzq  -eq  '0' )
{
outputanswer -answer "Turn off hybrid sleep (on battery) is enabled" -color Green
}
  elseif ( $bOEF2189wg3Dhzq  -eq  '1' )
{
outputanswer -answer "Turn off hybrid sleep (on battery) is disabled" -color Red
}
  else
{
outputanswer -answer "Turn off hybrid sleep (on battery) is set to an unknown setting" -color Red
}

$xcyp78VGK9RYUs0 = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\94ac6d29-73ce-41a6-809f-6363ba21b47e\'  -Name ACSettingIndex -ErrorAction SilentlyContinue|Select-Object -ExpandProperty ACSettingIndex
if ( $xcyp78VGK9RYUs0 -eq $null)
{
outputanswer -answer "Turn off hybrid sleep (plugged in) is not configured" -color Yellow
}
   elseif ( $xcyp78VGK9RYUs0  -eq  '0' )
{
outputanswer -answer "Turn off hybrid sleep (plugged in) is enabled" -color Green
}
  elseif ( $xcyp78VGK9RYUs0  -eq  '1' )
{
outputanswer -answer "Turn off hybrid sleep (plugged in) is disabled" -color Red
}
  else
{
outputanswer -answer "Turn off hybrid sleep (plugged in) is set to an unknown setting" -color Red
}

$LXGISnrDvyTAdjE = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer\'  -Name ShowHibernateOption -ErrorAction SilentlyContinue|Select-Object -ExpandProperty ShowHibernateOption
if ( $LXGISnrDvyTAdjE -eq $null)
{
outputanswer -answer "Show hibernate in the power options menu is not configured" -color Yellow
}
   elseif ( $LXGISnrDvyTAdjE  -eq  '0' )
{
outputanswer -answer "Show hibernate in the power options menu is disabled" -color Green
}
  elseif ( $LXGISnrDvyTAdjE  -eq  '1' )
{
outputanswer -answer "Show hibernate in the power options menu is enabled" -color Red
}
  else
{
outputanswer -answer "Show hibernate in the power options menu is set to an unknown setting" -color Red
}

$JwmcB8OLGS0loNP = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer\'  -Name ShowSleepOption -ErrorAction SilentlyContinue|Select-Object -ExpandProperty ShowSleepOption
if ( $JwmcB8OLGS0loNP -eq $null)
{
outputanswer -answer "Show sleep in the power options menu is not configured" -color Yellow
}
   elseif ( $JwmcB8OLGS0loNP  -eq  '0' )
{
outputanswer -answer "Show sleep in the power options menu is disabled" -color Green
}
  elseif ( $JwmcB8OLGS0loNP  -eq  '1' )
{
outputanswer -answer "Show sleep in the power options menu is enabled" -color Red
}
  else
{
outputanswer -answer "Show sleep in the power options menu is set to an unknown setting" -color Red
}

outputanswer -answer "POWERSHELL" -color White

$LMCJtZgR8FhxmbGke = Get-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EnableScriptBlockLogging
$UPCJtZgR8FhxmbGke = Get-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EnableScriptBlockLogging
if ( $LMCJtZgR8FhxmbGke -eq $null -and  $UPCJtZgR8FhxmbGke -eq $null)
{
outputanswer -answer "Turn on PowerShell Script Block Logging is not configured" -color Yellow
}
if ( $LMCJtZgR8FhxmbGke  -eq '1' )
{
outputanswer -answer "Turn on PowerShell Script Block Logging is enabled in Local Machine GP" -color Green
}
if ( $LMCJtZgR8FhxmbGke  -eq '0' )
{
outputanswer -answer "Turn on PowerShell Script Block Logging is disabled in Local Machine GP" -color Red
}
if ( $UPCJtZgR8FhxmbGke  -eq  '1' )
{
outputanswer -answer "Turn on PowerShell Script Block Logging is enabled in User GP" -color Green
}
if ( $UPCJtZgR8FhxmbGke  -eq  '0' )
{
outputanswer -answer "Turn on PowerShell Script Block Logging is disabled in User GP" -color Red
}

$LMCJtZgR8FhxmbGked = Get-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\' -Name EnableScriptBlockInvocationLogging -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EnableScriptBlockInvocationLogging
$UPCJtZgR8FhxmbGked = Get-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\' -Name EnableScriptBlockInvocationLogging -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EnableScriptBlockInvocationLogging
if ( $LMCJtZgR8FhxmbGked -eq $null -and  $UPCJtZgR8FhxmbGked -eq $null)
{
outputanswer -answer "Turn on PowerShell Script Block Invocation Logging is not configured" -color Yellow
}
if ( $LMCJtZgR8FhxmbGked  -eq '1' )
{
outputanswer -answer "Turn on PowerShell Script Block Invocation Logging is enabled in Local Machine GP" -color Green
}
if ( $LMCJtZgR8FhxmbGked  -eq '0' )
{
outputanswer -answer "Turn on PowerShell Script Block Invocation Logging is disabled in Local Machine GP" -color Red
}
if ( $UPCJtZgR8FhxmbGked  -eq  '1' )
{
outputanswer -answer "Turn on PowerShell Script Block Invocation Logging is enabled in User GP" -color Green
}
if ( $UPCJtZgR8FhxmbGked  -eq  '0' )
{
outputanswer -answer "Turn on PowerShell Script Block Invocation Logging is disabled in User GP" -color Red
}

$LMbMRxhAX7jTCJI2S = Get-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\PowerShell\' -Name EnableScripts -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EnableScripts
$UPbMRxhAX7jTCJI2S = Get-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\PowerShell\' -Name EnableScripts -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EnableScripts
if ( $LMbMRxhAX7jTCJI2S -eq $null -and  $UPbMRxhAX7jTCJI2S -eq $null)
{
outputanswer -answer "Turn on Script Execution is not configured" -color Yellow
}
if ( $LMbMRxhAX7jTCJI2S  -eq '1' )
{
outputanswer -answer "Turn on Script Execution is enabled in Local Machine GP" -color Green
}
if ( $LMbMRxhAX7jTCJI2S  -eq '0' )
{
outputanswer -answer "Turn on Script Execution is disabled in Local Machine GP" -color Red
}
if ( $UPbMRxhAX7jTCJI2S  -eq  '1' )
{
outputanswer -answer "Turn on Script Execution is enabled in User GP" -color Green
}
if ( $UPbMRxhAX7jTCJI2S  -eq  '0' )
{
outputanswer -answer "Turn on Script Execution is disabled in User GP" -color Red
}


$LMbMRxhAX7jTCJI2 = Get-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\PowerShell\' -Name ExecutionPolicy -ErrorAction SilentlyContinue|Select-Object -ExpandProperty ExecutionPolicy
$UPbMRxhAX7jTCJI2 = Get-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\PowerShell\' -Name ExecutionPolicy -ErrorAction SilentlyContinue|Select-Object -ExpandProperty ExecutionPolicy
if ( $LMbMRxhAX7jTCJI2 -eq $null -and  $UPbMRxhAX7jTCJI2S -eq $null)
{
outputanswer -answer "Script Execution is not configured" -color Yellow
}
if ( $LMbMRxhAX7jTCJI2  -eq '0' )
{
outputanswer -answer "Allow only signed powershell scripts is enabled in Local Machine GP" -color Green
}
if ( $LMbMRxhAX7jTCJI2  -eq '1' -or $LMbMRxhAX7jTCJI2  -eq '2' )
{
outputanswer -answer "Powershell scripts are set to allow all scripts or allow local scripts and remote signed scripts in Local Machine GP" -color Red
}
if ( $UPbMRxhAX7jTCJI2  -eq  '0' )
{
outputanswer -answer "Allow only signed powershell scripts is enabled in User GP" -color Green
}
if ( $UPbMRxhAX7jTCJI2  -eq '1' -or $UPbMRxhAX7jTCJI2  -eq '2')
{
outputanswer -answer "Powershell scripts are set to allow all scripts or allow local scripts and remote signed scripts in User GP" -color Red
}


outputanswer -answer "REGISTRY EDITING TOOLS" -color White

$ne3X0uL4lhqB1Ga = Get-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System\'  -Name DisableRegistryTools -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableRegistryTools
if ( $ne3X0uL4lhqB1Ga -eq $null)
{
outputanswer -answer "Prevent access to registry editing tools is not configured" -color Yellow
}
   elseif ( $ne3X0uL4lhqB1Ga  -eq  '2' )
{
outputanswer -answer "Prevent access to registry editing tools is enabled" -color Green
}
  elseif ( $ne3X0uL4lhqB1Ga  -eq  '1' )
{
outputanswer -answer "Prevent access to registry editing tools is disabled" -color Red
}
  else
{
outputanswer -answer "Prevent access to registry editing tools is set to an unknown setting" -color Red
}

outputanswer -answer "REMOTE ASSISTANCE" -color White

$4KQi6CmJpGgqVAs = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\policies\Microsoft\Windows NT\Terminal Services\'  -Name fAllowUnsolicited -ErrorAction SilentlyContinue|Select-Object -ExpandProperty fAllowUnsolicited
if ( $4KQi6CmJpGgqVAs -eq $null)
{
outputanswer -answer "Configure Offer Remote Assistance is not configured" -color Yellow
}
   elseif ( $4KQi6CmJpGgqVAs  -eq  '0' )
{
outputanswer -answer "Configure Offer Remote Assistance is disabled" -color Green
}
  elseif ( $4KQi6CmJpGgqVAs  -eq  '1' )
{
outputanswer -answer "Configure Offer Remote Assistance is enabled" -color Red
}
  else
{
outputanswer -answer "Configure Offer Remote Assistance is set to an unknown setting" -color Red
}

$ostWYT0pIug5Qcb = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\policies\Microsoft\Windows NT\Terminal Services\'  -Name fAllowToGetHelp -ErrorAction SilentlyContinue|Select-Object -ExpandProperty fAllowToGetHelp
if ( $ostWYT0pIug5Qcb -eq $null)
{
outputanswer -answer "Configure Solicited Remote Assistance is not configured" -color Yellow
}
   elseif ( $ostWYT0pIug5Qcb  -eq  '0' )
{
outputanswer -answer "Configure Solicited Remote Assistance is disabled" -color Green
}
  elseif ( $ostWYT0pIug5Qcb  -eq  '1' )
{
outputanswer -answer "Configure Solicited Remote Assistance is enabled" -color Red
}
  else
{
outputanswer -answer "Configure Solicited Remote Assistance is set to an unknown setting" -color Red
}

outputanswer -answer "REMOTE DESKTOP SERVICES" -color White

$kQwHe03XYWy17KG = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'  -Name fDenyTSConnections -ErrorAction SilentlyContinue|Select-Object -ExpandProperty fDenyTSConnections
if ( $kQwHe03XYWy17KG -eq $null)
{
outputanswer -answer "Allow users to connect remotely by using Remote Desktop Services is not configured" -color Yellow
}
   elseif ( $kQwHe03XYWy17KG  -eq  '0' )
{
outputanswer -answer "Allow users to connect remotely by using Remote Desktop Services is disabled" -color Green
}
  elseif ( $kQwHe03XYWy17KG  -eq  '1' )
{
outputanswer -answer "Allow users to connect remotely by using Remote Desktop Services is enabled" -color Red
}
  else
{
outputanswer -answer "Allow users to connect remotely by using Remote Desktop Services is set to an unknown setting" -color Red
}

$admins2 = @()
$group2 =[ADSI]"WinNT://localhost/Remote Desktop Users" 
$members2 = @($group2.psbase.Invoke("Members"))
$members2 | foreach {
 $obj2 = new-object psobject -Property @{
 Member = $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
 }
 $admins2 += $obj2
 } 
$resultsrd += $admins2
$members2 = $admins2.Member

If ($members2 -eq $null)
{
outputanswer -answer "No members are allowed to logon through remote desktop services, this setting is compliant" -color Green
}
else
{
outputanswer -answer "There are members allowing remote desktop users to logon locally, these members are: $members2. The compliant setting is to have no members of this group (if remote desktop is not explicity required). If remote desktop is required only 'Remote Desktop Users' should be listed as a member" -color Red
}

outputanswer -answer "Unable to check members of deny logon through remote desktop services at this time please manually check Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny Logon through Remote Desktop Services and ensure 'Administrators' 'Guests' and 'NT Authority\Local Account' are members" -color Cyan

$NQV54zJaxh6nOE0 = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredentialsDelegation\'  -Name AllowProtectedCreds -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AllowProtectedCreds
if ( $NQV54zJaxh6nOE0 -eq $null)
{
outputanswer -answer "Remote host allows delegation of non-exportable credentials is not configured" -color Yellow
}
   elseif ( $NQV54zJaxh6nOE0  -eq  '1' )
{
outputanswer -answer "Remote host allows delegation of non-exportable credentials is enabled" -color Green
}
  elseif ( $NQV54zJaxh6nOE0  -eq  '0' )
{
outputanswer -answer "Remote host allows delegation of non-exportable credentials is disabled" -color Red
}
  else
{
outputanswer -answer "Remote host allows delegation of non-exportable credentials is set to an unknown setting" -color Red
}

$rhnwzd2NLqTAf8J = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'  -Name AuthenticationLevel -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AuthenticationLevel
if ( $rhnwzd2NLqTAf8J -eq $null)
{
outputanswer -answer "Configure server authentication for client is not configured" -color Yellow
}
   elseif ( $rhnwzd2NLqTAf8J  -eq  '1' )
{
outputanswer -answer "Configure server authentication for client is enabled" -color Green
}
  elseif ( $rhnwzd2NLqTAf8J  -eq  '2' -or $rhnwzd2NLqTAf8J  -eq  '0' )
{
outputanswer -answer "Configure server authentication for client is set to a non-compliant setting" -color Red
}
  else
{
outputanswer -answer "Configure server authentication for client is set to an unknown setting" -color Red
}

$USPueEgdnK6yjIL = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'  -Name DisablePasswordSaving -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisablePasswordSaving
if ( $USPueEgdnK6yjIL -eq $null)
{
outputanswer -answer "Do not allow passwords to be saved is not configured" -color Yellow
}
   elseif ( $USPueEgdnK6yjIL  -eq  '1' )
{
outputanswer -answer "Do not allow passwords to be saved is enabled" -color Green
}
  elseif ( $USPueEgdnK6yjIL  -eq  '0' )
{
outputanswer -answer "Do not allow passwords to be saved is disabled" -color Red
}
  else
{
outputanswer -answer "Do not allow passwords to be saved is set to an unknown setting" -color Red
}


$fYIVuDva8ER2A9M = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'  -Name fDisableForcibleLogoff -ErrorAction SilentlyContinue|Select-Object -ExpandProperty fDisableForcibleLogoff
if ( $fYIVuDva8ER2A9M -eq $null)
{
outputanswer -answer "Deny logoff of an administrator logged in to the console session is not configured" -color Yellow
}
   elseif ( $fYIVuDva8ER2A9M  -eq  '1' )
{
outputanswer -answer "Deny logoff of an administrator logged in to the console session is enabled" -color Green
}
  elseif ( $fYIVuDva8ER2A9M  -eq  '0' )
{
outputanswer -answer "Deny logoff of an administrator logged in to the console session is disabled" -color Red
}
  else
{
outputanswer -answer "Deny logoff of an administrator logged in to the console session is set to an unknown setting" -color Red
}

$RWGtm1iw4Pj0Mhs = Get-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'  -Name fDisableClip -ErrorAction SilentlyContinue|Select-Object -ExpandProperty fDisableClip

if ( $RWGtm1iw4Pj0Mhs -eq $null)
{
outputanswer -answer "Do not allow Clipboard redirection is not configured" -color Yellow
}
   elseif ( $RWGtm1iw4Pj0Mhs  -eq  '1' )
{
outputanswer -answer "Do not allow Clipboard redirection is enabled" -color Green
}
  elseif ( $RWGtm1iw4Pj0Mhs  -eq  '0' )
{
outputanswer -answer "Do not allow Clipboard redirection is disabled" -color Red
}
  else
{
outputanswer -answer "Do not allow Clipboard redirection is set to an unknown setting" -color Red
}

$MJ2WdIt7mlhbckR = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'  -Name fDisableCdm -ErrorAction SilentlyContinue|Select-Object -ExpandProperty fDisableCdm
if ( $MJ2WdIt7mlhbckR -eq $null)
{
outputanswer -answer "Do not allow drive redirection is not configured" -color Yellow
}
   elseif ( $MJ2WdIt7mlhbckR  -eq  '1' )
{
outputanswer -answer "Do not allow drive redirection is enabled" -color Green
}
  elseif ( $MJ2WdIt7mlhbckR  -eq  '0' )
{
outputanswer -answer "Do not allow drive redirection is disabled" -color Red
}
  else
{
outputanswer -answer "Do not allow drive redirection is set to an unknown setting" -color Red
}

$lRPQ5MjsugZpCAI = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'  -Name fPromptForPassword -ErrorAction SilentlyContinue|Select-Object -ExpandProperty fPromptForPassword
if ( $lRPQ5MjsugZpCAI -eq $null)
{
outputanswer -answer "Always prompt for password upon connection is not configured" -color Yellow
}
   elseif ( $lRPQ5MjsugZpCAI  -eq  '1' )
{
outputanswer -answer "Always prompt for password upon connection is enabled" -color Green
}
  elseif ( $lRPQ5MjsugZpCAI  -eq  '0' )
{
outputanswer -answer "Always prompt for password upon connection is disabled" -color Red
}
  else
{
outputanswer -answer "Always prompt for password upon connection is set to an unknown setting" -color Red
}

$CPoKihTNYQpqsBz = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'  -Name fWritableTSCCPermTab -ErrorAction SilentlyContinue|Select-Object -ExpandProperty fWritableTSCCPermTab
if ( $CPoKihTNYQpqsBz -eq $null)
{
outputanswer -answer "Do not allow local administrators to customize permissions is not configured" -color Yellow
}
   elseif ( $CPoKihTNYQpqsBz  -eq  '0' )
{
outputanswer -answer "Do not allow local administrators to customize permissions is enabled" -color Green
}
  elseif ( $CPoKihTNYQpqsBz  -eq  '1' )
{
outputanswer -answer "Do not allow local administrators to customize permissions is disabled" -color Red
}
  else
{
outputanswer -answer "Do not allow local administrators to customize permissions is set to an unknown setting" -color Red
}

$k2FQDrJen34MOVg = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'  -Name fEncryptRPCTraffic -ErrorAction SilentlyContinue|Select-Object -ExpandProperty fEncryptRPCTraffic
if ( $k2FQDrJen34MOVg -eq $null)
{
outputanswer -answer "Require secure RPC communication is not configured" -color Yellow
}
   elseif ( $k2FQDrJen34MOVg  -eq  '1' )
{
outputanswer -answer "Require secure RPC communication is enabled" -color Green
}
  elseif ( $k2FQDrJen34MOVg  -eq  '0' )
{
outputanswer -answer "Require secure RPC communication is disabled" -color Red
}
  else
{
outputanswer -answer "Require secure RPC communication is set to an unknown setting" -color Red
}

$ycroPUFjHk1l4aq = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'  -Name SecurityLayer -ErrorAction SilentlyContinue|Select-Object -ExpandProperty SecurityLayer
if ( $ycroPUFjHk1l4aq -eq $null)
{
outputanswer -answer "Require use of specific security layer for remote (RDP) connections is not configured" -color Yellow
}
   elseif ( $ycroPUFjHk1l4aq  -eq  '2' )
{
outputanswer -answer "Require use of specific security layer for remote (RDP) connections is set to SSL" -color Green
}
  elseif ( $ycroPUFjHk1l4aq  -eq  '1' -or $ycroPUFjHk1l4aq  -eq  '0' )
{
outputanswer -answer "Require use of specific security layer for remote (RDP) connections set to Negotiate or RDP" -color Red
}
  else
{
outputanswer -answer "Require use of specific security layer for remote (RDP) connections is set to an unknown setting" -color Red
}

$vYkIVXt8CZfzRT3 = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'  -Name UserAuthentication -ErrorAction SilentlyContinue|Select-Object -ExpandProperty UserAuthentication
if ( $vYkIVXt8CZfzRT3 -eq $null)
{
outputanswer -answer "Require user authentication for remote connections by using Network Level Authentication is not configured" -color Yellow
}
   elseif ( $vYkIVXt8CZfzRT3  -eq  '1' )
{
outputanswer -answer "Require user authentication for remote connections by using Network Level Authentication is enabled" -color Green
}
  elseif ( $vYkIVXt8CZfzRT3  -eq  '0' )
{
outputanswer -answer "Require user authentication for remote connections by using Network Level Authentication is disabled" -color Red
}
  else
{
outputanswer -answer "Require user authentication for remote connections by using Network Level Authentication is set to an unknown setting" -color Red
}

$MXAzBSUFTGujfc1 = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'  -Name MinEncryptionLevel -ErrorAction SilentlyContinue|Select-Object -ExpandProperty MinEncryptionLevel
if ( $MXAzBSUFTGujfc1 -eq $null)
{
outputanswer -answer "Set client connection encryption level is not configured" -color Yellow
}
   elseif ( $MXAzBSUFTGujfc1  -eq  '3' )
{
outputanswer -answer "Set client connection encryption level is set to high" -color Green
}
  elseif ( $MXAzBSUFTGujfc1  -eq  '1' -or $MXAzBSUFTGujfc1  -eq  '2' )
{
outputanswer -answer "Set client connection encryption level is set to client compatible or a low level" -color Red
}
  else
{
outputanswer -answer "Set client connection encryption level is set to an unknown setting" -color Red
}


outputanswer -answer "REMOTE PROCEDURE CALL" -color White

$HWPLG72S8TrAqKk = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc\'  -Name RestrictRemoteClients -ErrorAction SilentlyContinue|Select-Object -ExpandProperty RestrictRemoteClients
if ( $HWPLG72S8TrAqKk -eq $null)
{
outputanswer -answer "Restrict Unauthenticated RPC clients is not configured" -color Yellow
}
   elseif ( $HWPLG72S8TrAqKk  -eq  '1' )
{
outputanswer -answer "Restrict Unauthenticated RPC clients is enabled" -color Green
}
  elseif ( $HWPLG72S8TrAqKk  -eq  '0' -or $HWPLG72S8TrAqKk  -eq  '2'  )
{
outputanswer -answer "Restrict Unauthenticated RPC clients is disabled" -color Red
}
  else
{
outputanswer -answer "Restrict Unauthenticated RPC clients is set to an unknown setting" -color Red
}


outputanswer -answer "REPORTING SYSTEM INFORMATION" -color White

$PNH7sOv6IUqTLd0 = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\'  -Name DisableQueryRemoteServer -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableQueryRemoteServer
if ( $PNH7sOv6IUqTLd0 -eq $null)
{
outputanswer -answer "Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider is not configured" -color Yellow
}
   elseif ( $PNH7sOv6IUqTLd0  -eq  '0' )
{
outputanswer -answer "Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider is disabled" -color Green
}
  elseif ( $PNH7sOv6IUqTLd0  -eq  '1' )
{
outputanswer -answer "Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider is enabled" -color Red
}
  else
{
outputanswer -answer "Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider is set to an unknown setting" -color Red
}

$pB5HU3iuVdShzK9 = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppCompat\'  -Name DisableInventory -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableInventory
if ( $pB5HU3iuVdShzK9 -eq $null)
{
outputanswer -answer "Turn off Inventory Collector is not configured" -color Yellow
}
   elseif ( $pB5HU3iuVdShzK9  -eq  '1' )
{
outputanswer -answer "Turn off Inventory Collector is enabled" -color Green
}
  elseif ( $pB5HU3iuVdShzK9  -eq  '0' )
{
outputanswer -answer "Turn off Inventory Collector is disabled" -color Red
}
  else
{
outputanswer -answer "Turn off Inventory Collector is set to an unknown setting" -color Red
}

$HhF0z6Ccr3LGPxd = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppCompat\'  -Name DisableUAR -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableUAR
if ( $HhF0z6Ccr3LGPxd -eq $null)
{
outputanswer -answer "Turn off Steps Recorder is not configured" -color Yellow
}
   elseif ( $HhF0z6Ccr3LGPxd  -eq  '1' )
{
outputanswer -answer "Turn off Steps Recorder is enabled" -color Green
}
  elseif ( $HhF0z6Ccr3LGPxd  -eq  '0' )
{
outputanswer -answer "Turn off Steps Recorder is disabled" -color Red
}
  else
{
outputanswer -answer "Turn off Steps Recorder is set to an unknown setting" -color Red
}

$LM8KSMxRACOWXwybq = Get-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\DataCollection\' -Name AllowTelemetry -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AllowTelemetry
$UP8KSMxRACOWXwybq = Get-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\DataCollection\' -Name AllowTelemetry -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AllowTelemetry
if ( $LM8KSMxRACOWXwybq -eq $null -and  $UP8KSMxRACOWXwybq -eq $null)
{
outputanswer -answer "Allow Telemetry is not configured" -color Yellow
}
if ( $LM8KSMxRACOWXwybq  -eq '0' )
{
outputanswer -answer "Allow Telemetry is enabled in Local Machine GP" -color Green
}
if ( $LM8KSMxRACOWXwybq  -eq '1' -or $LM8KSMxRACOWXwybq  -eq '2' -or $LM8KSMxRACOWXwybq  -eq '3' )
{
outputanswer -answer "Allow Telemetry is set to a non-compliant setting in Local Machine GP" -color Red
}
if ( $UP8KSMxRACOWXwybq  -eq  '0' )
{
outputanswer -answer "Allow Telemetry is enabled in User GP" -color Green
}
if ( $LM8KSMxRACOWXwybq  -eq '1' -or $LM8KSMxRACOWXwybq  -eq '2' -or $LM8KSMxRACOWXwybq  -eq '3' )
{
outputanswer -answer "Allow Telemetry is set to a non-compliant setting in User GP" -color Red
}


$KVHIZdcponOfwF7 = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\'  -Name CorporateWerServer -ErrorAction SilentlyContinue|Select-Object -ExpandProperty CorporateWerServer
if ( $KVHIZdcponOfwF7 -eq $null)
{
outputanswer -answer "Configure Corporate Windows Error Reporting is not configured" -color Red
}
  else
{
outputanswer -answer "The corporate WER server is configured as $KVHIZdcponOfwF7" -color Green
}

$KVHIZdcponOfwF = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\'  -Name CorporateWerUseSSL -ErrorAction SilentlyContinue|Select-Object -ExpandProperty CorporateWerUseSSL
if ( $KVHIZdcponOfwF -eq $null)
{
outputanswer -answer "Connect using SSL is not configured" -color Yellow
}
   elseif ( $KVHIZdcponOfwF  -eq  '1' )
{
outputanswer -answer "Connect using SSL is enabled" -color Green
}
  elseif ( $KVHIZdcponOfwF  -eq  '0' )
{
outputanswer -answer "Connect using SSL is disabled" -color Red
}

outputanswer -answer "SAFE MODE" -color White


$HhF0z6Ccr3LGPx = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\'  -Name SafeModeBlockNonAdmins -ErrorAction SilentlyContinue|Select-Object -ExpandProperty SafeModeBlockNonAdmins
if ( $HhF0z6Ccr3LGPx -eq $null)
{
outputanswer -answer "Block Non-Administrators in Safe Mode not configured" -color Yellow
}
   elseif ( $HhF0z6Ccr3LGPx  -eq  '1' )
{
outputanswer -answer "Block Non-Administrators in Safe Mode is enabled" -color Green
}
  elseif ( $HhF0z6Ccr3LGPx  -eq  '0' )
{
outputanswer -answer "Block Non-Administrators in Safe Mode is disabled" -color Red
}
  else
{
outputanswer -answer "Block Non-Administrators in Safe Mode is set to an unknown setting" -color Red
}

outputanswer -answer "SECURE CHANNEL COMMUNICATIONS" -color White

$securechannel = Get-ItemProperty -Path "Registry::HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" -Name RequireSignOrSeal -ErrorAction SilentlyContinue|Select-Object -ExpandProperty RequireSignOrSeal

if ($securechannel -eq $null)
{
outputanswer -answer "Domain member: Digitally encrypt or sign secure channel data (always) is not configured" -color Yellow
}
    elseif ($securechannel -eq '0')
    {
        outputanswer -answer "Domain member: Digitally encrypt or sign secure channel data (always) is disabled" -color Red
    }
    elseif  ($securechannel -eq '1')
    {
        outputanswer -answer "Domain member: Digitally encrypt or sign secure channel data (always) is enabled" -color Green
    }
    else
    {
        outputanswer -answer "Domain member: Digitally encrypt or sign secure channel data (always) is set to an unknown setting" -color Red
    }

$securechannel2 = Get-ItemProperty -Path "Registry::HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" -Name SealSecureChannel -ErrorAction SilentlyContinue|Select-Object -ExpandProperty SealSecureChannel

if ($securechannel2 -eq $null)
{
outputanswer -answer "Domain member: Digitally encrypt secure channel data (when possible) is not configured" -color Yellow
}
    elseif ($securechannel2 -eq '0')
    {
        outputanswer -answer "Domain member: Digitally encrypt secure channel data (when possible) is disabled" -color Red
    }
    elseif  ($securechannel2 -eq '1')
    {
        outputanswer -answer "Domain member: Digitally encrypt secure channel data (when possible) is enabled" -color Green
    }
    else
    {
        outputanswer -answer "Domain member: Digitally encrypt secure channel data (when possible)is set to an unknown setting" -color Red
    }

$securechannel3 = Get-ItemProperty -Path "Registry::HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" -Name SignSecureChannel -ErrorAction SilentlyContinue|Select-Object -ExpandProperty SignSecureChannel

if ($securechannel3 -eq $null)
{
outputanswer -answer "Domain member: Digitally sign secure channel data (when possible) is not configured" -color Yellow
}
    elseif ($securechannel3 -eq '0')
    {
        outputanswer -answer "Domain member: Digitally sign secure channel data (when possible) is disabled" -color Red
    }
    elseif  ($securechannel3 -eq '1')
    {
        outputanswer -answer "Domain member: Digitally sign secure channel data (when possible) is enabled" -color Green
    }
    else
    {
        outputanswer -answer "Domain member: Digitally sign secure channel data (when possible) is set to an unknown setting" -color Red
    }

$securechannel4 = Get-ItemProperty -Path "Registry::HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" -Name RequireStrongKey -ErrorAction SilentlyContinue|Select-Object -ExpandProperty RequireStrongKey

if ($securechannel4 -eq $null)
{
outputanswer -answer "Domain member: Require strong (Windows 2000 or later) session key is not configured" -color Yellow
}
    elseif ($securechannel4 -eq '0')
    {
        outputanswer -answer "Domain member: Require strong (Windows 2000 or later) session key is disabled" -color Red
    }
    elseif  ($securechannel4 -eq '1')
    {
        outputanswer -answer "Domain member: Require strong (Windows 2000 or later) session key is enabled" -color Green
    }
    else
    {
        outputanswer -answer "Domain member: Require strong (Windows 2000 or later) session key is set to an unknown setting" -color Red
    }


outputanswer -answer "SECURITY POLICIES" -color White

$ZCprfnJQOVLF4wT = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\wcmsvc\wifinetworkmanager\config\'  -Name AutoConnectAllowedOEM -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AutoConnectAllowedOEM
if ( $ZCprfnJQOVLF4wT -eq $null)
{
outputanswer -answer "Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services is not configured" -color Yellow
}
   elseif ( $ZCprfnJQOVLF4wT  -eq  '0' )
{
outputanswer -answer "Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services is disabled" -color Green
}
  elseif ( $ZCprfnJQOVLF4wT  -eq  '1' )
{
outputanswer -answer "Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services is enabled" -color Red
}
  else
{
outputanswer -answer "Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services is set to an unknown setting" -color Red
}


$x783w1bfW4nNCZV = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent\'  -Name DisableWindowsConsumerFeatures -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableWindowsConsumerFeatures
if ( $x783w1bfW4nNCZV -eq $null)
{
outputanswer -answer "Turn off Microsoft consumer experiences is not configured" -color Yellow
}
   elseif ( $x783w1bfW4nNCZV  -eq  '1' )
{
outputanswer -answer "Turn off Microsoft consumer experiences is enabled" -color Green
}
  elseif ( $x783w1bfW4nNCZV  -eq  '0' )
{
outputanswer -answer "Turn off Microsoft consumer experiences is disabled" -color Red
}
  else
{
outputanswer -answer "Turn off Microsoft consumer experiences is set to an unknown setting" -color Red
}

$PAch3CtoO9Ijfvr = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer\'  -Name NoHeapTerminationOnCorruption -ErrorAction SilentlyContinue|Select-Object -ExpandProperty NoHeapTerminationOnCorruption
if ( $PAch3CtoO9Ijfvr -eq $null)
{
outputanswer -answer "Turn off heap termination on corruption is not configured" -color Yellow
}
   elseif ( $PAch3CtoO9Ijfvr  -eq  '0' )
{
outputanswer -answer "Turn off heap termination on corruption is disabled" -color Green
}
  elseif ( $PAch3CtoO9Ijfvr  -eq  '1' )
{
outputanswer -answer "Turn off heap termination on corruption is enabled" -color Red
}
  else
{
outputanswer -answer "Turn off heap termination on corruption is set to an unknown setting" -color Red
}

$X7bBFV0iTPk6rYj = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'  -Name PreXPSP2ShellProtocolBehavior -ErrorAction SilentlyContinue|Select-Object -ExpandProperty PreXPSP2ShellProtocolBehavior
if ( $X7bBFV0iTPk6rYj -eq $null)
{
outputanswer -answer "Turn off shell protocol protected mode is not configured" -color Yellow
}
   elseif ( $X7bBFV0iTPk6rYj  -eq  '0' )
{
outputanswer -answer "Turn off shell protocol protected mode is disabled" -color Green
}
  elseif ( $X7bBFV0iTPk6rYj  -eq  '1' )
{
outputanswer -answer "Turn off shell protocol protected mode is enabled" -color Red
}
  else
{
outputanswer -answer "Turn off shell protocol protected mode is set to an unknown setting" -color Red
}

$LMwVsYrmNLSvR3156 = Get-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Feeds\' -Name DisableEnclosureDownload -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableEnclosureDownload
$UPwVsYrmNLSvR3156 = Get-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Internet Explorer\Feeds\' -Name DisableEnclosureDownload -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableEnclosureDownload
if ( $LMwVsYrmNLSvR3156 -eq $null -and  $UPwVsYrmNLSvR3156 -eq $null)
{
outputanswer -answer "Prevent downloading of enclosures is not configured" -color Yellow
}
if ( $LMwVsYrmNLSvR3156  -eq '1' )
{
outputanswer -answer "Prevent downloading of enclosures is enabled in Local Machine GP" -color Green
}
if ( $LMwVsYrmNLSvR3156  -eq '0' )
{
outputanswer -answer "Prevent downloading of enclosures is disabled in Local Machine GP" -color Red
}
if ( $UPwVsYrmNLSvR3156  -eq  '1' )
{
outputanswer -answer "Prevent downloading of enclosures is enabled in User GP" -color Green
}
if ( $UPwVsYrmNLSvR3156  -eq  '0' )
{
outputanswer -answer "Prevent downloading of enclosures is disabled in User GP" -color Red
}

$g0OCVPTHarb4FiU = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search\'  -Name AllowIndexingEncryptedStoresOrItems -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AllowIndexingEncryptedStoresOrItems
if ( $g0OCVPTHarb4FiU -eq $null)
{
outputanswer -answer "Allow indexing of encrypted files is not configured" -color Yellow
}
   elseif ( $g0OCVPTHarb4FiU  -eq  '0' )
{
outputanswer -answer "Allow indexing of encrypted files is disabled" -color Green
}
  elseif ( $g0OCVPTHarb4FiU  -eq  '1' )
{
outputanswer -answer "Allow indexing of encrypted files is enabled" -color Red
}
  else
{
outputanswer -answer "Allow indexing of encrypted files is set to an unknown setting" -color Red
}

$OqU8k1BrR0gFnNz = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\GameDVR\'  -Name AllowGameDVR -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AllowGameDVR
if ( $OqU8k1BrR0gFnNz -eq $null)
{
outputanswer -answer "Enables or disables Windows Game Recording and Broadcasting is not configured" -color Yellow
}
   elseif ( $OqU8k1BrR0gFnNz  -eq  '0' )
{
outputanswer -answer "Enables or disables Windows Game Recording and Broadcasting is disabled" -color Green
}
  elseif ( $OqU8k1BrR0gFnNz  -eq  '1' )
{
outputanswer -answer "Enables or disables Windows Game Recording and Broadcasting is enabled" -color Red
}
  else
{
outputanswer -answer "Enables or disables Windows Game Recording and Broadcasting is set to an unknown setting" -color Red
}


$machineaccdisable = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\ -Name DisablePasswordChange -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisablePasswordChange
if ( $machineaccdisable -eq $null)
{
outputanswer -answer "Domain member: Disable machine account password changes is not configured" -color Yellow
}
   elseif ( $machineaccdisable  -eq  '0' )
{
outputanswer -answer "Domain member: Disable machine account password changes is disabled" -color Green
}
  elseif ( $machineaccdisable  -eq  '1' )
{
outputanswer -answer "Domain member: Disable machine account password changes is enabled" -color Red
}
  else
{
outputanswer -answer "Domain member: Disable machine account password changes is set to an unknown setting" -color Red
}


$1AW2Cfp = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\'  -Name MaximumPasswordAge -ErrorAction SilentlyContinue|Select-Object -ExpandProperty MaximumPasswordAge
if ( $1AW2Cfp -eq $null)
{
outputanswer -answer "Domain member: Maximum machine account password age is not configured" -color Yellow
}
   elseif ( $1AW2Cfp  -eq  '30' )
{
outputanswer -answer "Domain member: Maximum machine account password age is set to a compliant setting" -color Green
}
  elseif ( $1AW2Cfp  -lt  '30' )
{
outputanswer -answer "Domain member: Maximum machine account password age is set to $1AW2CfpSKiewv0 which a compliant setting" -color Green
}
  elseif ( $1AW2Cfp  -gt  '30' )
{
outputanswer -answer "Domain member: Maximum machine account password age is set to $1AW2CfpSKiewv0 which is a higher value than 30 required for compliance" -color Red
}
  else
{
outputanswer -answer "Domain member: Maximum machine account password age is set to an unknown setting" -color Red
}

$AllowOnlineID = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\pku2u\ -Name AllowOnlineID -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AllowOnlineID
if ( $AllowOnlineID -eq $null)
{
outputanswer -answer "Network security: Allow PKU2U authentication requests to this computer to use online identities is not configured" -color Yellow
}
   elseif ( $AllowOnlineID  -eq  '0' )
{
outputanswer -answer "Network security: Allow PKU2U authentication requests to this computer to use online identities is disabled" -color Green
}
  elseif ( $AllowOnlineID  -eq  '1' )
{
outputanswer -answer "Network security: Allow PKU2U authentication requests to this computer to use online identities is enabled" -color Red
}
  else
{
outputanswer -answer "Network security: Allow PKU2U authentication requests to this computer to use online identities is set to an unknown setting" -color Red
}


outputanswer -answer "Unable to check Network security: Force logoff when logon hours expire because it is not a registry setting. Please manually check Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options and ensure this is set to enabled." -color Cyan

$LDAPClientIntegrity = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LDAP\' -Name LDAPClientIntegrity -ErrorAction SilentlyContinue|Select-Object -ExpandProperty LDAPClientIntegrity
if ( $LDAPClientIntegrity -eq $null)
{
outputanswer -answer "System objects: Require case insensitivity for non-Windows subsystems is not configured" -color Yellow
}
   elseif ( $LDAPClientIntegrity  -eq  '2' )
{
outputanswer -answer "Network security: LDAP client signing requirements is enabled and set to Require Signing, it should be set to Negotiate Signing" -color Red
}
  elseif ( $LDAPClientIntegrity  -eq  '1' )
{
outputanswer -answer "Network security: LDAP client signing requirements is enabled and set to Negotiate Signing" -color Green
}
  elseif ( $LDAPClientIntegrity  -eq  '0' )
{
outputanswer -answer "Network security: LDAP client signing requirements is enabled and set None, it should be set to Negotiate Signing" -color Red
}
  else
{
outputanswer -answer "System objects: Require case insensitivity for non-Windows subsystems is set to an unknown setting" -color Red
}

$ObCaseInsensitive = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\' -Name ObCaseInsensitive -ErrorAction SilentlyContinue|Select-Object -ExpandProperty ObCaseInsensitive
if ( $ObCaseInsensitive -eq $null)
{
outputanswer -answer "System objects: Require case insensitivity for non-Windows subsystems is not configured" -color Yellow
}
   elseif ( $ObCaseInsensitive  -eq  '0' )
{
outputanswer -answer "System objects: Require case insensitivity for non-Windows subsystems is disabled" -color Red
}
  elseif ( $ObCaseInsensitive  -eq  '1' )
{
outputanswer -answer "System objects: Require case insensitivity for non-Windows subsystems is enabled" -color Green
}
  else
{
outputanswer -answer "System objects: Require case insensitivity for non-Windows subsystems is set to an unknown setting" -color Red
}

$ProtectionMode = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\' -Name ProtectionMode -ErrorAction SilentlyContinue|Select-Object -ExpandProperty ProtectionMode
if ($ProtectionMode -eq $null)
{
outputanswer -answer "System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links) is not configured" -color Yellow
}
   elseif ($ProtectionMode  -eq  '0' )
{
outputanswer -answer "System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links) is disabled" -color Red
}
  elseif ($ProtectionMode  -eq  '1' )
{
outputanswer -answer "System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links) is enabled" -color Green
}
  else
{
outputanswer -answer "System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links) is set to an unknown setting" -color Red
}


outputanswer -answer "SERVER MESSAGE BLOCK SESSIONS" -color White


$JZyMnHu1K3IXh40 = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MrxSmb10\'  -Name Start -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Start
if ( $JZyMnHu1K3IXh40 -eq $null)
{
outputanswer -answer "Configure SMB v1 client driver is not configured" -color Yellow
}
   elseif ( $JZyMnHu1K3IXh40  -eq  '4' )
{
outputanswer -answer "Configure SMB v1 client driver is disabled" -color Green
}
  elseif ( $JZyMnHu1K3IXh40  -eq  '2' -or $JZyMnHu1K3IXh40  -eq  '3' )
{
outputanswer -answer "Configure SMB v1 client driver is set to manual or automatic start" -color Red
}
  else
{
outputanswer -answer "Configure SMB v1 client driver is set to an unknown setting" -color Red
}

$CJYvExedTmlj9OQ = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\'  -Name SMB1 -ErrorAction SilentlyContinue|Select-Object -ExpandProperty SMB1
if ( $CJYvExedTmlj9OQ -eq $null)
{
outputanswer -answer "Configure SMB v1 server is not configured" -color Yellow
}
   elseif ( $CJYvExedTmlj9OQ  -eq  '0' )
{
outputanswer -answer "Configure SMB v1 server is disabled" -color Green
}
  elseif ( $CJYvExedTmlj9OQ  -eq  '1' )
{
outputanswer -answer "Configure SMB v1 server is enabled" -color Red
}
  else
{
outputanswer -answer "Configure SMB v1 server is set to an unknown setting" -color Red
}

$RequireSecuritySignature = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\'  -Name RequireSecuritySignature -ErrorAction SilentlyContinue|Select-Object -ExpandProperty RequireSecuritySignature
if ( $RequireSecuritySignature -eq $null)
{
outputanswer -answer "Microsoft Network Client: Digitally sign communications (always) is not configured" -color Yellow
}
   elseif ( $RequireSecuritySignature  -eq  '1' )
{
outputanswer -answer "Microsoft Network Client: Digitally sign communications (always) is enabled" -color Green
}
  elseif ( $RequireSecuritySignature  -eq  '0' )
{
outputanswer -answer "Microsoft Network Client: Digitally sign communications (always) is disabled" -color Red
}
  else
{
outputanswer -answer "Microsoft Network Client: Digitally sign communications (always) is set to an unknown setting" -color Red
}

$EnableSecuritySignature = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\'  -Name EnableSecuritySignature -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EnableSecuritySignature
if ( $EnableSecuritySignature -eq $null)
{
outputanswer -answer "Microsoft network client: Digitally sign communications (if server agrees) is not configured" -color Yellow
}
   elseif ( $EnableSecuritySignature  -eq  '1' )
{
outputanswer -answer "Microsoft network client: Digitally sign communications (if server agrees) is enabled" -color Green
}
  elseif ( $EnableSecuritySignature  -eq  '0' )
{
outputanswer -answer "Microsoft network client: Digitally sign communications (if server agrees) is disabled" -color Red
}
  else
{
outputanswer -answer "Microsoft network client: Digitally sign communications (if server agrees) is set to an unknown setting" -color Red
}

$EnablePlainTextPassword = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\'  -Name EnablePlainTextPassword -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EnablePlainTextPassword
if ( $EnablePlainTextPassword -eq $null)
{
outputanswer -answer "Microsoft network client: Send unencrypted password to third-party SMB servers is not configured" -color Yellow
}
   elseif ( $EnablePlainTextPassword  -eq  '0' )
{
outputanswer -answer "Microsoft network client: Send unencrypted password to third-party SMB servers is disabled" -color Green
}
  elseif ( $EnablePlainTextPassword  -eq  '1' )
{
outputanswer -answer "Microsoft network client: Send unencrypted password to third-party SMB servers is enabled" -color Red
}
  else
{
outputanswer -answer "Microsoft network client: Send unencrypted password to third-party SMB servers is set to an unknown setting" -color Red
}

$AutoDisconnect = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\'  -Name AutoDisconnect -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AutoDisconnect
if ( $AutoDisconnect -eq $null)
{
outputanswer -answer "Microsoft network server: Amount of idle time required before suspending session is not configured" -color Yellow
}
   elseif ( $AutoDisconnect  -le  '15' )
{
outputanswer -answer "Microsoft network server: Amount of idle time required before suspending session is less than or equal to 15 mins" -color Green
}
  elseif ($AutoDisconnect -gt '15')
{
outputanswer -answer "Microsoft network server: Amount of idle time required before suspending session is $AutoDisconnect which is outside the compliant limit of 0 to 15 minutes" -color Red
}
 else
{
outputanswer -answer "Microsoft network server: Amount of idle time required before suspending session is configured incorrectly" -color Red
}

$RequireSecuritySignature1 = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\'  -Name RequireSecuritySignature -ErrorAction SilentlyContinue|Select-Object -ExpandProperty RequireSecuritySignature
if ( $RequireSecuritySignature1 -eq $null)
{
outputanswer -answer "Microsoft network server: Digitally sign communications (always) is not configured" -color Yellow
}
   elseif ( $RequireSecuritySignature1  -eq  '1' )
{
outputanswer -answer "Microsoft network server: Digitally sign communications (always) is enabled" -color Green
}
  elseif ( $RequireSecuritySignature1  -eq  '0' )
{
outputanswer -answer "Microsoft network server: Digitally sign communications (always) is disabled" -color Red
}
  else
{
outputanswer -answer "Microsoft network server: Digitally sign communications (always) is set to an unknown setting" -color Red
}

$EnableSecuritySignature1 = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\'  -Name EnableSecuritySignature -ErrorAction SilentlyContinue|Select-Object -ExpandProperty EnableSecuritySignature
if ( $EnableSecuritySignature1 -eq $null)
{
outputanswer -answer "Microsoft network server: Digitally sign communications (if client agrees) is not configured" -color Yellow
}
   elseif ( $EnableSecuritySignature1  -eq  '1' )
{
outputanswer -answer "Microsoft network server: Digitally sign communications (if client agrees) is enabled" -color Green
}
  elseif ( $EnableSecuritySignature1  -eq  '0' )
{
outputanswer -answer "Microsoft network server: Digitally sign communications (if client agrees) is disabled" -color Red
}
  else
{
outputanswer -answer "Microsoft network server: Digitally sign communications (if client agrees) is set to an unknown setting" -color Red
}

outputanswer -answer "SESSION LOCKING" -color White

$tMm2f35wdzqlIkg = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization\'  -Name NoLockScreenCamera -ErrorAction SilentlyContinue|Select-Object -ExpandProperty NoLockScreenCamera
if ( $tMm2f35wdzqlIkg -eq $null)
{
outputanswer -answer "Prevent enabling lock screen camera is not configured" -color Yellow
}
   elseif ( $tMm2f35wdzqlIkg  -eq  '1' )
{
outputanswer -answer "Prevent enabling lock screen camera is enabled" -color Green
}
  elseif ( $tMm2f35wdzqlIkg  -eq  '0' )
{
outputanswer -answer "Prevent enabling lock screen camera is disabled" -color Red
}
  else
{
outputanswer -answer "Prevent enabling lock screen camera is set to an unknown setting" -color Red
}

$9Ot0aqonKNiEm5b = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization\'  -Name NoLockScreenSlideshow -ErrorAction SilentlyContinue|Select-Object -ExpandProperty NoLockScreenSlideshow
if ( $9Ot0aqonKNiEm5b -eq $null)
{
outputanswer -answer "Prevent enabling lock screen slide show is not configured" -color Yellow
}
   elseif ( $9Ot0aqonKNiEm5b  -eq  '1' )
{
outputanswer -answer "Prevent enabling lock screen slide show is enabled" -color Green
}
  elseif ( $9Ot0aqonKNiEm5b  -eq  '0' )
{
outputanswer -answer "Prevent enabling lock screen slide show is disabled" -color Red
}
  else
{
outputanswer -answer "Prevent enabling lock screen slide show is set to an unknown setting" -color Red
}

$cbGLB9V2Rhk7fq5 = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System\'  -Name AllowDomainDelayLock -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AllowDomainDelayLock
if ( $cbGLB9V2Rhk7fq5 -eq $null)
{
outputanswer -answer "Allow users to select when a password is required when resuming from connected standby is not configured" -color Yellow
}
   elseif ( $cbGLB9V2Rhk7fq5  -eq  '0' )
{
outputanswer -answer "Allow users to select when a password is required when resuming from connected standby is disabled" -color Green
}
  elseif ( $cbGLB9V2Rhk7fq5  -eq  '1' )
{
outputanswer -answer "Allow users to select when a password is required when resuming from connected standby is enabled" -color Red
}
  else
{
outputanswer -answer "Allow users to select when a password is required when resuming from connected standby is set to an unknown setting" -color Red
}

$jrSiA6Xq2mBVpCZ = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System\'  -Name DisableLockScreenAppNotifications -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableLockScreenAppNotifications
if ( $jrSiA6Xq2mBVpCZ -eq $null)
{
outputanswer -answer "Turn off app notifications on the lock screen is not configured" -color Yellow
}
   elseif ( $jrSiA6Xq2mBVpCZ  -eq  '1' )
{
outputanswer -answer "Turn off app notifications on the lock screen is enabled" -color Green
}
  elseif ( $jrSiA6Xq2mBVpCZ  -eq  '0' )
{
outputanswer -answer "Turn off app notifications on the lock screen is disabled" -color Red
}
  else
{
outputanswer -answer "Turn off app notifications on the lock screen is set to an unknown setting" -color Red
}

$aBGYEMCPVjRLeFc = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer\'  -Name ShowLockOption -ErrorAction SilentlyContinue|Select-Object -ExpandProperty ShowLockOption
if ( $aBGYEMCPVjRLeFc -eq $null)
{
outputanswer -answer "Show lock in the user tile menu is not configured" -color Yellow
}
   elseif ( $aBGYEMCPVjRLeFc  -eq  '1' )
{
outputanswer -answer "Show lock in the user tile menu is enabled" -color Green
}
  elseif ( $aBGYEMCPVjRLeFc  -eq  '0' )
{
outputanswer -answer "Show lock in the user tile menu is disabled" -color Red
}
  else
{
outputanswer -answer "Show lock in the user tile menu is set to an unknown setting" -color Red
}

$oRJPdEy5i0DCqFX = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsInkWorkspace\'  -Name AllowWindowsInkWorkspace -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AllowWindowsInkWorkspace
if ( $oRJPdEy5i0DCqFX -eq $null)
{
outputanswer -answer "Allow Windows Ink Workspace is not configured" -color Yellow
}
   elseif ( $oRJPdEy5i0DCqFX  -eq  '1' )
{
outputanswer -answer "Allow Windows Ink Workspace is on but dissalow access above lock" -color Green
}
  elseif ( $oRJPdEy5i0DCqFX  -eq  '0' -or $oRJPdEy5i0DCqFX  -eq  '2' )
{
outputanswer -answer "Allow Windows Ink Workspace is disabled or turned on, both not recommended settings" -color Red
}
  else
{
outputanswer -answer "Allow Windows Ink Workspace is set to an unknown setting" -color Red
}

$bKErRNAU3b4k6hI = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\'  -Name inactivitytimeoutsecs -ErrorAction SilentlyContinue|Select-Object -ExpandProperty inactivitytimeoutsecs
if ( $bKErRNAU3b4k6hI -eq $null)
{
outputanswer -answer "No inactivity timeout has been configured" -color Yellow
}
   elseif ( $bKErRNAU3b4k6hI  -le  '900' )
{
outputanswer -answer "The machine inactivity limit has been set to $bKErRNAU3b4k6hI seconds which is a compliant setting" -color Green
}
  elseif ( $bKErRNAU3b4k6hI  -gt  '900' )
{
outputanswer -answer "The machine inactivity limit has been set to $bKErRNAU3b4k6hI seconds which is a non-compliant setting" -color Red
}
  else
{
outputanswer -answer "The machine inactivity limit is set to an unknown setting" -color Red
}

$nKErRNAU3b4k6hI = Get-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop\'  -Name ScreenSaveActive -ErrorAction SilentlyContinue|Select-Object -ExpandProperty ScreenSaveActive
if ( $nKErRNAU3b4k6hI -eq $null)
{
outputanswer -answer "Enable screen saver is not configured" -color Yellow
}
   elseif ( $nKErRNAU3b4k6hI  -eq  '1' )
{
outputanswer -answer "Enable screen saver is enabled" -color Green
}
  elseif ( $nKErRNAU3b4k6hI  -eq  '0' )
{
outputanswer -answer "Enable screen saver is disabled" -color Red
}
  else
{
outputanswer -answer "Enable screen saver is set to an unknown setting" -color Red
}

$v692ozEayg53Lfs = Get-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop\'  -Name ScreenSaverIsSecure -ErrorAction SilentlyContinue|Select-Object -ExpandProperty ScreenSaverIsSecure
if ( $v692ozEayg53Lfs -eq $null)
{
outputanswer -answer "Password protect the screen saver is not configured" -color Yellow
}
   elseif ( $v692ozEayg53Lfs  -eq  '1' )
{
outputanswer -answer "Password protect the screen saver is enabled" -color Green
}
  elseif ( $v692ozEayg53Lfs  -eq  '0' )
{
outputanswer -answer "Password protect the screen saver is disabled" -color Red
}
  else
{
outputanswer -answer "Password protect the screen saver is set to an unknown setting" -color Red
}

$EWeBJdm8rjbwAo3 = Get-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop\'  -Name ScreenSaveTimeOut -ErrorAction SilentlyContinue|Select-Object -ExpandProperty ScreenSaveTimeOut
if ( $EWeBJdm8rjbwAo3 -eq $null)
{
outputanswer -answer "Screen saver timeout is not configured" -color Yellow
}
   elseif ( $EWeBJdm8rjbwAo3  -eq  '900' )
{
outputanswer -answer "Screen saver timeout is set compliant" -color Green
}
  elseif ( $EWeBJdm8rjbwAo3  -lt '900')
{
outputanswer -answer "Screen saver timeout is lower than a compliant setting" -color Red
}
  elseif ( $EWeBJdm8rjbwAo3  -gt '900')
{
outputanswer -answer "Screen saver timeout is higher than the compliant setting" -color Green
}
  else
{
outputanswer -answer "Screen saver timeout is set to an unknown setting" -color Red
}

$7NdvQjghTrwKYW4 = Get-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\'  -Name NoToastApplicationNotificationOnLockScreen -ErrorAction SilentlyContinue|Select-Object -ExpandProperty NoToastApplicationNotificationOnLockScreen
if ( $7NdvQjghTrwKYW4 -eq $null)
{
outputanswer -answer "Turn off toast notifications on the lock screen is not configured" -color Yellow
}
   elseif ( $7NdvQjghTrwKYW4  -eq  '1' )
{
outputanswer -answer "Turn off toast notifications on the lock screen is enabled" -color Green
}
  elseif ( $7NdvQjghTrwKYW4  -eq  '0' )
{
outputanswer -answer "Turn off toast notifications on the lock screen is disabled" -color Red
}
  else
{
outputanswer -answer "Turn off toast notifications on the lock screen is set to an unknown setting" -color Red
}

$YcLMvmzxA0X3tu6 = Get-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CloudContent\'  -Name DisableThirdPartySuggestions -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableThirdPartySuggestions
if ( $YcLMvmzxA0X3tu6 -eq $null)
{
outputanswer -answer "Do not suggest third-party content in Windows spotlight is not configured" -color Yellow
}
   elseif ( $YcLMvmzxA0X3tu6  -eq  '1' )
{
outputanswer -answer "Do not suggest third-party content in Windows spotlight is enabled" -color Green
}
  elseif ( $YcLMvmzxA0X3tu6  -eq  '0' )
{
outputanswer -answer "Do not suggest third-party content in Windows spotlight is disabled" -color Red
}
  else
{
outputanswer -answer "Do not suggest third-party content in Windows spotlight is set to an unknown setting" -color Red
}


outputanswer -answer "SOFTWARE-BASED FIREWALLS" -color White

outputanswer -answer "Unable to confirm if an effective, application based software firewall is in use on this endpoint. Please confirm that a software firewall is in use on this host, listing explicitly which applications can generate inbound and outbound network traffic." -color Cyan
outputanswer -answer "SOUND RECORDER" -color White

$IAtVlOZ8HnEGCq5 = Get-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\SoundRecorder\'  -Name Soundrec -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Soundrec
if ( $IAtVlOZ8HnEGCq5 -eq $null)
{
outputanswer -answer "Do not allow Sound Recorder to run is not configured" -color Yellow
}
   elseif ( $IAtVlOZ8HnEGCq5  -eq  '1' )
{
outputanswer -answer "Do not allow Sound Recorder to run is enabled" -color Green
}
  elseif ( $IAtVlOZ8HnEGCq5  -eq  '0' )
{
outputanswer -answer "Do not allow Sound Recorder to run is disabled" -color Red
}
  else
{
outputanswer -answer "Do not allow Sound Recorder to run is set to an unknown setting" -color Red
}

outputanswer -answer "STANDARD OPERATING ENVIRONMENT" -color White

outputanswer -answer "This script is unable to check if a Standard Operating Environment (SOE) was used to build this image. Please manually confirm if the computer was built using a SOE image process" -color Cyan

outputanswer -answer "SYSTEM BACKUP AND RESTORE" -color White

outputanswer -answer "Unable to check Backup Files and Directories setting at this time, please check manually Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Backup Files and Directories. Only Administrators should be members of this setting" -color Cyan

outputanswer -answer "Unable to check Restore Files and Directories setting at this time, please check manually Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Restore Files and Directories. Only Administrators should be members of this setting" -color Cyan

outputanswer -answer "SYSTEM CRYPTOGRAPHY" -color White

$forceprotection = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\Cryptography" -Name ForceKeyProtection -ErrorAction SilentlyContinue|Select-Object -ExpandProperty ForceKeyProtection

if ($forceprotection -eq $null)
{
outputanswer -answer "System cryptography: Force strong key protection for user keys stored on the computer is not configured" -color Yellow
}
    elseif ($forceprotection -eq '2')
{
outputanswer -answer "System cryptography: Force strong key protection for user keys stored on the computer is set to user must enter a password each time they use a key" -color Green
}
    elseif ($forceprotection -eq '1')
{
outputanswer -answer "System cryptography: Force strong key protection for user keys stored on the computer is set to user is prompted when the key is first used, this is a non compliant setting" -color Red
}
    elseif ($forceprotection -eq '0')
{
outputanswer -answer "System cryptography: Force strong key protection for user keys stored on the computer is set to user input is not required when new keys are stored and used, this is a non compliant setting" -color Red
}

$9UNpgi6osfkQlnF = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Centrify\CentrifyDC\Settings\Fips\'  -Name fips.mode.enable -ErrorAction SilentlyContinue|Select-Object -ExpandProperty fips.mode.enable
if ( $9UNpgi6osfkQlnF -eq $null)
{
outputanswer -answer "Use FIPS compliant algorithms for encryption, hashing and signing is not configured" -color Yellow
}
   elseif ( $9UNpgi6osfkQlnF  -eq  'true' )
{
outputanswer -answer "Use FIPS compliant algorithms for encryption, hashing and signing is enabled" -color Green
}
  elseif ( $9UNpgi6osfkQlnF  -eq  'false' )
{
outputanswer -answer "Use FIPS compliant algorithms for encryption, hashing and signing is disabled" -color Red
}
  else
{
outputanswer -answer "Use FIPS compliant algorithms for encryption, hashing and signing is set to an unknown setting" -color Red
}

outputanswer -answer "USER RIGHTS POLICIES" -color White

outputanswer -answer "Unable to check this chapter as it requires a GPO export to view the settings (they are not stored locally). Please check policies located at 'Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment'" -color Cyan

outputanswer -answer "VIRTUALISED WEB AND EMAIL ACCESS" -color White

$Physicalorvirtual = Get-MachineType
If ($physicalorvirtual -eq $null)
{
outputanswer -answer "Unable to determine machine type, if this machine is a virtual machine and non-persistent (new upon every reboot) you are compliant with this chapter of the guide" -color Cyan
}
elseif ($Physicalorvirtual -match "Physical")
{
outputanswer -answer "This machine was detected to be a physical machine, if this machine is used to browse the web and check e-mail, you are non compliant with this chapter of the guide" -color Red
}
elseif ($Physicalorvirtual -match "Virtual")
{
outputanswer -answer "This machine was detected to be a virtual machine, if this machine is used to browse the web and check e-mail and the machine is non-persistent (new upon every reboot) you are compliant with this chapter of the guide" -color Cyan
}

outputanswer -answer "WINDOWS REMOTE MANAGEMENT" -color White

$q8Y9g4oz6TAULkJ = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client\'  -Name AllowBasic -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AllowBasic
if ( $q8Y9g4oz6TAULkJ -eq $null)
{
outputanswer -answer "Allow Basic authentication is not configured" -color Yellow
}
   elseif ( $q8Y9g4oz6TAULkJ  -eq  '0' )
{
outputanswer -answer "Allow Basic authentication is disabled" -color Green
}
  elseif ( $q8Y9g4oz6TAULkJ  -eq  '1' )
{
outputanswer -answer "Allow Basic authentication is enabled" -color Red
}
  else
{
outputanswer -answer "Allow Basic authentication is set to an unknown setting" -color Red
}


$svkG3Au1aOf5IwN = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client\'  -Name AllowUnencryptedTraffic -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AllowUnencryptedTraffic
if ( $svkG3Au1aOf5IwN -eq $null)
{
outputanswer -answer "Allow unencrypted traffic is not configured" -color Yellow
}
   elseif ( $svkG3Au1aOf5IwN  -eq  '0' )
{
outputanswer -answer "Allow unencrypted traffic is disabled" -color Green
}
  elseif ( $svkG3Au1aOf5IwN  -eq  '1' )
{
outputanswer -answer "Allow unencrypted traffic is enabled" -color Red
}
  else
{
outputanswer -answer "Allow unencrypted traffic is set to an unknown setting" -color Red
}

$Zvk72J5CFEsdqhg = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client\'  -Name AllowDigest -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AllowDigest
if ( $Zvk72J5CFEsdqhg -eq $null)
{
outputanswer -answer "Disallow Digest authentication is not configured" -color Yellow
}
   elseif ( $Zvk72J5CFEsdqhg  -eq  '0' )
{
outputanswer -answer "Disallow Digest authentication is enabled" -color Green
}
  elseif ( $Zvk72J5CFEsdqhg  -eq  '1' )
{
outputanswer -answer "Disallow Digest authentication is disabled" -color Red
}
  else
{
outputanswer -answer "Disallow Digest authentication is set to an unknown setting" -color Red
}

$R3rxMaJTWuI8Ggn = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service\'  -Name AllowBasic -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AllowBasic
if ( $R3rxMaJTWuI8Ggn -eq $null)
{
outputanswer -answer "Allow Basic authentication is not configured" -color Yellow
}
   elseif ( $R3rxMaJTWuI8Ggn  -eq  '0' )
{
outputanswer -answer "Allow Basic authentication is disabled" -color Green
}
  elseif ( $R3rxMaJTWuI8Ggn  -eq  '1' )
{
outputanswer -answer "Allow Basic authentication is enabled" -color Red
}
  else
{
outputanswer -answer "Allow Basic authentication is set to an unknown setting" -color Red
}

$WeNYH9rskqIXnld = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service\'  -Name AllowUnencryptedTraffic -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AllowUnencryptedTraffic
if ( $WeNYH9rskqIXnld -eq $null)
{
outputanswer -answer "Allow unencrypted traffic is not configured" -color Yellow
}
   elseif ( $WeNYH9rskqIXnld  -eq  '0' )
{
outputanswer -answer "Allow unencrypted traffic is disabled" -color Green
}
  elseif ( $WeNYH9rskqIXnld  -eq  '1' )
{
outputanswer -answer "Allow unencrypted traffic is enabled" -color Red
}
  else
{
outputanswer -answer "Allow unencrypted traffic is set to an unknown setting" -color Red
}

$Gl0HpCP1daqYn28 = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service\'  -Name DisableRunAs -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableRunAs
if ( $Gl0HpCP1daqYn28 -eq $null)
{
outputanswer -answer "Disallow WinRM from storing RunAs credentials is not configured" -color Yellow
}
   elseif ( $Gl0HpCP1daqYn28  -eq  '1' )
{
outputanswer -answer "Disallow WinRM from storing RunAs credentials is enabled" -color Green
}
  elseif ( $Gl0HpCP1daqYn28  -eq  '0' )
{
outputanswer -answer "Disallow WinRM from storing RunAs credentials is disabled" -color Red
}
  else
{
outputanswer -answer "Disallow WinRM from storing RunAs credentials is set to an unknown setting" -color Red
}


outputanswer -answer "WINDOWS REMOTE SHELL ACCESS" -color White

$traYJW4x86uMjUG = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS\'  -Name AllowRemoteShellAccess -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AllowRemoteShellAccess
if ( $traYJW4x86uMjUG -eq $null)
{
outputanswer -answer "Allow Remote Shell Access is not configured" -color Yellow
}
   elseif ( $traYJW4x86uMjUG  -eq  '0' )
{
outputanswer -answer "Allow Remote Shell Access is disabled" -color Green
}
  elseif ( $traYJW4x86uMjUG  -eq  '1' )
{
outputanswer -answer "Allow Remote Shell Access is enabled" -color Red
}
  else
{
outputanswer -answer "Allow Remote Shell Access is set to an unknown setting" -color Red
}

outputanswer -answer "WINDOWS SEARCH AND CORTANA" -color White

$nCf3tP6YSFhcpD0 = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search\'  -Name AllowCortana -ErrorAction SilentlyContinue|Select-Object -ExpandProperty AllowCortana
if ( $nCf3tP6YSFhcpD0 -eq $null)
{
outputanswer -answer "Allow Cortana is not configured" -color Yellow
}
   elseif ( $nCf3tP6YSFhcpD0  -eq  '0' )
{
outputanswer -answer "Allow Cortana is disabled" -color Green
}
  elseif ( $nCf3tP6YSFhcpD0  -eq  '1' )
{
outputanswer -answer "Allow Cortana is enabled" -color Red
}
  else
{
outputanswer -answer "Allow Cortana is set to an unknown setting" -color Red
}

$zKbSDWr3cMvUZu7 = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search\'  -Name ConnectedSearchUseWeb -ErrorAction SilentlyContinue|Select-Object -ExpandProperty ConnectedSearchUseWeb
if ( $zKbSDWr3cMvUZu7 -eq $null)
{
outputanswer -answer "Don't search the web or display web results in Search is not configured" -color Yellow
}
   elseif ( $zKbSDWr3cMvUZu7  -eq  '0' )
{
outputanswer -answer "Don't search the web or display web results in Search is enabled" -color Green
}
  elseif ( $zKbSDWr3cMvUZu7  -eq  '1' )
{
outputanswer -answer "Don't search the web or display web results in Search is disabled" -color Red
}
  else
{
outputanswer -answer "Don't search the web or display web results in Search is set to an unknown setting" -color Red
}

outputanswer -answer "WINDOWS TO GO" -color White

$rbWyQvlG5TAVoS7 = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\PortableOperatingSystem\'  -Name Launcher -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Launcher
if ( $rbWyQvlG5TAVoS7 -eq $null)
{
outputanswer -answer "Windows To Go Default Startup Options is not configured" -color Yellow
}
   elseif ( $rbWyQvlG5TAVoS7  -eq  '0' )
{
outputanswer -answer "Windows To Go Default Startup Options is disabled" -color Green
}
  elseif ( $rbWyQvlG5TAVoS7  -eq  '1' )
{
outputanswer -answer "Windows To Go Default Startup Options is enabled" -color Red
}
  else
{
outputanswer -answer "Windows To Go Default Startup Options is set to an unknown setting" -color Red
}

outputanswer -answer "DISPLAYING FILE EXTENSIONS" -color White

$rbWyQvlG5TAVoS = Get-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'  -Name HideFileExt -ErrorAction SilentlyContinue|Select-Object -ExpandProperty HideFileExt
if ( $rbWyQvlG5TAVoS -eq $null)
{
outputanswer -answer "Display file extensions is not configured" -color Yellow
}
   elseif ( $rbWyQvlG5TAVoS  -eq  '1' )
{
outputanswer -answer "Display file extensions is enabled" -color Green
}
  elseif ( $rbWyQvlG5TAVoS  -eq  '0' )
{
outputanswer -answer "Display file extensions is disabled" -color Red
}
  else
{
outputanswer -answer "Display file extensions is set to an unknown setting" -color Red
}

outputanswer -answer "FILE AND FOLDER SECURITY PROPERTIES" -color White

$7DTmwyr9KIcjvMi = Get-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'  -Name NoSecurityTab -ErrorAction SilentlyContinue|Select-Object -ExpandProperty NoSecurityTab
if ( $7DTmwyr9KIcjvMi -eq $null)
{
outputanswer -answer "Remove Security tab is not configured" -color Yellow
}
   elseif ( $7DTmwyr9KIcjvMi  -eq  '1' )
{
outputanswer -answer "Remove Security tab is enabled" -color Green
}
  elseif ( $7DTmwyr9KIcjvMi  -eq  '0' )
{
outputanswer -answer "Remove Security tab is disabled" -color Red
}
  else
{
outputanswer -answer "Remove Security tab is set to an unknown setting" -color Red
}

outputanswer -answer "LOCATION AWARENESS" -color White

$L0t3zDQOWT82Yjk = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LocationAndSensors\'  -Name DisableLocation -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableLocation
if ( $L0t3zDQOWT82Yjk -eq $null)
{
outputanswer -answer "Turn off location is not configured" -color Yellow
}
   elseif ( $L0t3zDQOWT82Yjk  -eq  '1' )
{
outputanswer -answer "Turn off location is enabled" -color Green
}
  elseif ( $L0t3zDQOWT82Yjk  -eq  '0' )
{
outputanswer -answer "Turn off location is disabled" -color Red
}
  else
{
outputanswer -answer "Turn off location is set to an unknown setting" -color Red
}

$wOWZP5iF8Ah2HLn = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LocationAndSensors\'  -Name DisableLocationScripting -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableLocationScripting
if ( $wOWZP5iF8Ah2HLn -eq $null)
{
outputanswer -answer "Turn off location scripting is not configured" -color Yellow
}
   elseif ( $wOWZP5iF8Ah2HLn  -eq  '1' )
{
outputanswer -answer "Turn off location scripting is enabled" -color Green
}
  elseif ( $wOWZP5iF8Ah2HLn  -eq  '0' )
{
outputanswer -answer "Turn off location scripting is disabled" -color Red
}
  else
{
outputanswer -answer "Turn off location scripting is set to an unknown setting" -color Red
}

$SbtA61CokgvnOKE = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LocationAndSensors\'  -Name DisableWindowsLocationProvider -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DisableWindowsLocationProvider
if ( $SbtA61CokgvnOKE -eq $null)
{
outputanswer -answer "Turn off Windows Location Provider is not configured" -color Yellow
}
   elseif ( $SbtA61CokgvnOKE  -eq  '1' )
{
outputanswer -answer "Turn off Windows Location Provider is enabled" -color Green
}
  elseif ( $SbtA61CokgvnOKE  -eq  '0' )
{
outputanswer -answer "Turn off Windows Location Provider is disabled" -color Red
}
  else
{
outputanswer -answer "Turn off Windows Location Provider is set to an unknown setting" -color Red
}


outputanswer -answer "MICROSOFT STORE" -color White

$64GduoTfcmp2iqY = Get-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer\'  -Name NoUseStoreOpenWith -ErrorAction SilentlyContinue|Select-Object -ExpandProperty NoUseStoreOpenWith
if ( $64GduoTfcmp2iqY -eq $null)
{
outputanswer -answer "Turn off access to the Store is not configured" -color Yellow
}
   elseif ( $64GduoTfcmp2iqY  -eq  '1' )
{
outputanswer -answer "Turn off access to the Store is enabled" -color Green
}
  elseif ( $64GduoTfcmp2iqY  -eq  '0' )
{
outputanswer -answer "Turn off access to the Store is disabled" -color Red
}
  else
{
outputanswer -answer "Turn off access to the Store is set to an unknown setting" -color Red
}

$2D3fnVsKR9pBEYm = Get-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\WindowsStore\'  -Name RemoveWindowsStore -ErrorAction SilentlyContinue|Select-Object -ExpandProperty RemoveWindowsStore
if ( $2D3fnVsKR9pBEYm -eq $null)
{
outputanswer -answer "Turn off the Store application is not configured" -color Yellow
}
   elseif ( $2D3fnVsKR9pBEYm  -eq  '1' )
{
outputanswer -answer "Turn off the Store application is enabled" -color Green
}
  elseif ( $2D3fnVsKR9pBEYm  -eq  '0' )
{
outputanswer -answer "Turn off the Store application is disabled" -color Red
}
  else
{
outputanswer -answer "Turn off the Store application is set to an unknown setting" -color Red
}


outputanswer -answer "PUBLISHING INFORMATION TO THE WEB" -color White


$8Ak7NpxH5Vs3bWE = Get-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'  -Name NoWebServices -ErrorAction SilentlyContinue|Select-Object -ExpandProperty NoWebServices
if ( $8Ak7NpxH5Vs3bWE -eq $null)
{
outputanswer -answer "Turn off Internet download for Web publishing and online ordering wizards is not configured" -color Yellow
}
   elseif ( $8Ak7NpxH5Vs3bWE  -eq  '1' )
{
outputanswer -answer "Turn off Internet download for Web publishing and online ordering wizards is enabled" -color Green
}
  elseif ( $8Ak7NpxH5Vs3bWE  -eq  '0' )
{
outputanswer -answer "Turn off Internet download for Web publishing and online ordering wizards is disabled" -color Red
}
  else
{
outputanswer -answer "Turn off Internet download for Web publishing and online ordering wizards is set to an unknown setting" -color Red
}

outputanswer -answer "RESULTANT SET OF POLICY REPORTING" -color White

$dc04uCRS6vJGiNf = Get-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\System\'  -Name DenyRsopToInteractiveUser -ErrorAction SilentlyContinue|Select-Object -ExpandProperty DenyRsopToInteractiveUser
if ( $dc04uCRS6vJGiNf -eq $null)
{
outputanswer -answer "Determine if interactive users can generate Resultant Set of Policy data is not configured" -color Yellow
}
   elseif ( $dc04uCRS6vJGiNf  -eq  '1' )
{
outputanswer -answer "Determine if interactive users can generate Resultant Set of Policy data is enabled" -color Green
}
  elseif ( $dc04uCRS6vJGiNf  -eq  '0' )
{
outputanswer -answer "Determine if interactive users can generate Resultant Set of Policy data is disabled" -color Red
}
  else
{
outputanswer -answer "Determine if interactive users can generate Resultant Set of Policy data is set to an unknown setting" -color Red
}

outputanswer -answer "" -color White

if ($displayconsole -ne 'y')
{
clear
}


#export report to specified file if chosen to write
if ($filepath -ne $null)
{
$report | Export-CSV -NoTypeInformation $filepath
write-host "`r`nAudit results have been written to $filepath`r`n" -ForegroundColor Green

$writetype = Read-Host "`r`nDo you want to compare these results to an existing results file? (y for Yes or n for No)"

If ($writetype -eq 'y')
{


while ($filepath2 -eq $null){
    $filepath2 = Read-Host "`r`nPlease specify the location of the existing results CSV file"
        if (-not(test-path $filepath2)){
            Write-host "Invalid location of the results CSV, please check path and re-enter"
            $filepath2 = $null
                }
            }

    write-host "`r`nThe comparison output file will be output to the following location $working\comparison.csv"

$comparisonfilepath = "$working\comparison.csv"


$Results1 = import-csv -Path $filepath
$Results2 = import-csv -Path $filepath2

Compare-Object $Results1 $Results2 -property Compliance -passthru | Where-Object {($_.SideIndicator -eq "=>")}|select Chapter, Setting, Compliance,Difference | ForEach-Object { $_.Difference = "Appears in the new version, but different in the previous version"; return $_ }|Export-Csv -Path $comparisonfilepath
write-host "`r`nAudit comparison results have been written to $comparisonfilepath`r`n" -ForegroundColor Green

        }
}
else
{
#donothing
}

$totals = $report.Compliance | group | % { $h = @{} } { $h[$_.Name] = $_.Count } { $h }
$compliant = $totals.Values | Select-Object -Index 0
$notconfigured = $totals.Values | Select-Object -Index 1
$noncompliant = $totals.Values | Select-Object -Index 2
$unabletobechecked = $totals.Values | Select-Object -Index 3

write-host "`r`nOut of a total of 346 controls checked there were:"
write-host "$compliant compliant settings" -ForegroundColor Magenta
write-host "$notconfigured Not-Configured (therefore treated as Non-Compliant) settings" -ForegroundColor Magenta
write-host "$noncompliant Non-Compliant settings" -ForegroundColor Magenta
write-host "$unabletobechecked settings that were unable to be checked due to various limitations" -ForegroundColor Magenta



pause
Get-Variable -Exclude PWD,*Preference | Remove-Variable -EA 0



