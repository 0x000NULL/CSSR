<#
.Synopsis
   A script to create/update the firewall settings in a group policy object
.DESCRIPTION
   This script is from the repository https://github.com/SteveUnderScoreN/WindowsFirewall/ and is used together with a partially configured group policy object in a backup folder
   to create/update the firewall settings in a group policy object. These partially configured backups can be downloaded from the repository.
   There are arrays of domain resources which can be configured to create very specific firewall rules specific to the enterprise environment.
   Any resources that do not exist in the environment can be left as the defaults within this script.
   The group policy management tools need to be installed on the computer running this script and it needs access to the DNS and AD infrastructure (RSAT or Add-WindowsFeature -Name GPMC).
   The following "Predefined set of computers" values are supported;
       "LocalSubnet"
       "DNS"
       "DHCP"
       "DefaultGateway"
       "Internet"
       "Intranet"
   Save and run the script or run it interactively, link the GPO to the target OU and ensure the new GPO is above any Microsoft supplied baselines.
   If your domain resources change run the script and select U to update all existing rules with new IP address values, version 0.8.0 updates need to be applied before selecting U.
.NOTES
   0.7.1   Corrected $SourceGPOBackupId and $TargetGpoName.
   0.8.0   Added existing rule update function (using the "Group" parameter of rules), moved code blocks around, added new firewall rules, added progress bars, added some error handling and updated comments.
   0.8.1   New Windows Defender Platform version rules added
   0.8.2   New Windows Defender Platform version rules added
.EXAMPLE
   $TargetGpoName = "Domain Firewall Baseline"
   $PathToGpoBackups = "C:\Temp\WindowsFirewall-GPO"
   $ProxyServers = "2a02:cc9:7732:5500::1","fd4e:eaa9:897b::1","172.19.110.1"
.EXAMPLE
   $TargetGpoName = "Domain Firewall Baseline"
   $PathToGpoBackups = "C:\Temp\WindowsFirewall-GPO"
   $ProxyServers = "proxy.mydomain.local","172.19.110.15","proxy-server3"
.EXAMPLE
   $TargetGpoName = "Domain Firewall Baseline"
   $PathToGpoBackups = "C:\Temp\WindowsFirewall-GPO"
   $ProxyServers = "10.10.10.0/24","proxy2","10.10.11.100-10.10.11.149"
#>

$SourceGpoBackupId = "{eb8aa8ac-840c-4e15-9ea4-dab25d6cb3a5}" # Do not modify this
$TargetGpoName = "SN-Domain Firewall Baseline"
$PathToGpoBackups = "C:\Temp\SN-GPO"
$DomainName = $env:USERDNSDOMAIN
# Version 0.7.0 domain resources
$DomainControllers = "127.0.0.1","SERVERNAME"
$ProxyServerPorts = "8080"
$ProxyServers = "LocalSubnet","Intranet"
$DnsServers = $DomainControllers # Specify these if you do not have DNS on each domain controller or you have additional DNS servers
$CrlServers = "LocalSubnet","Intranet"
$Wpad_PacFileServers = "LocalSubnet","Intranet"
$TierXManagementServers = "LocalSubnet","Intranet" # These are used in tier X firewall baselines to define which computers can manage the device at a particular tier
$SqlServers = "127.0.0.4"
$WebServers = "LocalSubnet","Intranet"
$FileServers = "LocalSubnet","Intranet"
$KeyManagementServers = "LocalSubnet","Intranet"
$BackupServers = "127.0.0.1"
$ClusteredNodesAndManagementAddresses = "LocalSubnet","Intranet"
$ExternalVpnEndpoints = "127.0.0.2 -  127.0.0.3" # This is the externally resolvable IPSec hostname or address
$DirectAccessServers = "127.0.0.128/25" # This is the externally resolvable hostname or address of the DirectAccess IPHTTPS endpoint
$TrustedDhcpSubnets = "Any" # This is client enterprise subnets and includes subnets issued by the VPN server, "Predefined set of computers" cannot be used here
# END of version 0.7.0 domain resources
# Version 0.8.0 domain resources
$ServerRoleAdministrationServers = "LocalSubnet","Intranet" # These are trusted machines used by tier administrators permitted to administer a server role
# END of version 0.8.0 domain resources

$Resources = "DomainControllers","ProxyServers","DnsServers","CrlServers","Wpad_PacFileServers","TierXManagementServers","SqlServers","WebServers","FileServers","KeyManagementServers","BackupServers","ClusteredNodesAndManagementAddresses","ExternalVpnEndpoints","DirectAccessServers","TrustedDhcpSubnets","ServerRoleAdministrationServers"

if ($PSVersionTable.PSEdition -eq "Core")
{
    Write-Warning "This script is not supported on PowerShell Core editions"
    break
}

function CimExceptionUpdatingExistingRules #To be used outside a try block with the "erroraction" preference set to "stop" or using the "errorvariable" either inside or outside a try block with the "erroraction" preference set to "stop" because these error objects are based on the "ActionPreferenceStopException" class and use ".ErrorRecord"
{
    if ($UpdatingExistingRules.ErrorRecord  -like "Indicates two revision levels are incompatible.*")
    {
        #Catch error ID "Windows System Error 1306,Set-NetFirewallRule"
        $WriteError = ($UpdatingExistingRules.ErrorRecord.InvocationInfo.Line).TrimStart()
        $Message = "Error executing the following command;`n$WriteError`nA rule appears to have been created or modified with a newer version of the management tools and cannot be updated from $env:COMPUTERNAME.`nNo more updates to existing rules will be attempted."
        Write-Error -ErrorId "Windows System Error 1306,Set-NetFirewallRule" -Category ResourceExists -RecommendedAction "Try running the script again on a computer with a more recent operating system." -Message $Message
    }
    elseif ($UpdatingExistingRules.ErrorRecord -like "Cannot create a file when that file already exists.*")
    {
        #Catch error ID "Windows System Error 183,New-NetFirewallRule"
        Write-warning "Rule already exists in the policy $TargetGpoName"
    }
    else
    {
        Write-Host -ForegroundColor "Red" " An unknown CimException has occurred"
        $UpdatingExistingRules.ErrorRecord |Out-String |Write-Host -ForegroundColor "Red" 
        Write-Host -ForegroundColor "Red" " No more updates to existing rules will be attempted."
    }
}

function UnknownErrorUpdatingExistingRules #To be used outside a try block with the "erroraction" preference set to "stop" or using the "errorvariable" either inside or outside a try block with the "erroraction" preference set to "stop" because these error objects are based on the "ActionPreferenceStopException" class and use ".ErrorRecord"
{
    Write-Host -ForegroundColor "Red" " An unknown error has occurred"
    $UpdatingExistingRules.ErrorRecord |Out-String |Write-Host -ForegroundColor "Red" 
    Write-Host -ForegroundColor "Red" " No more updates to existing rules will be attempted."
}

function AttemptResolveDnsName ($Name)
{
    try
    {
        $Addresses += (Resolve-DnsName $Name -ErrorAction Stop).IPAddress
    }
    catch
    {
        Write-warning "The hostname $Name could not be resolved, check connectivity to the DNS infrastructure and ensure there is a valid host record for $Name."
    }
}

function Version080Updates
{
    Write-Progress -Activity "Applying version 0.8.0 updates" -PercentComplete 1
    try
    {
        foreach ($InboundBackupServerRule in $InboundBackupServersRules)
        {
            Write-Progress -Activity "Applying version 0.8.0 updates - updating existing rules" -id 1 -PercentComplete "1"
            $Rule = Get-NetFirewallRule -Name $InboundBackupServerRule -GPOSession $GPOSession
            $Rule.Group = "InboundBackupServers"
            Set-NetFirewallRule -InputObject $Rule -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
        }
        foreach ($OutboundProxyServersRule in $OutboundProxyServersRules)
        {
            Write-Progress -Activity "Applying version 0.8.0 updates - updating existing rules" -id 1 -PercentComplete "10"
            $Rule = Get-NetFirewallRule -Name $OutboundProxyServersRule -GPOSession $GPOSession
            $Rule.Group = "OutboundProxyServers"
            Set-NetFirewallRule -InputObject $Rule -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
        }
        Write-Progress -Activity "Applying version 0.8.0 updates" -PercentComplete 25
        foreach ($OutboundDomainControllersRule in $OutboundDomainControllersRules)
        {
            Write-Progress -Activity "Applying version 0.8.0 updates - updating existing rules" -id 1 -PercentComplete "40"
            $Rule = Get-NetFirewallRule -Name $OutboundDomainControllersRule -GPOSession $GPOSession
            $Rule.Group = "OutboundDomainControllers"
            Set-NetFirewallRule -InputObject $Rule -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
        }
        foreach ($OutboundKeyManagementServersRule in $OutboundKeyManagementServersRules)
        {
            Write-Progress -Activity "Applying version 0.8.0 updates - updating existing rules" -id 1 -PercentComplete "80"
            $Rule = Get-NetFirewallRule -Name $OutboundKeyManagementServersRule -GPOSession $GPOSession
            $Rule.Group = "OutboundKeyManagementServers"
            Set-NetFirewallRule -InputObject $Rule -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
        }
        foreach ($OutboundCrlServersRule in $OutboundCrlServersRules)
        {
            Write-Progress -Activity "Applying version 0.8.0 updates - updating existing rules" -id 1 -PercentComplete "90"
            $Rule = Get-NetFirewallRule -Name $OutboundCrlServersRule -GPOSession $GPOSession
            $Rule.Group = "OutboundCRLServers"
            Set-NetFirewallRule -InputObject $Rule -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
        }
        Write-Progress -Activity "Applying version 0.8.0 updates - updating existing rules" -id 1 -Completed
        Write-Output "`n`nVersion 0.8.0 update to existing rules has completed"
    }
    catch [Microsoft.Management.Infrastructure.CimException]
    {
        Write-Progress -Activity "Applying version 0.8.0 updates - updating existing rules" -id 1 -Completed
        . CimExceptionUpdatingExistingRules
    }
    catch
    {
        Write-Progress -Activity "Applying version 0.8.0 updates - updating existing rules" -id 1 -Completed
        . UnknownErrorUpdatingExistingRules
    }
    Write-Progress -Activity "Applying version 0.8.0 updates" -PercentComplete 50
    Write-Progress -Activity "Applying version 0.8.0 updates - creating new rules" -id 1 -PercentComplete "1"
    [void](New-NetFirewallRule -GPOSession $GpoSession -Name "{20070420-f06b-4773-8ff8-d21db877f4db}" -DisplayName "Background Task Host (TCP-Out)" -Group "OutboundDomainControllers" -Profile "Domain" -Direction "Outbound" -RemoteAddress $DomainControllers -Protocol "TCP" -RemotePort "135","49152-65535" -Program "%SystemRoot%\System32\backgroundTaskHost.exe" -ErrorAction SilentlyContinue -ErrorVariable "Version080Updates")
    if ($Version080Updates.Exception.Message -like "Cannot create a file when that file already exists.*")
    {
        Write-Progress -Activity "Applying version 0.8.0 updates - creating new rules" -id 1 -Completed
        Write-warning "Version 0.8.0 new rules have been found, aborting new rule creation."
    }
    else
    {
        $PlatformVersion =  "4.16.17656.18052-0"
        $GuidComponent = $PlatformVersion.Split(".-")
        $GuidComponent = $GuidComponent[2] + $GuidComponent[3]
        [void](New-NetFirewallRule -GPOSession $GpoSession -Name "{725a67e5-68cd-4217-a159-48$GuidComponent}" -DisplayName "Antimalware Service Executable $PlatformVersion (TCP-Out)" -Group "OutboundProxyServers" -Profile "Domain" -Direction "Outbound" -RemoteAddress $ProxyServers -Protocol "TCP" -RemotePort $ProxyServerPorts -Program "%ALLUSERSPROFILE%\Microsoft\Windows Defender\Platform\$PlatformVersion\MsMpEng.exe")
        [void](New-NetFirewallRule -GPOSession $GpoSession -Name "{e92e00fa-918f-4e62-bd3e-a9$GuidComponent}" -DisplayName "Antimalware Service Executable $PlatformVersion (TCP-Out)" -Direction "Outbound" -Protocol "TCP" -RemotePort "80","443" -Program "%ALLUSERSPROFILE%\Microsoft\Windows Defender\Platform\$PlatformVersion\MsMpEng.exe")
        [void](New-NetFirewallRule -GPOSession $GpoSession -Name "{fabd86d5-92b1-4a15-b733-23$GuidComponent}" -DisplayName "Network Realtime Inspection Service $PlatformVersion (TCP-Out)" -Group "OutboundProxyServers" -Profile "Domain" -Direction "Outbound" -RemoteAddress $ProxyServers -Protocol "TCP" -RemotePort $ProxyServerPorts -Program "%ALLUSERSPROFILE%\Microsoft\Windows Defender\Platform\$PlatformVersion\NisSrv.exe")
        [void](New-NetFirewallRule -GPOSession $GpoSession -Name "{4b36d08c-cf11-41e2-8d9d-80$GuidComponent}" -DisplayName "Microsoft Malware Protection Command Line Utility $PlatformVersion (TCP-Out)" -Group "OutboundProxyServers" -Profile "Domain" -Direction "Outbound" -RemoteAddress $ProxyServers -Protocol "TCP" -RemotePort $ProxyServerPorts -Program "%ALLUSERSPROFILE%\Microsoft\Windows Defender\Platform\$PlatformVersion\MpCmdRun.exe")
        [void](New-NetFirewallRule -GPOSession $GpoSession -Name "{bd20eef3-283e-4fa1-ab43-47$GuidComponent}" -DisplayName "Microsoft Malware Protection Command Line Utility $PlatformVersion (TCP-Out)" -Direction "Outbound" -Protocol "TCP" -RemotePort "443" -Program "%ALLUSERSPROFILE%\Microsoft\Windows Defender\Platform\$PlatformVersion\MpCmdRun.exe")
        [void](New-NetFirewallRule -GPOSession $GpoSession -Name "{65c13740-9290-4caf-bd37-ac$GuidComponent}" -DisplayName "Microsoft Malware Protection Command Line Utility $PlatformVersion (TCP-Out)" -Group "OutboundWpad_PacFileServers" -Profile "Domain" -Direction "Outbound" -RemoteAddress $Wpad_PacFileServers -Protocol "TCP" -RemotePort "80" -Program "%ALLUSERSPROFILE%\Microsoft\Windows Defender\Platform\$PlatformVersion\MpCmdRun.exe")
        Write-Progress -Activity "Applying version 0.8.0 updates - creating new rules" -id 1 -PercentComplete "50"
        $PlatformVersion =  "4.18.1806.18062-0"
        $GuidComponent = $PlatformVersion.Split(".-")
        $GuidComponent = $GuidComponent[2] + $GuidComponent[3]
        [void](New-NetFirewallRule -GPOSession $GpoSession -Name "{725a67e5-68cd-4217-a159-48c$GuidComponent}" -DisplayName "Antimalware Service Executable $PlatformVersion (TCP-Out)" -Group "OutboundProxyServers" -Profile "Domain" -Direction "Outbound" -RemoteAddress $ProxyServers -Protocol "TCP" -RemotePort $ProxyServerPorts -Program "%ALLUSERSPROFILE%\Microsoft\Windows Defender\Platform\$PlatformVersion\MsMpEng.exe")
        [void](New-NetFirewallRule -GPOSession $GpoSession -Name "{e92e00fa-918f-4e62-bd3e-a91$GuidComponent}" -DisplayName "Antimalware Service Executable $PlatformVersion (TCP-Out)" -Direction "Outbound" -Protocol "TCP" -RemotePort "80","443" -Program "%ALLUSERSPROFILE%\Microsoft\Windows Defender\Platform\$PlatformVersion\MsMpEng.exe")
        [void](New-NetFirewallRule -GPOSession $GpoSession -Name "{fabd86d5-92b1-4a15-b733-233$GuidComponent}" -DisplayName "Network Realtime Inspection Service $PlatformVersion (TCP-Out)" -Group "OutboundProxyServers" -Profile "Domain" -Direction "Outbound" -RemoteAddress $ProxyServers -Protocol "TCP" -RemotePort $ProxyServerPorts -Program "%ALLUSERSPROFILE%\Microsoft\Windows Defender\Platform\$PlatformVersion\NisSrv.exe")
        [void](New-NetFirewallRule -GPOSession $GpoSession -Name "{4b36d08c-cf11-41e2-8d9d-803$GuidComponent}" -DisplayName "Microsoft Malware Protection Command Line Utility $PlatformVersion (TCP-Out)" -Group "OutboundProxyServers" -Profile "Domain" -Direction "Outbound" -RemoteAddress $ProxyServers -Protocol "TCP" -RemotePort $ProxyServerPorts -Program "%ALLUSERSPROFILE%\Microsoft\Windows Defender\Platform\$PlatformVersion\MpCmdRun.exe")
        [void](New-NetFirewallRule -GPOSession $GpoSession -Name "{bd20eef3-283e-4fa1-ab43-471$GuidComponent}" -DisplayName "Microsoft Malware Protection Command Line Utility $PlatformVersion (TCP-Out)" -Direction "Outbound" -Protocol "TCP" -RemotePort "443" -Program "%ALLUSERSPROFILE%\Microsoft\Windows Defender\Platform\$PlatformVersion\MpCmdRun.exe")
        [void](New-NetFirewallRule -GPOSession $GpoSession -Name "{65c13740-9290-4caf-bd37-ac0$GuidComponent}" -DisplayName "Microsoft Malware Protection Command Line Utility $PlatformVersion (TCP-Out)" -Group "OutboundWpad_PacFileServers" -Profile "Domain" -Direction "Outbound" -RemoteAddress $Wpad_PacFileServers -Protocol "TCP" -RemotePort "80" -Program "%ALLUSERSPROFILE%\Microsoft\Windows Defender\Platform\$PlatformVersion\MpCmdRun.exe")
        Write-Progress -Activity "Applying version 0.8.0 updates - creating new rules" -id 1 -Completed
        Write-Output "`n`nVersion 0.8.0 update to create new rules has completed"
    }
    Write-Progress -Activity "Applying version 0.8.0 updates" -Completed
}

function Version081Updates
{
    $PlatformVersion =  "4.18.1807.18075-0"
    $GuidComponent = $PlatformVersion.Split(".-")
    $GuidComponent = $GuidComponent[2] + $GuidComponent[3]
    Write-Progress -Activity "Applying version 0.8.1 updates - creating new rules" -PercentComplete "1"
    [void](New-NetFirewallRule -GPOSession $GpoSession -Name "{725a67e5-68cd-4217-a159-48c$GuidComponent}" -DisplayName "Antimalware Service Executable $PlatformVersion (TCP-Out)" -Group "OutboundProxyServers" -Profile "Domain" -Direction "Outbound" -RemoteAddress $ProxyServers -Protocol "TCP" -RemotePort $ProxyServerPorts -Program "%ALLUSERSPROFILE%\Microsoft\Windows Defender\Platform\$PlatformVersion\MsMpEng.exe" -ErrorAction SilentlyContinue -ErrorVariable "Version081Updates")
    if ($Version081Updates.Exception.Message -like "Cannot create a file when that file already exists.*")
    {
        Write-Progress -Activity "Applying version 0.8.1 updates - creating new rules" -Completed
        Write-warning "Version 0.8.1 new rules have been found, aborting new rule creation."
    }
    else
    {
        Write-Progress -Activity "Applying version 0.8.1 updates - creating new rules" -PercentComplete "50"
        [void](New-NetFirewallRule -GPOSession $GpoSession -Name "{e92e00fa-918f-4e62-bd3e-a91$GuidComponent}" -DisplayName "Antimalware Service Executable $PlatformVersion (TCP-Out)" -Direction "Outbound" -Protocol "TCP" -RemotePort "80","443" -Program "%ALLUSERSPROFILE%\Microsoft\Windows Defender\Platform\$PlatformVersion\MsMpEng.exe")
        [void](New-NetFirewallRule -GPOSession $GpoSession -Name "{fabd86d5-92b1-4a15-b733-233$GuidComponent}" -DisplayName "Network Realtime Inspection Service $PlatformVersion (TCP-Out)" -Group "OutboundProxyServers" -Profile "Domain" -Direction "Outbound" -RemoteAddress $ProxyServers -Protocol "TCP" -RemotePort $ProxyServerPorts -Program "%ALLUSERSPROFILE%\Microsoft\Windows Defender\Platform\$PlatformVersion\NisSrv.exe")
        [void](New-NetFirewallRule -GPOSession $GpoSession -Name "{4b36d08c-cf11-41e2-8d9d-803$GuidComponent}" -DisplayName "Microsoft Malware Protection Command Line Utility $PlatformVersion (TCP-Out)" -Group "OutboundProxyServers" -Profile "Domain" -Direction "Outbound" -RemoteAddress $ProxyServers -Protocol "TCP" -RemotePort $ProxyServerPorts -Program "%ALLUSERSPROFILE%\Microsoft\Windows Defender\Platform\$PlatformVersion\MpCmdRun.exe")
        [void](New-NetFirewallRule -GPOSession $GpoSession -Name "{bd20eef3-283e-4fa1-ab43-471$GuidComponent}" -DisplayName "Microsoft Malware Protection Command Line Utility $PlatformVersion (TCP-Out)" -Direction "Outbound" -Protocol "TCP" -RemotePort "443" -Program "%ALLUSERSPROFILE%\Microsoft\Windows Defender\Platform\$PlatformVersion\MpCmdRun.exe" )
        [void](New-NetFirewallRule -GPOSession $GpoSession -Name "{65c13740-9290-4caf-bd37-ac0$GuidComponent}" -DisplayName "Microsoft Malware Protection Command Line Utility $PlatformVersion (TCP-Out)" -Group "OutboundWpad_PacFileServers" -Profile "Domain" -Direction "Outbound" -RemoteAddress $Wpad_PacFileServers -Protocol "TCP" -RemotePort "80" -Program "%ALLUSERSPROFILE%\Microsoft\Windows Defender\Platform\$PlatformVersion\MpCmdRun.exe")
        Write-Progress -Activity "Applying version 0.8.1 updates - creating new rules" -Completed
        Write-Output "`n`nVersion 0.8.1 update to create new rules has completed"
    }
    Write-Progress -Activity "Applying version 0.8.1 updates - creating new rules" -Completed
}

function Version082Updates
{
    $PlatformVersion =  "4.18.1809.2-0"
    $GuidComponent = $PlatformVersion.Split(".-")
    $GuidComponent = $GuidComponent[2].PadLeft(5,"0") + $GuidComponent[3].PadLeft(5,"0")
    Write-Progress -Activity "Applying version 0.8.2 updates - creating new rules" -PercentComplete "1"
    [void](New-NetFirewallRule -GPOSession $GpoSession -Name "{725a67e5-68cd-4217-a159-48$GuidComponent}" -DisplayName "Antimalware Service Executable $PlatformVersion (TCP-Out)" -Group "OutboundProxyServers" -Profile "Domain" -Direction "Outbound" -RemoteAddress $ProxyServers -Protocol "TCP" -RemotePort $ProxyServerPorts -Program "%ALLUSERSPROFILE%\Microsoft\Windows Defender\Platform\$PlatformVersion\MsMpEng.exe" -ErrorAction SilentlyContinue -ErrorVariable "Version082Updates")
    if ($Version082Updates.Exception.Message -like "Cannot create a file when that file already exists.*")
    {
        Write-Progress -Activity "Applying version 0.8.2 updates - creating new rules" -Completed
        Write-warning "Version 0.8.2 new rules have been found, aborting new rule creation."
    }
    else
    {
        Write-Progress -Activity "Applying version 0.8.2 updates - creating new rules" -PercentComplete "50"
        [void](New-NetFirewallRule -GPOSession $GpoSession -Name "{e92e00fa-918f-4e62-bd3e-a9$GuidComponent}" -DisplayName "Antimalware Service Executable $PlatformVersion (TCP-Out)" -Direction "Outbound" -Protocol "TCP" -RemotePort "80","443" -Program "%ALLUSERSPROFILE%\Microsoft\Windows Defender\Platform\$PlatformVersion\MsMpEng.exe")
        [void](New-NetFirewallRule -GPOSession $GpoSession -Name "{fabd86d5-92b1-4a15-b733-23$GuidComponent}" -DisplayName "Network Realtime Inspection Service $PlatformVersion (TCP-Out)" -Group "OutboundProxyServers" -Profile "Domain" -Direction "Outbound" -RemoteAddress $ProxyServers -Protocol "TCP" -RemotePort $ProxyServerPorts -Program "%ALLUSERSPROFILE%\Microsoft\Windows Defender\Platform\$PlatformVersion\NisSrv.exe")
        [void](New-NetFirewallRule -GPOSession $GpoSession -Name "{4b36d08c-cf11-41e2-8d9d-80$GuidComponent}" -DisplayName "Microsoft Malware Protection Command Line Utility $PlatformVersion (TCP-Out)" -Group "OutboundProxyServers" -Profile "Domain" -Direction "Outbound" -RemoteAddress $ProxyServers -Protocol "TCP" -RemotePort $ProxyServerPorts -Program "%ALLUSERSPROFILE%\Microsoft\Windows Defender\Platform\$PlatformVersion\MpCmdRun.exe")
        [void](New-NetFirewallRule -GPOSession $GpoSession -Name "{bd20eef3-283e-4fa1-ab43-47$GuidComponent}" -DisplayName "Microsoft Malware Protection Command Line Utility $PlatformVersion (TCP-Out)" -Direction "Outbound" -Protocol "TCP" -RemotePort "443" -Program "%ALLUSERSPROFILE%\Microsoft\Windows Defender\Platform\$PlatformVersion\MpCmdRun.exe" )
        [void](New-NetFirewallRule -GPOSession $GpoSession -Name "{65c13740-9290-4caf-bd37-ac$GuidComponent}" -DisplayName "Microsoft Malware Protection Command Line Utility $PlatformVersion (TCP-Out)" -Group "OutboundWpad_PacFileServers" -Profile "Domain" -Direction "Outbound" -RemoteAddress $Wpad_PacFileServers -Protocol "TCP" -RemotePort "80" -Program "%ALLUSERSPROFILE%\Microsoft\Windows Defender\Platform\$PlatformVersion\MpCmdRun.exe")
        Write-Progress -Activity "Applying version 0.8.2 updates - creating new rules" -Completed
        Write-Output "`n`nVersion 0.8.2 update to create new rules has completed"
    }
    Write-Progress -Activity "Applying version 0.8.2 updates - creating new rules" -Completed
}

function SaveGpo
{
$SaveGpo = Start-Job -ScriptBlock {Save-NetGPO -GPOSession $args[0]} -ArgumentList $GpoSession #Bug in PWSH 5.1.17134.165 (1803) prevents the interactive use of $Using:
do
{
    $IndexNumber ++
    $CharacterArray = ("----------                             ").ToCharArray()
    Write-Progress -Activity "Saving group policy object back to the domain" -Status ([string]($CharacterArray[-$IndexNumber..($CharacterArray.Count - $IndexNumber)]))
    start-sleep -Milliseconds 500
    if ($IndexNumber -eq $CharacterArray.Count)
    {
        $IndexNumber = 0
    }
}
while ($SaveGpo.State -eq "Running")
$SaveGpo |Receive-Job -Keep
}

function DefineExistingRulesGroups
{
$InboundBackupServersRules = 
"{C245295B-F872-4582-8D46-4D16FC51C59C}"

$OutboundProxyServersRules = 
"{25C5B199-A7D0-47F0-9FE9-DB865ED8F81E}",
"{C3C97E3E-8B01-43E7-BD74-4ED58078EB5F}",
"{8283667D-A196-4B01-8D72-9F29216FF662}",
"{DC50E65E-F97A-4732-B105-5C501923B34B}",
"{487682B5-C30A-4137-8086-C2815809706A}",
"{F045E216-AA87-4FAB-A5B5-E17A0DB06DA5}",
"{529CF5BF-C0F7-4937-AF50-BDEE125792EB}",
"{021B839E-B818-446C-BC2F-8B58D371E609}",
"{8CDFE99B-E2E5-417A-9166-B5BDF815C19E}",
"{AC498E56-C4D3-4006-B0EA-7F8781BEDCE5}",
"{71A9E996-5EB1-4A2B-B69A-81216B149B1A}",
"{3CDDA904-F0F1-4889-A9B3-FDC2A4A52EF8}",
"{9671EB76-EEE2-4A48-A25B-FCB62D0C68CD}",
"{3557218E-C9B3-4398-B0E0-BC3FA10DB76C}",
"{9DA4A1C8-E145-4D70-98F4-236A90DB53D7}",
"{24640B17-6FC7-4E4C-A6ED-ECDDD6DE9D5B}",
"{64B3B85A-4716-4F83-A77B-5FE3487B80ED}",
"{C3DDF046-BB17-4F73-825A-D5AEB9125BE9}",
"{268553D7-EB7B-4003-8158-22AF750240FD}",
"{1B3D771D-0D1D-4247-BA97-19357648C439}",
"{86001CC7-7554-49DE-9F47-023540B9FD0C}",
"{CFD89AD8-AE18-412C-9E4F-24E8B39801FD}",
"{EAAC634E-2E0F-43D3-A104-02A4C4543EBB}",
"{E6FDD82B-6B1A-4CB9-82FB-74AB232F1D39}",
"{FE79F702-5E3F-4498-909B-C2B78C0A8D4A}",
"{4D66D753-FEAB-470E-975F-C2789912132F}",
"{6F74C19E-8B01-4A3F-9D6E-3DD629CE138D}",
"{72F7F255-42DA-4BE0-BAC4-7168798D1731}",
"{305D7555-6BDF-42AF-8CCD-BA50748642BF}",
"{FDA7F3F5-D1F9-4A1B-9F11-2427A4325FEC}",
"{AC2E7A6D-32E7-46E3-AC3C-D945B9CA4926}",
"{9F866747-18B8-4539-B7A4-CBFAC941AA41}",
"{8571CCC3-5D33-46B2-B046-D91895C51BEF}"
              
$OutboundDomainControllersRules = 
"{667F71F3-512A-4004-832F-37A1F04E8B37}",
"{E5102F82-3E96-43A1-A594-0ED82B5946B3}",
"{A2E68AF0-EAC7-4AAF-A337-821AB4100AF2}",
"{87FC29B6-C496-415A-AA86-806E2E1910D4}",
"{88205410-9317-4AD3-9FA7-EAEBF0B9D6E5}",
"{FA542913-DECD-4F46-86E1-9108CC3B9404}",
"{D5BF897C-86AA-4D24-808D-27CE7ADF9ECF}",
"{6A7837C1-5283-4430-94B3-9B4D02119703}",
"{EAC8E3B5-5C94-4F18-AAD7-B8FC2DA847FE}"
    
$OutboundKeyManagementServersRules = 
"{7A3D1F5E-89CE-4226-B73F-8243F3002634}"

$OutboundCRLServersRules = 
"{9EFABED8-AEB9-47CD-8D28-FFE914769085}",
"{22F125A5-55A4-4146-852E-641179E2AD3B}"
}

foreach ($Resource in $Resources)
{
    $ResourceIndex ++
    Write-Progress -Activity "Updating resource arrays" -Status "$Resource" -PercentComplete ($ResourceIndex*(100/$Resources.Count))
    $Addresses = @()
    $Names = (Get-Variable -Name $Resource).Value
    foreach ($Name in $Names.replace(" ",""))
    {
        switch -Wildcard ($Name)
        {
            "*/*"           {
                                $Addresses += $Name # A forward slash indicates a subnet has been specified
                                break
                            }
            "LocalSubnet"   {
                                $Addresses += $Name
                                break
                            }
            "Intranet"      {
                                $Addresses += $Name
                                break
                            }
            "DNS"           {
                                $Addresses += $Name
                                break
                            }
            "DHCP"          {
                                $Addresses += $Name
                                break
                            }
            "DefaultGateway"{
                                $Addresses += $Name
                                break
                            }
            "Internet"      {
                                $Addresses += $Name
                                break
                            }
            "Any"           {
                                $Addresses += $Name
                                break
                            }
            "*-*"           {
                                try
                                {
                                    if ([ipaddress]$Name.Split("-")[0] -and [ipaddress]$Name.Split("-")[1])
                                    {
                                        $Addresses += $Name # If each side of the hyphen is an IP address then a range has been specified
                                    }
                                }
                                catch [Management.Automation.PSInvalidCastException]
                                {
                                    . AttemptResolveDnsName $Name
                                }
                            }
            default         {
                                try
                                {
                                    if ([ipaddress]$Name)
                                    {
                                        $Addresses += $Name
                                    }
                                }
                                catch [Management.Automation.PSInvalidCastException]
                                {
                                    . AttemptResolveDnsName $Name
                                }
                            }
        }
    }
    Set-Variable -Name $Resource -Value $Addresses
}
Write-Progress -Activity "Updating resource arrays" -Completed
Remove-Variable ResourceIndex

if (Get-GPO -DisplayName $TargetGpoName -ErrorAction SilentlyContinue)
{
    $GpoSession = Open-NetGPO -PolicyStore "$DomainName\$TargetGpoName"
    Write-Output "`n`nThe GPO already exists."
    do
    {
        do
        {
            Write-Progress -Activity "Awaiting user input"
            Write-Output "`n`nA - Apply version 0.8.0 updates`n"
            Write-Output "B - Apply version 0.8.1 updates`n"
            Write-Output "C - Apply version 0.8.2 updates`n"
            Write-Output "U - Update all domain resource IP addresses in the existing rules (post version 0.8.0 only)`n"
            Write-Output "X - Exit and save the GPO back to the domain`n"
            $Choice = Read-Host -Prompt "Type your choice and press Enter"
            $Okay = $Choice -match "^[abcux]+$"
            if (-not $Okay) {Write-Output "`n`nInvalid selection"}
        }
        until ($Okay)
        switch -Regex ($Choice)
        {
            "A"
            {
                Write-Progress -Activity "Awaiting user input" -Completed
                . DefineExistingRulesGroups
                . Version080Updates
                break
            }
            "B"
            {
                Write-Progress -Activity "Awaiting user input" -Completed
                . DefineExistingRulesGroups
                . Version081Updates
                break
            }
            "C"
            {
                Write-Progress -Activity "Awaiting user input" -Completed
                . DefineExistingRulesGroups
                . Version082Updates
                break
            }
            "U"
            {
                Write-Progress -Activity "Awaiting user input" -Completed
                try
                {
                Write-Progress -Activity "Updating existing rules" -PercentComplete "1"
                Set-NetFirewallRule -Group "InboundBackupServers" -GPOSession $GpoSession -RemoteAddress $BackupServers -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
                Write-Progress -Activity "Updating existing rules" -PercentComplete "10"
                Set-NetFirewallRule -Group "OutboundProxyServers" -GPOSession $GpoSession -RemoteAddress $ProxyServers -RemotePort $ProxyServerPorts -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
                Write-Progress -Activity "Updating existing rules" -PercentComplete "40"
                Set-NetFirewallRule -Group "OutboundDomainControllers" -GPOSession $GpoSession -RemoteAddress $DomainControllers -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
                Write-Progress -Activity "Updating existing rules" -PercentComplete "70"
                Set-NetFirewallRule -Group "OutboundKeyManagementServers" -GPOSession $GpoSession -RemoteAddress $KeyManagementServers -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
                Write-Progress -Activity "Updating existing rules" -PercentComplete "80"
                Set-NetFirewallRule -Group "OutboundCrlServers" -GPOSession $GpoSession -RemoteAddress $CrlServers -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
                Write-Progress -Activity "Updating existing rules" -PercentComplete "90"
                Set-NetFirewallRule -Group "OutboundWpad_PacFileServers" -GPOSession $GpoSession -RemoteAddress $Wpad_PacFileServers -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
                Write-Progress -Activity "Updating existing rules" -Completed
                Write-Output "`n`nExisting rules update completed."
                break
                }
                catch [Microsoft.Management.Infrastructure.CimException]
                {
                    Write-Progress -Activity "Updating existing rules" -Completed
                    . CimExceptionUpdatingExistingRules
                }
                catch
                {
                    Write-Progress -Activity "Updating existing rules" -Completed
                    . UnknownErrorUpdatingExistingRules
                }
            }
        }
    }
    until ( $Choice -match "X" )
    Write-Progress -Activity "Awaiting user input" -Completed
    . SaveGpo
    break
}

if (!(Test-Path "$PathToGpoBackups\manifest.xml" -ErrorAction SilentlyContinue))
{
    Write-Warning "The GPO backups cannot be found, please ensure the backup zip file has been downloaded and extracted to $PathToGpoBackups"
    break
}

$ImportGpo = Start-Job -ScriptBlock {Import-GPO -BackupId $args[0] -Path $args[1] -TargetName $args[2] -CreateIfNeeded -ErrorAction Stop} -ArgumentList $SourceGpoBackupId,$PathToGpoBackups,$TargetGpoName #Bug in PWSH 5.1.17134.165 (1803) prevents the interactive use of $Using:
do
{
    $IndexNumber ++
    $CharacterArray = ("----------                             ").ToCharArray()
    Write-Progress -Activity "Importing group policy object" -Status ([string]($CharacterArray[-$IndexNumber..($CharacterArray.Count - $IndexNumber)]))
    start-sleep -Milliseconds 500
    if ($IndexNumber -eq $CharacterArray.Count)
    {
        $IndexNumber = 0
    }
}
while ($ImportGpo.State -eq "Running")
$ImportGpo |Receive-Job -Keep
if (($ImportGpo |Receive-Job -Keep).DisplayName -ne $TargetGpoName)
{
    Write-Output "An error has beeen encountered in the GPO restore job."
    break
}
Write-Progress -Activity "Importing group policy object" -Completed

$GpoSession = Open-NetGPO -PolicyStore "$DomainName\$TargetGpoName"
. DefineExistingRulesGroups
foreach ($InboundBackupServerRule in $InboundBackupServersRules)
{
    Write-Progress -Activity "Updating restored rules" -Status "Backup server rules" -PercentComplete "1"
    Set-NetFirewallRule -Name $InboundBackupServerRule -GPOSession $GpoSession -RemoteAddress $BackupServers
}
foreach ($OutboundProxyServersRule in $OutboundProxyServersRules)
{
    Write-Progress -Activity "Updating restored rules" -Status "Proxy server rules" -PercentComplete "10"
    Set-NetFirewallRule -Name $OutboundProxyServersRule -GPOSession $GpoSession -RemoteAddress $ProxyServers -RemotePort $ProxyServerPorts
}
foreach ($OutboundDomainControllersRule in $OutboundDomainControllersRules)
{
    Write-Progress -Activity "Updating restored rules" -Status "Domain controller rules" -PercentComplete "50"
    Set-NetFirewallRule -Name $OutboundDomainControllersRule -GPOSession $GpoSession -RemoteAddress $DomainControllers
}
foreach ($OutboundKeyManagementServersRule in $OutboundKeyManagementServersRules)
{
    Write-Progress -Activity "Updating restored rules" -Status "key management server rules" -PercentComplete "90"
    Set-NetFirewallRule -Name $OutboundKeyManagementServersRule -GPOSession $GpoSession -RemoteAddress $KeyManagementServers
}
foreach ($OutboundCrlServersRule in $OutboundCrlServersRules)
{
    Write-Progress -Activity "Updating restored rules" -Status "CRL server rules" -PercentComplete "95"
    Set-NetFirewallRule -Name $OutboundCrlServersRule -GPOSession $GpoSession -RemoteAddress $CrlServers
}
Write-Progress -Activity "Updating restored rules" -Completed
. Version080Updates
. Version081Updates
. Version082Updates
. SaveGpo
