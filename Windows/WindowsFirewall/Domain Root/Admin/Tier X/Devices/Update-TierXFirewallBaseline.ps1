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
   0.7.0   Initial release
   0.8.0   Added existing rule update function (using the "Group" parameter of rules), moved code blocks around, added new firewall rules, updated WMIPRVSE (TCP-Out) firewall rule, added progress bars, added some error handling and updated comments.
   0.8.1   No changes in this script
   0.8.2   No changes in this script
.EXAMPLE
   $TargetGpoName = "Tier 0 Firewall Baseline"
   $PathToGpoBackups = "C:\Temp\WindowsFirewall-GPO"
   $ProxyServers = "2a02:cc9:7732:5500::1","fd4e:eaa9:897b::1","172.19.110.1"
.EXAMPLE
   $TargetGpoName = "Tier 0 Firewall Baseline"
   $PathToGpoBackups = "C:\Temp\WindowsFirewall-GPO"
   $ProxyServers = "proxy.mydomain.local","172.19.110.15","proxy-server3"
.EXAMPLE
   $TargetGpoName = "Tier 0 Firewall Baseline"
   $PathToGpoBackups = "C:\Temp\WindowsFirewall-GPO"
   $ProxyServers = "10.10.10.0/24","proxy2","10.10.11.100-10.10.11.149"
#>

$SourceGpoBackupId = "{7a3ae19b-11be-4cf7-a078-15c03a897e90}" # Do not modify this
$TargetGpoName = "SN-Tier X Firewall Baseline"
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
        foreach ($InboundTierXManagementServersRule in $InboundTierXManagementServersRules)
        {
            Write-Progress -Activity "Applying version 0.8.0 updates - updating existing rules" -id 1 -PercentComplete "1"
            $Rule = Get-NetFirewallRule -Name $InboundTierXManagementServersRule -GPOSession $GpoSession
            $Rule.Group = "InboundTierXManagementServers"
            Set-NetFirewallRule -InputObject $Rule -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
        }
        foreach ($OutboundProxyServersRule in $OutboundProxyServersRules)
        {
            Write-Progress -Activity "Applying version 0.8.0 updates - updating existing rules" -id 1 -PercentComplete "10"
            $Rule = Get-NetFirewallRule -Name $OutboundProxyServersRule -GPOSession $GpoSession
            $Rule.Group = "OutboundProxyServers"
            Set-NetFirewallRule -InputObject $Rule -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
        }
        Write-Progress -Activity "Applying version 0.8.0 updates" -PercentComplete 25
        foreach ($OutboundDomainControllersRule in $OutboundDomainControllersRules)
        {
            Write-Progress -Activity "Applying version 0.8.0 updates - updating existing rules" -id 1 -PercentComplete "40"
            $Rule = Get-NetFirewallRule -Name $OutboundDomainControllersRule -GPOSession $GpoSession
            $Rule.Group = "OutboundDomainControllers"
            Set-NetFirewallRule -InputObject $Rule -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
        }
        foreach ($OutboundWebServersRule in $OutboundWebServersRules)
        {
            Write-Progress -Activity "Applying version 0.8.0 updates - updating existing rules" -id 1 -PercentComplete "70"
            $Rule = Get-NetFirewallRule -Name $OutboundWebServersRule -GPOSession $GpoSession
            $Rule.Group = "OutboundWebServers"
            Set-NetFirewallRule -InputObject $Rule -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
        }
        foreach ($InboundExternalVPNEndpointsRule in $InboundExternalVPNEndpointsRules)
        {
            Write-Progress -Activity "Applying version 0.8.0 updates - updating existing rules" -id 1 -PercentComplete "75"
            $Rule = Get-NetFirewallRule -Name $InboundExternalVPNEndpointsRule -GPOSession $GpoSession
            $Rule.Group = "InboundExternalVPNEndpoints"
            Set-NetFirewallRule -InputObject $Rule -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
        }
        foreach ($OutboundExternalVPNEndpointsRule in $OutboundExternalVPNEndpointsRules)
        {
            Write-Progress -Activity "Applying version 0.8.0 updates - updating existing rules" -id 1 -PercentComplete "80"
            $Rule = Get-NetFirewallRule -Name $OutboundExternalVPNEndpointsRule -GPOSession $GpoSession
            $Rule.Group = "OutboundExternalVPNEndpoints"
            Set-NetFirewallRule -InputObject $Rule -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
        }
        foreach ($OutboundDirectAccessServersRule in $OutboundDirectAccessServersRules)
        {
            Write-Progress -Activity "Applying version 0.8.0 updates - updating existing rules" -id 1 -PercentComplete "85"
            $Rule = Get-NetFirewallRule -Name $OutboundDirectAccessServersRule -GPOSession $GpoSession
            $Rule.Group = "OutboundDirectAccessServers"
            Set-NetFirewallRule -InputObject $Rule -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
        }
        foreach ($OutboundCRLServersRule in $OutboundCRLServersRules)
        {
            Write-Progress -Activity "Applying version 0.8.0 updates - updating existing rules" -id 1 -PercentComplete "90"
            $Rule = Get-NetFirewallRule -Name $OutboundCRLServersRule -GPOSession $GpoSession
            $Rule.Group = "OutboundCRLServers"
            Set-NetFirewallRule -InputObject $Rule -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
        }
        foreach ($OutboundWPAD_PACFileServersRule in $OutboundWPAD_PACFileServersRules)
        {
            Write-Progress -Activity "Applying version 0.8.0 updates - updating existing rules" -id 1 -PercentComplete "95"
            $Rule = Get-NetFirewallRule -Name $OutboundWPAD_PACFileServersRule -GPOSession $GpoSession
            $Rule.Group = "OutboundWPAD_PACFileServers"
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
    [void](New-NetFirewallRule -GPOSession $GpoSession -Name "{19e95b85-df9e-4f10-bf7c-afb3b95a5ad4}" -DisplayName "SVCHOST IKEEXT (UDP-Out)" -Group "OutboundExternalVPNEndpoints" -Enabled True -Profile Any -Direction Outbound -Action Allow -RemoteAddress $ExternalVPNEndpoints -Protocol UDP -RemotePort "500","4500" -Program "%SystemRoot%\System32\svchost.exe" -Service "IKEEXT" -ErrorAction SilentlyContinue -ErrorVariable "Version080Updates")
    if ($Version080Updates.Exception.Message -like "Cannot create a file when that file already exists.*")
    {
        Write-Progress -Activity "Applying version 0.8.0 updates - creating new rules" -id 1 -Completed
        Write-warning "Version 0.8.0 new rules have been found, aborting new rule creation."
    }
    else
    {
        Write-Progress -Activity "Applying version 0.8.0 updates - creating new rules" -id 1 -PercentComplete "50"
        [void](Get-NetFirewallRule -GPOSession $GpoSession -Name "{7A6C16B1-8717-41FD-848F-3133EABD0457}"|Get-NetFirewallPortFilter|Set-NetFirewallPortFilter -RemotePort "135","389","49152-65535") # Adding "49152-65535" to the remote ports in the WMIPRVSE (TCP-Out) rule
        Write-Progress -Activity "Applying version 0.8.0 updates - creating new rules" -id 1 -Completed
        Write-Output "`n`nVersion 0.8.0 update to create new rules has completed"
    }
    Write-Progress -Activity "Applying version 0.8.0 updates" -Completed
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
    $InboundTierXManagementServersRules = 
    "{B29AA00C-5CD1-4C86-B9F6-B24B3A652988}",
    "{B8DD676D-8553-4980-95FE-494171CA9353}",
    "{FC8B55E2-C3D2-4636-B6DA-5AF13F451B54}",
    "{C4476117-3D16-44E4-A89E-802D59429288}",
    "{973282B3-4D8A-4D77-8966-86C8A69A9D19}",
    "{0B7482C6-20B3-4F22-9F5D-4CBE0E41C4D5}",
    "{6E3791DE-11FA-4DEB-A87F-C895EB2C504A}",
    "{6F40346F-5FD5-467E-8C6C-B2ADD07DF5F9}",
    "{FF84E440-7B62-416B-B292-E22E757A2CCD}",
    "{CF2FC131-9A7C-43DC-9878-2BB78299FF31}",
    "{77F84D98-B590-41C9-954E-A922A789051F}",
    "{638F4F3A-870F-48BD-8CBF-2ED3D6CEE139}",
    "{278BE209-481F-44C0-BBCB-43AC665C9BED}",
    "{9C1E3A01-772F-4AA1-A36B-3C476B1D8069}",
    "{ECECE424-68BD-4057-8128-09FB41DF9AA3}"

    $OutboundProxyServersRules = 
    "{1CFA6C32-1C0C-44E9-8940-6578BC1DEBF6}",
    "{4D896BF4-2276-4DAB-A19D-12A438032CD3}",
    "{C356494C-8B03-49EA-86C9-6284959BEC0A}",
    "{F287CDD7-2E2D-4FC2-8153-FCE73D703F8C}",
    "{2BEED6C6-071D-4684-80A5-FCBA127AB3B8}",
    "{7B0A3582-A19F-41FE-8837-7F064EEBAC04}",
    "{1A884C71-20C9-4292-8F60-AC38222CA24D}",
    "{457BF377-745C-4B3B-9732-6523A84D96C5}",
    "{7855BBE0-8076-4D3C-A564-0BBF43D78310}"
        
    $OutboundDomainControllersRules = 
    "{1D5BB1AD-562A-4800-8D70-60BF0EF10531}",
    "{CF6963D8-8CCF-4580-B78A-8644F0F7D982}",
    "{45A03958-622B-4EBB-A27A-4EAE36EB2041}",
    "{1A1361E7-36E8-4022-8E88-4B51284FEF0E}",
    "{FBB4F6B7-F429-488E-B31C-0FD7AAFC657A}",
    "{DAEE009A-18CA-48FF-A4A6-C6C411577EDC}",
    "{ACA17873-D36F-4F9E-BFCC-F825E8244DFF}",
    "{F7C578F3-8346-450D-8322-9AB02E56B89C}",
    "{8800EFBD-8FBD-409E-9AEF-EF3B9A36D0CF}",
    "{7A3C4D61-E4D9-4425-AAC3-D2F26CDDC2D3}",
    "{F09FE220-2FE7-441E-B1DD-FBFD5AABF401}",
    "{AB948056-1926-4E38-815A-6F0DB9047F91}",
    "{D8DB381C-086F-4066-A134-8A4A9DF70AE0}",
    "{368DFBD9-C088-44E8-9E57-E1934B40033A}",
    "{FF1BD86E-7BE2-41AB-A51D-3E8F5858C29F}",
    "{78B9E45C-C680-4F2F-9C57-4A988D886F3D}",
    "{5062521C-789F-43A3-8EBC-E988387369E1}",
    "{7A6C16B1-8717-41FD-848F-3133EABD0457}",
    "{BAE8ABC9-817E-48FE-A778-D380F3F052AD}"
    
    $OutboundWebServersRules = 
    "{AAD5C065-7043-474E-8976-185068D26C73}",
    "{6C4AC4AB-596F-4911-9E1F-3C064BF5882A}"
    
    $InboundExternalVPNEndpointsRules = 
    "{516B8181-6B67-4978-BCFB-C9A449C292D1}",
    "{6D8DA039-A3B1-41D0-98C9-F5D0C0753790}"
    
    $OutboundExternalVPNEndpointsRules = 
    "{D8576910-5D61-4060-AF86-4D4000C3269F}"

    $OutboundDirectAccessServersRules = 
    "{CED6EDCB-ACEC-40BE-AEE1-C564B93C6364}"

    $OutboundCRLServersRules = 
    "{CF5B99A7-1457-4A9A-ABE5-DDE18858905F}",
    "{5E8C4752-59D1-4667-A049-7BAA5AC7C558}",
    "{445A0F5B-A6B5-45DE-AA51-916C94DE2EF7}"

    $OutboundWPAD_PACFileServersRules = 
    "{C571942E-894A-4225-B9AD-348D859EA660}",
    "{65CA3A6B-7E05-4140-937E-825CC8F46188}",
    "{5094D28B-2740-4AE8-8697-84BB211C02A6}"
   
    $TrustedDHCPSubnetsRules =
    "{CF6963D8-8CCF-4580-B78A-8644F0F7D982}",
    "{1D5BB1AD-562A-4800-8D70-60BF0EF10531}",
    "{1A1361E7-36E8-4022-8E88-4B51284FEF0E}",
    "{45A03958-622B-4EBB-A27A-4EAE36EB2041}",
    "{CF5B99A7-1457-4A9A-ABE5-DDE18858905F}",
    "{ACA17873-D36F-4F9E-BFCC-F825E8244DFF}",
    "{C356494C-8B03-49EA-86C9-6284959BEC0A}",
    "{F287CDD7-2E2D-4FC2-8153-FCE73D703F8C}",
    "{2BEED6C6-071D-4684-80A5-FCBA127AB3B8}",
    "{7B0A3582-A19F-41FE-8837-7F064EEBAC04}",
    "{8800EFBD-8FBD-409E-9AEF-EF3B9A36D0CF}",
    "{7A3C4D61-E4D9-4425-AAC3-D2F26CDDC2D3}",
    "{F09FE220-2FE7-441E-B1DD-FBFD5AABF401}",
    "{AB948056-1926-4E38-815A-6F0DB9047F91}",
    "{D8DB381C-086F-4066-A134-8A4A9DF70AE0}",
    "{1A884C71-20C9-4292-8F60-AC38222CA24D}",
    "{368DFBD9-C088-44E8-9E57-E1934B40033A}",
    "{C571942E-894A-4225-B9AD-348D859EA660}",
    "{78B9E45C-C680-4F2F-9C57-4A988D886F3D}",
    "{FF1BD86E-7BE2-41AB-A51D-3E8F5858C29F}",
    "{5062521C-789F-43A3-8EBC-E988387369E1}",
    "{5E8C4752-59D1-4667-A049-7BAA5AC7C558}",
    "{65CA3A6B-7E05-4140-937E-825CC8F46188}",
    "{457BF377-745C-4B3B-9732-6523A84D96C5}",
    "{7855BBE0-8076-4D3C-A564-0BBF43D78310}",
    "{BAE8ABC9-817E-48FE-A778-D380F3F052AD}",
    "{5094D28B-2740-4AE8-8697-84BB211C02A6}",
    "{445A0F5B-A6B5-45DE-AA51-916C94DE2EF7}",
    "{7A6C16B1-8717-41FD-848F-3133EABD0457}"
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
            Write-Output "U - Update all domain resource IP addresses in the existing rules (post version 0.8.0 only)`n"
            Write-Output "X - Exit and save the GPO back to the domain`n"
            $Choice = Read-Host -Prompt "Type your choice and press Enter"
            $Okay = $Choice -match "^[aux]+$"
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
            "U"
            {
                Write-Progress -Activity "Awaiting user input" -Completed
                try
                {
                Write-Progress -Activity "Updating existing rules" -PercentComplete "1"
                Set-NetFirewallRule -Group "InboundTierXManagementServers" -GPOSession $GpoSession -RemoteAddress $TierXManagementServers -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
                Write-Progress -Activity "Updating existing rules" -PercentComplete "10"
                Set-NetFirewallRule -Group "OutboundProxyServers" -GPOSession $GpoSession -RemoteAddress $ProxyServers -RemotePort $ProxyServerPorts -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
                Write-Progress -Activity "Updating existing rules" -PercentComplete "35"
                Set-NetFirewallRule -Group "OutboundDomainControllers" -GPOSession $GpoSession -RemoteAddress $DomainControllers -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
                Write-Progress -Activity "Updating existing rules" -PercentComplete "55"
                Set-NetFirewallRule -Group "OutboundWebServers" -GPOSession $GpoSession -RemoteAddress $WebServers -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
                Write-Progress -Activity "Updating existing rules" -PercentComplete "70"
                Set-NetFirewallRule -Group "InboundExternalVPNEndpoints" -GPOSession $GpoSession -RemoteAddress $ExternalVPNEndpoints -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
                Write-Progress -Activity "Updating existing rules" -PercentComplete "75"
                Set-NetFirewallRule -Group "OutboundExternalVPNEndpoints" -GPOSession $GpoSession -RemoteAddress $ExternalVpnEndpoints -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
                Write-Progress -Activity "Updating existing rules" -PercentComplete "80"
                Set-NetFirewallRule -Group "OutboundDirectAccessServers" -GPOSession $GpoSession -RemoteAddress $DirectAccessServers -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
                Write-Progress -Activity "Updating existing rules" -PercentComplete "85"
                Set-NetFirewallRule -Group "OutboundCRLServers" -GPOSession $GpoSession -RemoteAddress $CRLServers -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
                Write-Progress -Activity "Updating existing rules" -PercentComplete "90"
                Set-NetFirewallRule -Group "OutboundWPAD_PACFileServers" -GPOSession $GpoSession -RemoteAddress $WPAD_PACFileServers -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
                Write-Progress -Activity "Updating existing rules" -PercentComplete "95"
                . DefineExistingRulesGroups
                foreach ($TrustedDHCPSubnetsRule in $TrustedDHCPSubnetsRules)
                {
                    Set-NetFirewallRule -Name $TrustedDHCPSubnetsRule -GPOSession $GpoSession -LocalAddress $TrustedDHCPSubnets -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
                }
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
foreach ($InboundTierXManagementServersRule in $InboundTierXManagementServersRules)
{
    Write-Progress -Activity "Updating restored rules" -Status "Tier management server rules" -PercentComplete "1"
    Set-NetFirewallRule -Name $InboundTierXManagementServersRule -GPOSession $GpoSession -RemoteAddress $TierXManagementServers
}
foreach ($OutboundProxyServersRule in $OutboundProxyServersRules)
{
    Write-Progress -Activity "Updating restored rules" -Status "Proxy server rules" -PercentComplete "10"
    Set-NetFirewallRule -Name $OutboundProxyServersRule -GPOSession $GpoSession -RemoteAddress $ProxyServers -RemotePort $ProxyServerPorts
}
foreach ($OutboundDomainControllersRule in $OutboundDomainControllersRules)
{
    Write-Progress -Activity "Updating restored rules" -Status "Domain controller rules" -PercentComplete "20"
    Set-NetFirewallRule -Name $OutboundDomainControllersRule -GPOSession $GpoSession -RemoteAddress $DomainControllers
}
foreach ($OutboundWebServersRule in $OutboundWebServersRules)
{
    Write-Progress -Activity "Updating restored rules" -Status "Web server rules" -PercentComplete "40"
    Set-NetFirewallRule -Name $OutboundWebServersRule -GPOSession $GpoSession -RemoteAddress $WebServers
}
foreach ($InboundExternalVPNEndpointsRule in $InboundExternalVPNEndpointsRules)
{
    Write-Progress -Activity "Updating restored rules" -Status "External VPN endpoint rules" -PercentComplete "60"
    Set-NetFirewallRule -Name $InboundExternalVPNEndpointsRule -GPOSession $GpoSession -RemoteAddress $ExternalVPNEndpoints
}
foreach ($OutboundExternalVPNEndpointsRule in $OutboundExternalVPNEndpointsRules)
{
    Write-Progress -Activity "Updating restored rules" -Status "External VPN endpoint rules" -PercentComplete "70"
    Set-NetFirewallRule -Name $OutboundExternalVPNEndpointsRule -GPOSession $GpoSession -RemoteAddress $ExternalVPNEndpoints
}
foreach ($OutboundDirectAccessServersRule in $OutboundDirectAccessServersRules)
{
    Write-Progress -Activity "Updating restored rules" -Status "DirectAccess server rules" -PercentComplete "80"
    Set-NetFirewallRule -Name $OutboundDirectAccessServersRule -GPOSession $GpoSession -RemoteAddress $DirectAccessServers
}
foreach ($OutboundCRLServersRule in $OutboundCRLServersRules)
{
    Write-Progress -Activity "Updating restored rules" -Status "CRL server rules" -PercentComplete "85"
    Set-NetFirewallRule -Name $OutboundCRLServersRule -GPOSession $GpoSession -RemoteAddress $CRLServers
}
foreach ($OutboundWPAD_PACFileServersRule in $OutboundWPAD_PACFileServersRules)
{
    Write-Progress -Activity "Updating restored rules" -Status "WPAD/PAC file server rules" -PercentComplete "90"
    Set-NetFirewallRule -Name $OutboundWPAD_PACFileServersRule -GPOSession $GpoSession -RemoteAddress $WPAD_PACFileServers
}
foreach ($TrustedDHCPSubnetsRule in $TrustedDHCPSubnetsRules)
{
    Write-Progress -Activity "Updating restored rules" -Status "Trusted DHCP subnet rules" -PercentComplete "95"
    Set-NetFirewallRule -Name $TrustedDHCPSubnetsRule -GPOSession $GpoSession -LocalAddress $TrustedDHCPSubnets
}
Write-Progress -Activity "Updating restored rules" -Completed
. Version080Updates
. SaveGpo
