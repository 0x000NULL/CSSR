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
   0.7.1   Corrected $SourceGPOBackupId and $TargetGPOName
   0.8.0   Added existing rule update function (using the "Group" parameter of rules), moved code blocks around, added new firewall rules, added progress bars, added some error handling and updated comments.
   0.8.1   No changes in this script
   0.8.2   No changes in this script
.EXAMPLE
   $TargetGpoName = "Server Role - Remote Administration firewall Baseline"
   $PathToGpoBackups = "C:\Temp\WindowsFirewall-GPO"
   $ProxyServers = "2a02:cc9:7732:5500::1","fd4e:eaa9:897b::1","172.19.110.1"
.EXAMPLE
   $TargetGpoName = "Server Role - Remote Administration firewall Baseline"
   $PathToGpoBackups = "C:\Temp\WindowsFirewall-GPO"
   $ProxyServers = "proxy.mydomain.local","172.19.110.15","proxy-server3"
.EXAMPLE
   $TargetGpoName = "Server Role - Remote Administration firewall Baseline"
   $PathToGpoBackups = "C:\Temp\WindowsFirewall-GPO"
   $ProxyServers = "10.10.10.0/24","proxy2","10.10.11.100-10.10.11.149"
#>

$SourceGpoBackupId = "{c69d83c5-1636-4ad7-b632-1f9b6963054e}" # Do not modify this
$TargetGpoName = "SN-Server Role - Remote Administration firewall Baseline"
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
        foreach ($InboundSqlServersRule in $InboundSqlServersRules)
        {
            Write-Progress -Activity "Applying version 0.8.0 updates - updating existing rules" -id 1 -PercentComplete "1"
            $Rule = Get-NetFirewallRule -Name $InboundSqlServersRule -GPOSession $GpoSession
            $Rule.Group = "InboundSqlServers"
            Set-NetFirewallRule -InputObject $Rule -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
        }
        foreach ($OutboundSqlServersRule in $OutboundSqlServersRules)
        {
            Write-Progress -Activity "Applying version 0.8.0 updates - updating existing rules" -id 1 -PercentComplete "10"
            $Rule = Get-NetFirewallRule -Name $OutboundSqlServersRule -GPOSession $GpoSession
            $Rule.Group = "OutboundSqlServers"
            Set-NetFirewallRule -InputObject $Rule -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
        }
        foreach ($OutboundProxyServersRule in $OutboundProxyServersRules)
        {
            Write-Progress -Activity "Applying version 0.8.0 updates - updating existing rules" -id 1 -PercentComplete "30"
            $Rule = Get-NetFirewallRule -Name $OutboundProxyServersRule -GPOSession $GpoSession
            $Rule.Group = "OutboundProxyServers"
            Set-NetFirewallRule -InputObject $Rule -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
        }
        Write-Progress -Activity "Applying version 0.8.0 updates" -PercentComplete 25
        foreach ($OutboundDomainControllersRule in $OutboundDomainControllersRules)
        {
            Write-Progress -Activity "Applying version 0.8.0 updates - updating existing rules" -id 1 -PercentComplete "55"
            $Rule = Get-NetFirewallRule -Name $OutboundDomainControllersRule -GPOSession $GpoSession
            $Rule.Group = "OutboundDomainControllers"
            Set-NetFirewallRule -InputObject $Rule -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
        }
        foreach ($OutboundWebServersRule in $OutboundWebServersRules)
        {
            Write-Progress -Activity "Applying version 0.8.0 updates - updating existing rules" -id 1 -PercentComplete "80"
            $Rule = Get-NetFirewallRule -Name $OutboundWebServersRule -GPOSession $GpoSession
            $Rule.Group = "OutboundWebServers"
            Set-NetFirewallRule -InputObject $Rule -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
        }
        foreach ($OutboundClusteredNodesAndManagementAddressesRule in $OutboundClusteredNodesAndManagementAddressesRules)
        {
            Write-Progress -Activity "Applying version 0.8.0 updates - updating existing rules" -id 1 -PercentComplete "90"
            $Rule = Get-NetFirewallRule -Name $OutboundClusteredNodesAndManagementAddressesRule -GPOSession $GpoSession
            $Rule.Group = "OutboundClusteredNodesAndManagementAddresses"
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
    [void](New-NetFirewallRule -GPOSession $GpoSession -Name "{5d338b4c-c60c-4a34-9409-ec14df246ee6}" -DisplayName "Inspect VHD Dialog (TCP-Out)" -Enabled True -Profile Domain -Direction Outbound -Action Allow -RemoteAddress "LocalSubnet","Intranet" -Protocol TCP -RemotePort "5985" -Program "%ProgramFiles%\Hyper-V\InspectVhdDialog.exe" -ErrorAction SilentlyContinue -ErrorVariable "Version080Updates")
    if ($Version080Updates.Exception.Message -like "Cannot create a file when that file already exists.*")
    {
        Write-Progress -Activity "Applying version 0.8.0 updates - creating new rules" -id 1 -Completed
        Write-warning "Version 0.8.0 new rules have been found, aborting new rule creation."
    }
    else
    {
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
    $InboundSqlServersRules = 
    "{06366F05-FDB5-47B3-AD53-A1B3E3811DFC}"

    $OutboundProxyServersRules = 
    "{1E5D5774-1CD4-4468-A3F9-AFBB6FAFE3F9}",
    "{9D26817C-3792-482E-8173-39995E1E4821}",
    "{4B40B570-31A2-4315-9186-E65AEED0347B}"

    $OutboundDomainControllersRules = 
    "{2AAE42BB-84E7-47D5-9E0D-1C6DCD2F9719}",
    "{19FD81F5-2520-4378-B492-E9A68816F4C9}",
    "{B500642B-2DDB-4DE6-8A6D-2569061FBB7B}",
    "{BD9C4BB0-33EA-491B-9C93-480E5814A984}",
    "{69AA8E32-0D08-4EE2-95FA-01B94F7249FA}",
    "{82DDA6BB-674A-47DC-A0A0-1890B805DA0F}",
    "{C2D8E478-3BFD-4BDE-ACAF-4FE25C4FE553}",
    "{87D48CC0-21AD-4DD4-8931-A44134C19DF3}",
    "{7BAD2B46-F43F-4C1B-AF95-EE67F609657E}",
    "{CE9CB7EC-5713-4F83-9CEC-BC89080557A0}",
    "{3FD6B54C-9499-4728-9CE7-7DEBD83EC1A5}",
    "{A164981A-675A-4A6B-B194-DC5F22988094}",
    "{F6880716-35C0-4484-9CF5-1CB615A7D16A}",
    "{B37078CD-00F6-4E4E-BF2C-57005831B642}",
    "{F1E8A5D9-0B28-4FE7-9323-494BC9469129}",
    "{32A0C4AD-8994-4DEE-810F-D40AAC5C682D}",
    "{D8C6D330-F81F-4C42-9357-B59B223424DC}",
    "{7C16F956-F3D3-4D39-BF3B-5D0CA03D0F6C}"

    $OutboundWebServersRules = 
    "{769B7312-4575-461E-9AF0-FFA46B40D84D}",
    "{AE651744-34A4-4976-ADFC-54D20FEC9BDF}"

    $OutboundSqlServersRules = 
    "{B11CC9D5-9DDA-4021-9048-B7E21B1230AC}",
    "{9CD6A215-CEFE-4D32-9542-5753A069FA76}"

    $OutboundClusteredNodesAndManagementAddressesRules = 
    "{B0D25960-B3D4-415C-A426-E3F38F39B33E}",
    "{AC3A5E65-E04D-44E2-A5CF-4A59521FCC6D}"
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
                Set-NetFirewallRule -Group "InboundSqlServers" -GPOSession $GpoSession -RemoteAddress $SqlServers -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
                Write-Progress -Activity "Updating existing rules" -PercentComplete "10"
                Set-NetFirewallRule -Group "OutboundSqlServers" -GPOSession $GpoSession -RemoteAddress $SqlServers -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
                Write-Progress -Activity "Updating existing rules" -PercentComplete "20"
                Set-NetFirewallRule -Group "OutboundProxyServers" -GPOSession $GpoSession -RemoteAddress $ProxyServers -RemotePort $ProxyServerPorts -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
                Write-Progress -Activity "Updating existing rules" -PercentComplete "50"
                Set-NetFirewallRule -Group "OutboundDomainControllers" -GPOSession $GpoSession -RemoteAddress $DomainControllers -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
                Write-Progress -Activity "Updating existing rules" -PercentComplete "80"
                Set-NetFirewallRule -Group "OutboundWebServers" -GPOSession $GpoSession -RemoteAddress $WebServers -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
                Write-Progress -Activity "Updating existing rules" -PercentComplete "90"
                Set-NetFirewallRule -Group "OutboundClusteredNodesAndManagementAddresses" -GPOSession $GpoSession -RemoteAddress $ClusteredNodesAndManagementAddresses -ErrorAction Stop -ErrorVariable "UpdatingExistingRules"
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
foreach ($InboundSqlServersRule in $InboundSqlServersRules)
{
    Write-Progress -Activity "Updating restored rules" -Status "SQL server rules" -PercentComplete "1"
    Set-NetFirewallRule -Name $InboundSqlServersRule -GPOSession $GpoSession -RemoteAddress $SqlServers
}
foreach ($OutboundSqlServersRule in $OutboundSqlServersRules)
{
    Write-Progress -Activity "Updating restored rules" -Status "SQL server rules" -PercentComplete "10"
    Set-NetFirewallRule -Name $OutboundSqlServersRule -GPOSession $GpoSession -RemoteAddress $SqlServers
}
foreach ($OutboundProxyServersRule in $OutboundProxyServersRules)
{
    Write-Progress -Activity "Updating restored rules" -Status "Proxy server rules" -PercentComplete "20"
    Set-NetFirewallRule -Name $OutboundProxyServersRule -GPOSession $GpoSession -RemoteAddress $ProxyServers -RemotePort $ProxyServerPorts
}
foreach ($OutboundDomainControllersRule in $OutboundDomainControllersRules)
{
    Write-Progress -Activity "Updating restored rules" -Status "Domain controller server rules" -PercentComplete "50"
    Set-NetFirewallRule -Name $OutboundDomainControllersRule -GPOSession $GpoSession -RemoteAddress $DomainControllers
}
foreach ($OutboundWebServersRule in $OutboundWebServersRules)
{
    Write-Progress -Activity "Updating restored rules" -Status "Web server rules" -PercentComplete "80"
    Set-NetFirewallRule -Name $OutboundWebServersRule -GPOSession $GpoSession -RemoteAddress $WebServers
}
foreach ($OutboundClusteredNodesAndManagementAddressesRule in $OutboundClusteredNodesAndManagementAddressesRules)
{
    Write-Progress -Activity "Updating restored rules" -Status "Cluster server rules" -PercentComplete "90"
    Set-NetFirewallRule -Name $OutboundClusteredNodesAndManagementAddressesRule -GPOSession $GpoSession -RemoteAddress $ClusteredNodesAndManagementAddresses
}
Write-Progress -Activity "Updating restored rules" -Completed
. Version080Updates
. SaveGpo
