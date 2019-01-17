## To deploy the minimum policies required for a privileged access workstation;  
 - Download [this](https://github.com/SteveUnderScoreN/WindowsFirewall/archive/master.zip) repository as a zip and extract the following to C:\Temp\;
    - Domain Root/Update-DomainFirewallBaseline.ps1
    - Domain Root/Admin/Tier X/Devices/Update-TierXFirewallBaseline.ps1 
    - Domain Root/Admin/Tier X/Devices/Update-ServerRoleRemoteAdministrationFirewallBaseline.ps1 
    - SN-GPO.zip
 
 - Extract 'SN-GPO.zip' (The files should now be located in C:\Temp\SN-GPO\)
 - Review the domain resources arrays in one script and copy them to the other scripts, the minimum requirements are  
 the domain controllers names/IP addresses and the proxy server port
 - On a computer that has the Group Policy Management Console installed run each script and review the GPO's created (SN-... by default)
 - Link all policies to the 'Domain Root/Admin/Tier 0/Devices' OU, the policies are not linked to any OU by the scripts.  

These policies are designed to be used in conjunction with the Microsoft baselines found [here](https://blogs.technet.microsoft.com/secguide/).  
Create 2 group policy objects that are specific to your domain and will contain firewall rules not defined in the baselines e.g. "Server Role - Remote Administration Firewall" and "Tier 0 Firewall".  
The 'Server Role' policy is designed to be used by the PAW and by administrative Remote Desktop jump servers so rules to administer the domain belong there.  
The Tier policy is designed to contain rules for laptops and desktops and to define which resources are allowed access to the PAW over the network.  
The policies should be linked in the following order;
 - Server Role - Remote Administration Firewall
 - Tier 0 Firewall
 - Server Role - Remote Administration Firewall Baseline
 - Tier 0 Firewall Baseline
 - MSFT Windows 10 RS3 - Computer (and other MSFT baselines e.g. Bitlocker, Credential Guard)
 - Domain Firewall Baseline

Review the security event log for blocked connections (event ID 5157) and add them to the domain specific policies, the baselines should only be modified by the scripts provided.  
If there are rules that should be added to the baseline raise an issue in GitHub.

## When Using these policies;  
 - The SSDP discovery service should be set to disabled and the 'Turn off multicast name resolution'
group policy setting should be enabled.  
 - Remove all Appx packages that can be removed (Get-AppxPackage|Remove-AppxPackage).
 - Disable One Drive
 - Do not allow browsing to any websites other that those on the enterprise intranet.
