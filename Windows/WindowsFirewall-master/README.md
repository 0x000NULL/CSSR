# Windows Defender Firewall, PowerShell scripts/GUI tools
As part of a defence in depth strategy application whitelisting needs to be enforced at the OS level, this mitigates much of the malware in the current threat landscape. The OS should whitelist no only what is allowed to run, enforced with AppLocker and CI policies, but also what network connectivity an application is granted. This repository contains PowerShell scripts and firewall policies to configure Windows clients and servers including protocol, port, IP and application to help achieve that goal. These policies can be used with privileged access workstations as documented [here](https://docs.microsoft.com/en-gb/windows-server/identity/securing-privileged-access/privileged-access-workstations).
The scripts can be populated with the host names and/or IP addresses of your domain resources which will create very specific firewall rules for your domain. Any domain resources that do not exist in your domain can be left as the default loopback addresses as defined in the scripts. 
These policies should not be modified outside the scripts provided, domain specific policies should be created that sit above these baselines in the group policy link order. These domain specific policies (e.g. Domain Firewall, Tier 0 Devices Firewall, Server Role - Remote Administration Firewall) can have additional firewall allow or block rules. A block rule will override any rule in the baseline.
These baselines must be above any computer baseline [provided by Microsoft](https://docs.microsoft.com/en-gb/windows/security/threat-protection/windows-security-baselines) (e.g. MSFT Windows 10 RS3 - Computer).  
The domain firewall baseline enables auditing of denied connection attempts within the security event log (ID 5157), the tier x device firewall baseline enables auditing of denied and permitted connections (ID 5156). Permitted and denied connections are essential forensic evidence and should be archived. Logs should be set to automatically backup when full, a scheduled task can be created on event ID 1105 which runs a script to zip the logs locally. These logs can then be harvested by a central server and stored or imported into the event management system. Along with process creation auditing (and a little HEX to DEC conversion) these firewall audit entries can be used to track the user identity associated with particular network activity which is essential in the investigation in a multi-user environment like Terminal Services.
## Notes
### Supported  
 - IPSEC VPN  
 - IPv6  
 - Windows 10  
 - Windows Server 2012 R2/2016  
 - Privileged access workstations  
 - 'Predefined set of computers' is supported and the following applies;  
   - 'Local Subnet' - includes the connected IP range for which an IP address has been assigned  
   - 'Intranet' - includes the IP subnets that have been added to 'Sites and Services (dssite.msc)', these are harvested by the IP helper service and can be seen in the following registry key;  
                  HKLM:\SYSTEM\CurrentControlSet\Services\iphlpsvc\Parameters\ADHarvest  
   - 'DNS Servers' - does not include the IPv6 addresses of DNS servers  
   - 'Internet' - is everything that isn't in the ADHarvest registry key  
### Not supported
 - DirectAccess (at least not for now, consider migrating to IKEv2 device tunnels)
 - NetBIOS  
 - WINS  
### Other
 - NTLM should be blocked forcing mutual authentication via Kerberos, if there is a requirements for NTLM authentication to a server it should be whitelisted in the NTLM exceptions within a group policy object  
 - Some SVCHOST services do not honour the firewall settings, there are some temporary SVCHOST rules to cover these that may be refined at a later date  
## Changes
I've modified the existing scripts to use the "Group" parameter that matches the domain resources defined. This allows us to have a rule to set new parameter values on all rules that are in a specific group, for example;
 - I have 35 rules that have domain controllers as the destination IP address
 - I change the IP address of a domain controller which is updated in DNS
 - I add an IPv6 address to an existing domain controller which is created in DNS
 - I have a new domain controller at a new site and the address is created in DNS
 - I update the $DomainControllers domain resource variable to add the new server name along side the existing server names
 - I run the script against the GPO with the 35 rules
 - The script converts $DomainControllers from the names of the servers to an array of IP addresses
 - The script detects the existing GPO and presents a menu to select the "Update existing" option
 - When selected the script, with 1 line, updates all 35 rules that have the group as "DomainControllers"
 - The GPO is then saved back to the domain and is ready to be applied
