# Blocked firewall connections and GPO editing GUI tools
- Export existing Windows Defender Firewall rules to PowerShell commands - Use this tool to query a domain for policies that have existing firewall rules and then export a policy to a PowerShell script.
 - Find all policies with Windows Defender Firewall rules - Use this tool to query a domain for policies that have existing firewall rules, this list can then be saved to a text file as reference.
 - Update domain resources - Use this tool to update domain resources that can be used to create or update Windows Defender Firewall rules in group policy objects. Names can be used and will be translated into IP addresses which can be applied to multiple rules, IP ranges, predefined computers, existing domain resources and IP subnets can also be used. The resources can be exported and imported via XML for future use.
 - Edit existing Windows Defender Firewall rules - Use this tool to edit existing firewall rules, domain resources can be selected and DNS will be used to resolve all IP addresses to be used. Multiple rules can be edited at once and saved to a PowerShell script or saved back to the domain.
The current build will allow bulk/single modification of DisplayName, Description, Enabled, Direction, Action, LocalAddress, LocalPort, RemoteAddress, RemotePort, Package and Service with a preview and has the save to GPO/.ps1 function enabled. Beta 1.
 - Scan computer for blocked connections - Use this tool to scan a computer for blocked network connections and to create new Windows Defender Firewall rules that can be saved to a PowerShell script or saved to a group policy object. Beta 1.
 
They are all in the one script.
