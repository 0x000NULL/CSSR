
"
#################################################
###               EZSCRIPT SON                ###
#################################################
"
"created by xfaraday :))) "
"What do you want to do today?"
""
$ConfirmPreference = 'None'
#adjust this variable below before running, leave the quotes
$user = 'ADJUSTMEBEFORERUNNING'


$option = Read-Host '
1. File Dump Searcher(remember to adjust filepath to users desktop)
2. LAUNCH CYBER NUKE?(recommended but take out special needs)
 '
 if ($option -eq 1) {

    New-Item -Path C:\Users\$user\Desktop\scripterino -ItemType directory

    'What is the EXACT name of the user you are currently?'
    'no files are safe [.][.]'
    New-Item -Path C:\Users\$user\Desktop\scripterino\userfiles -ItemType directory
    New-Item -Path C:\Users\$user\Desktop\scripterino\programfiles -ItemType directory
    New-Item -Path C:\Users\$user\Desktop\scripterino\programfilesx86 -ItemType directory
    New-Item -Path C:\Users\$user\Desktop\scripterino\documents -ItemType directory
    'grabbing user files'
    Get-ChildItem -Path "C:\Users\*" -Include *.jpg,*.png,*.aac,*.ac3,*.avi,*.aiff,*.bat,*.bmp,*.exe,*.flac,*.gif,*.jpeg,*.mov,*.m3u,*.m4p,*.mp2,*.mp3,*.mp4,*.mpeg4,*.midi,*.msi,*.ogg,*.png,*.txt,*.sh,*.wav,*.wma,*.vqf,*.pcap,*.zip,*.pdf,*.json -Recurse | Copy-Item -Destination C:\Users\$user\Desktop\scripterino\userfiles
    'grabbing program files'
    Get-ChildItem -Path "C:\Program Files\*" -Include *.jpg,*.png,*.aac,*.ac3,*.avi,*.aiff,*.bat,*.bmp,*.exe,*.flac,*.gif,*.jpeg,*.mov,*.m3u,*.m4p,*.mp2,*.mp3,*.mp4,*.mpeg4,*.midi,*.msi,*.ogg,*.png,*.txt,*.sh,*.wav,*.wma,*.vqf,*.pcap,*.zip,*.pdf,*.json -Recurse | Copy-Item -Destination C:\Users\$user\Desktop\scripterino\programfiles
    Get-ChildItem -Path "C:\Program Files (x86)\*" -Include *.jpg,*.png,*.aac,*.ac3,*.avi,*.aiff,*.bat,*.bmp,*.exe,*.flac,*.gif,*.jpeg,*.mov,*.m3u,*.m4p,*.mp2,*.mp3,*.mp4,*.mpeg4,*.midi,*.msi,*.ogg,*.png,*.txt,*.sh,*.wav,*.wma,*.vqf,*.pcap,*.zip,*.pdf,*.json -Recurse | Copy-Item -Destination C:\Users\$user\Desktop\scripterino\programfilesx86
    'grabbing Documents'
    Get-ChildItem -Path "C:\Users\$user\Documents\*" -Include *.jpg,*.png,*.aac,*.ac3,*.avi,*.aiff,*.bat,*.bmp,*.exe,*.flac,*.gif,*.jpeg,*.mov,*.m3u,*.m4p,*.mp2,*.mp3,*.mp4,*.mpeg4,*.midi,*.msi,*.ogg,*.png,*.txt,*.sh,*.wav,*.wma,*.vqf,*.pcap,*.zip,*.pdf,*.json -Recurse | Copy-Item -Destination C:\Users\$user\Desktop\scripterino\documentsandsettings
    'catching them special media files'
    Get-ChildItem -Path C:\Users -Include .jpg,.png,.jpeg,.avi,.mp4,.mp3,*.wav -Exclude .dll,.doc,*.docx,  -File -Recurse -ErrorAction SilentlyContinue | Out-File -filepath C:\Users\$user\Desktop\scripterino\Mediafiles.txt
    'Proceed to search baby ;) keep in mind these are only copies of the originals'
 }



 if ($option -eq 2) {
    #setup

    'You chose the option NUKE THIS SHIT.....commencing...'    
    Start-Sleep -s 5
    'managing users'
    'grabbing users and user groups'
    net user > scripterino\users.txt
    
    net localgroup > scripterino\groups.txt

    #disabling guest/admin and renaming them
    'disabling Guest and Admin account'
    Get-LocalUser Guest | Disable-LocalUser
    Get-LocalUser Administrator | Disable-LocalUser
    'renaming guest and admin account'
    $adminAccount =Get-WMIObject Win32_UserAccount -Filter "Name='Administrator'"
    $result =$adminAccount.Rename("adminBOI")
    $guestAccount =Get-WMIObject Win32_UserAccount -Filter "Name='Guest'"
    $result =$guestAccount.Rename("guestBOI")



    #REKING PLEBS AND THEIR SHIT PASSWORDS
    'reking plebs and their shit passwords'
    get-wmiobject win32_useraccount | ForEach-Object {
    ([adsi](“WinNT://”+$_.caption).replace(“\”,”/”)).SetPassword(“K3wLP@SsW0rd”)
    }
    
    #AUDIT BABY
    'STARTING audit m9, this might take a while'
    #account policies

    net accounts /UNIQUEPW:24 /MAXPWAGE:60 /MINPWAGE:1 /MINPWLEN:12 /lockoutthreshold:5
    
    
    #localpolicies-audit policies
    auditpol /set /category:"Account Logon" /success:enable #is everything really just success and failure?
    auditpol /set /category:"Account Logon" /failure:enable

    auditpol /set /category:"Account Management" /success:enable
    auditpol /set /category:"Account Management" /failure:enable

    auditpol /set /category:"DS Access" /success:enable
    auditpol /set /category:"DS Access" /failure:enable

    auditpol /set /category:"Logon/Logoff" /success:enable
    auditpol /set /category:"Logon/Logoff" /failure:enable
    
    auditpol /set /category:"Object Access" /success:enable
    auditpol /set /category:"Object Access" /failure:enable

    auditpol /set /category:"Policy Change" /success:enable
    auditpol /set /category:"Policy Change" /failure:enable

    auditpol /set /category:"Privilege Use" /success:enable
    auditpol /set /category:"Privilege Use" /failure:enable

    auditpol /set /category:"Detailed Tracking" /success:enable
    auditpol /set /category:"Detailed Tracking" /failure:enable

    auditpol /set /category:"System" /success:enable 
    auditpol /set /category:"System" /failure:enable

    #subcategories of advanced audit polcies

    
	#grabbing network shares check if irregular
	'grabbing shares bb'
	net share > scripterino\shares.txt
    	

    #flush DNS
	'flushing dns cache'
	ipconfig /flushdns
    
    #Grabbing hosts file
    'grabbing hosts file'	
    New-Item -Path C:\Users\$user\Desktop\scripterino\hosts -ItemType directory
    Get-ChildItem -Path "C:\Windows\System32\drivers\etc\hosts" | Copy-Item -Destination C:\Users\$user\Desktop\scripterino\hosts


	'FEATURES BAAAABY'
	
	dism /online /disable-feature /featurename:IIS-WebServerRole
	dism /online /disable-feature /featurename:IIS-WebServer
	dism /online /disable-feature /featurename:IIS-CommonHttpFeatures
	dism /online /disable-feature /featurename:IIS-HttpErrors
	dism /online /disable-feature /featurename:IIS-HttpRedirect
	dism /online /disable-feature /featurename:IIS-ApplicationDevelopment
	dism /online /disable-feature /featurename:IIS-NetFxExtensibility
	dism /online /disable-feature /featurename:IIS-NetFxExtensibility45
	dism /online /disable-feature /featurename:IIS-HealthAndDiagnostics
	dism /online /disable-feature /featurename:IIS-HttpLogging
	dism /online /disable-feature /featurename:IIS-LoggingLibraries
	dism /online /disable-feature /featurename:IIS-RequestMonitor
	dism /online /disable-feature /featurename:IIS-HttpTracing
	dism /online /disable-feature /featurename:IIS-Security
	dism /online /disable-feature /featurename:IIS-URLAuthorization
	dism /online /disable-feature /featurename:IIS-RequestFiltering
	dism /online /disable-feature /featurename:IIS-IPSecurity
	dism /online /disable-feature /featurename:IIS-Performance
	dism /online /disable-feature /featurename:IIS-HttpCompressionDynamic
	dism /online /disable-feature /featurename:IIS-WebServerManagementTools
	dism /online /disable-feature /featurename:IIS-ManagementScriptingTools
	dism /online /disable-feature /featurename:IIS-IIS6ManagementCompatibility
	dism /online /disable-feature /featurename:IIS-Metabase
	dism /online /disable-feature /featurename:IIS-HostableWebCore
	dism /online /disable-feature /featurename:IIS-StaticContent
	dism /online /disable-feature /featurename:IIS-DefaultDocument
	dism /online /disable-feature /featurename:IIS-DirectoryBrowsing
	dism /online /disable-feature /featurename:IIS-WebDAV
	dism /online /disable-feature /featurename:IIS-WebSockets
	dism /online /disable-feature /featurename:IIS-ApplicationInit
	dism /online /disable-feature /featurename:IIS-ASPNET
	dism /online /disable-feature /featurename:IIS-ASPNET45
	dism /online /disable-feature /featurename:IIS-ASP
	dism /online /disable-feature /featurename:IIS-CGI 
	dism /online /disable-feature /featurename:IIS-ISAPIExtensions
	dism /online /disable-feature /featurename:IIS-ISAPIFilter
	dism /online /disable-feature /featurename:IIS-ServerSideIncludes
	dism /online /disable-feature /featurename:IIS-CustomLogging
	dism /online /disable-feature /featurename:IIS-BasicAuthentication
	dism /online /disable-feature /featurename:IIS-HttpCompressionStatic
	dism /online /disable-feature /featurename:IIS-ManagementConsole
	dism /online /disable-feature /featurename:IIS-ManagementService
	dism /online /disable-feature /featurename:IIS-WMICompatibility
	dism /online /disable-feature /featurename:IIS-LegacyScripts
	dism /online /disable-feature /featurename:IIS-LegacySnapIn
	dism /online /disable-feature /featurename:IIS-FTPServer
	dism /online /disable-feature /featurename:IIS-FTPSvc
	dism /online /disable-feature /featurename:IIS-FTPExtensibility
	dism /online /disable-feature /featurename:TFTP
	dism /online /disable-feature /featurename:TelnetClient
	dism /online /disable-feature /featurename:TelnetServer
    dism /online /disable-feature /featurename:"SMB1Protocol"
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

    #processes that have bigger loads
    'grabbing dem interesting process'
    Get-Process | Where-Object {$_.WorkingSet -gt 20000000} > scripterino\interestingprocess.txt

    #firewall settings
    'Firewall config start'
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
	Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -AllowUnicastResponseToMulticast True -LogFileName %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log
    netsh advfirewall import "C:\Users\$user\Desktop\Win10Firewall.wfw"
    netsh advfirewall firewall set rule name="Remote Assistance (DCOM-In)" new enable=no 
    netsh advfirewall firewall set rule name="Remote Assistance (PNRP-In)" new enable=no 
    netsh advfirewall firewall set rule name="Remote Assistance (RA Server TCP-In)" new enable=no 
    netsh advfirewall firewall set rule name="Remote Assistance (SSDP TCP-In)" new enable=no 
    netsh advfirewall firewall set rule name="Remote Assistance (SSDP UDP-In)" new enable=no 
    netsh advfirewall firewall set rule name="Remote Assistance (TCP-In)" new enable=no 
    netsh advfirewall firewall set rule name="Telnet Server" new enable=no 
    netsh advfirewall firewall set rule name="netcat" new enable=no
    #disable network discovery hopefully
    netsh advfirewall firewall set rule group="Network Discovery" new enable=No
    #disable file and printer sharing hopefully
    netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No

    netsh advfirewall firewall add rule name="block_RemoteRegistry_in" dir=in service="RemoteRegistry" action=block enable=yes
    netsh advfirewall firewall add rule name="block_RemoteRegistry_out" dir=out service="RemoteRegistry" action=block enable=yes
    
    New-NetFirewallRule -DisplayName "sshTCP" -Direction Inbound -LocalPort 22 -Protocol TCP -Action Block #ssh
    New-NetFirewallRule -DisplayName "ftpTCP" -Direction Inbound -LocalPort 21 -Protocol TCP -Action Block #ftp
    New-NetFirewallRule -DisplayName "telnetTCP" -Direction Inbound -LocalPort 23 -Protocol TCP -Action Block #telnet
    New-NetFirewallRule -DisplayName "SMTPTCP" -Direction Inbound -LocalPort 25 -Protocol TCP -Action Block #SMTP
    New-NetFirewallRule -DisplayName "POP3TCP" -Direction Inbound -LocalPort 110 -Protocol TCP -Action Block #POP3
    New-NetFirewallRule -DisplayName "SNMPTCP" -Direction Inbound -LocalPort 161 -Protocol TCP -Action Block #SNMP
    New-NetFirewallRule -DisplayName "RDPTCP" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Block #RDP

    #network profile to public so it denies file sharing, device discovery, etc.
    Set-NetConnectionProfile -NetworkCategory Public
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -ErrorAction SilentlyContinue



    'starting registry cancer'  
    Start-Sleep -s 2

    #disable remote desktop
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 0 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowSignedFiles" /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowUnsignedFiles" /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "DisablePasswordSaving" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Conferencing" /v "NoRDS" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" /v "AllowRemoteShellAccess" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowSignedFiles" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowUnsignedFiles" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "CreateEncryptedOnlyTickets" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "DisablePasswordSaving" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowUnsolicited" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fDenyTSConnections" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbBlockDeviceBySetupClass" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbNoAckIsochWriteToDevice" /t REG_DWORD /d 80 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbSelectDeviceByInterface" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\RemoteAdminSettings" /v "Enabled" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\RemoteDesktop" /v "Enabled" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\UPnPFramework" /v "Enabled" /t REG_DWORD /d 0 /f


    #Windows automatic updates
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 4 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v ElevateNonAdmins /t REG_DWORD /d 0 /f
    reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoWindowsUpdate /t REG_DWORD /d 0 /f
    reg add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
    reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f

    #Restrict CD ROM drive
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f

    #disable remote access to floppy disk
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f

    #disable auto admin login
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f

    #clear page file
    reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f

    #no printer drivers
    reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f

    #auditing to LSASS.exe
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f

    #Enable LSA protection
    reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 00000001 /f

    #Limit use of blank passwords
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
    
    #Auditing access of Global System Objects
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v auditbaseobjects /t REG_DWORD /d 1 /f
    
    #Auditing Backup and Restore
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v fullprivilegeauditing /t REG_DWORD /d 1 /f
    
    #Restrict Anonymous Enumeration #1
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f
    
    #Restrict Anonymous Enumeration #2
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f
    
    #Disable storage of domain passwords
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f
    
    #Take away Anonymous user Everyone permissions
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f
    
    #Allow Machine ID for NTLM
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v UseMachineId /t REG_DWORD /d 0 /f
    
    #Do not display last user on logon
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f
    
    #Enable UAC
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f

    #UAC set high
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1
    
    #UAC setting (Prompt on Secure Desktop)
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
    
    #Enable Installer Detection
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
    
    #Disable undocking without logon
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v undockwithoutlogon /t REG_DWORD /d 0 /f
    
    #Enable CTRL+ALT+DEL
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f
    
    #Max password age
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v MaximumPasswordAge /t REG_DWORD /d 15 /f

    #Disable machine account password changes
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f
    
    #Require strong session key
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f
    
    #Require Sign/Seal
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f
    
    #Sign Channel
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f
    
    #Seal Channel
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f
    
    #Set idle time to 45 minutes
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v autodisconnect /t REG_DWORD /d 45 /f
    
    #Require Security Signature - Disabled pursuant to checklist:::
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v enablesecuritysignature /t REG_DWORD /d 0 /f
    
    #Enable Security Signature - Disabled pursuant to checklist:::
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v requiresecuritysignature /t REG_DWORD /d 0 /f
    
    #Clear null session pipes
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
    
    #Restict Anonymous user access to named pipes and shares
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionShares /t REG_MULTI_SZ /d "" /f
    
    #Encrypt SMB Passwords
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
    
    #Clear remote registry paths
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths /v Machine /t REG_MULTI_SZ /d "" /f
    
    #Clear remote registry paths and sub-paths
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths /v Machine /t REG_MULTI_SZ /d "" /f
    
    #Enable smart screen for IE8
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV8 /t REG_DWORD /d 1 /f
    
    #Enable smart screen for IE9 and up
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
    
    #Disable IE password caching
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f
    
    #Warn users if website has a bad certificate
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonBadCertRecving /t REG_DWORD /d 1 /f
    
    #Warn users if website redirects
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f
    
    #Enable Do Not Track
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f

    #Show hidden files
    reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 1 /f
    
    #Disable sticky keys
    reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f
    
    #Show super hidden files
    reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSuperHidden /t REG_DWORD /d 1 /f
    
    #Disable dump file creation
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f
    
    #Disable autoruns
    reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f

    #enable internet explorer phishing filter
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 1 /f

    #block macros and other content execution
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\access\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "excelbypassencryptedmacroscan" /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\ms project\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\ms project\security" /v "level" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\outlook\security" /v "level" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\powerpoint\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\powerpoint\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\publisher\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\visio\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\visio\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "wordbypassencryptedmacroscan" /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\common\security" /v "automationsecurity" /t REG_DWORD /d 3 /f

    #Enable Windows Defender
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d 3 /f

    #TlntSvr = telnet
    #Msftpsvc = microsoft ftp 
    #ftpsvc = ftp
    #Smtpsvc = SMTP service
    #Termservice = remote desktop

    'shrinking attack service *hit the dab*'
    Start-Sleep -s 2

    #badservices
    cmd.exe /c 'sc stop tlntsvr'
	cmd.exe /c 'sc config tlntsvr start= disabled'
	cmd.exe /c 'sc stop msftpsvc'
	cmd.exe /c 'sc config msftpsvc start= disabled'
	cmd.exe /c 'sc stop snmptrap'
	cmd.exe /c 'sc config snmptrap start= disabled'
	cmd.exe /c 'sc stop ssdpsrv'
	cmd.exe /c 'sc config ssdpsrv start= disabled'
	cmd.exe /c 'sc stop termservice'
	cmd.exe /c 'sc config termservice start= disabled'
	cmd.exe /c 'sc stop sessionenv'
	cmd.exe /c 'sc config sessionenv start= disabled'
	cmd.exe /c 'sc stop remoteregistry'
	cmd.exe /c 'sc config remoteregistry start= disabled'
	cmd.exe /c 'sc stop Messenger'
	cmd.exe /c 'sc config Messenger start= disabled'
	cmd.exe /c 'sc stop upnphos'
	cmd.exe /c 'sc config upnphos start= disabled'
	cmd.exe /c 'sc stop WAS'
	cmd.exe /c 'sc config WAS start= disabled'
	cmd.exe /c 'sc stop RemoteAccess'
	cmd.exe /c 'sc config RemoteAccess start= disabled'
	cmd.exe /c 'sc stop mnmsrvc'
	cmd.exe /c 'sc config mnmsrvc start= disabled'
	cmd.exe /c 'sc stop NetTcpPortSharing'
	cmd.exe /c 'sc config NetTcpPortSharing start= disabled'
	cmd.exe /c 'sc stop RasMan'
	cmd.exe /c 'sc config RasMan start= disabled'
	cmd.exe /c 'sc stop TabletInputService'
	cmd.exe /c 'sc config TabletInputService start= disabled'
	cmd.exe /c 'sc stop RpcSs'
	cmd.exe /c 'sc config RpcSs start= disabled'
	cmd.exe /c 'sc stop SENS'
	cmd.exe /c 'sc config SENS start= disabled'
	cmd.exe /c 'sc stop EventSystem'
	cmd.exe /c 'sc config EventSystem start= disabled'
	cmd.exe /c 'sc stop XblAuthManager'
	cmd.exe /c 'sc config XblAuthManager start= disabled'
	cmd.exe /c 'sc stop XblGameSave'
	cmd.exe /c 'sc config XblGameSave start= disabled'
	cmd.exe /c 'sc stop XboxGipSvc'
	cmd.exe /c 'sc config XboxGipSvc start= disabled'
	cmd.exe /c 'sc stop xboxgip'
	cmd.exe /c 'sc config xboxgip start= disabled'
	cmd.exe /c 'sc stop xbgm'
	cmd.exe /c 'sc config xbgm start= disabled'
	cmd.exe /c 'sc stop SysMain'
	cmd.exe /c 'sc config SysMain start= disabled'
    cmd.exe /c 'sc stop seclogon'
    cmd.exe /c 'sc config seclogon start= disabled'
    cmd.exe /c 'sc stop TapiSrv'
    cmd.exe /c 'sc config TapiSrv start= disabled'
    cmd.exe /c 'sc stop p2pimsvc'
    cmd.exe /c 'sc config p2pimsvc start= disabled'
    cmd.exe /c 'sc stop simptcp'
    cmd.exe /c 'sc config simptcp start= disabled'
    cmd.exe /c 'sc stop fax'
    cmd.exe /c 'sc config fax start= disabled'
    cmd.exe /c 'sc stop Msftpsvc'
    cmd.exe /c 'sc config Msftpsvc start= disabled'
    cmd.exe /c 'sc stop iprip'
    cmd.exe /c 'sc config iprip start= disabled'
    cmd.exe /c 'sc stop ftpsvc'
    cmd.exe /c 'sc config ftpsvc start= disabled'
    cmd.exe /c 'sc stop RasAuto'
    cmd.exe /c 'sc config RasAuto start= disabled'
    cmd.exe /c 'sc stop W3svc'
    cmd.exe /c 'sc config W3svc start= disabled'
    cmd.exe /c 'sc stop Smtpsvc'
    cmd.exe /c 'sc config Smtpsvc start= disabled'
    cmd.exe /c 'sc stop Dfs'
    cmd.exe /c 'sc config Dfs start= disabled'
    cmd.exe /c 'sc stop TrkWks'
    cmd.exe /c 'sc config TrkWks start= disabled'
    cmd.exe /c 'sc stop MSDTC'
    cmd.exe /c 'sc config MSDTC start= disabled'
    cmd.exe /c 'sc stop ERSvc'
    cmd.exe /c 'sc config ERSvc start= disabled'
    cmd.exe /c 'sc stop NtFrs'
    cmd.exe /c 'sc config NtFrs start= disabled'
    cmd.exe /c 'sc stop Iisadmin'
    cmd.exe /c 'sc config Iisadmin start= disabled'
    cmd.exe /c 'sc stop IsmServ'
    cmd.exe /c 'sc config IsmServ start= disabled'
    cmd.exe /c 'sc stop WmdmPmSN'
    cmd.exe /c 'sc config WmdmPmSN start= disabled'
    cmd.exe /c 'sc stop helpsvc'
    cmd.exe /c 'sc config helpsvc start= disabled'
    cmd.exe /c 'sc stop Spooler'
    cmd.exe /c 'sc config Spooler start= disabled'
    cmd.exe /c 'sc stop RDSessMgr'
    cmd.exe /c 'sc config RDSessMgr start= disabled'
    cmd.exe /c 'sc stop RSoPProv'
    cmd.exe /c 'sc config RSoPProv start= disabled'
    cmd.exe /c 'sc stop SCardSvr'
    cmd.exe /c 'sc config SCardSvr start= disabled'
    cmd.exe /c 'sc stop lanmanserver'
    cmd.exe /c 'sc config lanmanserver start= disabled'
    cmd.exe /c 'sc stop Sacsvr'
    cmd.exe /c 'sc config Sacsvr start= disabled'
    cmd.exe /c 'sc stop TermService'
    cmd.exe /c 'sc config TermService start= disabled'
    cmd.exe /c 'sc stop uploadmgr'
    cmd.exe /c 'sc config uploadmgr start= disabled'
    cmd.exe /c 'sc stop VDS'
    cmd.exe /c 'sc config VDS start= disabled'
    cmd.exe /c 'sc stop VSS'
    cmd.exe /c 'sc config VSS start= disabled'
    cmd.exe /c 'sc stop WINS'
    cmd.exe /c 'sc config WINS start= disabled'
    cmd.exe /c 'sc stop CscService'
    cmd.exe /c 'sc config CscService start= disabled'
    cmd.exe /c 'sc stop hidserv'
    cmd.exe /c 'sc config hidserv start= disabled'
    cmd.exe /c 'sc stop IPBusEnum'
    cmd.exe /c 'sc config IPBusEnum start= disabled'
    cmd.exe /c 'sc stop PolicyAgent'
    cmd.exe /c 'sc config PolicyAgent start= disabled'
    #cmd.exe /c 'sc stop SCPolicySvc'
    #cmd.exe /c 'sc config SCPolicySvc start= disabled'
    cmd.exe /c 'sc stop SharedAccess'
    cmd.exe /c 'sc config SharedAccess start= disabled'
    cmd.exe /c 'sc stop SSDPSRV'
    cmd.exe /c 'sc config SSDPSRV start= disabled'
    cmd.exe /c 'sc stop Themes'
    cmd.exe /c 'sc config Themes start= disabled'
    cmd.exe /c 'sc stop upnphost'
    cmd.exe /c 'sc config upnphost start= disabled'
    cmd.exe /c 'sc stop nfssvc'
    cmd.exe /c 'sc config nfssvc start= disabled'
    cmd.exe /c 'sc stop nfsclnt'
    cmd.exe /c 'sc config nfsclnt start= disabled'
    cmd.exe /c 'sc stop MSSQLServerADHelper'
    cmd.exe /c 'sc config MSSQLServerADHelper start= disabled'
    cmd.exe /c 'sc stop SharedAccess'
    cmd.exe /c 'sc config SharedAccess start= disabled'
    cmd.exe /c 'sc stop UmRdpService'
    cmd.exe /c 'sc config UmRdpService start= disabled'
    cmd.exe /c 'sc stop SessionEnv'
    cmd.exe /c 'sc config SessionEnv start= disabled'
    cmd.exe /c 'sc stop Server'
    cmd.exe /c 'sc config Server start= disabled'
    cmd.exe /c 'sc stop TeamViewer'
    cmd.exe /c 'sc config TeamViewer start= disabled'
    cmd.exe /c 'sc stop TeamViewer7'
    cmd.exe /c 'sc config start= disabled'
    cmd.exe /c 'sc stop HomeGroupListener'
    cmd.exe /c 'sc config HomeGroupListener start= disabled'
    cmd.exe /c 'sc stop HomeGroupProvider'
    cmd.exe /c 'sc config HomeGroupProvider start= disabled'
    cmd.exe /c 'sc stop AxInstSV'
    cmd.exe /c 'sc config AXInstSV start= disabled'
    cmd.exe /c 'sc stop Netlogon'
    cmd.exe /c 'sc config Netlogon start= disabled'
    cmd.exe /c 'sc stop lltdsvc'
    cmd.exe /c 'sc config lltdsvc start= disabled'
    cmd.exe /c 'sc stop iphlpsvc'
    cmd.exe /c 'sc config iphlpsvc start= disabled'
    cmd.exe /c 'sc stop AdobeARMservice'
    cmd.exe /c 'sc config AdobeARMservice start= disabled'

    #goodservices
    cmd.exe /c 'sc start wuauserv'
    cmd.exe /c 'sc config wuauserv start= auto'
    cmd.exe /c 'sc start EventLog'
    cmd.exe /c 'sc config EventLog start= auto'
    cmd.exe /c 'sc start MpsSvc'
    cmd.exe /c 'sc config MpsSvc start= auto'
    cmd.exe /c 'sc start WinDefend'
    cmd.exe /c 'sc config WinDefend start= auto'
    cmd.exe /c 'sc start WdNisSvc'
    cmd.exe /c 'sc config WdNisSvc start= auto'
    cmd.exe /c 'sc start Sense'
    cmd.exe /c 'sc config Sense start= auto'
    cmd.exe /c 'sc start Schedule'
    cmd.exe /c 'sc config Schedule start= auto'
    cmd.exe /c 'sc start SCardSvr'
    cmd.exe /c 'sc config SCardSvr start= auto'
    cmd.exe /c 'sc start ScDeviceEnum'
    cmd.exe /c 'sc config ScDeviceEnum start= auto'
    cmd.exe /c 'sc start SCPolicySvc'
    cmd.exe /c 'sc config SCPolicySvc start= auto'
    cmd.exe /c 'sc start wscsvc'
    cmd.exe /c 'sc config wscsvc start= auto'

    

 }