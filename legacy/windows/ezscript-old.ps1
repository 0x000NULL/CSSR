
title "NotaVirus Windows Script"
echo "Welcome to Ethan's Script!"
pause
clear

Write-Progress -Status 'Progress->' -PercentComplete $I
	Script1
	function Script1
	{
		echo "SERVER2008?"
		SET /P M="Type y or n then press ENTER:"
		IF (%M%==y) goto SERVER2008GucciScript.bat
		IF (%M%==n) goto skip19
		:WIN7GucciScript.bat
		start WIN7GucciScript.bat
		:skip19
		pause

		echo "SERVER2016?"
		SET /P M=Type y or n then press ENTER:
		IF (%M%==y) goto SERVER2016GucciScript.bat
		IF (%M%==n) goto skip20
		:SERVER2016GucciScript.bat
		start SERVER2016GucciScript.bat
		:skip20
		pause 

		echo "WIN 7?"
		SET /P M=Type y or n then press ENTER:
		IF (%M%==y) goto WIN7GucciScript.bat
		IF (%M%==n) goto skip21
		:WIN7GucciScript.bat
		start WIN7GucciScript.bat
		:skip21
		pause 


		echo WIN 8?
		SET /P M=Type y or n then press ENTER:
		IF (%M%==y) goto WIN8GucciScript.bat
		IF (%M%==n) goto skip22
		:WIN8GucciScript.bat
		start WIN8GucciScript.bat
		:skip22
		pause 

		echo WIN 10?
		SET /P M=Type y or n then press ENTER:
		IF %M%==y goto WIN10GucciScript.bat
		IF %M%==n goto skip23
		:WIN10GucciScript.bat
		start WIN10GucciScript.bat
		:skip23
		pause
		
		cd files
		Echo Running scripts
		cd 2
		start CyberPatriotPowerShellScript.ps1
		cd ..
		pause
		cd 3
		start WindowsStigs.bat
		pause 
		start WidnowsSecurity.ps1
		pause
		cd ..
		cd DOFIRST
		pause
		start FirstRun.bat
		pause
		start Main.bat
		pause
		cd ..
		cd scripts
		
		echo block-telementry?
		SET /P M=Type y or n then press ENTER:
		IF %M%==y goto block-telementry
		IF %M%==n goto skip1
		:block-telementry
		start block-telementry.ps1
		:skip1
		pause

		echo disable services? This will diable many services. Please edit %cd%/disable-services.ps1
		SET /P M=Type y or n then press ENTER:
		IF %M%==y goto disable-services
		IF %M%==n goto skip2
		:disable-services
		start bdisable-services.ps1
		:skip2
		pause
		
		echo Fix Privacy Settings? This script will try to fix many of the privacy settings for the user. This is work in progress!
		SET /P M=Type y or n then press ENTER:
		IF %M%==y goto fix-privacy-settings
		IF %M%==n goto skip3
		:fix-privacy-settings
		start fix-privacy-settings.ps1
		:skip3
		pause
		
		echo "Optomixe UI?  This script will apply MarkC's mouse acceleration fix (for 100% DPI) and disable some accessibility features regarding keyboard input.  Additional some UI elements will be changed."
		SET /P M=Type y or n then press ENTER:
		IF %M%==y goto optimize-user-interface
		IF %M%==n goto skip4
		:optimize-user-interface
		start optimize-user-interface.ps1
		:skip4
		pause
		
		echo "Optomize Windows Updates? This script optimizes Windows updates by disabling automatic download and seeding updates to other computers."
		SET /P M=Type y or n then press ENTER:
		IF %M%==y goto optimize-windows-update
		IF %M%==n goto skip5
		:optimize-windows-update
		start optimize-windows-update.ps1
		:skip5
		pause
		
		echo remove default updates? This script removes unwanted Apps that come with Windows. If you  do not want to remove certain Apps comment out the apps in the files.
		SET /P M=Type y or n then press ENTER:
		IF %M%==y goto remove-default-apps
		IF %M%==n goto skip6
		:remove-default-apps
		start remove-default-apps.ps1
		:skip6
		pause
		
		echo Remove onedrive integration? This script will remove and disable OneDrive integration.
		SET /P M=Type y or n then press ENTER:
		IF %M%==y goto remove-onedrive
		IF %M%==n goto skip7
		:remove-onedrive
		start remove-onedrive.ps1
		:skip7
		pause
		
		echo Diable scedualed tasks? This script will disable certain scheduled tasks.
		SET /P M=Type y or n then press ENTER:
		IF %M%==y goto remove-onedrive
		IF %M%==n goto skip8
		:disable-scheduled-tasks
		start disable-scheduled-tasks.ps1
		:skip8
		pause
		
		echo Diable searchUI? 
		SET /P M=Type y or n then press ENTER:
		IF %M%==y goto disable-searchUI
		IF %M%==n goto skip9
		:disable-searchUI
		start disable-searchUI.bat
		:skip9
		pause
		cd ..
		
		
		cd WindowsFirewall
		cd tools 
		
		echo Open Firewall tools? 
		SET /P M=Type y or n then press ENTER:
		IF %M%==y goto FirewallToolsWithGui
		IF %M%==n goto skip10
		:FirewallToolsWithGui
		start FirewallToolsWithGui.ps1
		:skip10
		pause
		
		cd ..
		cd ..
		
		echo run misc script? 
		SET /P M=Type y or n then press ENTER:
		IF %M%==y goto all
		IF %M%==n goto skip11
		:all
		start all.bat
		:skip11
		pause
		
		echo opening gui!
		start hardentools.exe
		pause
		
		echo run audits?  These will allow you to check for compleatness. each will open in a new window.
		SET /P M=Type y or n then press ENTER:
		IF %M%==y goto audits
		IF %M%==n goto end
		:audits
		start ASD1709HardeningComplianceCheck.ps1
		start ASDOffice2016HardeningComplianceCheck.ps1
		:end
		pause
	}



