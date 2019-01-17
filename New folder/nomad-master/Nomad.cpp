// Nomad.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
using namespace std;

int displayBanner()
{
	cout << "                                   ||`-.___\n";
	cout << "                                   ||    _.>\n";
	cout << "                                   ||_.-'\n";
	cout << "               ==========================================\n";
	cout << "                `.:::::::.       `:::::::.       `:::::::.\n";
	cout << "                  \\:::::::.        :::::::.        :::::::\\ \n";
	cout << "                   L:::::::         :::::::         :::::::L\n";
	cout << "                   J::::::::        ::::::::        :::::::J\n";
	cout << "                    F:::::::        ::::::::        ::::::::L\n";
	cout << "                    |:::::::        ::::::::        ::::::::|\n";
	cout << "                    |:::::::        ::::::::        ::::::::|     .---.\n";
	cout << "                    |:::::::        ::::::::        ::::::::|    /(@  o`.\n";
	cout << "                    |:::::::       << Nomad >>      ::::::::|   |    /^^^\n";
	cout << "     __             |:::::::                        ::::::::|    \\ . \\vvv\n";
	cout << "   .'_ \\            |::::::: Portable security      ::::::::|     \\ `--'\n";
	cout << "   (( ) |           |:::::::    toolkit for mobile  ::::::::|      \\ `. \n";
	cout << "    `/ /            |:::::::       blue teams.      ::::::::|       L  \\ \n";
	cout << "    / /             |:::::::                        ::::::::|       |   \\ \n";
	cout << "   / /              |:::::::      --Numba Won--     ::::::::|       |   \\ \n";
	cout << "   J J              |:::::::      --2600 Club--     ::::::::|       |    L\n";
	cout << "   | |              |:::::::      --   5KB   --     ::::::::|       |    |\n";
	cout << "   | |              |:::::::        ::::::::        ::::::::|       F    |\n";
	cout << "   | J\\             F:::::::        ::::::::        ::::::::F      /     |\n";
	cout << "   |  L\\           J::::::::       .::::::::       .:::::::J      /      F\n";
	cout << "   J  J `.     .   F:::::::        ::::::::        ::::::::F    .'      J\n";
	cout << "    L  \\  `.  //  /:::::::'      .::::::::'      .::::::::/   .'        F\n";
	cout << "    J   `.  `//_..---.   .---.   .---.   .---.   .---.   <---<         J\n";
	cout << "     L    `-//_=/  _  \\=/  _  \\=/  _  \\=/  _  \\=/  _  \\=/  _  \\       /\n";
	cout << "     J     /|  |  (_)  |  (_)  |  (_)  |  (_)  |  (_)  |  (_)  |     /\n";
	cout << "      \\   / |   \\     //\\     //\\     //\\     //\\     //\\     /    .'\n";
	cout << "       \\ / /     `---//  `---//  `---//  `---//  `---//  `---'   .'\n";
	cout << "________/_/_________//______//______//______//______//_________.'_________\n";
	cout << "##RIT##VHS##MTHS##########################################################\n\n\n";
	return 0;
}

//file stream, number of users
int parseUsers(string fileName)
{
	//parse list of users in format "Administrators\n Me\n Users\n You\n"
	ifstream infile(fileName);
	string line;
	bool isAdmin;

	while (getline(infile, line))
	{
		istringstream iss(line);
		if (line == "Administrators")
		{
			isAdmin = true;
		}
		else if (line == "Users")
		{
			isAdmin = false;
		}
		else
		{
			if (isAdmin == true)
			{
				//dostuff for admins
				cout << "Admin: " << line << "\n";
			}
			else if (isAdmin == false)
			{
				//dostuff for users
				cout << "User: " << line << "\n";
			}
		}
	}

	system("pause");
	return 0;
}

int updatePasswords(string filename, string pass)
{
	//updates passwords of users listed in filename to secure_password9!
	ifstream infile(filename);
	string user;
	string toPass;
	bool isAdmin;

	while (getline(infile, user))
	{
		istringstream iss(user);
		if (user == "Administrators")
		{
			isAdmin = true;
		}
		else if (user == "Users")
		{
			isAdmin = false;
		}
		else
		{
			toPass = "net user " + user + " " + pass;
			system(toPass.c_str());
		}
	}

	system("pause");
	return 0;
}

int updatePasswordsISTS(string filename, string pass)
{
	//updates passwords of users listed in filename to the ISTS pass
	ifstream infile(filename);
	string user;
	string toPass;
	bool isAdmin;

	while (getline(infile, user))
	{
		istringstream iss(user);
		if (user == "Administrators")
		{
			isAdmin = true;
		}
		else if (user == "Users")
		{
			isAdmin = false;
		}
		else
		{
			toPass = "net user " + user + " " + pass;
			system(toPass.c_str());
		}
	}

	system("pause");
	return 0;
}

int generateDataISTS() {
	string command;

	command = "netstat -ano | findstr LIST | sort > stat.txt";
	system(command.c_str());
	command = "dir /B /S \windows\system32 > 32.txt";
	system(command.c_str());
	command = "dir /B /S \*.exe > exes.txt";
	system(command.c_str());
	command = "net share > shares.txt";
	system(command.c_str());
	command = "net user > users.txt";
	system(command.c_str());
	command = "net group 'Domain Admins' > dadmins.txt";
	system(command.c_str());
	command = "net start > svcs.txt";
	system(command.c_str());
	command = "net user guest /active:no";
	system(command.c_str());
	command = "icacls C:\Windows\Temp /inheritance:r /deny 'Everyone:(OI)(CI)(F)";
	system(command.c_str());

	system("pause");
	return 0;
}

int regroupUsers(string fileName)
{
	//remove unlisted users
	ifstream infile(fileName);
	string line;
	string lAdminY;
	string lAdminN;
	string lRDP;
	string lRMan;
	string lPower;
	string lCrypto;
	string lNetConf;
	string lUser;
	bool isAdmin;

	while (getline(infile, line))
	{
		istringstream iss(line);
		if (line == "Administrators")
		{
			isAdmin = true;
		}
		else if (line == "Users")
		{
			isAdmin = false;
		}
		else
		{
			if (isAdmin == true)
			{
				lAdminY = "net localgroup Administrators " + line + " /ADD";
				system(lAdminY.c_str());

			}
			else if (isAdmin == false)
			{
				string lUser = "net localgroup Users " + line + " /ADD";
				system(lUser.c_str());
				string lRDP = "net localgroup \"Remote Desktop Users\" " + line + " /DELETE";
				system(lRDP.c_str());
				string lAdminN = "net localgroup Administrators " + line + " /DELETE";
				system(lAdminN.c_str());
				string lPower = "net localgroup \"Power Users\" " + line + " /DELETE";
				system(lPower.c_str());
				string lCrypto = "net localgroup \"Cryptographic Operators\" " + line + " /DELETE";
				system(lCrypto.c_str());
				string lRMan = "net localgroup \"Remote Management Users\" " + line + " /DELETE";
				system(lRMan.c_str());
				string lNetConf = "net localgroup \"Network Configuration Operators\" " + line + " /DELETE";
				system(lNetConf.c_str());
				string gUser = "net group Users " + line + " /ADD";
				system(gUser.c_str());
				string gRDP = "net group \"Remote Desktop Users\" " + line + " /DELETE";
				system(gRDP.c_str());
				string gAdminN = "net group Administrators " + line + " /DELETE";
				system(gAdminN.c_str());
				string gPower = "net group \"Power Users\" " + line + " /DELETE";
				system(gPower.c_str());
				string gCrypto = "net group \"Cryptographic Operators\" " + line + " /DELETE";
				system(gCrypto.c_str());
				string gRMan = "net group \"Remote Management Users\" " + line + " /DELETE";
				system(gRMan.c_str());
				string gNetConf = "net group \"Network Configuration Operators\" " + line + " /DELETE";
				system(gNetConf.c_str());
			}
		}
	}

	system("pause");
	return 0;
}

//section name, key name, storage buffer
int modifyLSP(LPCWSTR section, LPCWSTR key, LPWSTR buffer)
{
	//cleaner way to update .ini files as seen in fixLSP()
	LPCWSTR iniFile = L"C:\\sec.cfg";
	WritePrivateProfileString(section, key, buffer, iniFile);
	return 0;
}

int fixLSP()
{
	//generate current configuration via SECEDIT
	system("SECEDIT /EXPORT /CFG C:\\sec.cfg");

	//update newsec keys via Windows .ini modifiers
	//TODO: cleanup code with modifyLSP()
	LPCWSTR iniSection = L"Privilege Rights";
	LPCWSTR iniKey;
	LPWSTR iniBuffer;
	LPCWSTR iniDefault = L"Not Found";
	DWORD iniLength = 1000;
	LPCWSTR iniFile = L"C:\\sec.cfg";

	iniSection = L"System Access";
	iniKey = L"MinimumPasswordAge";
	iniBuffer = L"10";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MaximumPasswordAge";
	iniBuffer = L"90";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MinimumPasswordLength";
	iniBuffer = L"8";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"PasswordComplexity";
	iniBuffer = L"1";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"PasswordHistorySize";
	iniBuffer = L"5";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"LockoutBadCount";
	iniBuffer = L"10";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"ResetLockoutCount";
	iniBuffer = L"30";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"LockoutDuration";
	iniBuffer = L"30";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"RequireLogonToChangePassword";
	iniBuffer = L"0";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"ForceLogoffWhenHourExpire";
	iniBuffer = L"1";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"NewAdministratorName";
	iniBuffer = L"batman";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"NewGuestName";
	iniBuffer = L"robin";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"ClearTextPasswordn";
	iniBuffer = L"0";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"LSAAnonymousNameLookup";
	iniBuffer = L"0";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"EnableAdminAccount";
	iniBuffer = L"0";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"EnableGuestAccount";
	iniBuffer = L"0";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);

	iniSection = L"Event Audit";
	iniKey = L"AuditSystemEvents";
	iniBuffer = L"3";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"AuditLogonEvents";
	iniBuffer = L"3";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"AuditObjectAccess";
	iniBuffer = L"3";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"AuditPrivilegeUse";
	iniBuffer = L"3";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"AuditPolicyChange";
	iniBuffer = L"3";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"AuditAccountManage";
	iniBuffer = L"3";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"AuditProcessTracking";
	iniBuffer = L"3";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"AuditDSAccess";
	iniBuffer = L"3";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"AuditAccountLogon";
	iniBuffer = L"3";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);

	iniSection = L"Registry Values";
	iniKey = L"MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Setup\\RecoveryConsole\\SecurityLevel";
	iniBuffer = L"4,0";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Setup\\RecoveryConsole\\SetCommand";
	iniBuffer = L"4,0";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AllocateCDRoms";
	iniBuffer = L"1,\"1\"";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AllocateFloppies";
	iniBuffer = L"1,\"1\"";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\CachedLogonsCount";
	iniBuffer = L"1,\"10\"";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\ForceUnlockLogon";
	iniBuffer = L"4,0";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\PasswordExpiryWarning";
	iniBuffer = L"4,5";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\ScRemoveOption";
	iniBuffer = L"1,\"0\"";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin";
	iniBuffer = L"4,5";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorUser";
	iniBuffer = L"4,3";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DontDisplayLastUserName";
	iniBuffer = L"4,1";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableInstallerDetection";
	iniBuffer = L"4,1";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA";
	iniBuffer = L"4,1";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableSecureUIAPaths";
	iniBuffer = L"4,1";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableUIADesktopToggle";
	iniBuffer = L"4,0";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableVirtualization";
	iniBuffer = L"4,1";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\FilterAdministratorToken";
	iniBuffer = L"4,0";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LegalNoticeCaption";
	iniBuffer = L"1,\"\"";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LegalNoticeText";
	iniBuffer = L"7,";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\PromptOnSecureDesktop";
	iniBuffer = L"4,1";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ScForceOption";
	iniBuffer = L"4,0";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ShutdownWithoutLogon";
	iniBuffer = L"4,0";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\UndockWithoutLogon";
	iniBuffer = L"4,1";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ValidateAdminCodeSignatures";
	iniBuffer = L"4,0";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\AuthenticodeEnabled";
	iniBuffer = L"4,0";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\AuditBaseObjects";
	iniBuffer = L"4,0";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\CrashOnAuditFail";
	iniBuffer = L"4,0";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\DisableDomainCreds";
	iniBuffer = L"4,0";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\EveryoneIncludesAnonymous";
	iniBuffer = L"4,0";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\FIPSAlgorithmPolicy\\Enabled";
	iniBuffer = L"4,0";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\ForceGuest";
	iniBuffer = L"4,0";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\FullPrivilegeAuditing";
	iniBuffer = L"3,0";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LimitBlankPasswordUse";
	iniBuffer = L"4,1";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\NTLMMinClientSec";
	iniBuffer = L"4,536870912";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\NTLMMinServerSec";
	iniBuffer = L"4,536870912";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\NoLMHash";
	iniBuffer = L"4,1";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous";
	iniBuffer = L"4,1";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymousSAM";
	iniBuffer = L"4,1";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Control\\Print\\Providers\\LanMan Print Services\\Servers\\AddPrinterDrivers";
	iniBuffer = L"4,0";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\Kernel\\ObCaseInsensitive";
	iniBuffer = L"4,1";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\ClearPageFileAtShutdown";
	iniBuffer = L"4,1";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\ClearPageFileAtShutdown";
	iniBuffer = L"4,0";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\ProtectionMode";
	iniBuffer = L"4,1";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\SubSystems\\optional";
	iniBuffer = L"7,";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\AutoDisconnect";
	iniBuffer = L"4,15";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\EnableForcedLogOff";
	iniBuffer = L"4,1";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\EnableSecuritySignature";
	iniBuffer = L"4,0";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\NullSessionPipes";
	iniBuffer = L"7,";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\RequireSecuritySignature";
	iniBuffer = L"4,0";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\RestrictNullSessAccess";
	iniBuffer = L"4,1";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\EnablePlainTextPassword";
	iniBuffer = L"4,0";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\EnableSecuritySignature";
	iniBuffer = L"4,1";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\RequireSecuritySignature";
	iniBuffer = L"4,0";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Services\\LDAP\\LDAPClientIntegrity";
	iniBuffer = L"4,1";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\DisablePasswordChange";
	iniBuffer = L"4,0";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\MaximumPasswordAge";
	iniBuffer = L"4,30";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\RequireSignOrSeal";
	iniBuffer = L"4,1";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\RequireStrongKey";
	iniBuffer = L"4,1";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\SealSecureChannel";
	iniBuffer = L"4,1";
	WritePrivateProfileString(iniSection, iniKey, iniBuffer, iniFile);
	iniKey = L"MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\SignSecureChannel";
	iniBuffer = L"4,1";

	//apply updated configuration via SECEDIT, remove config file
	system("SECEDIT /CONFIGURE /DB C:\\Windows\\security\\newsec.sdb /CFG C:\\sec.cfg /AREAS SECURITYPOLICY");
	system("del C:\\sec.cfg");

	cout << "\nLSP values updated.\n";
	system("pause");
	
	return 0;
}

int fixFirewall()
{
	//enable firewall profiles via netsh
	system("netsh advfirewall reset");
	system("netsh advfirewall set allprofiles blockinbound, allowoutbound");
	system("netsh advfirewall set allprofiles state on");

	//enable windows firewall service
	system("SC CONFIG mpssvc START= auto");
	system("NET START mpssvc");
	cout << "Enabled windows firewall service\n";

	cout << "Firewall enabled and updated\n";

	system("pause");

	return 0;
}

int fixServices()
{
	//enable and start important services via SC CONFIG and NET START

	//windows update service
	system("SC CONFIG wuaserv START= auto");
	system("NET START wuaserv");
	cout << "Enabled windows update service\n";

	//event log service
	system("SC CONFIG eventlog START= auto");
	system("NET START eventlog");
	cout << "Enabled event log service\n";

	//windows firewall
	system("SC CONFIG mpssvc START= auto");
	system("NET START mpssvc");
	cout << "Enabled windows firewall service\n";

	//base filtering engine
	system("SC CONFIG bfe START= auto");
	system("NET START bfe");
	cout << "Enabled base filtering engine\n";

	//security center
	system("SC CONFIG wscsvc START= auto");
	system("NET START wscsvc");
	cout << "Enabled security center\n";

	//system event notification service
	system("SC CONFIG sens	START= auto");
	system("NET START sens");
	cout << "Enabled system event notification service\n";

	//disable and stop known insecure services via SC CONFIG and NET START

	//telnet server
	system("SC CONFIG tlntsvr START= disabled");
	system("NET STOP tlntsvr");
	cout << "Disabled telnet server\n";

	//microsoft ftp server
	system("SC CONFIG ftpsvc START= disabled");
	system("NET STOP ftpsvc");
	cout << "Disabled ftp server\n";

	//snmp services
	system("SC CONFIG snmp START= disabled");
	system("NET STOP snmp");
	system("SC CONFIG snmp START= disabled");
	system("NET STOP snmp");
	cout << "Disabled snmp services\n";

	//windows remote management service
	system("SC CONFIG winrm START= disabled");
	system("NET STOP winrm");
	cout << "Disabled remote management service\n";

	//remote desktop service
	system("SC CONFIG termservice START= disabled");
	system("NET STOP termservice");
	cout << "Disabled remote desktop services\n";

	//microsoft web server
	system("SC CONFIG w3svc START= disabled");
	system("NET STOP w3svc");
	cout << "Disabled w3svc web server\n";

	//internet connection sharing
	system("SC CONFIG sharedaccess START= disabled");
	system("NET STOP sharedaccess");
	cout << "Disabled internet connection sharing\n";

	//routing and remote access service
	system("SC CONFIG remoteaccess START= disabled");
	system("NET STOP remoteaccess");
	cout << "Disabled routing and remote access service\n";
	cout << "Active Services";// All Active Sercies
	system("wmic service get caption"); 
	system("pause");

	return 0;
}

int updateSoftware()
{
	//TODO: detect and fix out of date software and dependencies on the machine

	return 0;
}

int displayStartup()
{
	system("wmic startup get command");// start up application Names
	system("pause");

	return 0;
}

int fileSearch()
{
	int x;
	cout << "Type 1 To Search Users, Type 2 to Search the Entire C: Drive";
	cin >> x;
	if (x == 1)
	{
		//Find Media Files Within Users
		system("dir /S C:\\Users\\*.png");
		system("dir /S C:\\Users\\*.JPEG");
		system("dir /S C:\\Users\\*.GIF");
		system("dir /S C:\\Users\\*.jpg");
		system("dir /S C:\\Users\\*.mp3");
		system("dir /S C:\\Users\\*.mov");//movies
		system("dir /S C:\\Users\\*.mp4");
	}
	if (x == 2)
	{
		//Media Files within the whole C Drive
		system("dir /S C:\\*.png");
		system("dir /S C:\\*.JPEG");
		system("dir /S C:\\*.GIF");
		system("dir /S C:\\*.jpg");
		system("dir /S C:\\*.mp3");
		system("dir /S C:\\*.mov");//movies
		system("dir /S C:\\*.mp4");
	}

	system("pause");

	return 0;
}

int updateSystem()
{
	//TODO: force system updates for the machine
	//TODO: Detect missing service packs, download and execute from MS website

	return 0;
}

int displayListening()
{
	//display listening ports via netstat
	system("C:\\Windows\\system32\\netstat.exe -aon");

	system("pause");
	
	return 0;
}

int testFunc()
{
	return 0;
}

int menu()
{
	displayBanner();

	int menSelect;
	cout << "21. ISTS Updates Passwords\n";
	cout << "22. ISTS Generate Data\n";
	cout << "1. Fix LSP\n";
	cout << "2. Fix Firewall\n";
	cout << "3. Fix Services\n";
	cout << "4. Parse Userlist\n";
	cout << "5. Media File Search\n";
	cout << "6. Display Startup Programs\n";
	cout << "7. Update User Passwords\n";
	cout << "8. Display Listening Ports\n";
	cout << "9. Fix User Groups\n";
	cout << "97. Test Function\n";
	cout << "98. Menu\n";
	cout << "99. Exit\n\n";
	cout << "viking# ";
	cin >> menSelect;

	//TODO: change to case statement
	if (menSelect == 1) {
		fixLSP();
		menu();
	}
	else if (menSelect == 21) {
		updatePasswordsISTS("C:\\users.txt", "WeWinISTS2018!!");
		menu();
	}
	else if (menSelect == 22) {
		generateDataISTS();
		menu();
	}
	else if (menSelect == 2) {
		fixServices();
		menu();
	}
	else if (menSelect == 3) {
		fixFirewall();
		menu();
	}
	else if (menSelect == 4) {
		parseUsers("C:\\users.txt");
		menu();
	}
	else if (menSelect == 5) {
		fileSearch();
		menu();
	}
	else if (menSelect == 6) {
		displayStartup();
		menu();
	}
	else if (menSelect == 7) {
		updatePasswords("C:\\users.txt", "secure_password9!");
		menu();
	}
	else if (menSelect == 8) {
		displayListening();
		menu();
	}
	else if (menSelect == 9) {
		regroupUsers("C:\\users.txt");
		menu();
	}
	else if (menSelect == 97) {
		testFunc();
		menu();
	}
	else if (menSelect == 98) {
		system("cls");
		menu();
	}

	return 0;
}


int main()
{
	menu();
    return 0;
}

