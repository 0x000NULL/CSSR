#!/bin/bash
#This is a script written by Ryan Galligher in order to assist him in fixing vulnerabilities in the CyberPatriot competition.
#This code comes as is and may not work on future versions of Linux or software it attempts to fix. Always test this on a non-competition image before use.


#------------NOTE THIS-------------
	#Needs file created with valid users and valid admins called users.txt and admin.txt
	#DO NOT FORGET TO CREATE README WITH ALL USERS NAMES, ELSE IT WILL DELETE SOMEONE YOU DON'T WANT IT TO
	#if adding users, create addusers.txt

	#Look up /etc/services
	
	
#Also, go into /etc/securetty and disallow the rest after 3-5, if not 1. Not sure how it would work for script
#Also, DOES NOT DELETE THE FILE/COMMAND STARTING NETCAT BACKDOOR, just grabs the executable and moves it. Usually gives points, but should still try and pinpoint where it is coming from
#Remember, go into dash, type remote and select Desktop sharing. This should be off and may be on, but just not sure how to script it yet
#MAKE SURE NO BAD REPOSITORIES
#SCRIPT EXPECTS TO BE RUN ON THE USER WHO IS LOGGED IN’S DESKTOP.

#save all of the logs before you begin messing with stuff
mkdir logs
echo "auth log:" > logs/authLogs.txt
cat /var/log/auth.log >> logs/authLogs.txt
#echo "" > logs/authLogs.txt
echo "dpkg log:" > logs/dpkgLogs.txt
cat /var/log/dpkg.log >> logs/dpkgLogs.txt
echo "" > logs/secureLogs.txt
cat /var/log/secure > logs/secureLogs.txt
echo  " " > logs/messageLogs.txt
cat /var/log/messages >> logs/messageLogs.txt
echo  " " > logs/historyLogs.txt
cat /var/log/apt/history.log >> logs/historyLogs.txt
echo " " > logs/historyLogs.txt
cp /root/.bash_history logs/root.bash_history

usrLoggedIn=$(pwd | cut -d'/' -f3)	#It’s either 3 or 2, depending
debian="debian"
distro=$(cat /etc/*-release | grep  "ID=" | grep -v "VERSION"| cut -d'=' -f2)
#Stops you so that you can finish the Forensics. This is helpful because it will save the log files before you begin messing with the computer but doesn’t start doing anything until you are ready.
echo -n "Are you ready to continue through the script? Are all of the Forensics Answered Yet?	"
read info

if [[ $(ls | grep -c -e "admin.txt" -e "users.txt") -ne 2 ]]; then
    echo "Necessary text files for users and admins are not present. Shutting down script."
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
   echo "Too Bad. This script must be run as root"
   exit 1
fi

#change root password
yes "H3LL0@" | passwd
echo "Finished with changing root password"
echo "" > usersChanged.txt


#Change all the user passwords
#For every user in the /etc/passwd file who has a UID >500 (generally newly added user), changes their password.
for i in $(cat /etc/passwd | cut -d: -f 1,3,6 | grep -e "[5-9][0-9][0-9]" -e "[0-9][0-9][0-9][0-9]" | grep "/home" | cut -d: -f1) ; do 
	yes "H3LL0@" | passwd $i ;
	#This changes in the shadow file the max and min password days
	passwd -x 85 $i;
	passwd -n 15 $i;
	#save the history into the log directory
	cp /home/$i/.bash_history /logs/$i
	echo $i  >> usersChanged.txt
done;
echo "Finished with changing all passwords"


#Delete bad users
#For every user in /etc/passwd file who isn’t mentioned in the README, removes them and deletes everything they have
for i in $(cat /etc/passwd | cut -d: -f 1,3,6 | grep -e "[5-9][0-9][0-9]" -e "[0-9][0-9][0-9][0-9]" | grep "/home" | cut -d: -f1) ; do
	if [[ $( grep -ic -e $i $(pwd)/README ) -eq 0 ]]; then	
		(deluser $i --remove-all-files >> RemovingUsers.txt 2>&1) &  #starts deleting in background
	fi
done
echo "Finished with deleting bad users"

#For everyone in the addusers file, creates the user
echo "" >> addusers.txt
for i in $(cat $(pwd)/addusers.txt); do
	useradd $i;
done
echo "Finished adding users"

#Goes and makes users admin/not admin as needed
#for every user with UID above 500 that has a home directory
for i in $(cat /etc/passwd | cut -d: -f 1,3,6 | grep -e "[5-9][0-9][0-9]" -e "[0-9][0-9][0-9][0-9]" | grep "/home" | cut -d: -f1); do
	#If the user is supposed to be a normal user but is in the sudo group, remove them from sudo
	BadUser=0
	if [[ $( grep -ic $i $(pwd)/users.txt ) -ne 0 ]]; then	
		if [[ $( echo $( grep "sudo" /etc/group) | grep -ic $i ) -ne 0 ]]; then	
			#if username is in sudo when shouldn’t
			deluser $i sudo;
			echo "removing $i from sudo" >> usersChanged.txt
		fi
if [[ $( echo $( grep "adm" /etc/group) | grep -ic $i ) -ne 0 ]]; then	
			#if username is in adm when shouldn’t
			deluser $i adm;
			echo "removing $i from adm" >> usersChanged.txt
		fi
	else
		BadUser=$((BadUser+1));
	fi
	#If user is supposed to be an adm but isn’t, raise privilege.
	if [[ $( grep -ic $i $(pwd)/admin.txt ) -ne 0 ]]; then	
		if [[ $( echo $( grep "sudo" /etc/group) | grep -ic $i ) -eq 0 ]]; then	
			#if username isn't in sudo when should
			usermod -a -G "sudo" $i
			echo "add $i to sudo"  >> usersChanged.txt
		fi
if [[ $( echo $( grep "adm" /etc/group) | grep -ic $i ) -eq 0 ]]; then	
			#if username isn't in adm when should
			usermod -a -G "adm" $i
			echo "add $i to adm"  >> usersChanged.txt
		fi
	else
		BadUser=$((BadUser+1));
	fi
	if [[ $BadUser -eq 2 ]]; then
		echo "WARNING: USER $i HAS AN ID THAT IS CONSISTENT WITH A NEWLY ADDED USER YET IS NOT MENTIONED IN EITHER THE admin.txt OR users.txt FILE. LOOK INTO THIS." >> usersChanged.txt
	fi
done
echo "Finished changing users"

#Also need to add a check for if in other insecure places like shadow group




#Reinstalls many (if not all) of the packages on the computer. Use this if you think the config files were royally messed up and too Trojaned to fix normally. Will take long time
echo  -n "Reinstall Everything?	"
read output
if [[ $output =~ ^[Yy]$ ]]
then 
	apt-get -V -y install --reinstall coreutils
fi






echo "This will attempt to turn on firewall and turn on logging" > Firewall.txt
echo "Starting Download of ufw, this may take awahile"
#Turns the firewall on, resets ufw to default, the turns logging on high, and adds in some standard rules. Firestarter package might be good gui for ufw
apt-get install ufw -y >> /dev/null 2>&1
(ufw enable  >> Firewall.txt; yes | ufw reset  >> Firewall.txt; ufw enable  >> Firewall.txt; ufw allow http; ufw allow https; ufw deny 23; ufw deny 2049; ufw deny 515; ufw deny 111; ufw logging high >> Firewall.txt; echo "" >> Firewall.txt) &
#The little & at the end will cause this entire section of code to be run synchronously with the rest of this script, meaning that it will execute in the background while the rest of this script continues on. NOTE: IF YOU CLOSE THE TERMINAL, IT WILL TERMINATE THIS BACKGROUND PROCESS AS WELL.
echo "Working on ufw"
#allow http - means
#allow https - means
#deny 23 - means
#deny 2049 - means
#deny 515 - means
#deny 111 - means

#Attempts to use iptables to set a few rules to secure computer DO NOT DISTURB WHAT YOU DON’T UNDERSTAND
#iptables -F #clears all existing rules
#DO NOT DO THIS WITHOUT KNOWING WHAT YOU ARE DOING!!! THIS IS WHAT BROKE THE NETWORK IN THE IMAGE

#allow all incoming ssh
#iptables –A INPUT –I eth0 –p tcp –dport 22 –m state –state NEW, ESTABLISHED –j ACCEPT

#prevent DoS attack on HTTP
#iptables –A INPUT –p tcp –dport 80 –m limit –limit 25/minute –limit-burst 100 –j ACCEPT

#log Dropped Packets
#iptables –N LOGGING
#iptables –A INPUT –j LOGGING
#iptables –A LOGGING –m limit –limit 2/min –j LOG –log-prefix "IPTables Packet Dropped: " –log-level iptables –A LOGGING –j DROP
#DO NOT USE THIS AS CURRENTLY STATED, AS THIS WILL GO TO THE LOGGING CHAIN AND THEN BEGIN DROPPING ALL PACKETS IT RECIEVES. ONLY REASON STILL HERE IS SO I CAN LEARN HOW TO NOT DO THIS

#iptables -A INPUT -p tcp -m tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT -p tcp -m tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT -I lo -j ACCEPT
#iptables -A INPUT -j DROP

#network security
#  iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 23 -j DROP         #Block Telnet
#  iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 2049 -j DROP       #Block NFS
#  iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 2049 -j DROP       #Block NFS
#  iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 6000:6009 -j DROP  #Block X-Windows
#  iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 7100 -j DROP       #Block X-Windows font server
#  iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 515 -j DROP        #Block printer port
#  iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 515 -j DROP        #Block printer port
#  iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 111 -j DROP        #Block Sun rpc/NFS
#  iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 111 -j DROP        #Block Sun rpc/NFS
#  iptables -A INPUT -p all -s localhost  -i eth0 -j DROP            #Deny outside packets from internet which claim to be from your loopback interface.



#Will go into the lightdm library and turn off guest accounts
/usr/lib/lightdm/lightdm-set-defaults -l false
echo $? >> WorkProperly.txt
echo "if last was 0, then lightdm was turned off properly" >> WorkProperly.txt

echo "allow-guest=false" >> /etc/lightdm/lightdm.conf
echo "" >> WorkProperly.txt

#Disables guest option and usernames on login screen (in /etc/lightdm/lightdm.conf)
TEXT="[SeatDefaults]\nautologin-guest=false\nautologin-user=none\nautologin-user-timeout=0\nautologin-session=lightdm-autologin\nallow-guest=false\ngreeter-hide-users=true"
printf $TEXT > /etc/lightdm/lightdm.conf
echo "Finished with Guest accounts"

#Lock people from logging straight into the root account
passwd -l root
echo "Finished locking the root account"

#Change the ownership and permissions of files that could commonly be exploited otherwise
chown root:root /etc/securetty
chmod 0600 /etc/securetty
chmod 644 /etc/crontab
chmod 640 /etc/ftpusers
chmod 440 /etc/inetd.conf
chmod 440 /etc/xinetd.conf
chmod 400 /etc/inetd.d
chmod 644 /etc/hosts.allow
chmod 440 /etc/sudoers
chmod 640 /etc/shadow
chown root:root /etc/shadow
echo "Finished changing permissions"


#Remove unwanted alias
echo "Bad Aliases:" > AliasesAndFunctions.txt
for i in $(echo $(alias | grep -vi -e "alias egrep='egrep --color=auto'" -e "alias fgrep='fgrep --color=auto'" -e "alias grep='grep --color=auto'" -e "alias l='ls -CF'" -e "alias la='ls -A'" -e "alias ll='ls -alF'" -e "alias ls='ls --color=auto'" | cut -f 1 -d=) | cut -f 2 -d ' ') ; do 
	echo $(alias | grep -e $i)  >> AliasesAndFunctions.txt;
	unalias $i;
done
echo "Finished unaliasing"

#Save what's a function currently
echo "" >> AliasesAndFunctions.txt
echo "Functions:" >> AliasesAndFunctions.txt
declare -F >> AliasesAndFunctions.txt
echo "Saved functions"

#Clears out the control-alt-delete, as this could possibly be a problem
echo "# control-alt-delete - emergency keypress handling
#
# This task is run whenever the Control-Alt-Delete key combination is
# pressed, and performs a safe reboot of the machine.
description	\"emergency keypress handling\"
author		\"Scott James Remnant <scott@netsplit.com>\"
start on control-alt-delete
task
exec false" > /etc/init/control-alt-delete.conf
echo "Finished cleaning control-alt-delete"


#goes and replaces the /etc/sudoers file with a clean one
if [[ $(ls -la /etc | grep -ic sudoers) -ne 0 ]]; then
	echo "Replacing /etc/sudoers" >> WorkProperly.txt
cp /etc/sudoers /etc/.sudoers
echo "#
# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
#
Defaults	env_reset
Defaults	secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"
# Host alias specification
# User alias specification
# Cmnd alias specification
# User privilege specification
root	ALL=(ALL:ALL) ALL
# Members of the admin group may gain root privileges
%admin ALL=(ALL) ALL
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL
# See sudoers(5) for more information on \"#include\" directives:

#includedir /etc/sudoers.d" > /etc/sudoers
echo "#
# As of Debian version 1.7.2p1-1, the default /etc/sudoers file created on
# installation of the package now includes the directive:
# 
# 	#includedir /etc/sudoers.d
# 
# This will cause sudo to read and parse any files in the /etc/sudoers.d 
# directory that do not end in '~' or contain a '.' character.
# 
# Note that there must be at least one file in the sudoers.d directory (this
# one will do), and all files in this directory should be mode 0440.
# 
# Note also, that because sudoers contents can vary widely, no attempt is 
# made to add this directive to existing sudoers files on upgrade.  Feel free
# to add the above directive to the end of your /etc/sudoers file to enable 
# this functionality for existing installations if you wish!
#" > /etc/sudoers.d/README

#Looks to see if there are any sudo configurations in sudoers.d. If there are, these are generally viruses and should be deleted. However, just in case they aren’t, this moves them to the folder that the script is currently running in.
for i in $(ls /etc/sudoers.d | grep -vi -e "\." -e "README" -e "total") ; do
	#Badname=$(ls /etc/sudoers.d | grep -v -e "\." -e "README" -e "total");	used to work when there also a -c, but would flip if nothing there
	cp /etc/sudoers.d/$i $(pwd)/$i		#/etc/sudoers.d/$Badname $(pwd)/$Badname;
	rm /etc/sudoers.d/$i			#/etc/sudoers.d/$Badname;
	echo $i " was a found file that shouldn't be there, copied and removed it" >> WorkProperly.txt
done
echo "" >> WorkProperly.txt

echo "Finished with sudoers, fixed main sudoers and cleaned README and tried to delete any other ones"
fi

#enable cookie protection
echo "#### ipv4 networking and equivalent ipv6 parameters ####

## TCP SYN cookie protection (default)
## helps protect against SYN flood attacks
## only kicks in when net.ipv4.tcp_max_syn_backlog is reached
net.ipv4.tcp_syncookies = 1

## protect against tcp time-wait assassination hazards
## drop RST packets for sockets in the time-wait state
## (not widely supported outside of linux, but conforms to RFC)
##CALLED TIME-WAIT ASSASSINATION PROTECTION
net.ipv4.tcp_rfc1337 = 1

## sets the kernels reverse path filtering mechanism to value 1(on)
## will do source validation of the packet's recieved from all the interfaces on the machine
## protects from attackers that are using ip spoofing methods to do harm
net.ipv4.conf.all.rp_filter = 1
net.ipv6.conf.all.rp_filter = 1

## tcp timestamps
## + protect against wrapping sequence numbers (at gigabit speeds)
## + round trip time calculation implemented in TCP
## - causes extra overhead and allows uptime detection by scanners like nmap
## enable @ gigabit speeds
net.ipv4.tcp_timestamps = 0
#net.ipv4.tcp_timestamps = 1

## log martian packets
net.ipv4.conf.all.log_martians = 1


## ignore echo broadcast requests to prevent being part of smurf attacks (default)
net.ipv4.icmp_echo_ignore_broadcasts = 1
## ignore bogus icmp errors (default)
net.ipv4.icmp_ignore_bogus_error_responses = 1
## send redirects (not a router, disable it)
net.ipv4.conf.all.send_redirects = 0


## ICMP routing redirects (only secure)
#net.ipv4.conf.all.secure_redirects = 1 (default)
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
" >> /etc/sysctl.conf
sysctl --system > /dev/null
echo "Enabled Cookie Protection"




#makes updates happen daily
echo "APT::Periodic::Update-Package-Lists \"1\";
APT::Periodic::Download-Upgradeable-Packages \"0\";
APT::Periodic::AutocleanInterval \"0\";" > /etc/apt/apt.conf.d/10periodic
echo "Checks for updates automatically"


#makes updates also come from right places, updates repositories. However, it does not clear out ones there, so remember to do so

if [[ $(echo $distro | grep -ic $debian) -eq 0 ]]
then
echo "deb http://security.ubuntu.com/ubuntu/ trusty-security main universe
deb http://us.archive.ubuntu.com/ubuntu/ trusty-updates main universe" >> /etc/apt/sources.list
add-apt-repository "deb http://archive.canonical.com/ubuntu precise partner"
add-apt-repository "deb http://archive.ubuntu.com/ubuntu precise multiverse main universe restricted"
add-apt-repository "deb http://security.ubuntu.com/ubuntu/ precise-security universe main multiverse restricted"
add-apt-repository "deb http://archive.ubuntu.com/ubuntu precise-updates universe main multiverse restricted"
echo "Updates also come from security and recommended updates"
else
	echo "" >> /etc/apt/sources.list
add-apt-repository "deb http://security.debian.org wheezy/updates main"
add-apt-repository "deb-src http://security.debian.org wheezy/updates main"
fi


#Cleans out the path file in case it has been modified to point to illegal places, makes a copy to the desktop in case you wanted to see it
cp /etc/environment $(pwd)/environment
echo "PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"" > /etc/environment
echo "Finished cleaning the PATH"


#restart all of the DNS caches to clear out any unwanted connections
/etc/init.d/dnsmasq restart > cacheClearing.txt
/etc/init.d/nscd -i hosts >> cacheClearing.txt #some others said reload or restart would do the same thing
/etc/init.d/nscd reload >> cacheClearing.txt
rndc flush >> cacheClearing.txt	#this clears the cache when bind9 is installed
echo "Clearing computer cache:" >> cacheClearing.txt
#These next few clear out the cache on the computer
free >> cacheClearing.txt
sync && echo 3 > /proc/sys/vm/drop_caches
#echoing the 3 in drop_caches tells the system to ___________________
echo "After" >> cacheClearing.txt
free >> cacheClearing.txt
echo "Finished restarting caches"
service xinetd reload



#Save all of the currently running services to be looked at later
( service --status-all 2>&1 | grep "+" >> Services.txt 2>&1 ; echo “Finished Printing out services” ) &




#Looks through the password file and determines if there are any users with root uid/gid
echo "And the stuff in the /etc/passwd file is:" > Warnings.txt
grep ":0:" < /etc/passwd >> Warnings.txt
#grep "*:0:*" < /etc/passwd >> Warnings.txt

echo $( grep ":0:" /etc/passwd | grep -v -e "root:x" -e "#" )
for i in $(grep ":0:" /etc/passwd | grep -v -e "root:x" -e "#"); do
	name=$(echo $i | cut -f1 -d: );
	echo $name
	#(deluser $name --remove-all-files  >> RemovingUsers.txt 2>&1) &    #Doesn’t work, as it fails and if you force it then it deletes root
	lineNumber=$(grep -in  -e $i /etc/passwd | cut -d: -f 1);
	sed -i '/'"$lineNumber"'/s/^/#/' /etc/passwd
	#These two actually find the line where the not root uid 0 is, and then comment that line out
	gnome-terminal -e "bash -c \"( echo "WARNING: THERE IS A HIDDEN ROOT USER ON THE COMPUTER. PLEASE RECTIFY THE SITUATION IMMEDIATELY."; exec bash )\"" & disown; sleep 2; 
	#This disown causes the terminal created to not be associated with the original terminal so when the original is closed it does not also close this one.
done

echo "" >> Warnings.txt
echo "Finished with Looking for hidden root users and removing them"


#for i in $(cat /etc/passwd | cut -d: -f 1,3,6 | grep -e "[5-9][0-9][0-9]" -e "[0-9][0-9][0-9][0-9]" | grep "/home" | cut -d: -f1); do
#done


#Looks through the passwd file and make sure that none of the users have the same uid/gid
#looks through the password file and makes sure that users that shouldn’t have a shell don’t have a shell.



#This clears out the HOST file so that unintentional/malicious networks are accidentally accessed.
echo "Clearing HOSTS file"
#echo $(date): Clearing HOSTS file >> Warnings.txt
cp /etc/hosts hosts
echo 127.0.0.1	localhost > /etc/hosts
echo 127.0.1.1	ubuntu  >> /etc/hosts

echo ::1     ip6-localhost ip6-loopback >> /etc/hosts
echo fe00::0 ip6-localnet >> /etc/hosts
echo ff00::0 ip6-mcastprefix >> /etc/hosts
echo ff02::1 ip6-allnodes >> /etc/hosts
echo ff02::2 ip6-allrouters >> /etc/hosts


#Determines if there are any netcat backdoors running, and will delete some of them
echo "netcat backdoors:" >> Warnings.txt
netstat -ntlup | grep -e "netcat" -e "nc" -e "ncat" >> Warnings.txt

#goes and grabs the PID of the first process that has the name netcat. Kills the executable, doesn’t go and kill the item in one of the crons. Will go through until it has removed all netcats.
a=0;
for i in $(netstat -ntlup | grep -e "netcat" -e "nc" -e "ncat"); do
	if [[ $(echo $i | grep -c -e "/") -ne 0  ]]; then
		badPID=$(ps -ef | pgrep $( echo $i  | cut -f2 -d'/'));
		realPath=$(ls -la /proc/$badPID/exe | cut -f2 -d'>' | cut -f2 -d' ');
		cp $realPath $a
		echo "$realPath $a" >> Warnings.txt;
		a=$((a+1));
		rm $realPath;
		kill $badPID;
	fi
done
echo "" >> Warnings.txt
echo "Finished looking for Netcat Backdoors"

#Remove any bad files that are in the users cron in /var/spool/cron/crontabs
for i in $(ls /var/spool/cron/crontabs); do
	cp /var/spool/cron/crontabs/$i $(pwd)/$i;
	rm /var/spool/cron/crontabs/$i;
done
echo "finished removing files in /var/spool/cron/crontabs"


#Make cron.allow and at.allow and deleting cron.deny and at.deny
/bin/rm -f /etc/cron.deny
/bin/rm -f /etc/at.deny
echo "root" > /etc/cron.allow
echo "root" > /etc/at.allow
/bin/chown root:root /etc/cron.allow
/bin/chown root:root /etc/at.allow
/bin/chmod 400 /etc/at.allow
/bin/chmod 400 /etc/cron.allow
echo "Finished creating cron/at.allow and deleting cron/at.deny"

packageName=("john" "telnetd" "logkeys" "hydra" "fakeroot" "nmap" "crack" "medusa" "nikto" "tightvnc" "bind9" "avahi" "cupsd" "postfix" "nginx" "frostwire" "vuze" "samba" "apache2" "ftp" "vsftpd" "netcat" "openssh" "weplab" "pyrit" "mysql" "php5" "proftpd-basic" "filezilla" "postgresql" "irssi")

dpkgName=("john john-data" "openbsd-inetd telnetd" "logkeys" " hydra-gtk hydra" "fakeroot libfakeroot" "nmap zenmap" "crack crack-common" "libssh2-1 medusa" "" "xtightvncviewer" "bind9 bind9utils" "avahi-autoipd avahi-daemon avahi-utils" "cups cups-core-drivers printer-driver-hpcups cupsddk indicator-printers printer-driver-splix hplip printer-driver-gutenprint bluez-cups printer-driver-postscript-hp cups-server-common cups-browsed cups-bsd cups-client cups-common cups-daemon cups-ppdc cups-filters cups-filters-core-drivers printer-driver-pxljr printer-driver-foo2zjs foomatic-filters cups-pk-helper" "postfix" "nginx nginx-core nginx-common" "frostwire" "azureus vuze" "samba samba-common samba-common-bin" "apache2 apache2.2-bin" "ftp" "vsftpd" "netcat-traditional netcat-openbsd" "openssh-server openssh-client ssh" "weplab" "pyrit" "mysql-server php5-mysql" "php5" "proftpd-basic" "filezilla" "postgresql" "irssi")

#FIND NIKTO PACKAGE NAME
#FIND TIGHTVNC PACKAGE NAME
#HOW DO YOU REMOVE JUST THE SERVER PART OF CUPS
#Can’t install frostwire with apt-get, but can remove it with that name

#automatically attempts to remove known bad programs that would never be allowed on a computer (and brings up option for others)
#yes | dpkg --remove john	#//password cracker
#yes | dpkg --remove telnetd	#//insecure server
#yes | dpkg --remove logkeys		#//keylogger
#yes | dpkg --remove Hydra	#//password cracker
#yes | dpkg --remove hydra
#yes | dpkg --remove fakeroot
#yes | dpkg --remove nmap	#//unnecessary polling tool
#yes | dpkg --remove Crack	#//password cracker
#yes | dpkg --remove crack
#yes | dpkg --remove medusa	#//brute force password cracker
#yes | dpkg --remove nikto 	#//polling tool/possible hacking tool
#yes | dpkg --remove tightvnc		#//remote desktop

tLen=${#packageName[@]}		#syntax to find total length of array
for (( i=0; $i<$tLen; i++)); do
	if [[ $(dpkg-query --list | grep -ic ${packageName[$i]}) -ne 0 ]]; then
		echo -n "Remove ${packageName[$i]} ? [Y/N]" #the -n option means don’t add new line after output
		read option
		if [[ $option =~ ^[Yy]$ ]]; then
			dpkg --purge ${dpkgName[$i]}  
		fi
	fi
done;


#dpkg --remove bind		//open DNS server
#dpkg --remove bind9
#dpkg --remove avahi
#dpkg --remove cupsd
#dpkg --remove master
#dpkg --remove nginx		//possibly unnecessary server
#dpkg --remove nginx-core nginx-common
#dpkg --remove frostwire	//bittorrent
#dpkg --remove Vuze		//bittorrent
#dpkg --remove vuze
#dpkg --remove samba		//possibly unnecessary server
#dpkg --remove apache2	//possibly unnecessary server
#dpkg --remove ftp		//possibly unnecessary server
#dpkg --remove vsftpd
#dpkg --remove netcat		//possibly unnecessary program that has netcat backdoors
#*dpkg --remove netcat-traditional
echo "Finished removing common bad packages"


#Looks at the package names and saves those that are deemed dangerous
echo "Bad Packages:" > badPackages.txt
( dpkg-query --list | grep -e "john" -e "Crack" -e "logkeys" -e "Hydra" -e "nginx" -e "Trojan" -e "password crack" -e "hack" -e "Hack" -e "telnetd" -e "fakeroot" -e "samba" -e "nmap" -e "crack" >> badPackages.txt ) &
(dpkg-query --list | grep -e "server" >> servers.txt; echo "Finished looking for bad known programs") &

#This will take all of the packages and store them in a file to be viewed later.
echo "" > allThePackages.txt
(dpkg-query --list >> allThePackages.txt) &

#Looks and sees if there are any illegal media files found on the computer in the home folder
echo "Media files:" > mediaFiles.txt
( for i in "*.jpg" "*.mp4" "*.mp6" "*.mp3" "*.mov" "*.png" "*.jpeg" "*.gif" "*.zip" "*.wav" "*.tif" "*.wmv" "*.avi" "*.mpeg" "*.tiff" "*.tar"; do find /home -name $i >> mediaFiles.txt; done; echo "" >> mediaFiles.txt ; echo "Done looking for bad media files" ) &

#Looks and sees if there are any illegal media files found on the computer as a total
echo "Media files:" > allMediaFiles.txt
( for i in "*.jpg" "*.mp4" "*.mp6" "*.mp3" "*.mov" "*.png" "*.jpeg" "*.gif" "*.wav" "*.tif" "*.tiff" "*.wmv" "*.avi" "*.mpeg"; do find / -name $i >> allMediaFiles.txt; done; echo "" >> allMediaFiles.txt ; echo "Done looking for bad media files" ) &

#Uses find, looks for type of regular file that has either permissions of suid of 2000 or 4000
echo "Suspicious SUID permission files" > suspectFind.txt
find / -type f \( -perm -04000 -o -perm -02000 \) >> suspectFind.txt 
echo "" >> suspectFind.txt
echo "Finished looking for suspicious files with SUID permissions"


#Finds files that appear to be placed down by no one. Would tell you if someone placed down something, then removed their user leaving that file around
( echo "Finding files with no Family" >> suspectFind.txt; find / \( -nouser -o -nogroup \) >> suspectFind.txt; echo "" >> suspectFind.txt; echo "Finished looking for suspicious file with no user/group" ) &

#finds directories that can be written by anyone, anywhere
( echo "finding world writable files" >> worldWrite.txt; find / -perm -2 ! -type l -ls >> worldWrite.txt; echo "Finished looking for world writable files") &




#install the needed programs like rkhunter, tree, etc
apt-get install rkhunter tree debsums libpam-cracklib chkrootkit clamav lynis -y > /dev/null 2>&1 

# VSFTPD
echo -n "Should VSFTP Be Installed/Reinstalled? [Y/n] "
read option
if [[ $option =~ ^[Yy]$ ]]
then
 	apt-get -y install vsftpd > /dev/null 2>&1 
 	# Disable anonymous uploads
 	sed -i '/^anon_upload_enable/ c\anon_upload_enable no   #' /etc/vsftpd.conf # outdated?
 	sed -i '/^anonymous_enable/ c\anonymous_enable=NO  #' /etc/vsftpd.conf
	# FTP user directories use chroot
	sed -i '/^chroot_local_user/ c\chroot_local_user=YES  #' /etc/vsftpd.conf
	service vsftpd restart
else
	dpkg --purge vsftpd > /dev/null 2>&1 
fi


# Apache2
echo -n "Should Apache2 Be Installed/Reinstalled? [Y/n] "
read option
if [[ $option =~ ^[Yy]$ ]]
then
 	apt-get install apache2 libapache2-mod-php5  > /dev/null 2>&1 
file=$( echo /etc/apache2/conf-enabled/security.conf )
#replace ServerTokens and ServerSignature
sed -i 's/ServerTokens/ServerTokens Prod  # /g' $file
sed -i 's/ServerSignature/ServerSignature Off # /g' $file
echo "<Directory />
    		Options -Indexes 
		</Directory>" >> $file
#Critical File Permissions
	chown -R root:root /etc/apache2
	chown -R root:root /etc/apache

	#Secure Apache 2
	if [[ -e /etc/apache2/apache2.conf ]]; then
		echo \<Directory \> >> /etc/apache2/apache2.conf
		echo -e ' \t AllowOverride None' >> /etc/apache2/apache2.conf
		echo -e ' \t Order Deny,Allow' >> /etc/apache2/apache2.conf
		echo -e ' \t Deny from all' >> /etc/apache2/apache2.conf
		echo \<Directory \/\> >> /etc/apache2/apache2.conf
		echo UserDir disabled root >> /etc/apache2/apache2.conf
	fi
#THIS MAY BREAK APACHE2, NOT ENTIRELY SURE, TEST FIRST

 else
	  dpkg --purge apache2 > /dev/null 2>&1 
fi


# MySQL
echo -n "Should MySQL Be Installed/Reinstalled? [Y/n] "
read option
if [[ $option =~ ^[Yy]$ ]]
then
 	apt-get install mysql-server php5-mysql -y > /dev/null 2>&1 
	mysql_secure_installation
file=$( echo /etc/mysql/my.cnf )
#bind-address = 127.0.0.1 #
sed -i 's/bind-address/bind-address = 127.0.0.1 # /g' $file
service mysql restart

 else
	  dpkg --purge mysql-server php5-mysql > /dev/null 2>&1 
fi


# Php
echo -n "Should PHP5 Be Installed/Reinstalled? [Y/n] "
read option
if [[ $option =~ ^[Yy]$ ]]
then
 	apt-get install python-software-properties -y > /dev/null 2>&1 
	add-apt-repository ppa:ondrej/php5-oldstable
	apt-get update -y > /dev/null 2>&1 
	apt-get install -y php5 > /dev/null 2>&1 
	file=$(echo /etc/php5/apache2/php.ini)

	#At the end of each of these lines is a ; instead of a #, this is b/c this configuration has different syntax than bash and the ; tells it to comment the rest out.

	sed -i 's/expose_php/expose_php=Off ; /g' $file
sed -i 's/allow_url_fopen/allow_url_fopen=Off ; /g' $file
sed -i 's/allow_url_include/allow_url_include=Off ; /g' $file
#disable_functions 
sed -i 's/disable_functions=/disable_functions=exec,shell_exec,passthru,system,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,proc_open,pcntl_exec,/g' $file
sed -i 's/upload_max_filesize/upload_max_filesize = 2M ; /g' $file
sed -i 's/max_execution_time/max_execution_time = 30 ; /g' $file
sed -i 's/max_input_time/max_input_time = 60 ; /g' $file
else
	  dpkg --purge php5 > /dev/null 2>&1 
fi


# SSH
echo -n "Should SSH Be Installed/Reinstalled? [Y/n] "
read option
if [[ $option =~ ^[Yy]$ ]]
then
apt-get install ssh openssh-server openssh-client -y > /dev/null 2>&1 
#goes and replaces the /etc/ssh/sshd_config with clean one
echo "Replacing /etc/ssh/sshd_config" >> WorkProperly.txt
cp /etc/ssh/sshd_config /etc/ssh/.sshd_config
echo "# Package generated configuration file
# See the sshd_config(5) manpage for details
# What ports, IPs and protocols we listen for
Port 22
# Use these options to restrict which interfaces/protocols sshd will bind to
#ListenAddress ::
#ListenAddress 0.0.0.0
Protocol 2
# HostKeys for protocol version 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
#Privilege Separation is turned on for security
UsePrivilegeSeparation yes
# Lifetime and size of ephemeral version 1 server key
KeyRegenerationInterval 3600
ServerKeyBits 768
# Logging
SyslogFacility AUTH
LogLevel INFO

# Authentication:
LoginGraceTime 120
PermitRootLogin no
StrictModes yes

RSAAuthentication yes
PubkeyAuthentication yes
#AuthorizedKeysFile	%h/.ssh/authorized_keys

# Don't read the user's ~/.rhosts and ~/.shosts files
IgnoreRhosts yes
# For this to work you will also need host keys in /etc/ssh_known_hosts
RhostsRSAAuthentication no
# similar for protocol version 2
HostbasedAuthentication no
# Uncomment if you don't trust ~/.ssh/known_hosts for RhostsRSAAuthentication
#IgnoreUserKnownHosts yes
# To enable empty passwords, change to yes (NOT RECOMMENDED)

PermitEmptyPasswords no
# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
ChallengeResponseAuthentication no

# Change to no to disable tunnelled clear text passwords
#PasswordAuthentication yes

# Kerberos options
#KerberosAuthentication no
#KerberosGetAFSToken no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes
X11Forwarding no

X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
#UseLogin no

#MaxStartups 10:30:60
#Banner /etc/issue.net
# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

Subsystem sftp /usr/lib/openssh/sftp-server

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the ChallengeResponseAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via ChallengeResponseAuthentication may bypass
# the setting of \"PermitRootLogin without-password\".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and ChallengeResponseAuthentication to 'no'.
UsePAM yes" > /etc/ssh/sshd_config
service ssh restart
echo "" >> WorkProperly.txt
echo "Finished with SSH"

else
	dpkg --purge ssh openssh-server openssh-client > /dev/null 2>&1 
fi


#Looks at the entire list of users so you can see what they all have
( tree /home >> homeDirectory.txt; echo "Finished saving entire home directory" ) &

#Add password policy
echo " " > /tmp/stuff
#echo "How many days do you want the max to be?" -n
#read output
output=15
sed -i 's/PASS_MAX_DAYS\t9999/PASS_MAX_DAYS\t'"$output"'/g' /etc/login.defs
#mv /tmp/stuff  /etc/login.defs
#echo " " > /tmp/stuff
sed  -i 's/PASS_MIN_DAYS\t0/PASS_MIN_DAYS\t10/g' /etc/login.defs

sed -i 's/password\trequisite\t\t\tpam_cracklib.so/password\trequisite\t\t\tpam_cracklib.so ucredit=-1 lcredit=-1 ocredit=-1 dcredit=-1/g' /etc/pam.d/common-password


#echo "password requisite pam_cracklib.so retry=3 minlen=6 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1" >> /etc/pam.d/common-password
#The sed command above should add the necessary stuff

echo "#auth optional pam_tally.so deny=5 unlock_time=900 onerr=fail audit silent " >> /etc/pam.d/common-auth
echo "password requisite pam_pwhistory.so use_authtok remember=24" >>  /etc/pam.d/common-password

#echo "Finished Password Policy"

#Add basic lockout policy
cp /etc/pam.d/common-auth /etc/pam.d/common-auth~
echo "auth [success=1 default=ignore] pam_unix.so nullok_secure 
auth required pam_deny.so 	#was requisite
auth required pam_permit.so
auth required pam_tally2.so onerr=fail deny=3 unlock_time=1800" > /etc/pam.d/common-auth
echo "Lockout policy enabled"



#Goes and updates all the updates quickly
gnome-terminal -e "bash -c \"(apt-get update; apt-get upgrade -y; apt-get dist-upgrade -y)\"" & disown; sleep 2; 
#kill -INT $$
#This will start a new terminal, uses disown to cut itself off from getting canceled from the original terminal, sleep for a bit for the error code, then sends contrl+c to the current terminal to allow script to continue ($$ means this script’s PID) THE KILL IS NOT NECESSARY
echo "updating in progress"
echo "updating in progress"
clear
#Doing all of that as (;;;) & will cause the output to show up in that terminal not a new one, but it is executed asynchronously.

#Runs rkhunter and saves any warnings
(echo "rkhunter says:" >> Warnings.rkhunter.txt; rkhunter -c --rwo >> Warnings.rkhunter.txt; echo "" >> Warnings.txt; echo "Finished rkhunter scan" ) &
disown; sleep 2; 

#run chkrootkit and save output into Warnings
( echo "Chkrootkit found (NOTE There may be false positives):" >> Warnings.chkrootkit.txt; chkrootkit -q >> Warnings.txt; echo "" >> Warnings.txt; echo "Finished chkrootkit scan" ) &
disown; sleep 2; 


#runs Debsums to check and see if there are any weirdly changed files around
( echo "Debsums says:" >> Warnings.txt; debsums -a -s >> Warnings.txt 2>&1; echo "" >> Warnings.txt; echo "Finished debsums scan" ) &
disown; sleep 2; 


#install Clamav onto the computer and begin running it
#apt-get install clamav	gets installed earlier
( freshclam; clamscan -r --bell -i / >> Clamav.txt; echo "Finished Clamav scanning" ) &
disown; sleep 2; 

#Starts lynis, which helps in securing computer
( lynis -c -Q >> LynisOutput.txt; echo "Finished Lynis" ) &
disown; sleep 2; 
#big q is don’t wait for user input, lower q is only show warnings, -c is do it for whole system

#https://github.com/bstrauch24/cyberpatriot/blob/master/security.sh (is able to accept feedback)
#https://github.com/willshiao/cyberpatriot/blob/master/Scripts/Linux/meme.sh
#https://github.com/JoshuaTatum/cyberpatriot/blob/master/harrisburg-linux.sh
#https://github.com/willshiao/cyberpatriot/blob/master/Checklists/Linux/CyberPatriot%20Linux%20Checklist.pdf
#https://github.com/hexidecimals/cyberpatriot/blob/master/linux.sh (has way to find readme by itself)

message="The script has finished executing on this computer. This is being run as $(whoami) and has $(finger $(whoami) )."
number=0000000001
#sendtext () { curl http://textbelt.com/text -d number=$number -d "message=$message";echo message sent; }
#sendtext();

#Text messages from terminal:
#https://linuxsupernoob.wordpress.com/2013/01/08/how-to-send-text-message-from-terminal/
#http://osxdaily.com/2014/03/12/send-sms-text-message-from-command-line/

echo "THIS SCRIPT IS NOW FINISHED. PROCEED TO DO OTHER THINGS."

