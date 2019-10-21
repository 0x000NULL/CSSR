#!/bin/bash
UserName=$(whoami)
LogTime=$(date '+%Y-%d %H:%M;%S')
DE=`echo $XDG_CURRENT_DESKTOP`

##Adds a pause statement
pause(){
	read -p "Press [Enter] key to continue..." fakeEnter
}

##Exits the script
exit20(){
	exit 1
	clear
}

##Detect the Operating System
gcc || apt-get install gcc >> /dev/null
gcc || yum install gcc >> /dev/null
gcc --version | grep -i ubuntu
if [ $? -eq 0 ]; then
	opsys="Ubuntu"
fi
gcc --version | grep -i debian >> /dev/null
if [ $? -eq 0 ]; then
	opsys="Debian"
fi

gcc --version | grep -i RedHat >> /dev/null
if [ $? -eq 0 ]; then
	opsys="RedHat"
fi

gcc --version | grep -i #CentOS >> /dev/null
if [ $? -eq 0 ]; then
	opsys="CentOS"
fi

##Updates the operating system, kernel, firefox, and libre office and also installs 'clamtk'
update(){

	case "$opsys" in
	"Debian"|"Ubuntu")
		sudo add-apt-repository -y ppa:libreoffice/ppa
		wait
		sudo apt-get update -y
		wait
		sudo apt-get upgrade -y
		wait
		sudo apt-get dist-upgrade -y
		wait
		killall firefox
		wait
		sudo apt-get --purge --reinstall install firefox -y
		wait
		sudo apt-get install clamtk -y	
		wait

		pause
	;;
	"RedHat"|"CentOS")
		yum update -y
		wait
		yum upgrade -y
		wait
		yum update firefox -y
		wait
		yum install clamtk -y
		wait

		pause
	;;
	esac
}

##Creates copies of critical files
backup() {
	mkdir /BackUps
	##Backups the sudoers file
	sudo cp /etc/sudoers /Backups
	##Backups the home directory
	cp /etc/passwd /BackUps
	##Backups the log files
	cp -r /var/log /BackUps
	##Backups the passwd file
	cp /etc/passwd /BackUps
	##Backups the group file
	cp /etc/group /BackUps
	##Back ups the shadow file
	cp /etc/shadow /BackUps
	##Backing up the /var/spool/mail
	cp /var/spool/mail /Backups
	##backups all the home directories
	for x in `ls /home`
	do
		cp -r /home/$x /BackUps
	done

	pause
}

##Sets Automatic Updates on the machine.
autoUpdate() {
echo "$LogTime uss: [$UserName]# Setting auto updates." >> output.log
	case "$opsys" in
	"Debian"|"Ubuntu")

	##Set daily updates
		sed -i -e 's/APT::Periodic::Update-Package-Lists.*\+/APT::Periodic::Update-Package-Lists "1";/' /etc/apt/apt.conf.d/10periodic
		sed -i -e 's/APT::Periodic::Download-Upgradeable-Packages.*\+/APT::Periodic::Download-Upgradeable-Packages "0";/' /etc/apt/apt.conf.d/10periodic
##Sets default broswer
		sed -i 's/x-scheme-handler\/http=.*/x-scheme-handler\/http=firefox.desktop/g' /home/$UserName/.local/share/applications/mimeapps.list
##Set "install security updates"
		cat /etc/apt/sources.list | grep "deb http://security.ubuntu.com/ubuntu/ trusty-security universe main multiverse restricted"
		if [ $? -eq 1 ]
		then
			echo "deb http://security.ubuntu.com/ubuntu/ trusty-security universe main multiverse restricted" >> /etc/apt/sources.list
		fi

		echo "###Automatic updates###"
		cat /etc/apt/apt.conf.d/10periodic
		echo ""
		echo "###Important Security Updates###"
		cat /etc/apt/sources.list
		pause
	;;
	"RedHat"|"CentOS")

		yum -y install yum-cron
	;;
	esac
}

##Finds all prohibited files on the machine and deletes them
pFiles() {
echo "$LogTime uss: [$UserName]# Deleting media files..." >> output.log
	##Media files
	echo "###MEDIA FILES###" >> pFiles.log
    	find / -name "*.mov" -type f >> pFiles.log
    	find / -name "*.mp4" -type f >> pFiles.log
	find / -name "*.mp3" -type f >> pFiles.log
	find / -name "*.wav" -type f >> pFiles.log
	##Pictures
	echo "###PICTURES###" >> pFiles.log
#	find / -name "*.png" -type f >> pFiles.log
    find / -name "*.jpg" -type f >> pFiles.log
	find / -name "*.jpeg" -type f >> pFiles.log
#	find / -name "*.gif" -type f >> pFiles.log
	##Other Files
	echo "###OTHER###" >> pFiles.log
	find / -name "*.tar.gz" -type f >> pFiles.log
	find / -name "*.php" -type f >> pFiles.log
	find / -name "*backdoor*.*" -type f >> pFiles.log
	find / -name "*backdoor*.php" -type f >> pFiles.log
	##Items without groups
	echo "###FILES WITHOUT GROUPS###" >> pFiles.log
	find / -nogroup >> pFiles.log
	echo "###GAMES###" >> pFiles.log
	dpkg -l | grep -i game

	##Deletes audio files
	find / -name "*.mp3" -type f -delete
	##Deletes Video files
	find / -name "*.mov" -type f -delete
	find / -name "*.mp4" -type f -delete
#	find / -name "*.gif" -type f -delete
	##Deletes pictures
#	find / -name "*.png" -type f -delete
	find / -name "*.jpg" -type f -delete
	find / -name "*.jpeg" -type f -delete
echo "$LogTime uss: [$UserName]# Media files deleted." >> output.log
	cat pFiles.log
	pause
}

##Configures the firewall
configureFirewall() {
echo "$LogTime uss: [$UserName]# Checking for firewall..." >> output.log
	case "$opsys" in
	"Ubuntu"|"Debian")
		dpkg -l | grep ufw >> output.log
		if [ $? -eq 1 ]
		then
			apt-get install ufw >> output.log
		fi
echo "$LogTime uss: [$UserName]# Enabling firewall..." >> output.log
		sudo ufw enable >>output.log
		sudo ufw status >> output.log
		sleep 1
echo "$LogTime uss: [$UserName]# Firewall has been turned on and configured." >> output.log
		ufw status
		pause
	;;
	"RedHat"|"CentOS")
		yum install ufw
echo "$LogTime uss: [$UserName]# Enabling firewall..." >> output.log
                sudo ufw enable >>output.log
                sudo ufw status >> output.log
                sleep 1
echo "$LogTime uss: [$UserName]# Firewall has been turned on and configured." >> output.log
                ufw status
                pause
	;;
	esac
}

##Edits the /etc/gdm3 /etc/lightdm/lightdm.conf config files.
loginConf() {
	case "$opsys" in
	"Debian") 
		typeset -r TMOUT=900
		sed -i 's/greeter-hide-users=.*/greeter-hide-users=true/' /etc/lightdm/lightdm.conf
		sed -i 's/greeter-allow-guest=.*/greeter-allow-guest=false/' /etc/lightdm/lightdm.conf
		sed -i 's/greeter-show-manual-login=.*/greeter-show-manual-login=true/' /etc/lightdm/lightdm.conf
		sed -i 's/allow-guest=.*/allow-guest=false/' /etc/lightdm/lightdm.conf
		sed -i 's/autologin-guest=.*/autologin-guest=false/' /etc/lightdm/lightdm.conf
		sed -i 's/autologin-user=.*/autologin-user=NONE/' /etc/lightdm/lightdm.conf

		sed -i 's/^# disable-user-.*/disable-user-list=true/' /etc/gdm3/greeter.dconf-defaults
		sed -i 's/^# disable-restart-.*/disable-restart-buttons=true/' /etc/gdm3/greeter.dconf-defaults
		sed -i 's/^#  AutomaticLoginEnable.*/AutomaticLoginEnable = false/' /etc/gdm3/custom.conf
	;;
	"Ubuntu")
		typeset -r TMOUT=900
echo "$LogTime uss: [$UserName]# Creating /etc/lightdm/lightdm.conf for 12.04 compatability." >> output.log
		if [ -f /etc/lightdm/lightdm.conf ];
		then
			sed -i '$a allow-guest=false' /etc/lightdm/lightdm.conf
			sed -i '$a greeter-hide-users=true' /etc/lightdm/lightdm.conf
			sed -i '$a greeter-show-manual-login=true' /etc/lightdm/lightdm.conf

			##Finds automatic login user if there is one and takes it out
			cat /etc/ligthdm/lightdm.conf | grep autologin-user >> /dev/null
			if [ $? -eq 0 ]
			then
				USER=`cat /etc/lightdm/lightdm.conf | grep autologin-user | cut -d= -f2`
				if [ "$USER" != "none" ]
				then
					echo "$USER has ben set to autologin."
					sed -i 's/autologin-user=.*/autologin-user=none/' /etc/lightdm/lightdm.conf
				fi
			else
				sed -i '$a autologin-user=none' /etc/lightdm/lightdm.conf
			fi
			cat /etc/lightdm/lightdm.conf
			pause
		else
			touch /etc/lightdm/lightdm.conf
			sed -i '$a [SeatDefault]' /etc/lightdm/lightdm.conf
			sed -i '$a allow-guest=false' /etc/lightdm/lightdm.conf
			sed -i '$a greeter-hide-users=true' /etc/lightdm/lightdm.conf
			sed -i '$a greeter-show-manual-login=true' /etc/lightdm/lightdm.conf

			#Finds automatic login user if there is one and takes it out
			cat /etc/ligthdm/lightdm.conf | grep autologin-user >> /dev/null
			if [ $? -eq 0 ]
			then
				USER=`cat /etc/lightdm/lightdm.conf | grep autologin-user | cut -d= -f2`
				if [ "$USER" != "none" ]
				then
					echo "$USER has ben set to autologin."
					sed -i 's/autologin-user=.*/autologin-user=none/' /etc/lightdm/lightdm.conf
				fi
			else
				sed -i '$a autologin-user=none' /etc/lightdm/lightdm.conf
			fi
			cat /etc/lightdm/lightdm.conf
			pause
		fi
echo "$LogTime uss: [$UserName]# Editing the ../50-ubuntu.conf for ubuntu 14.04" >> output.log
		sed -i '$a greeter-hide-users=true' /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
		sed -i '$a greeter-show-manual-login=true' /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
		sed -i '$a allow-guest=false' /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
		#Finds automatic login user if there is one and takes it out
		cat /etc/ligthdm/lightdm.conf | grep autologin-user >> /dev/null
		if [ $? -eq 0 ]
		then
			USER=`cat /etc/lightdm/lightdm.conf | grep autologin-user | cut -d= -f2`
			if [ "$USER" != "none" ]
			then
				echo "$USER has ben set to autologin."
				sed -i 's/autologin-user=.*/autologin-user=none/' /etc/lightdm/lightdm.conf
			fi
		else
			sed -i '$a autologin-user=none' /etc/lightdm/lightdm.conf
		fi
echo "$LogTime uss: [$UserName]# Lightdm files have been configured" >> output.log

		cat /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
		pause
		;;
	"RedHat"|"CentOS")
		typeset -r TMOUT=900
		mkdir /etc/dconf/db/gdm.d
		touch /etc/dconf/db/gdm.d/01-hide-users
		sed -i '$a [org/gnome/login-screen]' /etc/dconf/db/gdm.d/01-hide-users
		sed -i '$a banner-message-enable=true'/etc/dconf/db/gdm.d/01-hide-users
		sed -i '$a banner-message-text="This is a restricted server xd."' /etc/dconf/db/gdm.d/01-hide-users
		sed -i '$a disable-restart-buttons=true' /etc/dconf/db/gdm.d/01-hide-users
		sed -i '$a disable-user-list=true' /etc/dconf/db/gdm.d/01-hide-users

		touch /etc/dconf/profile/gdm
		sed -i '$a user-db:user' /etc/dconf/profile/gdm
		sed -i '$a system-db:gdm' /etc/dconf/profile/gdm
		dconf update
		;;
	esac
}

##Creates any missing users
createUser() {
	read -p "Are there any users you would like to add?[y/n]: " a
	while [ $a = y ]
	do
		read -p "Please enter the name of the user: " user
		useradd $user
		mkdir /home/$user
		read -p "Are there any more users you would like to add?[y/n]: " a
	done

	pause
}

##Changes all the user passwords
chgPasswd(){
echo "$LogTime uss: [$UserName]# Changing all the user passwords to Cyb3rPatr!0t$." >> output.log
	##Look for valid users that have different UID that not 1000+
	cut -d: -f1,3 /etc/passwd | egrep ':[0-9]{4}$' | cut -d: -f1 > users
	##Looks for users with the UID and GID of 0
	hUSER=`cut -d: -f1,3 /etc/passwd | egrep ':[0]{1}$' | cut -d: -f1`
	echo "$hUSER is a hidden user"
	sed -i '/root/ d' users

	PASS='Cyb3rPatr!0t$'
	for x in `cat users`
	do
		echo -e "$PASS\n$PASS" | passwd $x >> output.log
		echo -e "Password for $x has been changed."
		##Changes the USER password policy
		chage -M 90 -m 7 -W 15 $x
	done
echo "$LogTime uss: [$UserName]# Passwords have been changed." >> output.log

	pause
}

##Sets the password policy
passPol() {
echo "$LogTime uss: [$UserName]# Setting password policy..." >> output.log
echo "$LogTime uss: [$UserName]# Installing Craklib..." >> output.log
	apt-get install libpam-cracklib || yum install libpam-cracklib
	wait
echo "$LogTime uss: [$UserName]# Cracklib installed." >> output.log
	sed -i.bak -e 's/PASS_MAX_DAYS\t[[:digit:]]\+/PASS_MAX_DAYS\t90/' /etc/login.defs
	sed -i -e 's/PASS_MIN_DAYS\t[[:digit:]]\+/PASS_MIN_DAYS\t10/' /etc/login.defs
	sed -i -e 's/PASS_WARN_AGE\t[[:digit:]]\+/PASS_WARN_AGE\t7/' /etc/login.defs
	sed -i -e 's/difok=3\+/difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password
echo "$LogTime uss: [$UserName]# Password Policy." >> output.log

	pause
}

##Deletes users
delUser() {
	for x in `cat users`
	do
		read -p "Is $x a valid user?[y/n]: " a
		if [ $a = n ];
		then
			mv /home/$x /home/dis_$x
			sed -i -e "/$x/ s/^#*/#/" /etc/passwd
			sleep 1
		fi
	done
	pause
}

##Asks for any admin users
admin() {
	for x in `cat users`
	do
		read -p "Is $x considered an admin?[y/n]: " a
		if [ $a = y ]
		then
			##Adds to the adm group
			sudo usermod -a -G adm $x

			##Adds to the sudo group
			sudo usermod -a -G sudo $x
		else
			##Removes from the adm group
			sudo deluser $x adm

			##Removes from the sudo group
			sudo deluser $x sudo
		fi
	done

	pause
}

##Secures the root account
secRoot(){
echo "$LogTime uss: [$UserName] # Securing root..." >> output.log
	PASS='Cyb3rPatr!0t$'
	echo -e "$PASS\n$PASS" | passwd root  >> output.log
	sudo passwd -l root
echo "$LogTime uss: [$UserName] # Root has been secured." >> output.log
}

##Sets the lockout policy
lockoutPol() {
echo "$LogTime uss: [$UserName]# Setting lockout policy..." >> output.log
	sed -i 's/auth\trequisite\t\t\tpam_deny.so\+/auth\trequired\t\t\tpam_deny.so/' /etc/pam.d/common-auth
	sed -i '$a auth\trequired\t\t\tpam_tally2.so deny=5 unlock_time=1800 onerr=fail' /etc/pam.d/common-auth
	sed -i 's/sha512\+/sha512 remember=13/' /etc/pam.d/common-password
echo "$LogTime uss: [$UserName]# Lockout poicy set." >> output.log

	pause
}

##Checks for SSH, if it is needed then it is installed and secured
##FiX FOR FEDORA
sshd() {
echo "$LogTime uss: [$UserName]# Checking for ssh..." >> output.log
	dpkg -l | grep openssh-server >> output.log
        	if [ $? -eq 0 ];
        	then
                	read -p "Do you want SSH installed on the system?[y/n]: " a
                	if [ $a = n ];
                	then
                        	apt-get autoremove -y --purge openssh-server ssh >> output.log
echo "$LogTime uss: [$UserName]# SSH has been removed." >> output.log
	         		else
echo "$LogTime uss: [$UserName]# SSH has been found, securing now..." >> output.log
							sed -i 's/LoginGraceTime .*/LoginGraceTime 60/g' /etc/ssh/sshd_config
                        	sed -i 's/PermitRootLogin .*/PermitRootLogin no/g' /etc/ssh/sshd_config
                        	sed -i 's/Protocol .*/Protocol 2/g' /etc/ssh/sshd_config
                        	sed -i 's/#PermitEmptyPasswords .*/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
                        	sed -i 's/PasswordAuthentication .*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
                        	sed -i 's/X11Forwarding .*/X11Forwarding no/g' /etc/ssh/sshd_config

							##Only allows authroized users
							sed -i '$a AllowUsers' /etc/ssh/sshd_config
							for x in `cat users`
							do
								sed -i "/^AllowUser/ s/$/ $x /" /etc/ssh/sshd_config
							done
echo "$LogTime uss: [$UserName]# SSH has been secured." >> output.log
				pause
                	fi
        	else
                	read -p "Does SSH NEED to be installed?[y/n]: " a
                	if [ $a = y ];
                	then
echo "$LogTime uss: [$UserName]# Installing and securing SSH now..." >> output.log
                        	apt-get install -y openssh-server ssh >> output.log
				wait
							sed -i 's/LoginGraceTime .*/LoginGraceTime 60/g' /etc/ssh/sshd_config
                        	sed -i 's/PermitRootLogin .*/PermitRootLogin no/g' /etc/ssh/sshd_config
                        	sed -i 's/Protocol .*/Protocol 2/g' /etc/ssh/sshd_config
                        	sed -i 's/#PermitEmptyPasswords .*/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
                        	sed -i 's/PasswordAuthentication .*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
                        	sed -i 's/X11Forwarding .*/X11Forwarding no/g' /etc/ssh/sshd_config
							##uses PAM
							##Uses Privilege seperation

							##Only allows authroized users
							sed -i '$a AllowUsers' /etc/ssh/sshd_config
							for x in `cat users`
							do
								sed -i "/^AllowUser/ s/$/ $x /" /etc/ssh/sshd_config
							done
				pause
			fi
        	fi
}

##Secures the /etc/shadow file
secureShadow() {
echo "$LogTime uss: [$UserName]# Securing /etc/shadow..." >> output.log
	chmod 640 /etc/shadow

	ls -l /etc/shadow
	pause
}

##Removes basik hak tools
hakTools() {

##CHANGE TO GREP -i
echo "$LogTime uss: [$UserName]# Removing hacking tools..." >> output.log
##Looks for apache web server
	dpkg -l | grep apache >> output.log
	if [ $? -eq 0 ];
	then
        	read -p "Do you want apache installed on the system[y/n]: "
        	if [ $a = n ];
        	then
      	        	apt-get autoremove -y --purge apache2 >> output.log
			else
            		if [ -e /etc/apache2/apache2.conf ]
				then
					chown -R root:root /etc/apache2
					chown -R root:root /etc/apache
					echo \<Directory \> >> /etc/apache2/apache2.conf
					echo -e ' \t AllowOverride None' >> /etc/apache2/apache2.conf
					echo -e ' \t Order Deny,Allow' >> /etc/apache2/apache2.conf
					echo -e ' \t Deny from all' >> /etc/apache2/apache2.conf
					echo UserDir disabled root >> /etc/apache2/apache2.conf
				else
					##Installs and configures apache
					apt-get install apache2 -y
						chown -R root:root /etc/apache2
						chown -R root:root /etc/apache
						echo \<Directory \> >> /etc/apache2/apache2.conf
						echo -e ' \t AllowOverride None' >> /etc/apache2/apache2.conf
						echo -e ' \t Order Deny,Allow' >> /etc/apache2/apache2.conf
						echo -e ' \t Deny from all' >> /etc/apache2/apache2.conf
						echo UserDir disabled root >> /etc/apache2/apache2.conf

					##Installs and configures sql
					apt-get install mysql-server -y

					##Installs and configures php5
					apt-get install php5 -y
					chmod 640 /etc/php5/apache2/php.ini
				fi
        	fi
	else
        echo "Apache is not installed"
		sleep 1
	fi
##Looks for john the ripper
	dpkg -l | grep john >> output.log
	if [ $? -eq 0 ];
	then
        	echo "JOHN HAS BEEEN FOUND! DIE DIE DIE"
        	apt-get autoremove -y --purge john >> output.log
        	echo "John has been ripped"
			sleep 1
	else
        	echo "John The Ripper has not been found on the system"
			sleep 1
	fi
##Look for HYDRA
	dpkg -l | grep hydra >>output.log
	if [ $? -eq 0 ];
	then
		echo "HEIL HYDRA"
		apt-get autoremove -y --purge hydra >> output.log
	else
		echo "Hydra has not been found."
	fi
##Looks for nginx web server
	dpkg -l | grep nginx >> output.log
	if [ $? -eq 0 ];
	then
        	echo "NGINX HAS BEEN FOUND! OHHHH NOOOOOO!"
        	apt-get autoremove -y --purge nginx >> output.log
	else
        	echo "NGINX has not been found"
			sleep 1
	fi
##Looks for samba
	if [ -d /etc/samba ];
	then
		read -p "Samba has been found on this system, do you want to remove it?[y/n]: " a
		if [ $a = y ];
		then
echo "$LogTime uss: [$UserName]# Uninstalling samba..." >> output.log
			sudo apt-get autoremove --purge -y samba >> output.log
			sudo apt-get autoremove --purge -y samba >> output.log
echo "$LogTime uss: [$UserName]# Samba has been removed." >> output.log
		else
			sed -i '82 i\restrict anonymous = 2' /etc/samba/smb.conf
			##List shares
		fi
	else
		echo "Samba has not been found."
		sleep 1
	fi
##LOOK FOR DNS
	if [ -d /etc/bind ];
	then
		read -p "DNS server is running would you like to shut it down?[y/n]: " a
		if [ $a = y ];
		then
			apt-get autoremove -y --purge bind9 
		fi
	else
		echo "DNS not found."
		sleep 1
	fi
##Looks for FTP
	dpkg -l | grep -i 'vsftpd|ftp' >> output.log
	if [ $? -eq 0 ]
	then	
		read -p "FTP Server has been installed, would you like to remove it?[y/n]: " a
		if [ $a = y ]
		then
			PID = `pgrep vsftpd`
			sed -i 's/^/#/' /etc/vsftpd.conf
			kill $PID
			apt-get autoremove -y --purge vsftpd ftp
		else
			sed -i 's/anonymous_enable=.*/anonymous_enable=NO/' /etc/vsftpd.conf
			sed -i 's/local_enable=.*/local_enable=YES/' /etc/vsftpd.conf
			sed -i 's/#write_enable=.*/write_enable=YES/' /etc/vsftpd.conf
			sed -i 's/#chroot_local_user=.*/chroot_local_user=YES/' /etc/vsftpd.conf
		fi
	else
		echo "FTP has not been found."
		sleep 1
	fi
##Looks for TFTPD
	dpkg -l | grep tftpd >> output.log
	if [ $? -eq 0 ]
	then
		read -p "TFTPD has been installed, would you like to remove it?[y/n]: " a
		if [ $a = y ]
		then
			apt-get autoremove -y --purge tftpd
		fi
	else
		echo "TFTPD not found."
		sleep 1
	fi
##Looking for VNC
	dpkg -l | grep -E 'x11vnc|tightvncserver' >> output.log
	if [ $? -eq 0 ]
	then
		read -p "VNC has been installed, would you like to remove it?[y/n]: " a
		if [ $a = y ]
		then
			apt-get autoremove -y --purge x11vnc tightvncserver 
		##else
			##Configure VNC
		fi
	else
		echo "VNC not found."
		sleep 1
	fi

##Looking for NFS
	dpkg -l | grep nfs-kernel-server >> output.log
	if [ $? -eq 0 ]
	then	
		read -p "NFS has been found, would you like to remove it?[y/n]: " a
		if [ $a = 0 ]
		then
			apt-get autoremove -y --purge nfs-kernel-server
		##else
			##Configure NFS
		fi
	else
		echo "NFS has not been found."
		sleep 1
	fi
##Looks for snmp
	dpkg -l | grep snmp >> output.log
	if [ $? -eq 0 ]
	then	
		echo "SNMP HAS BEEN LOCATED!"
		apt-get autoremove -y --purge snmp
	else
		echo "SNMP has not been found."
		sleep 1
	fi
##Looks for sendmail and postfix
	dpkg -l | grep -E 'postfix|sendmail' >> output.log
	if [ $? -eq 0 ]
	then
		echo "Mail servers have been found."
		apt-get autoremove -y --purge postfix sendmail
	else
		echo "Mail servers have not been located."
		sleep 1
	fi
##Looks xinetd
	dpkg -l | grep xinetd >> output.log
	if [ $? -eq 0 ]
	then
		echo "XINIT HAS BEEN FOUND!"
		apt-get autoremove -y --purge xinetd
	else
		echo "XINETD has not been found."
		sleep 1
	fi
	pause
}

#RHhakTools() {
	##Redo all of the hak tools function just for fedora

#}

##Edits the sysctl.conf file
sys() {
	##Disables IPv6
	sed -i '$a net.ipv6.conf.all.disable_ipv6 = 1' /etc/sysctl.conf 
	sed -i '$a net.ipv6.conf.default.disable_ipv6 = 1' /etc/sysctl.conf
	sed -i '$a net.ipv6.conf.lo.disable_ipv6 = 1' /etc/sysctl.conf 

	##Disables IP Spoofing
	sed -i '$a net.ipv4.conf.all.rp_filter=1' /etc/sysctl.conf

	##Disables IP source routing
	sed -i '$a net.ipv4.conf.all.accept_source_route=0' /etc/sysctl.conf

	##SYN Flood Protection
	sed -i '$a net.ipv4.tcp_max_syn_backlog = 2048' /etc/sysctl.conf
	sed -i '$a net.ipv4.tcp_synack_retries = 2' /etc/sysctl.conf
	sed -i '$a net.ipv4.tcp_syn_retries = 5' /etc/sysctl.conf
	sed -i '$a net.ipv4.tcp_syncookies=1' /etc/sysctl.conf

	##IP redirecting is disallowed
	sed -i '$a net.ipv4.ip_foward=0' /etc/sysctl.conf
	sed -i '$a net.ipv4.conf.all.send_redirects=0' /etc/sysctl.conf
	sed -i '$a net.ipv4.conf.default.send_redirects=0' /etc/sysctl.conf

	sysctl -p
	pause
}

##Lists the running processes
proc() {
	lsof -Pnl +M -i > runningProcesses.log
	##Removing the default running processes
	sed -i '/avahi-dae/ d' runningProcesses.log
	sed -i '/cups-brow/ d' runningProcesses.log
	sed -i '/dhclient/ d' runningProcesses.log
	sed -i '/dnsmasq/ d' runningProcesses.log
	sed -i '/cupsd/ d' runningProcesses.log

	pause
}

##Searches for netcat and its startup script and comments out the lines
nc(){

#yum list | grep -i 'nc|netcat' 
#if [ $? -eq 0 ]
#then
	cat runningProcesses.log
		read -p "What is the name of the suspected netcat?[none]: " nc
			if [ $nc == "none"]
			then
				echo "k xd"
			else
				whereis $nc > Path
				ALIAS=`alias | grep nc | cut -d' ' -f2 | cut -d'=' -f1`
				PID=`pgrep $nc`
				for path in `cat Path`
				do
						echo $path
						if [ $? -eq 0 ]
						then
								sed -i 's/^/#/' $path
								kill $PID
						else
								echo "This is not a netcat process."
						fi
				done
			fi

			ls /etc/init | grep $nc.conf >> /dev/null
			if [ $? -eq 0 ]
			then
					cat /etc/init/$nc.conf | grep -E -i 'nc|netcat|$ALIAS' >> /dev/null
					if [ $? -eq 0 ]
					then
							sed -i 's/^/#/' /etc/init/$nc.conf
							kill $PID
					else
							echo "This is not a netcat process."
					fi
			fi

			ls /etc/init.d | grep $nc >>/dev/null
			if [ $? -eq 0 ]
			then
					cat /etc/init.d/$nc | grep -E -i 'nc|netcat|$ALIAS' >> /dev/null
					if [ $? -eq 0 ]
					then
							sed -i 's/^/#/' /etc/init.d/$nc
							kill $PID
					else
							echo "This is not a netcat process."
					fi
			fi

			ls /etc/cron.d | grep $nc >>/dev/null
			if [ $? -eq 0 ]
			then
					cat /etc/cron.d/$nc | grep -E -i 'nc|netcat|$ALIAS' >> /dev/null
					if [ $? -eq 0 ]
					then
							sed -i 's/^/#/' /etc/init.d/$nc
							kill $PID
					else
							echo "This is not a netcat process."
					fi
			fi

			ls /etc/cron.hourly | grep $nc >>/dev/null
			if [ $? -eq 0 ]
			then
					cat /etc/cron.hourly/$nc | grep -E -i 'nc|netcat|$ALIAS' >> /dev/null
					if [ $? -eq 0 ]
					then
							sed -i 's/^/#/' /etc/init.d/$nc
							kill $PID
					else
							echo "This is not a netcat process."
					fi
			fi

			for x in $(ls /var/spool/cron/crontabs)
			do
				cat $x | grep '$nc|nc|netcat|$ALIAS'
				if [ $? -eq 0 ]
				then
					sed -i 's/^/#/' /var/spool/cron/crontabs/$x
					kill $PID
				else
					echo "netcat has not been found in $x crontabs."
				fi
			done

			cat /etc/crontab | grep -i 'nc|netcat|$ALIAS'
			if [ $? -eq 0 ]
			then
				echo "NETCAT FOUND IN CRONTABS! GO AND REMOVE!!!!!!!!!!"
			fi
			echo "Uninstalling netcat now."

#			apt-get autoremove --purge netcat netcat-openbsd netcat-traditional
#else
	#echo "Netcat is not installed"
#fi
	pause
}

##Exports the /etc/sudoers file and checks for a timeout and NOPASSWD value
sudoers() {

	cat /etc/sudoers | grep NOPASSWD.* >> /dev/null
	if [ $? -eq 0 ]
	then
		echo "## NOPASSWD VALUE HAS BEEN FOUND IN THE SUDOERS FILE, GO CHANGE IT." >> postScript.log
	fi
	##Looks for a timeout value and and delete is.
	cat /etc/sudoers | grep timestamp_timeout >> /dev/null
	if [ $? -eq 0 ]
	then
		TIME=`cat /etc/sudoers | grep timestamp_timeout | cut -f2 | cut -d= -f2`
		echo "## Time out value has been set to $TIME Please go change it or remove it." >> postScript
	fi

	pause
}

##Lists all the cron jobs, init, init.d
cron() {

#	Listing all the cronjobs
	echo "###CRONTABS###" > cron.log
	for x in $(cat users); do crontab -u $x -l; done >> cron.log
	echo "###CRON JOBS###" >> cron.log
	ls /etc/cron.* >> cron.log
	ls /var/spool/cron/crontabs/.* >> cron.log
	ls /etc/crontab >> cron.log

#	Listing the init.d/init files
	echo "###Init.d###" >> cron.log
	ls /etc/init.d >> cron.log

	echo "###Init###" >> cron.log
	ls /etc/init >> cron.log
	cat cron.log
	pause
}

CAD() {
	sed -i '/exec shutdown -r not "Control-Alt-Delete pressed"/#exec shutdown -r not "Control-Alt-Delete pressed"/' /etc/init/control-alt-delete.conf
}

#VirtualCon() {
	##Comment out every virtual terminal except tty1
#}

show_menu(){
	case "$opsys" in
	"Ubuntu")
				echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
				echo "           ██╗   ██╗██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗         "
				echo "           ██║   ██║██╔══██╗██║   ██║████╗  ██║╚══██╔══╝██║   ██║         "
				echo "           ██║   ██║██████╔╝██║   ██║██╔██╗ ██║   ██║   ██║   ██║         "
				echo "           ██║   ██║██╔══██╗██║   ██║██║╚██╗██║   ██║   ██║   ██║         "
				echo "           ╚██████╔╝██████╔╝╚██████╔╝██║ ╚████║   ██║   ╚██████╔╝         "
				echo "            ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝    ╚═════╝          "
				echo "~~~~~~~~~~~~~~~~Written by: Ethan Fowler Team-ByTE~~~~~~~~~~~~~~~~~~~~~~~~"
				echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
				echo " "
				echo "1) Update the machine.			2) Set automatic updates."
				echo "3) Search for prohibited file.		4) configure the firewall."
				echo "5) Configure login screen.		6) Create any new users."
				echo "7) Change all the passwords.		8) Delete any users."
				echo "9) Set all the admins.			10) List all cronjobs."
				echo "11) Set the password policy.		12) Set the lockout policy."
				echo "13) Remove the hacking tools.		14) Configure SSH."
				echo "15) Edit the sysctl.conf.			16) Export the sudoers file."
				echo "17) List all running processes.		18) Remove NetCat."
				echo "19) Reboot the machine.			20) Secure the root account"
				echo "21) PostScript				22)Disable ctrl-alt-del"
				echo "23) Disable Virtual Terminals		24)Exit"
	;;
	"Debain")
				echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
				echo "		 ██████╗ ███████╗██████╗  █████╗ ██╗███╗   ██╗			"
				echo "		 ██╔══██╗██╔════╝██╔══██╗██╔══██╗██║████╗  ██║			"
				echo "		 ██║  ██║█████╗  ██████╔╝███████║██║██╔██╗ ██║			"
				echo "		 ██║  ██║██╔══╝  ██╔══██╗██╔══██║██║██║╚██╗██║			"
				echo "		 ██████╔╝███████╗██████╔╝██║  ██║██║██║ ╚████║			"
				echo "	     ╚═════╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝			"
				echo "~~~~~~~~~~~~~~~~Written by: Ethan Fowler Team-ByTE~~~~~~~~~~~~~~~~~~~~~~~~"
				echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
				echo " "
				echo "1) Update the machine.                    2) Set automatic updates."
				echo "3) Search for prohibited file.            4) configure the firewall."
				echo "5) Configure login screen.                6) Create any new users."
				echo "7) Change all the passwords.              8) Delete any users."
				echo "9) Set all the admins.                    10) List all cronjobs."
				echo "11) Set the password policy.              12) Set the lockout policy."
				echo "13) Remove the hacking tools.             14) Configure SSH."
				echo "15) Edit the sysctl.conf.                 16) Export the sudoers file."
				echo "17) List all running processes.           18) Remove NetCat."
				echo "19) Reboot the machine.                   20) Secure the root account"
				echo "21) PostScript                            22) Disable ctrl-alt-del"
				echo "23) Disable Virtual Terminals     	24) Exit"
	;;
	"RedHat")
				echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
				echo "			██████╗ ███████╗██████╗ ██╗  ██╗ █████╗ ████████╗				"
				echo "			██╔══██╗██╔════╝██╔══██╗██║  ██║██╔══██╗╚══██╔══╝				"
				echo "			██████╔╝█████╗  ██║  ██║███████║███████║   ██║   				"
				echo "			██╔══██╗██╔══╝  ██║  ██║██╔══██║██╔══██║   ██║   				"
				echo "			██║  ██║███████╗██████╔╝██║  ██║██║  ██║   ██║   				"
				echo "			╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   				"
				echo "~~~~~~~~~~~~~~~~Written by: Ethan Fowler Team-ByTE~~~~~~~~~~~~~~~~~~~~~~~~"
                echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
                echo " "
			##NOT ALL OF THESE WORK YET, NEED TO FIX
                echo "1) Update the machine.                    2) Set automatic updates."
                echo "3) Search for prohibited file.            4) configure the firewall."
                echo "5) Configure login screen.                6) Create any new users."
                echo "7) Change all the passwords.              8) Delete any users."
                echo "9) Set all the admins.                    10) List all cronjobs."
                echo "11) #Set the password policy.              12) Set the lockout policy."
                echo "13) #Remove the hacking tools.             14) #Configure SSH."
                echo "15) Edit the sysctl.conf.                 16) Export the sudoers file."
                echo "17) List all running processes.           18) #Remove NetCat."
                echo "19) Reboot the machine.                   20) Secure the root account"
                echo "21) PostScript                            22) Disable ctrl-alt-del"
                echo "23) Disable Virtual Terminals     	24) Exit"
	;;
	"CentOS")
				echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
				echo "			 ██████╗███████╗███╗   ██╗████████╗ ██████╗ ███████╗			"
				echo "			██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔═══██╗██╔════╝			"
				echo "			██║     █████╗  ██╔██╗ ██║   ██║   ██║   ██║███████╗			"
				echo "			██║     ██╔══╝  ██║╚██╗██║   ██║   ██║   ██║╚════██║			"
				echo "			╚██████╗███████╗██║ ╚████║   ██║   ╚██████╔╝███████║			"
				echo " 	  	     ╚═════╝╚══════╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚══════╝			"
                echo "~~~~~~~~~~~~~~~~Written by: Ethan Fowler Team-ByTE~~~~~~~~~~~~~~~~~~~~~~~~"
                echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
                echo " "
                ##NOT ALL OF THESE WORK YET, NEED TO FIX
                echo "1) Update the machine.                    2) Set automatic updates."
                echo "3) Search for prohibited file.            4) configure the firewall."
                echo "5) Configure login screen.                6) Create any new users."
                echo "7) Change all the passwords.              8) Delete any users."
                echo "9) Set all the admins.                    10) List all cronjobs."
                echo "11) #Set the password policy.              12) Set the lockout policy."
                echo "13) #Remove the hacking tools.             14) #Configure SSH."
                echo "15) Edit the sysctl.conf.                 16) Export the sudoers file."
                echo "17) List all running processes.           18) #Remove NetCat."
                echo "19) Reboot the machine.                   20) Secure the root account"
                echo "21) PostScript                            22) Disable ctrl-alt-del"
                echo "23) Disable Virtual Terminals    		24) Exit"
	;;
	esac

}

read_options(){
	case $opsys in
	"Ubuntu"|"Debain")
		local choice
		read -p "Pease select item you wish to do: " choice

		case $choice in
			1) update;;
			2) autoUpdate;;
			3) pFiles;;
			4) configureFirewall;;
			5) loginConf;;
			6) createUser;;
			7) chgPasswd;;
			8) delUser;;
			9) admin;;
			10) cron;;
			11) passPol;;
			12) lockoutPol;;
			13) hakTools;;
			14) sshd;;
			15) sys;;
			16) sudoers;;
			17) proc;;
			18) nc;;
	 		19) reboot;;
			20) secRoot;;
			21) cat postScript; pause;;
			22) CAD;;
			23)VirtualCon;;
			24) exit20;;
			69)runFull;;
			*) echo "Sorry that is not an option please select another one..."
			;;
		esac
	;;
	"CentOS")
		local choice
		read -p "Pease select item you wish to do: " choice

		case $choice in
			1) update;;
			2) autoUpdate;;
			3) pFiles;;
			4) configureFirewall;;
			5) loginConf;;
			6) createUser;;
			7) chgPasswd;;
			8) delUser;;
			9) admin;;
			10) cron;;
			11) passPol;;
			12) lockoutPol;;
			13) hakTools;;
			14) sshd;;
			15) sys;;
			16) sudoers;;
			17) proc;;
			18) nc;;
	 		19) reboot;;
			20) secRoot;;
			21) cat postScript; pause;;
			22) CAD;;
			23)VirtualCon;;
			24) exit20;;
			69)runFull;;
			*) echo "Sorry that is not an option please select another one..."
			;;
		esac
	;;
	"RedHat")
		local choice
		read -p "Pease select item you wish to do: " choice

		case $choice in
			1) update;;
			2) autoUpdate;;
			3) pFiles;;
			4) configureFirewall;;
			5) loginConf;;
			6) createUser;;
			7) chgPasswd;;
			8) delUser;;
			9) admin;;
			10) cron;;
			11) passPol;;
			12) lockoutPol;;
			13) hakTools;;
			14) sshd;;
			15) sys;;
			16) sudoers;;
			17) proc;;
			18) nc;;
	 		19) reboot;;
			20) secRoot;;
			21) cat postScript; pause;;
			22) CAD;;
			23)VirtualCon;;
			24) exit20;;
			69)runFull;;
			*) echo "Sorry that is not an option please select another one..."
			;;
		esac
	;;
	
	esac
}

##This runs .the actual script
while true
do
	clear
	show_menu
	read_options
done
