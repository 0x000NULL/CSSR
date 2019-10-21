#!/bin/bash
#Author: Jacee K. Gonzales
#Title: Mililani High School Cyberpatriot Open Division Script, Linux

#Variables
PWDt=$(pwd)

#Startup
echo "$(date +'%m/%d/%Y %r'): Verifying an internet connection with aptitude"
echo "$(date +'%m/%d/%Y %r'): Verifying an internet connection with aptitude" >> $PWDt/log/mhs.log
apt-get install cowsay -y &> /dev/null
if [ "$?" -eq "1" ]; then
   echo "$(date +'%m/%d/%Y %r'): This script cannot access aptitude properly."
   echo "$(date +'%m/%d/%Y %r'): Apititude check failed" >> $PWDt/log/mhs.log
   exit 1
fi
unalias -a
echo "unalias -a" >> ~/.bashrc
echo "unalias -a" >> /root/.bashrc
echo "$(date +'%m/%d/%Y %r'): Starting script" >> $PWDt/log/mhs.log

if ! [ -d $PWDt/config ]; then
	echo "$(date +'%m/%d/%Y %r'): Please Cd into cyberpat directory and run the script there."
	echo "$(date +'%m/%d/%Y %r'): Please Cd into cyberpat directory and run the script there." >> $PWDt/log/mhs.log
	exit
fi

if [ "$EUID" -ne 0 ]; then
	echo "$(date +'%m/%d/%Y %r'): Run as Root" 
	echo "$(date +'%m/%d/%Y %r'): Run as Root" >> $PWDt/log/mhs.log
	exit
fi

#Functions
appinstall() {
	echo "$(date +'%m/%d/%Y %r'): Installing applications (chkrootkit clamav rkhunter apparmor apparmor-profiles firefox hardinfo iptables portsentry lynis ufw gufw sysv-rc-conf nessus)"
	echo "$(date +'%m/%d/%Y %r'): Installing applications (chkrootkit clamav rkhunter apparmor apparmor-profiles firefox hardinfo iptables portsentry lynis ufw gufw sysv-rc-conf nessus)" >> $PWDt/log/mhs.log
	apt-get -V -y install chkrootkit clamav rkhunter apparmor apparmor-profiles firefox hardinfo iptables portsentry lynis ufw gufw sysv-rc-conf nessus
	apt-get -V -y install --reinstall coreutils
	apt-get update
	apt-get upgrade -y
	apt-get dist-upgrade -y
	apt-get install -f -y
	apt-get autoremove -y
	apt-get autoclean -y
	apt-get check
		stop
}

stop() {
	echo "Continue? (Y/N) "
	read continu
	if [ "$continu" = "N" ] || [ "$continu" = "n" ]; then
		echo "$(date +'%m/%d/%Y %r'): Ending script"
		echo "$(date +'%m/%d/%Y %r'): Ending script" >> $PWDt/log/mhs.log
		exit;
	fi
}

firewall() {
	echo "$(date +'%m/%d/%Y %r'): Enabling Universal Firewall (ufw)"
	echo "$(date +'%m/%d/%Y %r'): Enabling Universal Firewall (ufw)" >> $PWDt/log/mhs.log
	ufw enable
		stop 
}

guestaccnt() {
	read -p "Turn Guest On or Off?: "
	if [ $REPLY == "on" ] || [ $REPLY == "On" ]; then
		echo "$(date +'%m/%d/%Y %r'): Restoring Guest Login"
		echo "$(date +'%m/%d/%Y %r'): Restoring Guest Login" >> $PWDt/log/mhs.log
		sudo rm /etc/lightdm/lightdm.conf.d/50-no-guest.conf
			stop
	elif [ $REPLY == "off" ] || [ $REPLY == "Off" ]; then
		echo "$(date +'%m/%d/%Y %r'): Removing Guest login, to get back guest login again remove 50-no-guest.conf"
		echo "$(date +'%m/%d/%Y %r'): Removing Guest login, to get back guest login again remove 50-no-guest.conf" >> $PWDt/log/mhs.log
		sudo sh -c 'printf "[Seat:*]\nallow-guest=false\n" > /etc/lightdm/lightdm.conf.d/50-no-guest.conf'
			stop
	fi
}

sshconf() {
	echo "$(date +'%m/%d/%Y %r'): Configuring SSH"
	echo "$(date +'%m/%d/%Y %r'): Configuring SSH" >> $PWDt/log/mhs.log
	cat $PWDt/config/sshd_config > /etc/ssh/sshd_config
	/usr/sbin/sshd -t
	systemctl restart ssh.service
		stop 
}

#ERROR
#guestaccntoff() {
#	echo "Restoring Guest Login"
#	sudo rm /etc/lightdm/lightdm.conf.d/50-no-guest.conf
#		stop
#}

updating() {
	echo "$(date +'%m/%d/%Y %r'): Updating Computer"
	echo "$(date +'%m/%d/%Y %r'): Updating Computer" >> $PWDt/log/mhs.log
	apt-get update
	apt-get upgrade -y
	apt-get dist-upgrade -y
	apt-get install -f -y
	apt-get autoremove -y
	apt-get autoclean -y
	apt-get check
		stop
}

zeroUid(){
	echo "$(date +'%m/%d/%Y %r'): Checking for UID's of 0 (Root Access Accounts)"
	echo "$(date +'%m/%d/%Y %r'): Checking for UID's of 0 (Root Access Accounts)" >> $PWDt/log/mhs.log
	touch $PWDt/log/zerouidusers
	touch $PWDt/log/uidusers

	cut -d: -f1,3 /etc/passwd | egrep ':0$' | cut -d: -f1 | grep -v root > $PWDt/log/zerouidusers

	if [ -s $PWDt/log/zerouidusers ]
	then
		echo "$(date +'%m/%d/%Y %r'): There are Zero UID Users! I'm fixing it now!"
		echo "$(date +'%m/%d/%Y %r'): There are Zero UID Users! I'm fixing it now!" >> $PWDt/log/mhs.log

		while IFS='' read -r line || [[ -n "$line" ]]; do
			thing=1
			while true; do
				rand=$(( ( RANDOM % 999 ) + 1000))
				cut -d: -f1,3 /etc/passwd | egrep ":$rand$" | cut -d: -f1 > $PWDt/log/uidusers
				if [ -s $PWDt/log/uidusers ]
				then
					echo "Couldn't find unused UID. Trying Again... $(date +'%m/%d/%Y %r')"
					echo "Couldn't find unused UID. Trying Again... $(date +'%m/%d/%Y %r')" >> $PWDt/log/mhs.log
				else
					break
				fi
			done
			usermod -u $rand -g $rand -o $line
			touch /tmp/oldstring
			old=$(grep "$line" /etc/passwd)
			echo $old > /tmp/oldstring
			sed -i "s~0:0~$rand:$rand~" /tmp/oldstring
			new=$(cat /tmp/oldstring)
			sed -i "s~$old~$new~" /etc/passwd
			echo "ZeroUID User: $line"
			echo "Assigned UID: $rand"
		done < "$PWDt/log/zerouidusers"
		update-passwd
		cut -d: -f1,3 /etc/passwd | egrep ':0$' | cut -d: -f1 | grep -v root > $PWDt/log/zerouidusers

		if [ -s $PWDt/log/zerouidusers ]
		then
			echo "$(date +'%m/%d/%Y %r'): WARNING: UID CHANGE UNSUCCESSFUL!"
			echo "$(date +'%m/%d/%Y %r'): WARNING: UID CHANGE UNSUCCESSFUL!" >> $PWDt/log/mhs.log
		else
			echo "$(date +'%m/%d/%Y %r'): Successfully Changed Zero UIDs!"
			echo "$(date +'%m/%d/%Y %r'): Successfully Changed Zero UIDs!" >> $PWDt/log/mhs.log
		fi
	else
		echo "$(date +'%m/%d/%Y %r'): No Zero UID Users"
		echo "$(date +'%m/%d/%Y %r'): No Zero UID Users" >> $PWDt/log/mhs.log
	fi
		stop	
}
	
sh_menu() {
	clear
	echo "$(date +'%m/%d/%Y %r')"
	echo "
   __  _____ ______  ____                  ____        _      __ 
  /  |/  / // / __/ / __ \___  ___ ___    / __/_______(_)__  / /_
 / /|_/ / _  /\ \  / /_/ / _ \/ -_) _ \  _\ \/ __/ __/ / _ \/ __/
/_/  /_/_//_/___/  \____/ .__/\__/_//_/ /___/\__/_/ /_/ .__/\__/ 
                       /_/                           /_/         
"
	echo "------------------"
	echo " M A I N _ M E N U"
	echo "------------------"
	echo "1) Enable Firewall"
	echo "2) Edit Guest Account Config"
	echo "3) Secure ssh Config"
	echo "4) Update computer"
	echo "5) Check for UID's of 0 (Root Access Acounts)"
	echo "6) Install Security Applications"
	echo "7) Do All Above"
	echo "8) Go to Logs"
	echo "9) Exit"
}

read_choice() {
	read -p "Enter choice 1-9: "
	if  [ $REPLY == "1" ]; then
		firewall;

	elif [ $REPLY == "2" ]; then
		guestaccnt;
#ERROR
#	elif [ $REPLY == "3" ]; then
#		guestaccntoff;
	
	elif [ $REPLY == "3" ]; then
		sshconf;


	elif [ $REPLY == "9" ]; then
		echo "$(date +'%m/%d/%Y %r'): Ending script"
		echo "$(date +'%m/%d/%Y %r'): Ending script" >> $PWDt/log/mhs.log
		exit 0;

	elif [ $REPLY == "4" ]; then
		updating;

	elif [ $REPLY == "5" ]; then
		zeroUid;

	elif [ $REPLY == "7" ]; then
		appinstall;
		guestaccnt;
		sshconf;
		firewall;
		zeroUid;
		updating;

	elif [ $REPLY == "8" ]; then
		gedit $PWDt/log/mhs.log

	elif [ $REPLY == "6" ]; then
		appinstall;

	fi
}

trap '' SIGINT SIGQUIT SIGTSTP

while true; do

	sh_menu
	read_choice

done
