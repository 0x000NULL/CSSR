#! /bin/bash

echo 'Hello, user! Welcome to my script.'
echo 'The script is now running...'

function main {
	echo "main function running..."

#	begin scripts

#	verwd #check what the working directory is
	aptf #apt-get update #
	toolbelt #install tools #
	noport #enables ufw
	lockdown #locks accounts #
	nopass #sets password policies
	sshfix #sshconfig #
	nomedia #gets rid of media files #
	rootkits #configures rootkit tools to run weekly
	scruboff #get rid of software

#	end of scripts

	echo "Script is complete..."
	cont
}


# function that pauses between steps
function cont {
	read -n1 -p "Press space to continue, AOK to quit" key
	if [ "$key" = "" ]; then
		echo "Moving forward..."
	else
		echo "Quitting script..."
		exit 1
	fi
}

#apt update
function aptf {
	echo ""
	echo "Updating the system..."

	#offline solution
	read -n1 -p "Press 1 if on Ubuntu, 2 if on Debian, AOK to quit" osin
	if [ "$osin" = "1" ]; then
		cp ../resources/mysources.list /etc/apt/sources.list
	elif [ "$osin" = "2" ]; then
		cp ../resources/mydebsources.list /etc/apt/sources.list
	fi

	apt-get -y update
	apt-get -y upgrade
#	apt-get -y install --reinstall coreutils
	echo "Finished updating"
	cont
}

#install tools to use for misc purposes
function toolbelt {
	echo ""
	echo "Installing Utilities..."
	apt-get -y install \
	vim \
	ufw \
	gufw \
	firefox \
	clamav \
	libpam-cracklib \
	lsof \
	chkrootkit \
	openssh-server \
	rkhunter
	echo "Finished installs"
	updatedb
	echo "Updated database"
	cont
}

# hardens network security
function noport {
	echo ""
	echo "Enabling Uncomplicated Firewall..."
	ufw enable
	cont

	echo "Hardening IP security..."

	netsecfilea="$(find /etc/sysctl.d/ -maxdepth 1 -type f -name '*network-security.conf')" # finds default net-sec config file
	netsecfile="${netsecfilea// }" # eliminates whitespace from the string (if there is any)
	netsecfileb=$netsecfile"~" # names the backup file

	cp $netsecfile $netsecfileb # creates a backup of the config file
	chmod a-w $netsecfileb # makes backup read-only

	cp /etc/sysctl.conf /etc/sysctl.conf~ # backup sysctl config
	chmod a-w /etc/sysctl.conf~ # read only

	echo "Backups created"

	# 3 cases - found file, no file, multiple files
	#TODO test the line by line method for all cases
	if [ -z $netsecfile ] # true if FIND didn't find anything
	then
		echo "find could not find the file you were looking for, attempting to use sysctl -w"
		# reads from ipsec2 line by line using sysctl command to change settings

		file="../resources/ipsec2.conf"
		while IFS= read -r line
		do
			# reads from ipsec2 line by line and uses sysctl command
			sysctl -w "$line"
		done <"$file"
		sysctl -p

	else
		echo "File was found, appending settings to end of file"
		# if the file exists, we will append our settings from our file

		cat ../resources/ipsec.conf >> "$netsecfile"
		service procps start

	fi
	cont

	echo "Verify rules..."
	ufw status
	cont
	echo "Finished managing rules"
}


#locks root user and home directory
function lockdown {
	echo ""
	echo "Locking root user"
	passwd -l root
	echo "root locked"
	hahahome='HOME'
	chmod 0750 ${!hahahome}
	echo "home directory locked"
	cont
}


#manages password policies
#this should be its own script
function nopass {
	echo ""
	echo "Changing password policies requires manual interaction\n"

	#run cracklib

	#login.defs
	echo "Making a backup login.defs file..."
	cp /etc/login.defs /etc/login.defs~
	chmod a-w /etc/login.defs~
	cont

	echo "Copying local login.defs file..."
	cp ../resources/my_login.defs /etc/login.defs

	#common-password
	echo "Making a backup config file..."
	cp /etc/pam.d/common-password /etc/pam.d/common-password~
	chmod a-w /etc/pam.d/common-password~
	cont

	echo "Copying local common-password file..."
	cp ../resources/my_common-password /etc/pam.d/common-password

	echo 'Password policies configured'
	# done configuring

	# will change pass age for users aready created
	echo "Applying to all users..."
	for i in $(awk -F':' '/\/home.*sh/ { print $1 }' /etc/passwd); do chage -m 3 -M 60 -W 7 $i; done
	echo "Password Policies finished."
	cont
}


function sshfix {
	echo ''
	echo 'Turn off root login settings for ssh'
	echo 'This must be performed manually'
	echo "Making a backup config file..."
	cp /etc/ssh/sshd_config /etc/ssh/sshd_config~
	chmod a-w /etc/ssh/sshd_config~
	cont

#TODO make sure that default config doesn't change after installing openssh-server
	#permitrootlogin
	cp ../resources/sshdconfig /etc/ssh/sshd_config
	cont

	#enables/disables ssh
	service ssh restart
	read -n1 -r -p "Press 1 to turn off ssh, space to continue..." key
	if [ "$key" = '1' ]; then
		service ssh stop
	fi

	echo 'Finished ssh config editing'
	cont
}

#finds and deletes media files
function nomedia {
	echo "Deleting media..."
	find / -name '*.mp3' -type f -delete
	find / -name '*.mov' -type f -delete
	find / -name '*.mp4' -type f -delete
	find / -name '*.avi' -type f -delete
	find / -name '*.mpg' -type f -delete
	find / -name '*.mpeg' -type f -delete
	find / -name '*.flac' -type f -delete
	find / -name '*.m4a' -type f -delete
	find / -name '*.flv' -type f -delete
	find / -name '*.ogg' -type f -delete
	find /home -name '*.gif' -type f -delete
	find /home -name '*.png' -type f -delete
	find /home -name '*.jpg' -type f -delete
	find /home -name '*.jpeg' -type f -delete
	echo "Media deleted"
	cont
}


#actually running the script
unalias -a #Get rid of aliases
echo "unalias -a" >> /root/.bashrc # gets rid of aliases when root
cd $(dirname $(readlink -f $0))
if [ "$(id -u)" != "0" ]; then
	echo "Please run as root"
	exit
else
	main
fi
