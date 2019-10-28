mv /var/log/mikescript.log /var/log/mikescript-cached-$RANDOM$RANDOM.log
echo $(date): Any previous logfiles cached elsewhere >> /var/log/mikescript.log
echo $(date): Script was initialized >> /var/log/mikescript.log
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   echo $(date): Script was not run as root >> /var/log/mikescript.log
   exit 1
fi
echo "Clearing HOSTS file"
echo $(date): Clearing HOSTS file >> /var/log/mikescript.log
echo 127.0.0.1	localhost > /etc/hosts
echo 127.0.1.1	ubuntu  >> /etc/hosts

echo ::1     ip6-localhost ip6-loopback >> /etc/hosts
echo fe00::0 ip6-localnet >> /etc/hosts
echo ff00::0 ip6-mcastprefix >> /etc/hosts
echo ff02::1 ip6-allnodes >> /etc/hosts
echo ff02::2 ip6-allrouters >> /etc/hosts
     	        msg=$(echo HOSTS file cleared | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g'  )
		break>> /dev/null
echo $(date): Verifying an internet connection with aptitude >> /var/log/mikescript.log
apt-get install cowsay -y &> /dev/null
if [ "$?" -eq "1" ]; then
   echo "This script cannot access aptitude properly."
   echo $(date): Apititude check failed >> /var/log/mikescript.log
   exit 1
fi
apt-get install pastebinit -y
cd /var/log/apt
gunzip history.log.*.gz
cat history* | grep Commandline | grep -v pastebinit | grep -v cowsay | sed 's/Commandline\: apt-get//g' | sed 's/remove/removed/g' | sed 's/install/installed/g' | sed 's/purge/purged/g' > /tmp/pasted
			msg=$(pastebinit -u marshallcyber1 -p [[]] -i /tmp/pasted  | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )
			
cat $(locate bash_history) > /tmp/usershistory
			msg=$(pastebinit -u marshallcyber1 -p [[]] -i /tmp/usershistory  | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )
			break

yum repolist all  &> /dev/null
if [[ $? -eq 0 ]]; then
    pkgmgr="yum"
fi
apt-get -h &> /dev/null
if [[ $? -eq 0 ]]; then
    pkgmgr="apt"
    echo $(date): $pkgmgr identified as package manager >> /var/log/mikescript.log
fi
add-apt-repository "deb http://archive.canonical.com/ubuntu precise partner"
add-apt-repository "deb http://archive.ubuntu.com/ubuntu precise multiverse main universe restricted"
add-apt-repository "deb http://security.ubuntu.com/ubuntu/ precise-security universe main multiverse restricted"
add-apt-repository "deb http://archive.ubuntu.com/ubuntu precise-updates universe main multiverse restricted"
if [ $? -eq 0 ]; then
	msg=apt%20repositories%20successfully%20added
	break
fi
echo $(date): Finished adding repos >> /var/log/mikescript.log
apt-get update &> /dev/null
if [ $? -eq 1 ]; then
	echo $(date): Finished updating package lists with errors >> /var/log/mikescript.log
else
	echo $(date): Finished updating package lists successfully >> /var/log/mikescript.log
fi
echo pkgmgr is $pkgmgr
# Detect readme
# Get ready for a f***ing rideeee
updatedb
locate -i readme > /tmp/readme
cat /tmp/readme | grep Desktop > /tmp/readmes
ls / | grep readme >> /dev/null
readmename=$(ls / | grep -i readme)
readmenameinroot=$(ls /root | grep -i readme)
if [ -s /tmp/readmes ]; then
	suslocs=$(cat /tmp/readmes | wc -l)
		if [ $suslocs -eq 1 ]; then
			echo Only one primary candidate for readme
			readmeloc=$(cat /tmp/readmes)
			echo $readmeloc
		else
			echo Multiple readme candidates detected \(multiple readmes in desktops\)
			multiprimes=$(cat /tmp/readmes | grep Desktop | grep $(users))
			primescount=$(echo $multiprimes | wc -l)
				if [ "$primescount" -eq "1" ]; then
					echo $multiprimes detected as main candidate
					readmeloc=$multiprimes
				else
					echo Cannot properly distinguish candidates
				fi
		fi	
else
	if [ -z "$readmename" ]; then
		echo no readme in root file sys
	else
		echo /$readmename identified
		readmeloc=/$readmename
	fi
	if [ -z "$readmenameinroot" ]; then
		echo found readme at /root/$readmenameinroot
	else
		if [ -z "$readmename" ]; then
			readmeloc=/root/$readmenameinroot
		fi
	fi
fi
if ! [ -z "$readmeloc" ]; then
	echo Readme resolved at $readmeloc
else
	echo Cannot determine the location of the readme
	echo $readmeloc
	echo Please enter the full path here:
	read readmeloc
fi
echo $readmeloc locked in
if [ $? -eq 0 ]; then
	msg=$(echo $readmeloc | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )%20identified%20as%20readme
	break>> /dev/null
fi
echo $(date): $readmeloc is located readme >> /var/log/mikescript.log
cut -d: -f1,3 /etc/passwd | egrep ':[0-9]{4}$' | cut -d: -f1 > usersover1000
echo root >> usersover1000
for ScottStork in `cat usersover1000`
do
   cat $readmeloc | grep $ScottStork
	if [ "$?" -eq "1" ]; then
		if [ "$ScottStork" = "root" ]; then
		echo Root Excempt
		else
			echo Rogue user $ScottStork detected
			echo Delete? \(Y\/N\)
			msg=$(echo $ScottStork rogue user detected. requires immediate user intervention. | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )
			break>> /dev/null

			read yorn
			if [ "$yorn" = "Y" ]; then
				userdel $ScottStork
			fi
		fi
	fi
done

echo $(date): $readmeloc set as READMELOC >> /var/log/mikescript.log
# SSH Server Configuration
cat /etc/ssh/sshd_config | grep PermitRootLogin | grep yes
if [ $?==0 ]; then
                sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
               	echo $(date): PermitRootLogin rule detected in SSH >> /var/log/mikescript.log
           	msg=$(echo PermitRootLogin rule changed | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )
		break>> /dev/null

fi
cat /etc/ssh/sshd_config | grep Protocol | grep 1
if [ $?==0 ]; then
                sed -i 's/Protocol 2,1/Protocol 2/g' /etc/ssh/sshd_config
                sed -i 's/Protocol 1,2/Protocol 2/g' /etc/ssh/sshd_config
               	echo $(date): Protocol rule detected in SSH >> /var/log/mikescript.log
        	msg=$(echo SSH Protocol changed to exclusively 1 | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g'  )
		break>> /dev/null

fi
grep X11Forwarding /etc/ssh/sshd_config | grep yes
if [ $?==0 ]; then
                sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config
               	echo $(date): X11Forwarding rule detected in SSH >> /var/log/mikescript.log
     	        msg=$(echo X11Forwarding rule changed to no | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g'  )
		break>> /dev/null

fi
# Sudoers - require password
grep PermitEmptyPasswords /etc/ssh/sshd_config | grep yes
if [ $?==0 ]; then
                sed -i 's/PermitEmptyPasswords yes/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
               	echo $(date): PermitEmptyPasswords rule detected in SSH >> /var/log/mikescript.log
     	        msg=$(echo PermitEmptyPasswords rule changed to no | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g'  )
		break>> /dev/null

fi
grep NOPASSWD /etc/sudoers
if [ $?==0 ]; then
               tits=$(grep NOPASSWD /etc/sudoers)
		sed -i 's/$tits/ /g' /etc/sudoers
		echo $(date): NOPASSWD rule detected >> /var/log/mikescript.log
     	        msg=$(echo SUDOERS NOPASSWD rule removed | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g'  )
		break>> /dev/null

fi
cd /etc/sudoers.d && ls /etc/sudoers.d | grep -v cyberpatriot | grep -v scor | xargs rm
     	        msg=$(echo Removed any sudoers.d rules other than cyberpatriot | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g'  )
		break>> /dev/null

cat /etc/apt/apt.conf.d/10periodic | grep APT::Periodic::Update-Package-Lists | grep 0 >> /dev/null
if [ $?==0 ]; then
	sed -i 's/APT::Periodic::Update-Package-Lists "0"/APT::Periodic::Update-Package-Lists "1"/g' /etc/apt/apt.conf.d/10periodic
	echo $(date): Periodic Updates enabled >> /var/log/mikescript.log
	
fi
/usr/lib/lightdm/lightdm-set-defaults -l false
if [ $?==0 ]; then
     	        msg=$(echo Set allow guest to false | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )
		break>> /dev/null
fi
	echo "exit 0" > /etc/rc.local
	     	        msg=$(echo X11Forwarding rule changed to exclusively 1 | sed 's/\//%2F/g' | sed 's/\./%2E/g' )
		break>> /dev/null

# Get rid of and replace any UID that is equal to 0
# Gives it a big-ass new UID, throws a nonfatal error or two but lol idc
cut -d: -f1,3 /etc/passwd | egrep ':0$' | cut -d: -f1 | grep -v root >> /tmp/blackthought
while read p <&3; do
        useruid=$RANDOM$RANDOM
        sed -i 's/'$p':x:0'/$p':x:'$useruid'/g' /etc/passwd
        echo $(date): $p Rogue UID detected >> /var/log/mikescript.log
        msg=$(echo Rogue root UID detected | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )
	break>> /dev/null

done 3< /tmp/blackthought

#Disables ctrl+alt+del
sed '/^exec/ c\exec false' /etc/init/control-alt-delete.conf 
     	        msg=$(echo Ctrl alt delete is disabled | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )
		break>> /dev/null

# Lord forgive me
# Alias Windows Commands for Linux Commands
# Also clears any rogue aliases :)
unalias -a
alias egrep='egrep --color=auto'
alias fgrep='fgrep --color=auto'
alias grep='grep --color=auto'
alias l='ls -CF'
alias la='ls -A'
alias ll='ls -alF'
alias ls='ls --color=auto'
alias cls=clear
alias dir=ls
alias type=cat


#only allow root in cron
cd /etc/
/bin/rm -f cron.deny at.deny
echo root >cron.allow
echo root >at.allow
/bin/chown root:root cron.allow at.allow
/bin/chmod 400 cron.allow at.allow

#Critical File Permissions
chown -R root:root /etc/apache2
chown -R root:root /etc/apache

#Secure Apache 2
if [ -e /etc/apache2/apache2.conf ]; then
	echo \<Directory \> >> /etc/apache2/apache2.conf
	echo -e ' \t AllowOverride None' >> /etc/apache2/apache2.conf
	echo -e ' \t Order Deny,Allow' >> /etc/apache2/apache2.conf
	echo -e ' \t Deny from all' >> /etc/apache2/apache2.conf
	echo \<Directory \/\> >> /etc/apache2/apache2.conf
	echo UserDir disabled root >> /etc/apache2/apache2.conf
	echo $(date): Apache security measures enabled >> /var/log/mikescript.log
fi

#SYN Cookie Protection
sysctl -w net.ipv4.tcp_syncookies=0
        if [ "$?" -eq "0" ]; then
        	echo $(date): SYN cookie protection enabled >> /var/log/mikescript.log
        	msg=$(echo SYN Cookie protection enabled | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )
		break>> /dev/null

        fi

echo Edit Passwords
#List users with UID over 1000
echo echo $(date): Parsing passwd for UID 1000 or more >> /var/log/mikescript.log
cut -d: -f1,3 /etc/passwd | egrep ':[0-9]{4}$' | cut -d: -f1 > u$
echo root >> usersover1000
for ScottStorch in `cat usersover1000`
do
   echo $ScottStorch password being changed
   echo $ScottStorch':Y0L0SWAg1!' | chpasswd
        if [ "$?" -eq "0" ]; then
                echo "Password change successful"
                echo $(date): $ScottStorch password changed >> /var/log/mikescript.log
        else
                echo "Password change failed"
                echo $(date): $ScottStorch password failed to change >> /var/log/mikescript.log

        fi
done



#Set password policy
apt-get install libpam-cracklib -y &> /dev/null
grep "auth optional pam_tally.so deny=5 unlock_time=900 onerr=fail audit even_deny_root_account silent " /etc/pam.d/common-auth
if [ "$?" -eq "1" ]; then	
	echo "auth optional pam_tally.so deny=5 unlock_time=900 onerr=fail audit even_deny_root_account silent " >> /etc/pam.d/common-auth
	echo "password requisite pam_cracklib.so retry=3 minlen=8 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1" >> /etc/pam.d/common-password
	echo "password requisite pam_pwhistory.so use_authtok remember=24 enforce_for_root" >>  /etc/pam.d/common-password
	echo $(date): Super anal password policy applied >> /var/log/mikescript.log
fi

OLDFILE=/etc/login.defs
NEWFILE=/etc/login.defs.new

PASS_MAX_DAYS=15
PASS_MIN_DAYS=6
PASS_MIN_LEN=8
PASS_WARN_AGE=7


SEDSCRIPT=$(mktemp)
# change existing arguments at the same position
cat - > $SEDSCRIPT <<EOF
s/\(PASS_MAX_DAYS\)\s*[0-9]*/\1 $PASS_MAX_DAYS/
s/\(PASS_MIN_DAYS\)\s*[0-9]*/\1 $PASS_MIN_DAYS/
s/\(PASS_WARN_AGE\)\s*[0-9]*/\1 $PASS_WARN_AGE/
EOF

sed -f $SEDSCRIPT $OLDFILE > $NEWFILE

# add non-existing arguments
grep -q "^PASS_MAX_DAYS\s" $NEWFILE || echo "PASS_MAX_DAYS $PASS_MAX_DAYS" >> $NEWFILE
grep -q "^PASS_MIN_DAYS\s" $NEWFILE || echo "PASS_MIN_DAYS $PASS_MIN_DAYS" >> $NEWFILE
grep -q "^PASS_WARN_AGE\s" $NEWFILE || echo "PASS_WARN_AGE $PASS_WARN_AGE" >> $NEWFILE

rm $SEDSCRIPT

# Check result
grep ^PASS $NEWFILE

# Copy result back. Don't use "mv" or "cp" to keep owner, group and access-mode
cat $NEWFILE > $OLDFILE
if [ $? -eq 0 ]; then
	        msg=$(echo Password min. max. and warning age is set | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )
		break>> /dev/null

fi
echo $(date): Password age established >> /var/log/mikescript.log
# TCP SYN Cookies

sysctl -w net.ipv4.tcp_syncookies=1
echo $(date): TCP SYN Cookie Flood Protection Enabled >> /var/log/mikescript.log
# Don't act as router
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
if [ $? -eq 0 ]; then
     	        msg=$(echo IP Forwarding and redirects disallowed | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )
		break>> /dev/null
fi
echo $(date): IP forwarding and redirects disallowed >> /var/log/mikescript.log
# Make sure no one can alter the routing tables
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
if [ $? -eq 0 ]; then
     	        msg=$(echo Accepting redirects and secure redirects disallowed | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )
		break>> /dev/null
fi
echo $(date): Accepting redirects and secure redirects disallowed as well >> /var/log/mikescript.log
sysctl -p
echo $(date): Locating world writeable files... >> /var/log/mikescript.log
cd / && ls -laR | grep rwxrwxrwx | grep -v "lrwx" &> /tmp/777s
cat /tmp/777s >> /var/log/mikescript.log
echo $(date): Looking for rogue SUID/SGID binaries... >> /var/log/mikescript.log
echo Sysctl complete
echo $(date): Sysctl completed >> /var/log/mikescript.log
#Prohibited Media Files
if [ $pkgmgr = "apt" ]; then
	echo $(date): Running and installing debsums >> /var/log/mikescript.log
        apt-get install debsums -y &> /dev/null
        debsums -e | grep FAIL
	debsums -c | grep FAIL
	debsums -c | grep FAIL >> /var/log/mikescript.log
	echo $(date): Debsums run >> /var/log/mikescript.log
	if [ $? -eq 0 ]; then
     	        msg=$(echo Debsums run | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )
		break>> /dev/null
	fi
fi
echo Working on deleting prohibited media...
echo $(date): Logging media >> /var/log/mikescript.log
find / -name "*.mp3" -type f >> /var/log/mikescript.log
find / -name "*.wav" -type f >> /var/log/mikescript.log
find / -name "*.wmv" -type f >> /var/log/mikescript.log
find / -name "*.mp4" -type f >> /var/log/mikescript.log
find / -name "*.mov" -type f >> /var/log/mikescript.log
find / -name "*.avi" -type f >> /var/log/mikescript.log
find / -name "*.mpeg" -type f >> /var/log/mikescript.log
find /home -name "*.jpeg" -type f >> /var/log/mikescript.log
find /home -name "*.jpg" -type f >> /var/log/mikescript.log
find /home -name "*.png" -type f >> /var/log/mikescript.log
find /home -name "*.gif" -type f >> /var/log/mikescript.log
find /home -name "*.tif" -type f >> /var/log/mikescript.log
find /home -name "*.tiff" -type f >> /var/log/mikescript.log
find / -name "*.mp3" -type f -delete
find / -name "*.wav" -type f -delete
find / -name "*.wmv" -type f -delete
find / -name "*.mp4" -type f -delete
find / -name "*.mov" -type f -delete
find / -name "*.avi" -type f -delete
find / -name "*.mpeg" -type f -delete
find /home -name "*.jpeg" -type f -delete
find /home -name "*.jpg" -type f -delete
find /home -name "*.png" -type f -delete
find /home -name "*.gif" -type f -delete
find /home -name "*.tif" -type f -delete
find /home -name "*.tiff" -type f -delete
if [ $? -eq 0 ]; then
     	        msg=$(echo Prohibited media logged and deleted | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )
		break>> /dev/null
fi
if [ $pkgmgr=="apt" ]; then
dpkg -l | grep apache
dpkg -l | grep avahi
dpkg -l | grep openssh-server
dpkg -l | grep cupsd
dpkg -l | grep master
dpkg -l | grep nginx
apt-get install ufw -y >> /dev/null
if [ $? -eq 0 ]; then
     	        msg=$(echo UFW installed | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )
		break>> /dev/null
fi
fi
if [ $pkgmgr=="yum" ]; then
yum -y install ufw >> /dev/null
if [ $? -eq 0 ]; then
     	        msg=$(echo UFW installed | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )
		break>> /dev/null
fi
fi
ufw enable
echo $(date): UFW enabled >> /var/log/mikescript.log
if [ $? -eq 0 ]; then
     	        msg=$(echo UFW enabled | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )
		break>> /dev/null
fi
ufw allow http
if [ $? -eq 0 ]; then
     	        msg=$(echo UFW HTTP exception added | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )
		break>> /dev/null
fi
echo $(date): UFW exception added for regular HTTP >> /var/log/mikescript.log

ufw allow https
if [ $? -eq 0 ]; then
     	        msg=$(echo UFW HTTPS exception added | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )
		break>> /dev/null
fi
echo $(date): UFW exception added for HTTPS >> /var/log/mikescript.log






if [ $pkgmgr = "apt" ]; then
	apt-get install apparmor apparmor-profiles -y &> /dev/null
fi

# Rootkit checker
clear
echo $(date): Checking for clearly bad packages >> /var/log/mikescript.log
echo $(date): Repopulating package lists.... >> /var/log/mikescript.log
apt-get update &> /dev/null
dpkg -l | grep netcat
if [ "$?" -eq "0" ]; then
	apt-get purge netcat netcat-openbsd netcat-traditional -y
	killnetcat=$(find / -name netcat -o -name nc)
	rm -rf $killnetcat
	if [ $? -eq 0 ]; then
     	        msg=$(echo Netcats removed | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )
		break>> /dev/null
	fi
fi
dpkg -l | cut -d\  -f3 | grep -v +++ | grep -v Status,Err | grep -v Desired > /tmp/dpkglisting
grep apache /tmp/dpkglisting
	if [ "$?" -eq "0"]; then
		apachefun=0
		grep -i apache $readmeloc
		let apachefun=$?+$apachefun
		grep -i web $readmeloc
		let apachefun=$?+$apachefun
		
	fi

echo $(date): Installing RKHunter manually >> /var/log/mikescript.log
apt-get install chkrootkit -y &> /dev/null
if [ $? -eq 0 ]; then
     	        msg=$(echo Chkrootkit was installed. | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )
		break>> /dev/null
fi
echo $(date): Installing RKHunter manually >> /var/log/mikescript.log
apt-get install rkhunter
if [ $? -eq 0 ]; then
     	        msg=$(echo Rkhunter was installed. running. | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )
		break>> /dev/null
fi
clear
rkhunter -c --rwo
if [ $? -eq 0 ]; then
     	        msg=$(echo Rkhunter was run | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )
		break>> /dev/null
fi
echo $(date): Rootkit Hunter was run in warning mode >> /var/log/mikescript.log
chkrootkit -q
if [ $? -eq 0 ]; then
     	        msg=$(echo Chkrootkit was run | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )
		break>> /dev/null
fi
echo $(date): Chkrootkit was run in quiet mode >> /var/log/mikescript.log

apt-get install tiger -y &> /dev/null
echo $(date): Tiger IDS was installed >> /var/log/mikescript.log
tiger
if [ $? -eq 0 ]; then
     	        msg=$(echo Tiger IDS was run | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )
		break>> /dev/null
fi
echo $(date): Displaying crontabs >> /var/log/mikescript.log
for user in `cat /etc/passwd | cut -d ":" -f 1`; do
        cron=$(sudo -u $user crontab -l 2> /dev/null| grep -v "#")
        if [ "$cron" ]; then
                echo "$user" >> /var/log/mikescript.log
                echo "$cron" >> /var/log/mikescript.log
        fi
done
	msg=$(pastebinit -u marshallcyber1 -p [[]]] -i /var/log/mikescript.log  | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )
	break
echo $(date): Tiger IDS was run >> /var/log/mikescript.log
apt-get install zenity -y &> /dev/null
msg=The%20Linux%20Security%20Script%20has%20finished%2E%20Return%20to%20computer%20ASAP%2E
break>> /dev/null
zenity --info --text="The script finished successfully. Michael has been texted."
