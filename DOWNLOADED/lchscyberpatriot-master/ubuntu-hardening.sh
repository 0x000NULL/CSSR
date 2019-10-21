#!/bin/bash

########################################
# cyberpatriot ubuntu hardening script
########################################

sudo apt-get install libpam-cracklib --force-yes -y
sudo apt-get update -y
sudo apt-get dist-upgrade -y

# check to see if there is a pam_tally.so line - add if absent, replace if necessary
tallyExists=$(grep pam_tally.so /etc/pam.d/common-auth|wc -l)

if [ $tallyExists -eq 0 ]; then
	sudo bash -c 'echo "auth optional pam_tally.so deny=5 unlock_time=900 onerr=fail audit even_deny_root_account silent" >> /etc/pam.d/common-auth'
else
	sudo perl -pi -e 's/.*pam_tally.so.*/auth optional pam_tally.so deny=5 unlock_time=900 onerr=fail audit even_deny_root_account silent/g' /etc/pam.d/common-auth
fi

# check to see if there is a pam_cracklib.so line - add if absent, replace if necessary
cracklibExists=$(grep pam_cracklib.so /etc/pam.d/common-password|wc -l)

if [ $cracklibExists -eq 0 ]; then
	sudo bash -c 'echo "password requisite pam_cracklib.so retry=3 minlen=8 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1" >> /etc/pam.d/common-password'
else
	sudo perl -pi -e 's/.*pam_cracklib.so.*/password requisite pam_cracklib.so retry=3 minlen=8 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1/g' /etc/pam.d/common-password
fi

# check to see if there is a pam_pwhistory.so line - add if absent, replace if necessary
historyExists=$(grep pam_pwhistory.so /etc/pam.d/common-password|wc -l)

if [ $historyExists -eq 0 ]; then
	sudo bash -c 'echo "password requisite pam_pwhistory.so use_authok remember=24 enforce_for_root" >> /etc/pam.d/common-password'
else
	sudo perl -pi -e 's/.*pam_pwhistory.so.*/password requisite pam_pwhistory.so use_authok remember=24 enforce_for_root/g' /etc/pam.d/common-password
fi

# check to see if there is a pam_unix.so line - add if absent, replace if necessary
unixExists=$(grep pam_unix.so /etc/pam.d/common-password|wc -l)

if [ $unixExists -eq 0 ]; then
	sudo bash -c 'echo "password [success=1 default=ignore] pam_unix.so obscure use_authtok sha512 shadow" >> /etc/pam.d/common-password'
else
	sudo perl -pi -e 's/.*pam_unix.so.*/password [success=1 default=ignore] pam_unix.so obscure use_authtok sha512 shadow/g' /etc/pam.d/common-password
fi

# check to see if there is a PASS_MIN_DAYS line - add if absent, replace if necessary
minDaysExists=$(cat /etc/login.defs|grep -v \#|grep PASS_MIN_DAYS|wc -l)

if [ $minDaysExists -eq 0 ]; then
	sudo bash -c 'echo "PASS_MIN_DAYS 7" >> /etc/login.defs'
else
	sudo perl -pi -e 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/g' /etc/login.defs
fi

# check to see if there is a PASS_MAX_DAYS line - add if absent, replace if necessary
maxDaysExists=$(cat /etc/login.defs|grep -v \#|grep PASS_MAX_DAYS|wc -l)

if [ $maxDaysExists -eq 0 ]; then
	sudo bash -c 'echo "PASS_MAX_DAYS 90" >> /etc/login.defs'
else
	sudo perl -pi -e 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/g' /etc/login.defs
fi

# check to see if there is a PASS_WARN_AGE line - add if absent, replace if necessary
warnAgeExists=$(cat /etc/login.defs|grep -v \#|grep PASS_WARN_AGE|wc -l)

if [ $warnAgeExists -eq 0 ]; then
	sudo bash -c 'echo "PASS_WARN_AGE 14" >> /etc/login.defs'
else
	sudo perl -pi -e 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/g' /etc/login.defs
fi

echo "########################################"
echo "# check out these ports, make sure they look non-suspicious"
echo "########################################"
netstat -an|grep LISTEN|grep -v ING
echo "########################################"
echo "# To find what process is using a port, run the following"
echo "# sudo lsof -i :<portnumber>"
echo "########################################"

echo "########################################"
echo "# check out these crontabs, make sure they look non-suspicious"
echo "########################################"
for user in $(cut -f1 -d: /etc/passwd); do echo $user; sudo crontab -u $user -l; done
echo "########################################"

echo "########################################"
echo "# check out these admins, make sure they should be administrators"
echo "########################################"
cat /etc/group|grep admin
echo "########################################"

echo "########################################"
echo "# check out these running services"
echo "########################################"
sudo service --status-all 2>&1 | grep +
echo "########################################"
echo "# to remove a serivce:"
echo "# sudo apt-get -y autoremove --purge <package>"
echo "# probably leave ssh and vmware-tools* alone"
echo "########################################"

echo "########################################"
echo "# check out /etc/passwd"
echo "########################################"
cat /etc/passwd
echo "########################################"
echo "# make sure none of the fields have plain text password in them"
echo "########################################"

echo "########################################"
echo "# if you need telnet:"
echo "remove from /etc/xinet.d/telnet:"
echo "  server_args = -L /usr/local/bin/autologin"
echo "add to /etc/xinet.d/telnet:"
echo "  only_from = 127.0.0.1 192.168.1.0/24"
echo "remove ubuntu line from /etc/issue.net"
echo "comment out all lines in /etc/update-motd.d/00-header"
echo "comment out all lines in /etc/update-motd.d/10-help-test"
echo "########################################"
