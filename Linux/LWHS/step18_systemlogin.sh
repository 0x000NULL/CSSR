#!/bin/bash
# In the book "Hardening Linux", pg 20, it says using "/dev/null" is bad.
echo "Basically change the '/sbin/nologin' portion to '/dev/null' in /etc/passwd"
echo " and add an exclamation point to the password field in /etc/shadow."
cd /etc
for NAME in `cut -d: -f1 /etc/passwd`; do
     MyUID=`id -u $NAME`
     if [ $MyUID -lt 500 -a $NAME != 'root' ]; then
         /usr/sbin/usermod -L -s /dev/null $NAME
     fi
done
ls -la /etc/passwd
echo "sdiff passwd-preCIS passwd"
echo "--------------------------"
chown root:root /etc/passwd
chmod 0644      /etc/passwd
sdiff passwd-preCIS passwd
ls -la /etc/shadow
echo "sdiff shadow-preCIS shadow"
echo "--------------------------"
chown root:root /etc/shadow
chmod 0400       /etc/shadow
sdiff shadow-preCIS shadow
cd $cishome
