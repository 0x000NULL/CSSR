#!/bin/bash
xyz="`tail -1 /etc/hosts.deny`"
if [ "$xyz" != "ALL: ALL" ]; then
     # Only make the change once
     echo "ALL: ALL" >> /etc/hosts.deny
fi
chown root:root /etc/hosts.deny
chmod 0644        /etc/hosts.deny
echo "diff   /etc/hosts.deny-preCIS /etc/hosts.deny"
      diff   /etc/hosts.deny-preCIS /etc/hosts.deny

#
#
# host.allow sample entires
# ASSUMTION: netmask is 255.255.255.0
#
# Change /etc/hosts.allow from:
# ALL: localhost, 192.168.50.2/255.255.255.0
# to:
# sshd : 192.168.50.4
# ALL EXCEPT sshd: localhost, 192.168.50.4/255.255.255.255

printf "ALL: localhost" >> /etc/hosts.allow
for I in `/sbin/ifconfig | grep "inet addr" | cut -f2 -d: | cut -f1-3 -d"." \
     | grep -v ^127 | sort -n`
do
     echo   "Adding (, $I) to /etc/hosts.allow."
     printf ", $I." >> /etc/hosts.allow;
done
echo >> /etc/hosts.allow
chown root:root /etc/hosts.allow
chmod 0644         /etc/hosts.allow
echo "diff /etc/hosts.allow-preCIS /etc/hosts.allow"
      diff /etc/hosts.allow-preCIS /etc/hosts.allow


