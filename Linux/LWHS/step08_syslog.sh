#!/bin/bash
#
if [ `grep -v '^#' /etc/syslog.conf | grep -c 'authpriv'` -eq 0 ]; then
       echo "Established the following record in /etc/syslog.conf"
       echo "authpriv.*\t\t\t\t/var/log/secure"
       echo -e "authpriv.*\t\t\t\t/var/log/secure" >> /etc/syslog.conf
else
       echo "syslog OK. Didn't have to change syslog.conf for authpriv; the"
       echo "following record is good:"
       grep "^authpriv" /etc/syslog.conf | grep '/var/log/secure'
fi
# Add record for 'auth.*', too, placing it after the authpriv record
if [ `grep -v '^#' /etc/syslog.conf | grep -c 'auth.\*'` -eq 0 ]; then
     ed /etc/syslog.conf <<END_SCRIPT
1
/^authpriv
a
auth.*                                           /var/log/messages
.
w
q
END_SCRIPT
else
       echo "syslog OK. Didn't have to change syslog.conf for auth.*; the"
       echo "following record is good:"
       grep 'auth.\*' /etc/syslog.conf
fi

chown root:root /etc/syslog.conf
# Original/default permissions are 0644.
chmod 0600       /etc/syslog.conf
echo "diff /etc/syslog.conf-preCIS /etc/syslog.conf"
      diff /etc/syslog.conf-preCIS /etc/syslog.conf

# Create the log file if it doesn't already exist.
touch /var/log/secure
chown root:root /var/log/secure
chmod 0600      /var/log/secure
echo "Restarting syslog service to immediately implement the latest configuration."
/sbin/service syslog stop
/sbin/service syslog start
