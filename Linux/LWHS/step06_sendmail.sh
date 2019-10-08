#!/bin/bash 
# Uncomment these lines if you DO need sendmail running
#cd /etc/sysconfig
#cp -pf sendmail-preCIS sendmail
#chown root:root sendmail
#chmod 0644 sendmail
#
#
# Comment the following lines if sendmail needed
echo "DAEMON=no" > /etc/sysconfig/sendmail
echo "QUEUE=1h" >> /etc/sysconfig/sendmail
/sbin/chkconfig --list    sendmail
/sbin/chkconfig --level 12345 sendmail off
/sbin/chkconfig --list    sendmail
chown root:root     /etc/sysconfig/sendmail
chmod 0644          /etc/sysconfig/sendmail
echo "diff /etc/sysconfig/sendmail-preCIS /etc/sysconfig/sendmail"
      diff /etc/sysconfig/sendmail-preCIS /etc/sysconfig/sendmail
