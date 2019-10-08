#!/bin/bash
ls -lad /etc/cron* /var/spool/cron*
chown root:root /etc/crontab
chmod 0400        /etc/crontab
chown -R root:root /var/spool/cron
chmod -R go-rwx       /var/spool/cron
cd /etc
ls | grep cron | grep -v preCIS | xargs chown -R root:root
ls | grep cron | grep -v preCIS | xargs chmod -R go-rwx
cd $cishome
    # What about permissions for the following:
    #   drwxr-xr-x 2 root root 4096 Aug 2 2006   /etc/cron.d
    #   drwxr-xr-x 2 root root 4096 Aug 2 2006   /etc/cron.daily
    #   -rw-r--r-- 1 root root    0 Aug 2 2006   /etc/cron.deny
    #   drwxr-xr-x 2 root root 4096 Aug 2 2006   /etc/cron.hourly
    #   drwxr-xr-x 2 root root 4096 Aug 2 2006   /etc/cron.monthly
    #   drwxr-xr-x 2 root root 4096 Aug 2 2006   /etc/cron.weekly
    #   -rw-r--r-- 1 root root 255 Dec 10 2005   /etc/crontab
echo "After..."
ls -lad /etc/cron* /var/spool/cron*
