#!/bin/bash
#echo "Some errors MAY appear here for directories, logs and/or files not installed on this system."
cd /var/log
# Part 1
echo "Extra---Ensure the btmp log file for 'lastb' is in place and with proper"
echo "         permissions. This satisfies DISA SRR (GEN000440)"
touch /var/log/btmp
chown root:root /var/log/btmp
chmod 0600        /var/log/btmp
echo "Before listing of the log directory [explicit]."
ls -la /var/log
# Part 2
echo "LogPerms Part 1."
for LogFile in \
    boot.log          \
    btmp              \
    cron              \
    dmesg             \
    ksyms             \
    httpd             \
    lastlog           \
    maillog           \
    mailman           \
    messages          \
    news              \
    pgsql             \
    rpmpkgs           \
    sa                \
    samba             \
    scrollkeeper.log \
    secure            \
    spooler           \
    squid             \
    vbox              \
    wtmp
do
    # This check allows only entries that exist to have permissions set.
    # Visually cleaner for the person running it.
    if [ -e ${LogFile} ]; then
          # Utilizing recursive here is harmless when applied to a single file.
           chmod -R  o-rwx  ${LogFile}*
     else
           echo "LogFile didn't exist ($LogFile)."
     fi
done
echo "LogPerms Part 2."
for LogFile in \
     boot.log            \
     cron                \
     dmesg               \
     gdm                 \
     httpd               \
     ksyms               \
     lastlog             \
     maillog             \
     mailman             \
     messages            \
     news                \
     pgsql               \
     rpmpkgs             \
     samba               \
     sa                  \
     scrollkeeper.log \
     secure              \
     spooler             \
     squid               \
     vbox
do
     if [ -e ${LogFile} ]; then
           chmod -R g-w ${LogFile}*
     else
           echo "LogFile didn't exist ($LogFile)."
     fi
done
echo "LogPerms Part 3."
for LogFile in \
     boot.log          \
     cron              \
     httpd             \
     lastlog           \
     maillog           \
     mailman           \
     messages          \
     pgsql             \
     sa                \
     samba             \
     secure            \
     spooler
do
     if [ -e ${LogFile} ]; then
           chmod -R g-rx ${LogFile}*
     else
           echo "LogFile didn't exist ($LogFile)."
     fi
done
echo "LogPerms Part 4."
for LogFile in \
     gdm         \
     httpd       \
     news        \
     samba       \
     squid       \
     sa          \
     vbox
do
     if [ -e ${LogFile} ]; then
           chmod -R o-w ${LogFile}*
     else
           echo "LogFile didn't exist ($LogFile)."
     fi
done
echo "LogPerms Part 5."
for LogFile in \
     httpd       \
     samba       \
     squid       \
     sa
do
     if [ -e ${LogFile} ]; then
           chmod -R o-rx ${LogFile}*
     else
           echo "LogFile didn't exist ($LogFile)."
     fi
done
echo "LogPerms Part 6."
for LogFile in \
     kernel      \
     lastlog     \
     mailman     \
     syslog      \
     loginlog
do
     if [ -e ${LogFile} ]; then
           chmod -R u-x ${LogFile}*
     else
           echo "LogFile didn't exist ($LogFile)."
     fi
done
echo "LogPerms Part 7."
# Removing group write permissions to btmp and wtmp
chgrp utmp btmp
chmod g-w btmp
chgrp utmp wtmp
chmod g-w wtmp
# Fixing "/etc/rc.d/rc.sysinit", as it unsecures permissions for wtmp.
awk '( $1 == "chmod" && $2 == "0664" && $3 == "/var/run/utmp" && $4 == "/var/log/wtmp" ) {
	       print "chmod 0600 /var/run/utmp /var/log/wtmp"; next }; 
      ( $1 == "chmod" && $2 == "0664" && $3 == "/var/run/utmpx" && $4 == "/var/log/wtmpx" ) {
         print " chmod 0600 /var/run/utmpx /var/log/wtmpx"; next };
      { print }' /etc/rc.d-preCIS/rc.sysinit > /etc/rc.d/rc.sysinit
chown root:root /etc/rc.d/rc.sysinit
chmod 0700       /etc/rc.d/rc.sysinit
echo "diff /etc/rc.d-preCIS/rc.sysinit /etc/rc.d/rc.sysinit"
      diff /etc/rc.d-preCIS/rc.sysinit /etc/rc.d/rc.sysinit
echo "LogPerms Part 8."
[ -e news ]     && chown -R news:news news
[ -e pgsql ]    && chown postgres:postgres pgsql
[ -e squid ]    && chown -R squid:squid squid
[ -e lastlog ] && chmod  0600 lastlog
chown -R root:root .
echo ""
echo "Follow-on listing of the log directory [explicit]."
ls -la /var/log
