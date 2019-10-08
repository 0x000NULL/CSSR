#!/bin/bash

ROOT_DIR="/root"

# Create $ROOT_DIR/do-restore.sh
echo -e "Creating do-restore.sh file in $ROOT_DIR...\c"
cat <<EOF > $ROOT_DIR/do-restore.sh
#!/bin/bash

# This script restores the files changed by the CISecurity 
# Linux Benchmark do-backup.sh script. 
unalias rm mv cp

sed -n "31,9999p" $ROOT_DIR/do-restore.sh | while read LINE; do
    FILE=\`echo \$LINE | awk '{print \$1}'\`
    PERMS=\`echo \$LINE | awk '{print \$2}'\`
    echo "Restoring \$FILE with \$PERMS permissions"
    [ -f \${FILE}-preCIS ] && /bin/cp -p \${FILE}-preCIS \${FILE}
    /bin/chmod \${PERMS} \${FILE}
    [ -f \${FILE}-preCIS ] && /bin/rm \${FILE}-preCIS
done

echo "Completed file restoration - restoring directories"
for DIR in \
    /etc/xinetd.d    /etc/rc.d \
    /var/spool/cron  /etc/cron.* \
    /etc/pam.d       /etc/skel
do
    if [ -d \${DIR}-preCIS ]; then
        echo "Restoring \${DIR}"
        /bin/cp -pr \${DIR}-preCIS \${DIR}
        /bin/rm -rf \${DIR}-preCIS
    fi
done

echo "If you installed Bastille, please run "
echo "/usr/sbin/RevertBastille and examine its list of changed files."
exit 0

### END OF SCRIPT.  DYNAMIC DATA FOLLOWS. ###
EOF
/bin/chmod 0700 $ROOT_DIR/do-restore.sh
echo -e "\tDONE"

echo -e "Backing up individual files...\c"

for FILE in \
/etc/ssh/ssh_config \
/etc/ssh/sshd_config \
/etc/hosts.deny \
/etc/hosts.allow \
/etc/init.d/functions \
/etc/sysconfig/init \
/etc/sysconfig/sendmail \
/etc/inittab \
/etc/sysctl.conf \
/etc/syslog.conf \
/etc/ftpaccess \
/etc/vsftpd.conf \
/etc/vsftpd/vsftpd.conf \
/etc/syslog.conf \
/etc/fstab \
/etc/security/console.perms \
/etc/security/access.conf \
/etc/passwd \
/etc/shadow \
/etc/ftpusers \
/etc/vsftpd.ftpusers \
/etc/X11/xdm/Xservers \
/etc/X11/gdm/gdm.conf \
/etc/X11/xinit/xserverrc \
/etc/cron.deny \
/etc/at.deny \
/etc/crontab \
/etc/securetty \
/etc/lilo.conf \
/etc/grub.conf \
/etc/exports \
/etc/sudoers \
/etc/init.d/syslog \
/etc/profile \
/etc/csh.login \
/etc/csh.cshrc \
/etc/bashrc \
$ROOT_DIR/.bash_profile \
$ROOT_DIR/.bashrc \
$ROOT_DIR/.cshrc \
$ROOT_DIR/.tcshrc \
/etc/security/limits.conf \
/etc/issue \
/etc/motd \
/etc/issue.net \
/etc/X11/xdm/Xresources \
/etc/X11/xdm/kdmrc; do
    if [ -f ${FILE} ]; then 
        # Backup file
        /bin/cp -fup ${FILE} ${FILE}-preCIS
        # Add it to the do-restore script
        echo ${FILE} `find ${FILE} -printf "%m"` >> $ROOT_DIR/do-restore.sh
    fi
done

echo -e "\tDONE"
echo -e "Backing up directories...\c"
for DIR in \
    /etc/xinetd.d    /etc/rc.d \
    /var/spool/cron  /etc/cron.* \
    /etc/pam.d       /etc/skel
do 
  if [[ ${DIR} != *preCIS ]]; then
      [ -d ${DIR} ] && /bin/cp -pufr ${DIR} ${DIR}-preCIS
  fi
done
echo -e "\tDONE"

echo -e "Recording log permissions...\c"
find /var/log -printf "%h/%f %m\n" >> $ROOT_DIR/do-restore.sh
echo -e "\tDONE"
echo "Backup complete."

