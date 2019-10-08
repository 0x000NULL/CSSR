#!/bin/bash

ARCHIVE_DIR="./archive-"`hostname`;
FILESIGNATURE=$ARCHIVE_DIR/fileSignature.md5

echo -e "Checking $ARCHIVE_DIR directory...\c"
if [ ! -d $ARCHIVE_DIR ] 
    then
    echo -e "\nCreating $ARCHIVE_DIR directory...\c"
    /bin/mkdir -p $ARCHIVE_DIR || (echo -e "\nFailed to create $ARCHIVE_DIR, Exiting... "; exit 1)
fi
echo -e "\tDONE"

echo -e "\nThis scrtipt will create fingerprint DB of most essential system files"
echo "on this system. In a future, you can verify whether any of them"
echo "have been altered. You will need SUDO rights to run this script."
echo "------------------------------"
echo "Press [C]reate fingerpint DB of system files, or "
echo "Press [V]erify them against most recent DB" 

read -n1 -s keyenter

if [[ $keyenter == 'C' || $keyenter == 'c' ]]
then

    echo -e "Creating fingerprint DB... \c"
    
    [ -f $FILESINGATURE ] && /bin/mv -f $FILESIGNATURE $FILESIGNATURE".BCK"

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
	/etc/X11/xdm/kdmrc \
        /etc/xinetd.d/* \
        /etc/rc.d/* \
        /etc/pam.d/* ;
      do
      if [ -f ${FILE} ]; then 
      # 
	  PATH=`/usr/bin/dirname $FILE`
	  if [ ! -d $ARCHIVE_DIR$PATH ] 
	      then
	      /bin/mkdir -p $ARCHIVE_DIR$PATH
	  fi

	  /usr/bin/sudo /bin/cp $FILE $ARCHIVE_DIR$FILE
	  /usr/bin/sudo /usr/bin/md5sum $FILE >> $FILESIGNATURE
      fi
    done
    echo "DONE"
elif [[ $keyenter == 'V' || $keyenter == 'v' ]]
then
    echo -e "Verifying system files against most recent fingerprint DB...\n"
    sudo /usr/bin/md5sum -cw $FILESIGNATURE
    echo -e "\n... DONE"
else
    echo -e "\nYou've pressed a wrong key:" $keyenter "... exiting"
fi

