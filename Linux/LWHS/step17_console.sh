#!/bin/bash
echo console > /etc/securetty
# These are acceptable for the GUI and runlevel 3, when trimmed down to 6
for i in `seq 1 6`; do
      echo vc/$i >> /etc/securetty
done
#
#### Commented this out to be more secure as it denies root logins to the physical TEXT console.
#### Additionally, disabling this is in compliance with the DISA STIG, as well.
#     Check pg 14 in Hardening Linux for additional safety in the /etc/inittab file.
# Do we want this as a required argument submitted on the command line?
#
#for i in `seq 1 6`; do
#        echo tty$i >> /etc/securetty
#done
chown root:root /etc/securetty
chmod 0400         /etc/securetty
echo "diff /etc/securetty-preCIS /etc/securetty"
       diff /etc/securetty-preCIS /etc/securetty
# Part 2
# Second modification of gdm.conf, if it exists.
if [ -e /etc/X11/gdm/gdm.conf ]; then
      #### There is another file to consider: "/etc/X11/gdm/gdm.conf"
      # "AllowRoot=true" should be set to false to prevent root from logging in to the gdm GUI.
      # "AllowRemoteRoot=true" should be set to false to prevent root logins from remote systems.
      # Doing this change is supportive of logging in as a regular user and using 'su' to get to root.
      # Before allowing a reboot, ensure at least one account is created for a SysAdmin type.
      cd /etc/X11/gdm
      /bin/cp -pf gdm.conf /tmp/cis/gdm.conf.tmp
      sed -e 's/AllowRoot=true/AllowRoot=false/'             \
          -e 's/AllowRemoteRoot=true/AllowRemoteRoot=false/' \
          -e 's/^#Use24Clock=false/Use24Clock=true/' /tmp/cis/gdm.conf.tmp > gdm.conf
      chown root:root gdm.conf
      chmod 0644      gdm.conf
      echo "diff gdm.conf-preCIS gdm.conf"
            diff gdm.conf-preCIS gdm.conf
      cd $cishome
else
     echo "No /etc/X11/gdm/gdm.conf file to further secure."
fi
# Part 3
echo "The following is only required when a serial console is used for this server."
echo "Either of these would be added manually post-baseline compliance, depending"
echo "on the COM port the serial cable is physically attached to."
echo "#     echo ttyS0 >> /etc/securetty"
echo "#     echo ttyS1 >> /etc/securetty"
chmod -R 0400 /tmp/cis/*
