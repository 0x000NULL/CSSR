#!/bin/bash

unalias cp rm mv
SSH_CONFIG='/etc/ssh/ssh_config'
SSHD_CONFIG='/etc/ssh/sshd_config'
if [ -e $SSH_CONFIG ]; then
   echo "Securing $SSH_CONFIG"
   grep -v "^Host \*" /etc/ssh/ssh_config-preCIS | grep -v "#     Protocol 2,1" \
            > /tmp/cis/ssh_config.tmp
   awk '/^#.* Host /                { print "Host *"; print "Protocol 2"; next };
         /^#.*Port /                { print "Port 22"; next };
         /^#.*PubkeyAuthentication/ { print "PubkeyAuthentication yes"; next };
                                    { print }' /tmp/cis/ssh_config.tmp \
                                              > /tmp/cis/ssh_config.tmp2
   if [ "`egrep -l ^Protocol /tmp/cis/ssh_config.tmp2`" == "" ]; then
         echo 'Protocol 2' >> /tmp/cis/ssh_config.tmp2
   fi
   /bin/cp -pf /tmp/cis/ssh_config.tmp2 $SSH_CONFIG
   chown root:root $SSH_CONFIG
   chmod 0644        $SSH_CONFIG
   echo "diff $SSH_CONFIG-preCIS $SSH_CONFIG"
          diff $SSH_CONFIG-preCIS $SSH_CONFIG
else
   echo "OK - No $SSH_CONFIG to secure."
fi
if [ -e $SSHD_CONFIG ]; then
   echo "Securing $SSHD_CONFIG"
   # Had to put the " no" in for the RhostsRSAAuthentication source pattern
   # match, as otherwise the change was taking place twice so the file ended
   # up with TWO records like that. The " no" pattern made the one unique.
   # That 2nd record was a combination of comments in the original file.
   # Some lines ARE duplicated in the original config file, one is commented
   # out, the next one isn't.
   # Also, the spacing below is a little off so lines fit on the page.
   awk '/^#.*Port /                      { print "Port 22"; next };
         /^#.*Protocol /                 { print "Protocol 2"; next };
         /^#.*LogLevel /                 { print "LogLevel VERBOSE"; next };
         /^#PermitRootLogin /            { print "PermitRootLogin no"; next };
         /^#RhostsRSAAuthentication no / { print "RhostsRSAAuthentication no"; next };
         /^#HostbasedAuthentication / { print "HostbasedAuthentication no"; next };
         /^#.*IgnoreRhosts /             { print "IgnoreRhosts yes"; next };
         /^#.*PasswordAuthentication / { print "PasswordAuthentication no"; next };
         /^#.*PermitEmptyPasswords /     { print "PermitEmptyPasswords no"; next };
         /^PasswordAuthentication yes/   { next };
         /^#.*Banner /                   { print "Banner /etc/issue.net"; next };
                                        { print }' /etc/ssh/sshd_config-preCIS  > $SSHD_CONFIG
   chown root:root $SSHD_CONFIG
   chmod 0600      $SSHD_CONFIG
   echo "diff $SSHD_CONFIG-preCIS $SSHD_CONFIG"
         diff $SSHD_CONFIG-preCIS $SSHD_CONFIG
else
   echo "OK - No $SSHD_CONFIG to secure."
fi
chmod -R 0400 /tmp/cis/*
unset SSH_CONFIG SSHD_CONFIG CONFIGITEM

