#!/bin/bash
# The /etc/sudoers file contains one line that can be uncommented out to suitably
# permit SysAdmins with membership in the wheel group (i.e. the same ones who
# 'could' su to root) to utilize 'sudo' instead. Note: file consists of TABs
# between fields. 'visudo' IS the proper command to manually change this file,
# yet the change below passes muster when visudo is next executed.
echo "Implementing permissions for members of the wheel group to utilize sudo;"
echo "This prevents any user from having to 'su' to root for common"
echo "administrative tasks. Ideally now the root password would be changed to"
echo "something very few would know (hint!)."
sed 's/# %wheel   ALL=(ALL)   NOPASSWD: ALL/%wheel    ALL=(ALL)    NOPASSWD: ALL/' \
     /etc/sudoers-preCIS > /etc/sudoers
chown root:root /etc/sudoers
chmod 0440       /etc/sudoers
echo "diff /etc/sudoers-preCIS /etc/sudoers"
      diff /etc/sudoers-preCIS /etc/sudoers
echo  "More specifically, system owners are strongly encouraged to more tightly"
echo  "restrict who can utilize sudo on a name by name basis (explicitly) as well"
echo  "as further restrict what commands those SysAdmins are limited to using."
echo  "Align this with least-privilege."
