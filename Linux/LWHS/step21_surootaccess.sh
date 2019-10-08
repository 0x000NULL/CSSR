#!/bin/bash
echo "Note: With this activated, only members of the wheel group can su to root."
cd /etc/pam.d/
awk '( $1=="#auth" && $2=="required" && $3~"pam_wheel.so" ) \
     { print "auth\t\trequired\t",$3,"\tuse_uid"; next };
     { print }' /etc/pam.d-preCIS/su > /etc/pam.d/su
chown root:root /etc/pam.d/su
chmod 0644       /etc/pam.d/su
echo "diff /etc/pam.d-preCIS/su /etc/pam.d/su"
      diff /etc/pam.d-preCIS/su /etc/pam.d/su
cd $cishome
# Part 2
# The process is beneficial when using kickstart for building of systems, then
# deliberately go back to all those systems and forcefully change the
# root/SysAdmin passwords to be in new.
echo "(${AdminsComma}) are to be System Administrators for this system."
for USERID in `echo $AdminSP`
    do
       echo "1. Dealing with userid($USERID)..."
       ID=`cat /etc/passwd | cut -d: -f1 | grep $USERID 2>&1`
       if [ "$ID" != "$USERID" ]; then
          # The user-id was NOT found
          echo "2a Adding new user ($USERID) 'procedure-compliant'."
          # Use grub-md5-crypt to generate the encrypted password
          useradd -f 7 -m -p '$1$PyDA7$L81b0Sp1u.DyGnjbRUp/3/' $USERID
          chage -m 7 -M 90 -W 14 -I 7 $USERID
       else
          echo "2b User ($USERID) already in the system."
          chage -m 7 -M 90 -W 14 -I 7 $USERID
       fi
       ls -la /home
    done
echo "Doing pwck -r"
/usr/sbin/pwck -r
echo ""
# Part 3
# Perform steps to ensure any users identified in $Admins are added to the "wheel"
# group. This is probably only going to add the example 'tstuser' account, or
# whichever userID the system builder names during the initial system build.
# Note: /etc/group requires entries to be comma-separated.
if [ "$Admins" != "" ]; then
     echo "At least one AdminID has been identified to be added to the wheel
group."
     echo "Admins(${Admins}), AdminSP(${AdminSP}), AdminsComma(${AdminsComma})."
     cd /etc
     # Resultant /etc/group file is now nicely sorted as well
     /bin/cp -pf group /tmp/cis/group.tmp
     awk -F: '($1~"wheel" && $4~"root") { print $0 "," Adds }; \
               ($1 != "wheel") {print}' Adds="`echo $AdminsComma`" \
              /tmp/cis/group.tmp | sort -t: -nk 3 > /tmp/cis/group.tmp1
     chown root:root /tmp/cis/group.tmp1
     chmod 0644       /tmp/cis/group.tmp1
     /bin/cp -pf /tmp/cis/group.tmp1 group
     echo "sdiff group-preCIS group"
            sdiff group-preCIS group
     cd $cishome
else
         echo "BAD.  No SysAdmin IDs were identified to be added to the wheel
group."
fi

#
#
# Part 4
echo "#### This is done in concert with Bastille that was executed before this step in the"
echo "#### standard baseline hardening. This will add SPACE-delimited SysAdmin userIDs to"
echo "#### the /etc/security/access.conf file. These are the same names as are added to"
echo "#### the wheel group in the /etc/group file. This action prohibits any user NOT in"
echo "#### the wheel group from logging in to the system on the physical console."
echo "#### Can treat this as a known entity with one entry to deal with since the state of"
echo "#### this system up to this point is well known."
echo "#### No differences may appear, if the same users are listed here, as were added by bastille."
#    The line in question resembles the following, 3 colon-separated fields:
#    -:ALL EXCEPT root tstuser:LOCAL
#    To be turned into something that looks like the following (sorted IDs are easier to read):
#    -:ALL EXCEPT abc-Admin root def-Admin tstuser:LOCAL
#
cd /etc/security
# Check if there are any uncommented lines to ADD $Admins to.
x="`grep -v ^# access.conf | wc -l | cut -d: -f1`"
echo "x($x)"
if [ "$x" == "0" ]; then
     # Most likely the Bastille hardening hasn't been applied yet.
     # Must manually add the users, as the file is otherwise 'empty'.
     echo "Manually adding the ($Admins); none previously existed there."
     echo "-:ALL EXCEPT root" $AdminSP":LOCAL" >> access.conf
else
     # Extract just the userIDs
     x="`grep -v ^# access.conf | cut -d: -f2 | cut -d' ' -f3-`"
     # Bundle in the new SysAdmin IDs passed during script invocation, and sort the names alphabetically.
     # Need a piece here to compare what's there with what we have to add, to avoid duplicates.
     y="`echo $AdminsComma $x | tr -s ',' ' ' | tr ' ' '\012' | sort -u | tr '\012' ' '`"
     echo "x($x), y($y)"; echo ""
     # 2nd -e is to eliminate the extra space before the final colon, if one exists.
     sed -e "s/$x/$y/" -e 's/ :L/:L/' access.conf-preCIS > access.conf
     # sed "s/$x/$y/" access.conf-preCIS | sed 's/ :L/:L/' > access.conf
fi
echo "diff /etc/security/access.conf-preCIS /etc/security/access.conf"
      diff /etc/security/access.conf-preCIS /etc/security/access.conf
chown root:root /etc/security/access.conf
chmod 0640       /etc/security/access.conf
cd $cishome
chmod -R 0400 /tmp/cis/*


