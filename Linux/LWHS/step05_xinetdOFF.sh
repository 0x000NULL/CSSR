#!/bin/bash
echo "The 'chkconfig' status of 'xinetd' is shown before it is turned off and"
echo "then after so it can visually be compared."
echo "Note: The remaining chkconfig checks, in this hardening script, do the"
echo "same thing."
/sbin/chkconfig --list    xinetd
/sbin/chkconfig --level 12345 xinetd off
/sbin/chkconfig --list    xinetd
