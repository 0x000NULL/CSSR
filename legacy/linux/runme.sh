#!/bin/bash
# CSSR legacy Linux runner (2018-2019). Runs the bundled hardening scripts in order.
# Written for Ubuntu 16.04/16.10 and not maintained. Read legacy/README.md first, and
# use audit/linux/cssr-audit.sh on current images instead.

if [[ $EUID -ne 0 ]]
then
  echo "You must be root to run this script."
  exit 1
fi

here=$(cd "$(dirname "$0")" && pwd)

cd "$here/dofirst" || exit 1
chmod +x main.sh
./main.sh

cd "$here/nixarmor" || exit 1
chmod +x debian_harden.sh
./debian_harden.sh

cd "$here/oshardening" || exit 1
echo "Are you running 16.04 LTS, or 16.10? Y for LTS, N for 16.10"
read -r foo
if [ "$foo" = "Y" ]; then
  chmod +x ubuntu_16.04LTS.sh
  ./ubuntu_16.04LTS.sh
else
  chmod +x ubuntu_16.10.sh
  ./ubuntu_16.10.sh
fi

#### Network and kernel parameters for better security
# (The old performance-tuning block that disabled TCP SACK, IPv6 and changed buffer
# sizes and swappiness was removed: it isn't hardening and could break an image.)
# Disable core dumps of setuid programs
echo "0" > /proc/sys/fs/suid_dumpable
# Full address space layout randomization
echo "2" > /proc/sys/kernel/randomize_va_space
# Disable packet forwarding (if this machine is not a router)
echo "0" > /proc/sys/net/ipv4/ip_forward
echo "0" > /proc/sys/net/ipv4/conf/all/send_redirects
echo "0" > /proc/sys/net/ipv4/conf/default/send_redirects
# Enable tcp_syncookies to accept legitimate connections when faced with a SYN flood attack
echo "1" > /proc/sys/net/ipv4/tcp_syncookies
# Turn off IPv4 features which have few legitimate uses and are easy to abuse
echo "0" > /proc/sys/net/ipv4/conf/all/accept_source_route
echo "0" > /proc/sys/net/ipv4/conf/default/accept_source_route
echo "0" > /proc/sys/net/ipv4/conf/all/accept_redirects
echo "0" > /proc/sys/net/ipv4/conf/default/accept_redirects
echo "0" > /proc/sys/net/ipv4/conf/all/secure_redirects
echo "0" > /proc/sys/net/ipv4/conf/default/secure_redirects
# Log suspicious packets
echo "1" > /proc/sys/net/ipv4/conf/all/log_martians
# Ignore broadcast pings
echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
# Enable RFC-recommended source validation
echo "1" > /proc/sys/net/ipv4/conf/all/rp_filter
echo "1" > /proc/sys/net/ipv4/conf/default/rp_filter

clear
echo "FINISHED"
echo "Check Users and Questions!"
