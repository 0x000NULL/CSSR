#!/bin/bash
#
# Perform hardening operations for Fedora distributions
#####################
# Author : Emir Ozer
# Creation Date: 13 Jan 2015
#####################
echo -n "I do not claim any responsibility for your use of this script."

sys_upgrades() {
    yum -y update
    yum -y upgrade
    yum -y autoremove
}

unattended_upg() {
    # IMPORTANT - Unattended upgrades may cause issues
    # But it is known that the benefits are far more than
    # downsides
    yum -y install yum-cron
    chkconfig --level 345 yum-cron on
    service yum-cron start
}

disable_root() {
    passwd -l root
    # for any reason if you need to re-enable it:
    # sudo passwd -l root
}

user_pass_expirations() {
    # Passwords will expire every 180 days
    perl -npe 's/PASS_MAX_DAYS\s+99999/PASS_MAX_DAYS 180/' -i /etc/login.defs
    # Passwords may only be changed once a day
    perl -npe 's/PASS_MIN_DAYS\s+0/PASS_MIN_DAYS 1/g' -i /etc/login.defs
}

harden_ssh(){
    sudo sh -c 'echo "PermitRootLogin no" >> /etc/ssh/sshd_config'
}

set_chkrootkit() {
    # check the github page for cronning this task
    yum -y install chkrootkit
    chkrootkit
}

logwatch_reporter() {
    yum -y install logwatch
    # make it run weekly
    mv /etc/cron.daily/0logwatch /etc/cron.weekly/    
}

remove_atd() {
    yum -y remove at
    # less layers equals more security
}

disable_ipv6() {
    sysctl -w net.ipv6.conf.default.disable_ipv6=1
    sysctl -w net.ipv6.conf.all.disable_ipv6=1
}

permission_narrowing() {
    chmod 700 /root
    chmod 700 /var/log/audit
    chmod 740 /etc/rc.d/init.d/iptables
    chmod 740 /sbin/iptables
    chmod –R 700 /etc/skel
    chmod 600 /etc/rsyslog.conf
    chmod 640 /etc/security/access.conf
    chmod 600 /etc/sysctl.conf
}

disable_avahi(){
    systemctl stop avahi-daemon.socket avahi-daemon.service
    systemctl disable avahi-daemon.socket avahi-daemon.service
}

disable_postfix() {
    systemctl stop postfix
    systemctl disable postfix
}

kernel_tuning() {
    sysctl kernel.randomize_va_space=1
    
    # Enable IP spoofing protection
    sysctl net.ipv4.conf.all.rp_filter=1

    # Disable IP source routing
    sysctl net.ipv4.conf.all.accept_source_route=0
    
    # Ignoring broadcasts request
    sysctl net.ipv4.icmp_echo_ignore_broadcasts=1
    sysctl net.ipv4.icmp_ignore_bogus_error_messages=1
    
    # Make sure spoofed packets get logged
    sysctl net.ipv4.conf.all.log_martians=1
    sysctl net.ipv4.conf.default.log_martians=1

    # Disable ICMP routing redirects
    sysctl -w net.ipv4.conf.all.accept_redirects=0
    sysctl -w net.ipv6.conf.all.accept_redirects=0
    sysctl -w net.ipv4.conf.all.send_redirects=0
    sysctl -w net.ipv6.conf.all.send_redirects=0

    # Disables the magic-sysrq key
    sysctl kernel.sysrq=0
    
    # Turn off the tcp_timestamps
    sysctl net.ipv4.tcp_timestamps=0

    # Enable TCP SYN Cookie Protection
    sysctl net.ipv4.tcp_syncookies=1

    # Enable bad error message Protection
    sysctl net.ipv4.icmp_ignore_bogus_error_responses=1
    
    # RELOAD WITH NEW SETTINGS
    sysctl -p
}

main() {
    sys_upgrades
    unattended_upg
    disable_root
    user_pass_expirations
    harden_ssh
    set_chkrootkit
    logwatch_reporter
    remove_atd
    permission_narrowing
    disable_avahi
    disable_postfix
    kernel_tuning
}

main "$@"
