#!/bin/bash
for SERVICE in    \
    amanda        \
    chargen       \
    chargen-udp   \
    cups          \
    cups-lpd      \
    daytime       \
    daytime-udp   \
    echo          \
    echo-udp      \
    eklogin       \
    ekrb5-telnet  \
    finger        \
    gssftp        \
    imap          \
    imaps         \
    ipop2         \
    ipop3         \
    klogin        \
    krb5-telnet   \
    kshell        \
    ktalk         \
    ntalk         \
    rexec         \
    rlogin        \
    rsh           \
    rsync         \
    talk          \
    tcpmux-server \
    telnet        \
    tftp          \
    time-dgram    \
    time-stream   \
    uucp;
do
     if [ -e /etc/xinetd.d/$SERVICE ]; then
           echo "Disabling SERVICE($SERVICE) - `ls -la /etc/xinetd.d/$SERVICE`."
           /sbin/chkconfig ${SERVICE} off
     else
           echo "OK. SERVICE doesn't exist on this system ($SERVICE)."
     fi
done
