#!/bin/bash
echo " When doing this from within Xwindows the display will slow to a horrible"
echo " crawl as soon as the xfs service is disabled. Recommend doing this"
echo " script from init 3 (runlevel 3)."
# From a scripted perspective, this will be backwards from what the CIS Benchmark
# recommends. Philosophy is to leave the few known/necessary services on, that
# do remain in the minimialized baseline, and then as each other step/procedure
# below is covered, it will disable what we know we don't need for a secure and
# hardened baseline.
#
# The following services ARE stopped/disabled using the following effort for the
# baseline:
#
# This affects network/NFS mapping during system building and/or during kickstart
# %post processing.
#     autofs
#     automount
#     iptables
#     portmap
#     NFS services
#     NFS statd
#     system message bus
# ** Warning** Disabling 'nfs' at this point in the script forcefully unmounts
#               any NFS network mounts.
# The following services should normally be enabled, unless there is a compelling
# reason not to: (which is why this hardening section does not alter their state)
   for SERVICE in                 \
       acpid                      \
       amd                        \
       anacron                    \
       apmd                       \
       arpwatch                   \
       atd                        \
       autofs                     \
       avahi-daemon               \
       avahi-dnsconfd             \
       bpgd                       \
       bluetooth                  \
       bootparamd                 \
       capi                       \
       conman                     \
       cups                       \
       cyrus-imapd                \
       dc_client                  \
       dc_server                  \
      dhcdbd                     \
      dhcp6s                     \
       dhcpd                      \
       dhcrelay                   \
       dovecot                    \
       dund                       \
       firstboot                  \
       gpm                        \
       haldaemon                  \
       hidd                       \
       hplip           \
       httpd           \
       ibmasm          \
       ip6tables       \
       ipmi            \
       irda            \
       iscsi           \
       iscsid          \
       isdn            \
       kadmin          \
       kdump           \
       kprop           \
       krb524          \
       krb5kdc         \
       kudzu           \
       ldap            \
       lisa            \
       lm_sensors      \
       mailman         \
       mcstrans        \
       mdmonitor       \
       mdmpd           \
       microcode_ctl   \
       multipathd      \
       mysqld          \
       named           \
       netplugd        \
       nfs             \
       nfslock         \
       nscd            \
       ntpd            \
       openibd         \
       ospf6d          \
       ospfd           \
       pand            \
       pcscd           \
       portmap         \
       postgresql      \
       privoxy         \
       psacct          \
       radvd           \
       rarpd           \
       rdisc           \
       readahead_early \
       readahead_later \
       rhnsd           \
       ripd            \
       ripngd          \
       rpcgssd         \
       rpcidmapd       \
       rpcsvcgssd      \
       rstatd          \
       rusersd         \
       rwhod           \
       saslauthd       \
       sendmail        \
     setroubleshoot             \
     smartd                     \
     smb                        \
     snmpd                      \
     snmptrapd                  \
     spamassassin               \
     squid                      \
     tog-pegasus                \
     tomcat5                    \
     tux                        \
     winbind                    \
     wine                       \
     wpa_supplicant             \
     xend                       \
     xendomains                 \
     xinetd                     \
     ypbind                     \
     yppasswdd                  \
     ypserv                     \
     ypxfrd                     \
     yum-updatesd               \
     zebra;
do
      if [ -e /etc/init.d/$SERVICE ]; then
            # Doing business this way causes less needless errors that a
            # reviewer of the hardening process doesn't need to deal with.
            /sbin/service $SERVICE stop
            /sbin/chkconfig --level 12345 $SERVICE off
      else
            echo "SERVICE doesn't exist on this system ($SERVICE)."
      fi
done
