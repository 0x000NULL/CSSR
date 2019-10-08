#!/bin/bash
sed 's/022/027/'  /etc/rc.d-preCIS/init.d/functions > /etc/rc.d/init.d/functions
echo "umask 027"  >> /etc/sysconfig/init
chown root:root   /etc/sysconfig/init
chmod 0755        /etc/sysconfig/init
echo "diff /etc/sysconfig/init-preCIS  /etc/sysconfig/init"
      diff /etc/sysconfig/init-preCIS  /etc/sysconfig/init

