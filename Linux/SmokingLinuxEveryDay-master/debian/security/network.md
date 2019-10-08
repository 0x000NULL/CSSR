### Secure network in sysctl.conf file
```bash
sed -i "/net\.ipv4\.conf\.default\.rp_filter=.*/s/^#//g" /etc/sysctl.conf
sed -i "/net\.ipv4\.conf\.all\.rp_filter=.*/s/^#//g" /etc/sysctl.conf
sed -i "/net\.ipv4\.tcp_syncookies=.*/s/^#//g" /etc/sysctl.conf
sed -i "s/^#net\.ipv4\.ip_forward=1$/net\.ipv4\.ip_forward=0/g" /etc/sysctl.conf
sed -i "/net\.ipv4\.conf\.all\.accept_redirects.*=.*/s/^#//g" /etc/sysctl.conf
sed -i "/net\.ipv4\.conf\.all\.send_redirects.*=.*/s/^#//g" /etc/sysctl.conf
sed -i "/net\.ipv4\.conf\.all\.accept_source_route.*=.*/s/^#//g" /etc/sysctl.conf
sed -i "/net\.ipv4\.conf\.all\.log_martians.*=.*/s/^#//g" /etc/sysctl.conf
```

