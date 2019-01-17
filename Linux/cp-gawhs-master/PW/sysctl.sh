#This script will replace (And append) the /etc/sysctl.conf file

#Updating the entire "Database." Not sure why this is required, but lets do it anyways
updatedb
#Replacing /etc/sysctl.conf file
sudo chattr -i /etc/systl.conf
sudo chmod 777 /etc/sysctl.conf


#securing sysctl.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.send_redirects = 0" >> etc/sysctl.conf

#securing 99-sysctl.conf
echo "net.ipv4.conf.default.rp_filter=1" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.conf.all.rp_filter=1" >> /etc/sysctl.d/99-sysctl.conf

#Kernel Security
echo "kernel.kptr_restrict=2" >> /etc/sysctl.d/10-kernel-hardening.conf


sudo chmod 770 /etc/sysctl.conf
