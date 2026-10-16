#Root needed
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

#!/bin/bash
#Color code
blue=`tput setaf 2`
red=`tput setaf 1`
yellow=`tput setaf 3`
reset=`tput setaf 7`
mkdir OSHardeningLogs

#Intro
echo "${yellow}Welcome to OSHardening Scripts${reset}"
echo "${yellow}Github: github.com/NitescuLucian/OSHardening${reset}"
echo "${yellow}Issues: github.com/NitescuLucian/OSHardening/issues${reset}"
echo "${yellow}Licence: GNU Lesser General Public License v3.0${reset}"
echo "${yellow}Donation: paypal.me/LNitescu${reset}"
read pause

#System update date & Instalations
echo "${yellow}Would you like to update your system and tools? (y/n)${reset}"
read foo
if [ "$foo" = "y" ]; then
apt-get clean
apt-get update
apt-get upgrade -y
apt-get dist-upgrade -y
apt-get install chkrootkit
apt-get install lynis
apt-get -f install
apt-get install lynis
apt-get install rkhunter
rkhunter --update
sudo apt-get install ufw
apt-get autoremove
fi

#Authentification security
echo "${blue}Please change your password for this user!${reset}"
passwd
echo "${blue}Checking for users with no password. Log will be saved in ./OSHardeningLogs/no_password_users.txt.${reset}"
cat /etc/shadow | awk -F: '($2==""){print $1}'
cat /etc/shadow | awk -F: '($2==""){print $1}' > ./OSHardeningLogs/no_password_users.txt

#Network Security
echo "${blue}Please replace your hostname (save & close)."
gedit /etc/hostname
echo "${blue}Please redifine your host according to your new/previous hostname (save & close).${reset}"
gedit /etc/hosts
echo "${blue}Checking for all open ports. Log will be saved in ./OSHardeningLogs/open_ports_log.txt.${reset}"
netstat -tulpn
netstat -tulpn > ./OSHardeningLogs/open_ports_log.txt
echo "${yellow}Please close unwanted ports using iptables -A INPUT -p tcp --dport PORT_NUMBER -j DROP or with UFW Firewall Rules.${reset}"
echo "${blue}Checking iptables. Log will be saved in ./OSHardeningLogs/iptables_log.txt${reset}"
iptables -L -n -v > ./OSHardeningLogs/iptables_log.txt
echo "${blue}Checking local firewall status. Log will be saved in ./OSHardeningLogs/ufw_log.txt${reset}"
sudo ufw status verbose
sudo ufw status verbose > ./OSHardeningLogs/ufw_log.txt
echo "${yellow}Would you like to block all ports? (without SSH) (y/n)${reset}"
read foa
if [ "$foa" = "y" ]; then
sudo ufw allow ssh
sudo ufw enable
fi
echo "${yellow}Ignore ICMP Request ${reset}"
echo net.ipv4.icmp_echo_ignore_all = 1 >> /etc/sysctl.conf
echo "${yellow}Ignore Broadcast Request ${reset}"
echo net.ipv4.icmp_echo_ignore_broadcasts = 1 >> /etc/sysctl.conf
sysctl -p
#Preventing IP spoofing
echo "${yellow}Would you like to prevent IP spoofing? (This will reset you /etc/host.conf) (y/n)${reset}"
read foe
if [ "$foe" = "y" ]; then
echo order bind,hosts > /etc/host.conf
echo nospoof on >> /etc/host.conf
fi

#Specific System Security
echo "${yellow}Would you like to secure shared memory? Keep in mind that a reboot is required. (y/n)${reset}"
read fod
if [ "$fod" = "y" ]; then
echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" | sudo tee -a /etc/fstab
fi

#Log management
echo "${yellow}Would you like to copy all system logs in ./SystemLogs? (y/n)${reset}"
read foc
if [ "$foc" = "y" ]; then
mkdir SystemLogs
cp -a /var/log/. ./SystemLogs/
fi


#Aditional System Security Audits
echo "${blue}Running chkrootkit. Wait! Log will be saved in ./OSHardeningLogs/chkrootkit_log.txt.${reset}"
sudo chkrootkit > ./OSHardeningLogs/chkrootkit_log.txt
echo "${blue}Running lynis. Wait! Log will be saved in ./OSHardeningLogs/lynis_log.txt.${reset}"
lynis audit system -Q > ./OSHardeningLogs/lynis_log.txt
echo "${blue}Running rkhunter. Wait!${reset}"
rkhunter -c

echo "${yellow}Would you like to reboot? (y/n)${reset}"
read fob
if [ "$fob" = "y" ]; then
sudo reboot
fi
