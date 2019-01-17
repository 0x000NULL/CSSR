#This script will secure samba

#This will overwrite the contents inside /etc/samba/smb.conf
sudo updatedb
chattr -i /etc/samba/smb.conf
chmod 777 /etc/samba/smb.conf
sudo cp -TRv samba_mod.conf /etc/samba/smb.conf
systemctl restart samba.service
sudo service samba restart
chmod 770 /etc/samba/smb.conf

