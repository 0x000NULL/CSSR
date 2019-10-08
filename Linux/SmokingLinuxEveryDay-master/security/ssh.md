### Secure ssh access
```bash
sed -i "s/Port 22/Port 65001/g" /etc/ssh/sshd_config
sed -i "s/PermitRootLogin without-password/PermitRootLogin no/g" /etc/ssh/sshd_config
echo "" >> /etc/ssh/sshd_config
echo "AllowGroups wheel" >> /etc/ssh/sshd_config
echo "" >> /etc/ssh/sshd_config
echo "DebianBanner no" >> /etc/ssh/sshd_config
echo "Ciphers 3des-cbc,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com" >> /etc/ssh/sshd_config
echo "KexAlgorithms diffie-hellman-group1-sha1,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1" >> /etc/ssh/sshd_config
```

