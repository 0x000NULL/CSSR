### Updating dropbear ssh password

*at your client machine:*
```bash
ssh-keygen -f ~/.ssh/id_rsa -p
ssh-copy-id remote-server.org
```

*at your server:*
```bash
cat ~/.ssh/authorized_keys > /etc/dropbear/root_key
rm ~/.ssh/authorized_keys
mkinitcpio -p linux-lts
mkinitcpio -p linux
grub-mkconfig -o /boot/grub/grub.cfg
```


