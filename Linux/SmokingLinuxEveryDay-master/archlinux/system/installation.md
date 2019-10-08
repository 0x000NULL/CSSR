### System installation instructions

#### Partitioning
```bash
fdisk /dev/sda
```
* *sda1 [/boot 300MB] => Type: Linux (83) BOOTABLE flag*
* *sda2 [LVM]   => Type: Linux LVM (8E)*

#### Encryption setup
```bash
modprobe dm-crypt
cryptsetup --cipher aes-xts-plain64 --key-size 512 --hash sha512 --iter-time 5000 --use-random --verify-passphrase luksFormat /dev/sda2
cryptsetup luksOpen /dev/sda2 lvm
```

#### LVM SETUP
```bash
pvcreate /dev/mapper/lvm
vgcreate archvg /dev/mapper/lvm
lvcreate -L 8GB -n swap archvg
lvcreate -l 100%FREE -n root archvg
```

#### Filesystems
```bash
mkswap /dev/mapper/archvg-swap
swapon /dev/mapper/archvg-swap
mkfs.ext4 /dev/mapper/archvg-root
mkfs.ext2 /dev/sda1
```

#### Installation
```bash
mount /dev/mapper/archvg-root /mnt
mkdir /mnt/boot
mount /dev/sda1 /mnt/boot
pacstrap /mnt base base-devel
genfstab -p -U /mnt >> /mnt/etc/fstab
arch-chroot /mnt
```

```bash
nano /etc/locale.gen # (uncomment Greek and English)
locale-gen
echo LANG=en_US.UTF-8 > /etc/locale.conf
export LANG=en_US.UTF-8
```

```bash
ln -s /usr/share/zoneinfo/Europe/Athens /etc/localtime
echo arch > /etc/hostname
```

#### Dropbear setup
*server side:*
```bash
useradd -m -G wheel -s /bin/bash gbk
nano /etc/sudoers => uncomment: %wheel ALL=(ALL) ALL
passwd gbk
curl -O https://aur.archlinux.org/packages/dr/dropbear_initrd_encrypt/dropbear_initrd_encrypt.tar.gz
tar jxpf dropbear_initrd_encrypt.tar.gz
cd dropbear_initrd_encrypt
makepkg -si
```

*at your client machine:*
```bash
ssh-keygen -t rsa -b 4096 -C "$(whoami)@$(hostname)-$(date -I)"
ssh-copy-id -p 22 serverIP
```

*at the server again:*
```bash
cat /root/.ssh/authorized_keys > /etc/dropbear/root_key
rm /root/.ssh/authorized_keys
```

```bash
nano /etc/mkinitcpio.conf
```

* add "encrypt lvm2 shutdown" BEFORE filesystems at HOOKS array
* add "dropbear encryptssh" BEFORE filesystems at HOOKS array(replace the above encrypt with encryptssh)
* add "net" BETWEEN modconf and block at HOOKS array

```bash
mkinitcpio -p linux
```

#### GRUB
```bash
grub-install /dev/sda
vi /etc/default/grub
GRUB_CMDLINE_LINUX="cryptdevice=/dev/sda2:archvg ip=192.168.1.93::192.168.1.254:255.255.255.0::eth0:none"
```

* **WARNING**: at the above line, the IP address should be different than the static that you will assign
```bash
grub-mkconfig -o /boot/grub/grub.cfg
```

#### Cleanup
```bash
passwd
exit
umount /mnt/boot
umount /mnt/home
umount /mnt
```


