### cryptsetup setup LUKS etc
```bash
dd if=/dev/zero of=/dev/sdX iflag=nocache oflag=direct bs=4096
```

```bash
fdisk /dev/sdX
```

```bash
cryptsetup -v -y -c aes-xts-plain64 -s 512 -h sha512 -i 5000 --use-random luksFormat /dev/sdX1
```

```bash
cryptsetup luksHeaderBackup --header-backup-file /path/to/file.img /dev/sdX1
```

```bash
cryptsetup luksOpen /dev/sdX1 external01
```

```bash
mkfs.ext4 /dev/mapper/external01
```

```bash
mount /dev/mapper/external01 /mnt/external
```

```bash
umount /mnt/external
```

```bash
cryptsetup luksClose /dev/mapper/external01
```

### cryptestup quick mounting
```bash
cryptsetup luksOpen /dev/sdX1 external01
```

```bash
mount /dev/mapper/external01 /mnt/external
```

*DO YOUR WORK HERE*

```bash
umount /mnt/external
```

```bash
cryptsetup luksClose /dev/mapper/external01
```

### add/remove cryptestup keys luks password
```bash
cryptsetup luksDump /dev/<device> |grep BLED
```

```bash
cryptsetup luksAddKey /dev/<device>
```

```bash
cryptsetup luksChangeKey /dev/<device> -S 6
```

```bash
cryptsetup luksRemoveKey /dev/<device>
```

```bash
cryptsetup luksKillSlot /dev/<device> 6
```



