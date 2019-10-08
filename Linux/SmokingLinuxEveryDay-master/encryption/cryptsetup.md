## cryptsetup

### Get cryptsetup device information

```bash
cryptsetup -v status /dev/mapper/sda5_crypt
```


### Encrypting a second hard drive

* Open GParted and delete all partitions on the disk you want to encrypt.
* Encrypt the partition:

```
sudo cryptsetup -y -v luksFormat /dev/sda
```

* Decrypt the new partition so that you can format it with ext4:

```
sudo cryptsetup luksOpen /dev/sda sda_crypt
sudo mkfs.ext4 /dev/mapper/sda_crypt
```

* Mount your new encrypted partition:

```
sudo mount /dev/mapper/sda_crypt /<mount-point>
```

* Automatically mount and decrypt your second drive on startup:

```
sudo dd if=/dev/urandom of=/root/.keyfile bs=1024 count=4
sudo chmod 0400 /root/.keyfile
sudo cryptsetup luksAddKey /dev/sda /root/.keyfile
```

* Add the following line to /etc/crypttab to automatically use it to unlock the partition on startup:

```
sda_crypt UUID=<device UUID> /root/.keyfile luks,discard
```

* To get your parition’s UUID:

```
sudo blkid
```

The value you want is the UUID of /dev/sda, not dev/mapper/sda_crypt. Also make sure to copy the UUID, not the PARTUUID.

* Add this line to /etc/fstab to actually mount the partition on startup:

```
/dev/mapper/sda_crypt  /<mount-point>   ext4    defaults        0       2
```

* Change Owner:

```
sudo chown <user>:<user> /<mount-point> -R
```
