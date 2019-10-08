### Setting the timezone

```bash
dpkg-reconfigure tzdata
```

### Synchronizing time with an NTP server

```bash
apt-get install ntpdate
ntpdate us.pool.ntp.org
```

### Set the hardware clock on your system

```bash
hwclock --systohc
```

### Ensure that your server’s clock is always accurate

```bash
apt-get install ntp
```


