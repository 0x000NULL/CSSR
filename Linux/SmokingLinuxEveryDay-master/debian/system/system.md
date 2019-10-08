### Check if command is available

```bash
command -v command_name >/dev/null && return 0 || { return 1; }
```

### Log Off Idle Users

```bash
echo "" >> /etc/profile
echo "TMOUT=$user_timeout" >> /etc/profile
echo "readonly TMOUT" >> /etc/profile
echo "export TMOUT" >> /etc/profile
```

### Limit HOMEs access for new users

```bash
sed -i "s/DIR_MODE=[[:digit:]]\+/DIR_MODE=0750/" /etc/adduser.conf
```

### Configure root .bashrc

```bash
sed -i "/PS1=.*/s/^# //g" /root/.bashrc
sed -i "/umask.*022/s/^# //g" /root/.bashrc
sed -i "/alias rm=/s/^# //g" /root/.bashrc
sed -i "/alias cp=/s/^# //g" /root/.bashrc
sed -i "/alias mv=/s/^# //g" /root/.bashrc
```

### Use sudo

```bash
apt -qq -y install sudo
useradd -m myuser
groupadd wheel
usermod -aG wheel myuser
echo "%wheel  ALL=(ALL:ALL) ALL" >> /etc/sudoers
```

### Update system

```bash
apt update
apt -y full-upgrade
```

### Days since last system update (sort of)

```bash
echo $(( ( $(date -u '+%s') -  $(stat -c %Y /var/cache/apt/) )/60/60/24 ))
```

### Disable core dumps

```bash
echo "" >> /etc/sysctl.conf
echo "fs.suid_dumpable=0" >> /etc/sysctl.conf
echo "" >> /etc/security/limits.conf
echo "*     hard   core    0" >> /etc/security/limits.conf
echo "" >> /etc/profile
echo "ulimit -S -c 0 > /dev/null 2>&1" >> /etc/profile
```

### Install i386 packages

```bash
dpkg --add-architecture i386 && apt-get update 
```

### Show what archs we have installed

```bash
dpkg --print-foreign-architectures
```

### Remove all i386 packages

```bash
apt-get remove -f --purge ".*:i386"
```

### Remove i386 architecture

```bash
dpkg --remove-architecture i386 && apt-get update
```

### List dependencies of a package

```bash
apt depends {PACKAGE}
```

### List reverse dependencies

```bash
apt rdepends {PACKAGE}
```

### Change hostname

```bash
nano /etc/hostname
nano /etc/hosts
reboot now
```

