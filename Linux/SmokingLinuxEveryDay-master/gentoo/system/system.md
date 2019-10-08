### remove vlan interface created from frogger
```bash
vconfig rem eth0.100  (100 is the VLAN ID)
```

### create vlan interface
```bash
vconfig add eth0 100
```

### View files
```bash
equery files alsa-utils
```

### View use flags
```bash
emerge --info | grep ^USE
```

### View used USE flags for installed package
```bash
equery uses nmap
```

### Portage features
```bash
emerge --info | grep ^FEATURES=
```

### List all packages within a category
```bash
ls /usr/portage/xfce-extra/
```

### List all packages from an overlay
```bash
ls /var/lib/layman/pentoo/
```

### Installing a particular package version
```bash
echo "=app-emulation/virtualbox-5.0.24" > /etc/portage/package.accept_keywords/virtualbox
```

*Remove the version and the '=' to install the latest*
```

### Patching. For example systemd:

*create the respective folder and put the patch in:*
```bash
/etc/portage/patches/sys-apps/systemd-226-r2/
```

### Reverse dependencies (which packages depend on q):
```bash
equery depends openrc
```

### remove vlan interface created from frogger
```bash
vconfig rem eth0.100  (100 is the VLAN ID)
```

### create vlan interface
```bash
vconfig add eth0 100
```

### reset all configuration for an interface
```bash
ip addr flush dev eth0
```

### convert DOS to Unix files
```bash
tr -d '\015' <DOS-file >UNIX-file
```

### maybe gtk boost:
```bash
mkdir ~/.compose-cache
```



