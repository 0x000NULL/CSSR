### What package owns a command/package?
```bash
pacman -Qo /bin/pkgname
```

### Get what packages have been installed from a specific repo (e.g. multilib, core)
```bash
paclist multilib
```

### Maintenance commands 

#### Orphaned
```bash
pacman -Rsn `pacman -Qqdt`
```

#### Clear uninstalled program's cache
```bash
pacman -Sc
```

#### Optimize pacman db
```bash
pacman-optimize
```

#### Find missing files from packages
```bash
pacman -Qk
```

### List all installed packages with size
```bash
pacman -Qi | awk '/^Name/ {pkg=$3} /Size/ {print $4$5,pkg}' | sort -n
```

### Listing changed configuration files
```bash
pacman -Qii | awk '/^MODIFIED/ {print $2}'
```

### Installed packages from official repositories
```bash
pacman -Qqe | grep -vx "$(pacman -Qqm)" > installed_from_off
```

### Installed packages from AUR
```bash
pacman -Qqm > installed_from_aur 
```

### Re-install all packages from official repos
```bash
xargs -a installed_from_off pacman -S --needed
```

### If you mess up with "rm -rf"

#### If your system does not contain AUR to re-install everything
```bash
pacman -Qeq | pacman -S -
```

#### You should run both of these
```bash
pacman -Qdq | pacman -S --asdeps -
```

### System Setup Info - Utilities
```bash
pacman -S openssh htop linux-lts mlocate
```

```bash
pacman -Rsn linux
```

```bash
grub-mkconfig -o /boot/grub/grub.cfg
```

```bash
pacman -S linux
```

```bash
grub-mkconfig -o /boot/grub/grub.cfg
```

```bash
updatedb
```


