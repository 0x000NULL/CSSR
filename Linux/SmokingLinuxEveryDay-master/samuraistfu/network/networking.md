### eth0 missing

```bash
nano /etc/network/interfaces
```

* Contents

```
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
```

```bash
/etc/init.d/networking restart
```
