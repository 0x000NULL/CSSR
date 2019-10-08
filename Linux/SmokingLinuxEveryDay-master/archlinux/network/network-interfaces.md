### UDEV NIC NAMES
```bash
nano /etc/udev/rules.d/10-network-rules
SUBSYSTEM=="net", ACTION=="add", ATTR{address}=="00:1e:4f:a9:7c:31", NAME="eth0"
```

*save and exit and reboot*

