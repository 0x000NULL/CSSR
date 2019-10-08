## Power Management

### pstate

```bash
zgrep -i pstate /boot/config-$(uname -r)
```

### cpupower

```bash
apt install linux-cpupower
cpupower frequency-info
```

### scaling governor

```bash
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
```

### acpi

```bash
apt install acpi
```

### kernel config

```bash
zgrep -i performance /boot/config-$(uname -r)
```

### performance governor

```bash
cpupower -c all frequency-set -g performance
cpupower frequency-info
```

### cpufrequtils

```bash
apt install cpufrequtils
```

### create cpufrequtils

```bash
nano /etc/default/cpufrequtils
```

contents:

```
GOVERNOR="performance"
```

### TLP

```bash
apt install tlp tlp-rdw
systemctl unmask tlp.service
systemctl enable tlp
systemctl start tlp
```
