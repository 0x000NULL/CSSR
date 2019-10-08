### power saving
```bash
systemctl list-unit-files
```

* install powertop (UPDATE: avoid installing powertop now)

* blacklist btusb bluetooth

* add param at kernel boot 
```bash
nmi_watchdog = 0
```

* edit /etc/sysctl.d/laptop.conf and add 
```bash
vm.laptop_mode = 5
```

* edit /etc/udev/rules.d/70-disable_wol.rules and add 
```bash
ACTION=="add", SUBSYSTEM=="net", KERNEL=="eth*", RUN+="/usr/bin/ethtool -s %k wol d"
```

* to disable Wake On Lan edit /etc/modprobe.d/audio_powersave.conf
```bash
options snd_hda_intel power_save=5
```

* edit /etc/sysctl.d/dirty.conf
```bash
vm.dirty_writeback_centisecs = 6000
```

* edit /sys/module/pcie_aspm/parameters/policy (UNSTABLE?)
```bash
set [powersave]
```

* edit /etc/udev/rules.d/pci_pm.rules (UNSTABLE?)
```bash
ACTION=="add", SUBSYSTEM=="pci", ATTR{power/control}="auto"
```



