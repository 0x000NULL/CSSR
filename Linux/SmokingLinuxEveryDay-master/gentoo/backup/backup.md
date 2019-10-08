### Take Gentoo Backup
```bash
tar jcpf mac-gentoo-back-`date +"%d-%m-%Y"`.tar.bz2 /proc/config.gz emerge-hints gentoo-install-guide ~/.tmux.conf /var/lib/portage/world /etc/portage/make.conf /etc/portage/package.* /etc/portage/patches /etc/default/grub /etc/X11/xorg.conf.d/50-synaptics.conf /etc/systemd/system/vmware-usbarbitrator.service /etc/systemd/system/vmware.service /usr/lib64/systemd/system/nessusd.service
```

