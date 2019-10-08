### Kernel upgrade
*backup existing kernel config*
*eselect kernel list (select the kernel you want)*
```bash
cd /usr/src/linux # (verify its the new kernel symlink)
zcat /proc/config.gz > /usr/src/linux/.config
make silentoldconfig
make -j4 modules_prepare
emerge --ask @module-rebuild
make -j4 && make -j4 modules_install && make install
genkernel --luks --lvm initramfs
grub-mkconfig -o /boot/grub/grub.cfg
```
