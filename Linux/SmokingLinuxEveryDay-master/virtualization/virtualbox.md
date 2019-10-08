### Resize vmdk disc

```bash
vboxmanage clonehd "blahblah.vmdk" "blahblah.vdi" --format vdi
vboxmanage modifyhd "blahblah.vdi" --resize 204800
```

