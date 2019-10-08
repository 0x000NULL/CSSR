### Enable BackSpace keyboard shortcut on nautilus
*edit file ~/.config/nautilus/accels and add:*
```bash
(gtk_accel_path "<Actions>/ShellActions/Up" "BackSpace")
```

*restart nautilus:*
```bash
killall nautilus
```


