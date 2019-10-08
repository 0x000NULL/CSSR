### VMWARE auto update crash resolution

*apply this line at /usr/bin/vmware and /usr/bin/vmplayer:*
```bash
export LD_LIBRARY_PATH=/usr/lib/vmware/lib/libcurl.so.4
```

*here:*
```bash
if "$BINDIR"/vmware-modconfig --appname="VMware Workstation"
--icon="vmware-workstation" &&
   vmware_module_exists $vmmon; then
   export LD_LIBRARY_PATH=/usr/lib/vmware/lib/libcurl.so.4
   exec "$libdir"/bin/"vmware" "$@"
fi
```


