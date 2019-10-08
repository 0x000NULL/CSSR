### show all msgs from last boot
```bash
journalctl -b
```

### show all msgs from the previous boot
```bash
journalctl -b -1
```

### show all msgs from the second previous and so on
```bash
journalctl -b -2
```

### show all msgs from date (and optional time)
```bash
journalctl --since="2016-10-1"
```

### show all msgs since 20 mins ago
```bash
journalctl --since "20 min ago"
```

### follow new
```bash
journalctl -f
```

### show all msgs by a specific executable
```bash
journalctl /usr/bin/something
```

### show all msgs by a specific process
```bash
journalctl _PID=1
```

### 
```bash
journalctl -b -u sshd
```

### show all msgs by a specific unit
```bash
journalctl -u netcfg
```

### kernel ring
```bash
journalctl -k
```

### auth logs
```bash
journalctl -f -l SYSLOG_FACILITY=10
```


