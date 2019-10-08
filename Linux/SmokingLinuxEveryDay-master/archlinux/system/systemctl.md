### view services
```bash
systemctl list-unit-files
```

### mask so that it's impossible to start it
```bash
systemctl mask unit 
```

### unmask
```bash
systemctl unmask unit
```

### help page/man
```bash
systemctl help unit
```

### systemd services that failed to start
```bash
systemct --state=failed
```


