## Netstat

### Incoming connections

```bash
netstat -vnpltu
```

### Outbound connections

```bash
netstat -nputw
```

or

```bash
netstat -nputwc
```

### Outbound connections - IPs only

```bash
netstat -nputw | tr -s ' ' | cut -f5 -d ' ' | grep -v '127.0.0.1'
```

