### Create Full Backup
```bash
tar -zcvpf backup-filename-`date '+%Y-%m-%d-%H.%M'`.tar.gz /path/to/my/data/
```

### Create incremental backups

```bash
tar -zcvpf backup-filename.tar.gz -g snapshot-filename.snar /path/to/my/data/
```

### Restore incremental backups

* level0

```bash
tar -zxvf backup-filename.0.tar.gz -g /dev/null 
```

* level1

```bash
tar -zxvf backup-filename.1.tar.gz -g /dev/null 
```

* level2

```bash
tar -zxvf backup-filename.2.tar.gz -g /dev/null 
```

### Keep last 3 backups

```bash
ls -tdp /path/to/backups/*.tar.gz | grep -v '/$' | tail -n +4 | xargs -I {} rm -- {}
```

