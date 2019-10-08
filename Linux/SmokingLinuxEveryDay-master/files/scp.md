### Upload one file
```bash
scp ~/path/to/file/name user@x.x.x.x:/home/user
```

### Upload one file - specify port
```bash
scp -P port_number ~/path/to/file/name user@x.x.x.x:/home/user
```

### Upload one file - specify authentication
```bash
scp -o PreferredAuthentications=password ~/path/to/file/name user@x.x.x.x:/home/user
```

### Upload folder
```bash
scp -r /path/to/folder user@x.x.x.x:/home/user/path/to/folder
```

### Upload folder - specify authentication
```bash
scp -o PreferredAuthentications=password -r /path/to/folder user@x.x.x.x:/home/user/path/to/folder
```

### Download one file
```bash
scp user@x.x.x.x:/home/user/path/to/file/name /path/to/save/file/name
```

### Download one file - specify port
```bash
scp -P port_number user@x.x.x.x:/home/user/path/to/file/name /path/to/save/file/name
```

### Download one file - specify authentication
```bash
scp -o PreferredAuthentications=password user@x.x.x.x:/home/user/path/to/file/name /path/to/save/file/name
```

### Download folder
```bash
scp -r user@x.x.x.x:/home/user/path/to/folder /path/to/save/folder
```

### Download folder - specify authentication
```bash
scp -o PreferredAuthentications=password -r user@x.x.x.x:/home/user/path/to/folder /path/to/save/folder
```


