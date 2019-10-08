### Sync local and remote folder

```bash
rsync --rsh="/usr/bin/ssh" -rtvs --progress --delete /local/path/to/folder user@example.com:/path/to/folder
```

### Sync local and remote folder - specify authentication

```bash
rsync --rsh="/usr/bin/ssh -o PreferredAuthentications=password" -rtvs --progress --delete /local/path/to/folder user@example.com:/path/to/folder
```

### Usage Example

```bash
rsync --exclude='*.swp' --exclude='.gitignore' --exclude='.git/' --rsh="/usr/bin/ssh -o PreferredAuthentications=password" -rtvs --progress --delete ~/work/project1 user@example.com:/home/user/work/
```

### Backup

```bash
rsync -r -t -v --progress --delete -s /home/user/foldername /media/user/backup_disk/
```

```bash
rsync --exclude=*.vdi -av -h --progress SOURCE DESTINATION #(without tr /)
```

```bash
rsync --exclude=*.vdi -av -h --progress /home/user/folder1 /home/user/folder2 /home/user/folder3 /home/user/folder4 /mnt/external/disk
```

### Sync files /var/www/html/

```bash
usermod -aG www-data <username>
chown -R <username>:www-data /var/www/html/myapp
chmod -R 755 /var/www/html/myapp

### download

```bash
scp -o PreferredAuthentications=password -r <username>@example.com:/var/www/html/myapp ./
```

### upload-sync

```bash
rsync --rsh="/usr/bin/ssh -o PreferredAuthentications=password" -rtvs --progress --delete /var/www/html/myapp <username>@example.com:/var/www/html/
chown -R <username>:www-data /var/www/html/myapp
```


