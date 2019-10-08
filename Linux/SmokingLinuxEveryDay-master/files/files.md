### Get file type
```bash
file <filename>
```

### Get file status
```bash
stat <filename>
```

### Find and delete directories
```bash
find . -name ".git" -type d -exec rm -rf "{}" \;
```

### Find and delete files
```bash
find . -name ".gitignore" -type f -exec rm -f "{}" \;
```

