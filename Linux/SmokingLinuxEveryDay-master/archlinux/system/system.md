### find all files and calculate their hashes
```bash
find . -type f -name '*' -exec sha512sum '{}' + > hashes.txt
```


### delete all hidden files
```bash
find . -iname '.*' -type f -delete
```

### regexps
```bash
if FILE is "some-file.jpg" then:
FILE=some-file.jpg
${FILE%.*}=some-file
${FILE##*.}=jpg
```

### searches all files recursively to find the text WITHIN a file
```bash
grep -r -i TEXTTOSEARCHINFILE
```

### creates a 5 mb file
```bash
dd if=/dev/zero of=wtf.dat bs=1M count=5
```

### creates a 500mb file
```bash
dd if=/dev/zero of=bigfile bs=500M count=1
```

### if cursor disappears, mouse
```bash
xsetroot -cursor_name left_ptr
```

### Generates a random password with 30 characters
```bash
tr -cd '[:graph:]' < /dev/urandom | head -c 30;echo
```

### IP COMMANDS
```bash
ip link set eth0 up
```

#### set ip address new way
```bash
ip addr add 192.168.1.100/24 broadcast 192.168.1.255 dev eth0
```

#### set gw new way
```bash
ip route add default via 192.168.1.254
```


