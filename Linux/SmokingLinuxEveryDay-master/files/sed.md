### Words boundaries

*e.g. match spaces: word1 word2*

```bash
sed -i 's/word1.*word2/word3 word4/' /path/to/file/name
```

### Prepend line (add line before SearchPattern)

```bash
sed -i '/SearchPattern/ithis is a new line' /path/to/file/name
```

### Append line (add line after SearchPattern)

```bash
sed -i '/SearchPattern/athis is a new line' /path/to/file/name
```

### Add string between strings (using groups)

*e.g. "string1 string2" --> "string1 string3 string2"*
```bash
sed -i 's/\(string1\)\(.*string2\)/\1 string3 \2/' /path/to/file/name
```

### Comment line containing specific string

```bash
sed -i '/SearchPattern/s/^/#/g' /path/to/file/name
```

### Uncomment line containing specific string

```bash
sed -i '/SearchPattern/s/^#//g' /path/to/file/name
```

### Trim spaces at the end of each line

```bash
sed -i 's/[[:blank:]]*$//' /path/to/file/name
```

