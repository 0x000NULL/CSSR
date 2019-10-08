### Bypass ssl certificate checks
```bash
wget https://example.com/ --no-check-certificate
```

### Download website offline
```bash
wget --mirror --convert-links --html-extension --adjust-extension --page-requisites --restrict-file-names=windows --domains example.org --wait=1 -o log https://example.org
```

