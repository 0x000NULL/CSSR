### Intel syntax
```bash
objdump -M intel -D myapp
```

### Dump main function
```bash
objdump -M intel -D myapp | grep -Axx main.:
```

*e.g. 20 lines*

```bash
objdump -M intel -D myapp | grep -A20 main.:
```


