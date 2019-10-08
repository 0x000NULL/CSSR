### gdb basics
```bash
gdb -q ./myapp
break main
run
info registers
quit
```

### gdb intel syntax
```bash
set disassembly intel
```

**permanent**
```bash
echo "set disassembly intel" > ~/.gdbinit
```

### Dump of assembler code for function main
```bash
disassemble main
```

### Display EIP register value
```bash
info register eip
```
or
```bash
i r eip
```


