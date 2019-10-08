### gcc do not delete intermediate files

* shows .i and .s and .o files

```bash
gcc file.c -o file -save-temps
```

### Display the sections' header
```bash
readelf -S file
```

### Compile x86 (32-bit) application
```bash
gcc -m32 -o myapp myapp.c
```

### Compile x86-64 (64-bit) application
```bash
gcc -m64 -o myapp myapp.c
```

### Produce debugging information (debugging symbols)

* GDB can work with this debugging information.

```bash
gcc -g -o myapp myapp.c
```
or
```bash
gcc -ggdb -o myapp myapp.c
```

* radare2 can work with this debugging information.

```bash
gcc -gdwarf -o myapp myapp.c
```
