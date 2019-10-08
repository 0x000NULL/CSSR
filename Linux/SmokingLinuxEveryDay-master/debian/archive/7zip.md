### 7z Installation

```bash
apt-get install p7zip-full
```

### 7z Compress file

```bash
7z a myfile.7z myfile.pdf
```

### 7z Compress folder

```bash
7z a -r myfile.7z folder_name/
```

### 7z Compress folder - Exclude hidden

```bash
7z a -xr'!.*' myfile.7z folder_name/
```

### 7z Compress file - Password protected

```bash
7z a -p myfile.7z myfile.pdf
```

### 7z Compress folder - Password protected

```bash
7z a -p -r myfile.7z folder_name/
```

### 7z Compress folder - Password protected - Exclude hidden

```bash
7z a -p -xr'!.*' myfile.7z folder_name/
```

### 7z Extract archive contents

```bash
7z x myfile.7z
```

### 7z List archive contents

```bash
7z l myfile.7z
```



