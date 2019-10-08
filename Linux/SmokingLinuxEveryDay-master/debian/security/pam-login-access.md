### set users default umask
```bash
sed -i "s/UMASK.*/UMASK   077" /etc/login.defs
```

### restrict the execution of su
```bash
sed -i "/auth.*required.*pam_wheel\.so/s/^# //g" /etc/pam.d/su
```

### increase the delay time between login prompts 
```bash
sed -i "s/delay=[[:digit:]]\+/delay=10000000/" /etc/pam.d/login
```

### Disallow remote administrative access 
```bash
sed -i "/-:wheel:ALL EXCEPT LOCAL.*/s/^#//g" /etc/security/access.conf
```

### Harden Password Policy
```bash
apt -qq -y install libpam-cracklib
sed -i "s/minlen=[[:digit:]]\+/minlen=12/" /etc/pam.d/common-password
sed -i "s/\bdifok=3\b/& reject_username/" /etc/pam.d/common-password
sed -i "s/\bpam_cracklib.so\b/& minclass=3/" /etc/pam.d/common-password
sed -i "s/\bminclass=3\b/& maxrepeat=2/" /etc/pam.d/common-password
sed -i "s/\bpam_unix.so\b/& remember=24/" /etc/pam.d/common-password
sed -i "s/\bpam_unix.so\b/& minlen=12/" /etc/pam.d/common-password
```

### Max days a password may be used
```bash
sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   40/" /etc/login.defs
```

### Use password aging on existing users
```bash
chage -m 0 -M 40 myuser
```

