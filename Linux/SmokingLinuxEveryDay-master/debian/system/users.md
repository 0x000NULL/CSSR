### Days since last user password change

```bash
echo $(( ( $(date -u '+%s') -  $(date -ud "$(passwd -S <username> | cut -d' ' -f3)" +'%s') )/60/60/24 )) days
```

### Add user to group

```bash
usermod -aG <group_name> <username>
```

### List user groups

```bash
groups <username>
```

### Change user password

```bash
passwd <username>
```

### Impersonate user

```bash
su - <username>
```

### Change user defaut shell

```bash
chsh -s /bin/bash <username>
```

### Create new users group

```bash
groupadd <group_name>
```

### Create new user with home dir

```bash
useradd -m <username>
```

### Create new user with home dir, add to group and assign bash shell

```bash
useradd -m -G <group> -s /bin/bash <username>
```

### Change user password

```bash
echo "$username:$newpassword" | chpasswd
```

### Check if group exists

```bash
grep -q "group_name" /etc/group; echo $?
```

### Check if user exists

```bash
id -u <username> 1>/dev/null 2>&-; echo $?
```

### Generate password

```bash
newpassword=$(tr -dc 'a-zA-Z0-9!@#$%^&*:./?=+_[]{}()<>' < /dev/urandom | head -c 20)
newpassword="$(sed s/[\'\"\`\\]/*/g <<<$newpassword)"
```

### Colored shell

```bash
nano ~/.bashrc
alias ls='ls --color=auto'
alias dir='dir --color=auto'
alias grep='grep --color=auto'
source ~/.bashrc
```

### Bash Completion

```bash
apt-get install bash-completion
```

