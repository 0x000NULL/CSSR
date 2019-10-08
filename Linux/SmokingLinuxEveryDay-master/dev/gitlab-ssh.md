### Generate a new SSH key pair

```bash
ssh-keygen -t rsa -C "your.email@example.com" -b 4096
```

### Copy new SSH key pair

```bash
cat ~/.ssh/id_rsa_blahblah.pub
```

### Working with non-default SSH key pair paths

```bash
eval $(ssh-agent -s)
ssh-add ~/.ssh/other_id_rsa
```

Edit ~/.ssh/config:

```bash
Host my.gitlab.example.com
IdentityFile ~/.ssh/id_rsa_blahblah
```

