### Connect
```bash
ssh user@x.x.x.x
```

### Connect - specify port
```bash
ssh user@x.x.x.x -p 60001
```

### Connect - specify authentication
```bash
ssh -o PreferredAuthentications=password user@x.x.x.x
```

### Connect - specify identity file
```bash
ssh -i ~/.ssh/id_rsa -o IdentitiesOnly=yes user@x.x.x.x
```

### Add SSH key to ssh-agent
```bash
eval "$(ssh-agent -s)"
```

```bash
ssh-add ~/.ssh/id_rsa
```

### Add SSH key to ssh-agent permanently
```bash
ssh-add -k ~/.ssh/id_rsa
```
