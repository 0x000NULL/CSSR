### Append path to local user profile

* Edit file

```bash
nano ~/.profile
```

* Append path (Add this line at the end of .profile)

```
export PATH=$PATH:/path/to/my/folder
```

* Source your .profile file

```bash
source ~/.profile
```

### Include ~/.bin in $PATH

```bash
nano ~/.zprofile
```

```bash
if [ -d "$HOME/bin" ] ; then
    PATH="$HOME/bin:$PATH"
fi
```
