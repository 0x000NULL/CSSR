### To create a branch and switch to it at the same time
```bash
git checkout -b develop
```

### Adding Submodules to a Git Repository
```bash
git submodule add git@github.com:openssl/openssl.git
```

### Using Submodules
```bash
git submodule init
git submodule update
```

### Pull latest of all submodules
```bash
git pull --recurse-submodules
git submodule update --recursive --remote
```

### Ignore changes in git submodules

* Edit .gitmodules file
* Append this line to each submodule:
```bash
ignore = dirty
```

e.g.
```bash
[submodule "openssl"]
	path = openssl
	url = git@github.com:openssl/openssl.git
	ignore = dirty
```

### Remove submodule
```bash
git submodule deinit openssl
git rm openssl
rm -rf .git/modules/openssl
rm -rf openssl
```

* Remove the submodule’s entry in the .gitmodules file. If any.
* Remove the submodule’s entry in the .git/config. If any.

### Clean repository - preview
Preview what would be removed.
```bash
git clean -Xdn
```

### Clean repository
Remove ignored files and directories.
```bash
git clean -Xdf
```

### Forget about a file that was tracked but is now in .gitignore
```bash
git rm -r --cached .
git add .
git commit -m "Remove ignored files"
```

### View the change history of a file
```bash
git log --follow -p -- <filename>
```

### git pull over all subdirectories

```bash
find . -mindepth 1 -maxdepth 1 -type d -exec git --git-dir={}/.git --work-tree=$PWD/{} pull origin master \;
```


