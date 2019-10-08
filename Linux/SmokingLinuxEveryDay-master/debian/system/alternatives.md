### Add an application as a choice in update-alternatives

```bash
update-alternatives --install /usr/bin/editor editor /usr/bin/subl 100
```

### Remove an application from update-alternatives

```bash
update-alternatives --remove editor /usr/bin/subl
```

### Change default Editor

```bash
update-alternatives --config editor
```

