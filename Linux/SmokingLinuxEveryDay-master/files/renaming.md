### Replace recursively all spaces and underscores with dashes

#### do the directories first
```bash
find -name "* *" -type d | rename -v 's/ /-/g'
find -name "*_*" -type d | rename -v 's/_/-/g'
```

#### then files
```bash
find -name "* *" -type f | rename -v 's/ /-/g'
find -name "*_*" -type f | rename -v 's/_/-/g'
```

