### Run every 10 minutes
```bash
*/10 * * * * /path/to/filename.sh
```

### Run every 12 hours
```bash
* */12 * * * /path/to/filename.sh
```

### Run once, daily at 8pm
```bash
0 20 * * * /path/to/filename.sh
```

### Run every day at 10am, except Saturday and Sunday
```bash
0 10 * * 1,2,3,4,5 /path/to/filename.sh
```
