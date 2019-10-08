### Apt - Install latest packages

* For jessie add this line to your sources.list:

```
deb http://ftp.debian.org/debian jessie-backports main
```

* Update

```bash
apt-get update
```

* Add key

```bash
gpg --keyserver pgpkeys.mit.edu --recv-key  xxxxxxxxxxxxxxxxx
gpg -a --export xxxxxxxxxxxxxxxxx | sudo apt-key add -
apt-get update
```

* Installation

```bash
apt-get -t jessie-backports install <packagename>
```

### Force Apt-Get to IPv4

```bash
sudoedit /etc/apt/apt.conf.d/99force-ipv4
```

* Append the following contents:

```
Acquire::ForceIPv4 "true";
```

