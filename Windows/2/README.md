# cyberpatriot
# It is against Cyber Patriot rules to use this script by the way. 

A bash script used for the Linux Ubuntu machine during the Cyber Patriot security competition. 

# sources

This repository pulls techniques from a variety of links and articles. They are listed here.

https://github.com/lfit/itpol/blob/master/linux-workstation-security.md

http://www.yolinux.com/TUTORIALS/LinuxSecurityTools.html

https://www.debian.org/doc/manuals/securing-debian-howto/index.en.html

https://wiki.archlinux.org/index.php/Security

http://www.ibm.com/developerworks/linux/tutorials/l-harden-server/index.html

http://www.ibm.com/developerworks/linux/tutorials/l-harden-desktop/index.html

http://crunchbang.org/forums/viewtopic.php?id=24722

https://www.debian.org/doc/manuals/securing-debian-howto/securing-debian-howto.en.pdf

#how-to

This script can be run on a Linux system by typing the following into a terminal:

```
sudo sh harrisburg-linux.sh
```

If you wish to log out the output of script as well as get output to the console, run the following:

```
sudo sh harrisburg-linux.sh 2>&1 | tee /root/.logfiles/output.log
```

