Expanded verison with notes and commentary in-line is available online
https://github.com/deaks/cyberpatriot/blob/master/README-ubuntu_14.04_cpix.md

#### I.    Complete Forensic Tasks
Read and re-read the forensic prompt (README). Complete all of the
forensics questions.

#### II.   Check Repos, Configure Updates, Update Package Lists
Click Unity then type/select `Software & Updates` from the list of
available system utility icons.

`Verify that typical repos are checked`
```
main
universe
restricted
multiverse

Canonical Partners

trusty-security
trusty-updates
trusty-backports

x Automatically check for updates daily
x Download and install immediately security updates
```

`Update Package Lists`
```
sudo apt-get update
```

#### III.  Verify/Install Triage Utilities

```
sudo apt-get install \
    bash \
    clamav \
    gksu \
    libpam-cracklib \
    lsof \
    nano \
    openssh-server \
    terminator \
    ufw \
    vim

sudo apt-get install \
    htop \
    nmap

sudo apt-get install \
    gufw \
    zenmap
```

#### IV.   Configure Firewall
Standardize on ufw and its graphical configuration tool gufw for now.

`Configure Uncomplicted Firewall (ufw)`
```
sudo ufw allow ${service}          # allow service by name
sudo ufw allow ${port}/${protocol} # allow port/protocol for any program
sudo ufw allow ${port}             # allow port indiscriminately
```

e.g. Tell UFW to determine installed SSH server and setup rules on the default 22/tcp for this service.
```
$ sudo ufw allow ssh
```

`Lock down networking with sysctl`

#### V.    Manage User Accounts and Login
The `/etc/shadow` and `/etc/gshadow` file should only be readable by
the root user and all of the above files should only be writable by the
root user.

Only administrator users should be listed on the `sudo` and any of
`adm` or `admin` lines in `/etc/group`. Typically making a user an
administrator in the graphical interface adds them to this `sudo` group.

`Lockdown accounts`
```
sudo passwd -l root
```

Using the terminal you can also disable other accounts:
```
sudo passwd -l ${username}  # lock account
sudo chage -E 1 ${username} # set early expiration date (SSH logins)
```

These same user accounts can be (re)enabled as follows if needed:
```
sudo passwd -u ${username}   # unlock account
sudo chage -E -1 ${username} # clear expiration, the dash is important
```

Disable the guest login used with lightdm
```
sudo nano /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
```
by appending the following line and saving the file:
`allow-guest=false`

`Update password duration and complexity policy`
This is changed in two places.
```
sudo nano /etc/login.defs
```
Set as follows:
PASS_MAX_DAYS=90
PASS_MIN_DAYS=1
PASS_WARN_AGE=7

```
sudo nano /etc/pam.d/common-password
```
To remember the last set of passwords and disallow them, add at the end
of the pam_unix.so line:
```
remember=5
```
Also modify the set of password complexity requirements, replace after
pam_cracklib.so with the following:
```
retry=3 difok=3 ucredit=1 lcredit=1 dcredit=1 ocredit=1 maxrepeat=2 minlen=12
```

`Disable accounts, apply least privilege, reset passwords`
Click Unity and type/select `User Accounts` from the list of available
system utility icons. Choose `Unlock` from the top-right corner and
enter the password for the administrator user account you are using,
this is the same password used with sudo.

`Inspect the /etc/sudoers configuration`
Use the `visudo` command to view and/or edit the `sudo` configuration
but you may want to make sure to have a terminal running as root when
making such changes just in case something goes awry. You can open
such a terminal with the following command, reserved for this
occasion and not meant for normal use:
```
sudo su -
```

#### VI.   Start Upgrade of Installed Packages and Security Patching
```
sudo apt-get upgrade
```

Continue with steps below while this program (upgrade) continues by
opening a new terminal.

#### VII.  Update and Run Antivirus
TBD (clamav has been giving me issues, looking for a good alternate)

#### VIII. Configure and Bring Critical Services On-Line

`Configure and start SSH`
```
sudo nano /etc/ssh/sshd_config
...
PermitRootLogin no
...
sudo service ssh restart
```

#### IX.   Identify and Remove Rogue Applications and Cron/Startup Entries
Click Unity and select `Ubuntu Software Center` then select `Installed`
along the top of the window and scan through all the installed programs
for anything that looks suspicious or unfamiliar.

Unless specified as a critical service for the VM scenario services
like ftp, telnet, rsh/rlogin, vnc, tftp, and ncat/netcat/nc, are likely
candidates for removal as non-essential services that expose weakness
or may have been installed by malicious users. Other suspicious
services may include NFS, samba/SMB/CIFS, and the NTP server/daemon each
of which has a specific purpose that seems like it should be specified
as part of the scenario if it is a critical service.

Typical web-servers include apache, lighttpd, and nginx configured as
a web-server or a reverse proxy (providing portal-type access to multiple
independent web sites).

Typical FTP servers may include vsftp or xinetd.

Typical SSH may include openssh or dropbear, be on the lookout for
multiple SSH servers running on different ports especially on something
other than the default port 22/tcp.

`List installed services on the command-line`
```
sudo service --status-all | less

sudo dpkg --get --selections | less
sudo dpkg --get --selections | grep ${suspect}
```

`Use top to monitor running processes`

`Use nmap or netstat to do a local port scan`
Look for non-essential services or port numbers to research online.

```
sudo nmap -sS -sU -T4 -A -v 127.0.0.1

OR

sudo netstat -anlp | grep -i listen
```

`Check crontab and rc.local for suspicious service entries`
Look at `sudo nano /etc/rc.local` and `sudo crontab -e` for anything
suspicious either based on familiarity you already have or by comparison
to standard configurations you can find online.

`Purge the installed packages that are not longer needed`
Cleanup packages no longer needed after updates and removals.
```
sudo apt-get --purge autoremove
```

#### X.    Fishing for points

`Delete unauthorized users disabled in a previous step`
Ensure that you have completed the forensic questions before deleting
any user accounts.

If you are sure that you want to delete unauthorized user accounts,
which should already be disabled at this point, do so as follows:
```
sudo deluser --remove-home ${username}
```
e.g. Delete the user named `megatron`
```
sudo deluser --remove-home megatron
```

`Do your research, a cautionary tale of chkrootkit`
One student removed the /sbin/init process due to a false detection in
this tool and decided to reboot the VM. These two unfortunate decisions
led to a VM that would not boot normally. We were able to boot the VM
and verify that /sbin/init had been deleted from the virtual disk but
did not have a copy of that binary handy with which to recover the VM
and the team had to start over with a fresh copy of the VM.

#### Credits
I greatly appreciate the work of those who have come before and chose
to align this content with checklists that the Rocklin High team have
found useful and was prepared by past Cyber Patriot teams.

Kyle and Venkata, thank you for pointing me to this wonderful checklist
which I have just re-organized and expanded upon here. A special thank
you goes out to the teams at Cochise College who put these together
originally and the Linux developers, as well as Debian and Ubuntu
maintainers who make this excellent software readily available to us.

http://cyberpatriotarchives.com/Checklists/Checklist%20-%20Ubuntu%20-%20cochise.pdf
http://cyberpatriotarchives.com/Checklists/Checklist%20-%20Ubuntu%202%20-%20cochise.pdf
