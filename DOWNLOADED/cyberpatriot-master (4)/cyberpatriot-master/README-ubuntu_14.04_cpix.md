# I.    Complete Forensic Tasks
Read and re-read the forensic prompt (README). Complete all of the
forensics questions.

Try to time-box this to be no more than about 30 minutes. This may take
considerably longer depending on the number of questions, their
difficulty to understand/resolve, and user familiarity with the
commands involved (familiarity can offset some time spent googling to
determine what to do and how to do it).

Familiarity with the rest of this checklist will serve you well here as
you may need to employ tools for finding/locating files, listing running
processes, or capturing user information for which notes and commands
are scattered throughout out this document.

# II.   Check Repos, Configure Updates, Update Package Lists
Click Unity then type/select `Software & Updates` from the list of
available system utility icons.

## II.A Verify that typical repos are checked, typically it is OK to pull in.

`Ubuntu Software`
```
main
universe
restricted
multiverse
```

`Other Software`
```
Canonical Partners
```

`Updates`
```
trusty-security
trusty-updates
trusty-backports

x Automatically check for updates daily
x Download and install immediately security updates
```

## II.B Update Package Lists
Close the `Software & Updates` window and open a terminal window.
```
sudo apt-get update
```

# III.  Verify/Install Triage Utilities
Install some basic tools and optionally install convenience tools and
graphic front-ends to ease use. There is a minor cost for the installs
in time spent to install additional tools but this is typically time
well spent because once we begin the more significant OS updates we
will not be able to install any new packages for a little while so these
need to bridge the team through that period of time.

## III.A Install the basic tools
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
```

## III.B Install additional convenience tools
```
sudo apt-get install \
    htop \
    nmap
```

## III.C Install additional graphical front-ends (recommended)
```
sudo apt-get install \
    gufw \
    zenmap
```

# IV.   Configure Firewall
Standardize on ufw and its graphical configuration tool gufw for now.

## IV.A Configure Uncomplicted Firewall (ufw)
Allow inbound traffic by service/port/protocol, port/protocol (only port protocol), or by port (for all protocolsr

If uncomfortable at the command-line, consider using 'gksudo gufw'
```
sudo ufw allow ${service}          # allow service by name
sudo ufw allow ${port}/${protocol} # allow port/protocol for any program
sudo ufw allow ${port}             # allow port indiscriminately
```

e.g. Tell UFW to determine installed SSH server and setup rules on the default 22/tcp for this service.
```
$ sudo ufw allow ssh
```

## IV.B Lock down networking with sysctl
Develop your own set of sysctl practices such as disabling IPv6, IPv4
forwarding/reverse-path-filtering, and generally build some best
practices for tweaking the network stack to make it more resilient
against attackers.

# V.    Manage User Accounts and Login
Ensure user accounts are being used in accordance with policy that
the scenario defines as acceptable. If unsure, trust the checklist and
watch for bad-sounds that may indicate a misstep.

Relevant file locations include the following:
```
/etc/passwd  # user account info lives here
/etc/group   # group information and membership is here
/etc/shadow  # salted/encrypted passwords and/or lock status are here
/etc/gshadow # salted/encrypted group passwords can be stored here
```
The `/etc/shadow` and `/etc/gshadow` file should only be readable by
the root user and all of the above files should only be writable by the
root user.

User account data may live in user home directories, typically within
`/home/${username}` but the path is captured in `/etc/passwd` for easy
reference.

Only administrator users should be listed on the `sudo` and any of
`adm` or `admin` lines in `/etc/group`. Typically making a user an
administrator in the graphical interface adds them to this `sudo` group.

## V.A Lockdown accounts
Using the terminal, ensure the root account is locked down:
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

## V.B Update password duration and complexity policy
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

## V.C Disable accounts, apply least privilege, reset passwords
Disable any unauthorized accounts and reset passwords for all remaining
users.

Click Unity and type/select `User Accounts` from the list of available
system utility icons. Choose `Unlock` from the top-right corner and
enter the password for the administrator user account you are using,
this is the same password used with sudo.

Right click the `Account Type`, typically `Administrator` or `Standard`
to change this setting. Similarly click the hidden password to change
the password from this graphical user interface. By selecting the most
restrictive class of user account allowed by the scenario for each user
we give them the least amount of privilege required to do their work.

## V.D Inspect the /etc/sudoers configuration
Use the `visudo` command to view and/or edit the `sudo` configuration
but you may want to make sure to have a terminal running as root when
making such changes just in case something goes awry. You can open
such a terminal with the following command, reserved for this
occasion and not meant for normal use:
```
sudo su -
```
Check `/etc/sudoers` for explicit entries for unauthorized users or
un-privileged user groups and remove these entries by commenting them
out with a `#` (pound-sign) in the leftmost column of those lines.

# VI.   Start Upgrade of Installed Packages and Security Patching
```
sudo apt-get upgrade
```

Continue with steps below while this program (upgrade) continues by
opening a new terminal.

# VII.  Update and Run Antivirus
Standardize on clamav or now.

Once again, continue with steps below while clamav does updates and
scans by opening a new terminal.

## VII.A Use ClamAV
```
NOTE: when I was preparing for this talk, I ran through some checklists
that worked for our teams and I just was not able to get clamav to
reliably connect to the virus database and pull an initial set of files.
```
Update the virus database
```
sudo freshclam
```

Start a full system scan
```
sudo clamscan -i -r --remove=yes /
```

Once again, continue with steps below while this program runs by opening
a new terminal.

# VIII. Configure and Bring Critical Services On-Line
Critical services will be clearly defined or else alluded to in the
scenario description README that defines the scope of this exercise.

## VIII.A Configure and start SSH
Disable root logins via SSH. We have already disabled unauthorized
accounts using the expiration date as well as password or deleted them.

Open `/etc/ssh/sshd_config`
```
sudo nano /etc/ssh/sshd_config
```
and edit the
`PermitRootLogin` option or add the option if it is not present like so:
```
PermitRootLogin no
```

This is the point to perform any further SSH lockdown, if any, such as
limiting the number of concurrent sessions.

Now restart the SSH server/daemon. Here we use restart by convention
even if the service is not already running, in that case you may see an
error that the SSH service could not be stopped.
```
sudo service ssh restart
```

# IX.   Identify and Remove Rogue Applications and Cron/Startup Entries
Click Unity and select `Ubuntu Software Center` then select `Installed`
along the top of the window and scan through all the installed programs
for anything that looks suspicious or unfamiliar.

Uninstall things that look wrong, and ask a partner to investigate the
rest, handling them as that information comes in.

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

## IX.A List installed services on the command-line
```
sudo service --status-all | less
```
Use the pager program `less` to scan through the service list by hitting
the enter key (advance one line) or space key (advance one page).

Also list the installed packages and search for typical suspects:
```
sudo dpkg --get --selections | less
sudo dpkg --get --selections | grep ${suspect}
```

## IX.B Use top to monitor running processes
Look for unrecognized processes or things you know to be suspicious from
past experience. Use `locate` or `find` to identify the location of
rogue process files and investigate how they got there.

## IX.C Use nmap or netstat to do a local port scan
Look for non-essential services or port numbers to research online.

For example you may see port 631 (cups) open so that your computer can
act as a print server for a locally attached printer. If this is not
needed then this process is a candidate for being disabled and certainly
worth verifying that the process appears to be the standard cups service
and is not a malware process.

An example of generally innocuous services may include `dhcp` (68)
and `zeroconf` (5353) services.

## IX.C.1 Use nmap to scan 127.0.0.1 (localhost)
Use nmap
```
sudo nmap -sS -sU -T4 -A -v 127.0.0.1
```
or configure zenmap
```
gksudo zenmap
```
with address `127.0.0.1` and choose the profile for

### IX.C.2 Use netstat to check for listening ports
Search all ports (tcp, udp, unix domain sockets), do not try to map port
numbers to well known service names, list listening ports, and include
process names in the listing.
```
sudo netstat -anlp | grep -i listen
```

## IX.D Check crontab and rc.local for suspicious service entries
Look at `sudo nano /etc/rc.local` and `sudo crontab -e` for anything
suspicious either based on familiarity you already have or by comparison
to standard configurations you can find online.

Simplistic malware may hook into your system at boot-time through
rc.local and persist and/or exfiltrate data through creative use of cron.

## IX.E Purge the installed packages that are not longer needed
Cleanup packages no longer needed after updates and removals.
```
sudo apt-get --purge autoremove
```

# X.    Fishing for points
At this point, we are gathering more information to identify and
resolve the remaining issues on this system after completing all of the
best practices captured in the rest of the checklist.

## X.A Delete unauthorized users disabled in a previous step
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

## X.B Do your research, a cautionary tale of chkrootkit
The tool `chkrootkit` can still be useful but has various known issues
that remain unresolved and users are best served by doing research on
any findings from this tool before removing programs/packages.

One student removed the /sbin/init process due to a false detection in
this tool and decided to reboot the VM. These two unfortunate decisions
led to a VM that would not boot normally. We were able to boot the VM
and verify that /sbin/init had been deleted from the virtual disk but
did not have a copy of that binary handy with which to recover the VM
and the team had to start over with a fresh copy of the VM.

For those that do not know, init is the first process that is started
by the kernel, on Ubuntu 14.04 these responsibilities are managed by
the upstart subsystem which takes over the SYS V init job. On later
versions of Ubuntu and other very recent Linux distribution versions
the systemd software takes on this role (and a bunch of others).

# Credits
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
