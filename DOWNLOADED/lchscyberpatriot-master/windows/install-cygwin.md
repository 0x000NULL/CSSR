# install cygwin

## set bridged networking in vmware fusion

* In VMware Fusion (but not inside the VM)
	* type `Command-E`
	* choose **"Network Adapter"**
	* choose **"Bridged Networking"** - **"Autodetect"**
* Choose **"Work"** network when prompted in image

## open powershell as administrator

Start Menu...type `Powershell`...right-click **"Windows PowerShell"** in list and choose **"Run as administrator"**

Copy the text below, right-click your PowerShell window, and hit `enter`

```
$client = new-object System.Net.WebClient
$client.DownloadFile( "http://cygwin.org/setup-x86.exe", "c:\Users\Public\setup-x86.exe" )

Remove-Item c:\Users\Public\runme.cmd
Add-Content c:\Users\Public\runme.cmd "`ncd c:\Users\Public"
Add-Content c:\Users\Public\runme.cmd "`nsetup-x86.exe ^"
Add-Content c:\Users\Public\runme.cmd "`--quiet-mode ^"
Add-Content c:\Users\Public\runme.cmd "`--site http://mirrors.kernel.org/sourceware/cygwin/ ^"
Add-Content c:\Users\Public\runme.cmd "`--root c:\cygwin ^"
Add-Content c:\Users\Public\runme.cmd "`--packages ^"
Add-Content c:\Users\Public\runme.cmd "`openssh,wget,perl,python,curl,rsync,git"

cmd /c c:\Users\Public\runme.cmd

(gc c:\cygwin\cygwin.bat) -replace "bash --login -i", "set CYGWIN=binmode ntsec`r`nbash --login -i" | sc c:\cygwin\cygwin.bat
```

# [Win 7] set password for CyberPatriot user

* net user CyberPatriot Passw0rd!

# [Win 7] start cygwin terminal as administrator

* Right-click **"Cygwin Terminal"** on Desktop and choose **"Run as administrator"**

# [Win 2008] start cygwin terminal as administrator

* Click **"Start Menu...All Programs...Cygwin"**
* Right-click **"Cygwin Terminal"** and choose **"Run as administrator"**

## [Win 7] configure sshd

```
$ ssh-host-config
```
> `*** Query: Should StrictModes be used? (yes/no)` **`yes`**

> `*** Query: Should privilege separation be used? (yes/no)` **`no`**

> `*** Query: Do you want to install sshd as a service?`

> `*** Query: (Say "no" if it is already installed as a service) (yes/no)` **`yes`**

> `*** Query: Enter the value of CYGWIN for the daemon: []` **`binmode ntsec`**

> `*** Query: Do you want to use a different name? (yes/no)` **`yes`**

> `*** Query: Enter the new user name:` **`CyberPatriot`**

> `*** Query: Reenter:` **`CyberPatriot`**

> `*** Query: Please enter the password for user 'CyberPatriot':` **`Passw0rd!`**

> `*** Query: Reenter:` **`Passw0rd!`**

## [Win 2008] configure sshd

```
$ ssh-host-config
```
> `*** Query: Should StrictModes be used? (yes/no)` **`yes`**

> `*** Query: Should privilege separation be used? (yes/no)` **`yes`**

> `*** Query: new local account 'sshd'? (yes/no)` **`yes`**

> `*** Query: Do you want to install sshd as a service?`

> `*** Query: (Say "no" if it is already installed as a service) (yes/no)` **`yes`**

> `*** Query: Enter the value of CYGWIN for the daemon: []` **`binmode ntsec`**

> `*** Query: Do you want to use a different name? (yes/no)` **`no`**

> `*** Query: Create new privileged user account 'WIN-2JFUJDRWO6B\cyg_server' (Cygwin name: 'cyg_server')? (yes/no)` **`yes`**

> `*** Query: Please enter the password:` **`Passw0rd!`**

> `*** Query: Reenter:` **`Passw0rd!`**

## start sshd server
```
cygrunsrv -S sshd
```

## open firewall
```
netsh advfirewall firewall add rule name="sshd" dir=in action=allow protocol=TCP localport=22
```

## setup shared key access
```
mkdir ~/.ssh; chmod 700 ~/.ssh
echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDQavlw6H+P5/a65KAiQOomPEzObI17AVTC4lbX2qDWui/zSV8j6WO+nps0vTw2gHWgoliBOjNE60ZXYxcbeGPwu5QWSFtgB/NI1Y3weZvSLT/sre15fiL+YEV+ggjtpOAdmF+bER8fGEXhM6IvyJdmKMPtVgvHypHVb9GaotIYi4c5+uqnXHxk9tCc5e+kCQNayiX3kkJUeJNFGpDHx3aDj40Ro/wIStI6ZxUNUmwBsRLdSxumsF4HySx6PvSwleXp04MMex9Xgm9JU0gURmJcGGsEKJlYt07A10jvwvCw4s0ef+xcsPJaSXgK0PyWo1DrJySC6/OcixWX6XKKGMPP >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/*
```

## [Win 7] test local ssh
```
ssh CyberPatriot@localhost
# enter 'Passw0rd!' when prompted
```	

## [Win 2008] test local ssh
```
ssh cyg_server@localhost
# enter 'Passw0rd!' when prompted
```	
