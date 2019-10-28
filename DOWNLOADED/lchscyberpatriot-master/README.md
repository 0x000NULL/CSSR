# lchscyberpatriot

Once you've cloned this in the windows box:

```
cp gitconfig ~/.gitconfig
```

When you've cloned this on your macbook:

```
cp cyberpatriot ~/.ssh/
chmod 600 ~/.ssh/*
```

# first things first
* Open up VM on "primary" laptop, and install cygwin
	- See: <https://github.com/VagueSalutations/lchscyberpatriot/blob/master/windows/install-cygwin.md>
	- Announce the ip address to everyone
		- `ipconfig /all`
* Everyone connects over ssh
	- Windows 7
		- `ssh CyberPatriot@ip-address -i ~/.ssh/cyberpatriot`
	* Windows 2008
		- `ssh cyg_server@ip-address -i ~/.ssh/cyberpatriot`
* Everyone copies the README and Scored Questions locally
	- `scp -i ~/.ssh/cyberpatriot CyberPatriot@ip-address:/cygdrive/c/Users/CyberPatriot/Desktop/README* ~/Desktop/`
	- `scp -i ~/.ssh/cyberpatriot CyberPatriot@ip-address:/cygdrive/c/Users/CyberPatriot/Desktop/Scored* ~/Desktop/`

# doing the work
* assign someone to the scored questions
* assign someone to run the "always run" scripts
	- `ssh CyberPatriot@ip-address -i ~/.ssh/cyberpatriot`
	- `mkdir "myname"; cd "myname"`
	- `git clone https://github.com/VagueSalutations/lchscyberpatriot.git`
	- `cd windows/bash/always`
	- run the scripts
* assign a person to work on each "sometimes" scripts
	- `ssh CyberPatriot@ip-address -i ~/.ssh/cyberpatriot`
	- `mkdir "myname"; cd "myname"`
	- `git clone https://github.com/VagueSalutations/lchscyberpatriot.git`
	- `cd windows/bash/sometimes`
	- run the scripts
	- every person gets one script at a time
		+ every person should have their own git clone, but you can share if you're working together
	- when you finish your script, you can move on to the next unassigned one
		+ or help out the guy who it is assigned to
* assign someone to dig for any manual stuff
	- add/remove programs + deleting files, etc - custom scripting

# tracking the work
* as things get fixed, and done, log your actions/activity on google drive so other people can see
