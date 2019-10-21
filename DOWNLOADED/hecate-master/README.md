# hecate
Hecate is designed to improve the security of Ubuntu 14/16 systems. It is a good idea to look at the code in each one of the scripts before you run them. That way, you can get an idea of if there will be any conflicts with whatever version of Ubuntu you're running, such as deprecated commands and/or functionality.

## How to Get Hecate
Run ```git clone https://github.com/rleboeu/hecate``` in a terminal. This will create a directory you can ```cd``` to and then run the scripts.

## Usage
All scripts should be able to be run with ```./scriptname``` assuming that you are ```cd```'d into the hecate directory. If for some reason you cannot execute a script, running ```chmod +x scriptname``` should allow you to run it. Alternatively, ```sh scriptname``` or ```bash scriptname``` should work, but this may vary depending on the system.

### update ###
Enables Ubuntu firewall, installs ```htop```, and updates apt configuration to enable
auto updates and periodic update checks.
Updates and upgrades the software packages currently installed on the system.

Note: A reboot is recommended after the system update process finishes. Additionally, you can double check that the firewall is on with the ```gufw``` GUI firewall package. If it's not currently installed on the system, ```sudo apt-get install gufw``` will install it, and you can run it by typing ```gufw``` into a terminal.

### set_pass ###
Replaces all existing users passwords (except root password) with a
user-defined password.
The max password age, minimum days between password change, and warn before
password change options are also set as follows:
- Max Password Age = 30 days
- Warn Before Password Change = 7 days
- Minimum days between password change = 0 days (can change any time)

### auth ###
Running ```auth``` removes any unauthorized users present on the system. If a user
isn't included in the user-defined file ```users.authorized```, they will be removed
from the system. Including administrators is important! The users will be manually
entered at run-time.

A log of deleted users is stored in ```users.deleted```.

### guest ###
Disables the guest account on LightDM. Does not work on Ubuntu versions past
16.04 LTS.

### logindefs ###
Assigns ```PASS_MIN_DAYS```, ```PASS_MAX_DAYS```, and ```PASS_WARN_AGE``` to ```0```, ```30```, and ```7```, respectively.
It is not necessary to run this script after running ```set_pass```.

### perms ###
Note: ```auth``` must be run before this script as auth creates ```users.authorized```.
Alternatively, you can create and populate ```users.authorized``` if you do not want
to run ```auth```.

This script manages users in the group ```sudo```. If a user should be a member of ```sudo```
(with respect to the user-defined file ```admins```) then it will add them to the group
if they are not already a member. Otherwise, it will delete them from the group
```sudo``` if they are a member and should not be.

### info (directory) ###
Required by update script. Contains ```update.template```. See update section for more info.
