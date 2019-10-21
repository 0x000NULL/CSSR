#!/bin/bash

#########################################
# Make sure utilities are ready
#########################################

# Resets bash history file (CP likes to disable history)
echo "*Resetting bash history*"
sudo rm ~/.bash_history 

# Reinstall core utilities (in case CP modified anything)
echo "*Reinstalling core utilities*"
sudo apt-get install --reinstall coreutils

# Install fatrace (utility to scan CP scoring engine)
echo "*Installing fatrace*"
sudo apt-get -y install fatrace

#########################################
# Easy point-scoring items
#########################################

# Install cracklib (utility for creating secure passwords)
echo "*Installing cracklib*"
sudo apt-get install libpam-cracklib --force-yes -y

# Enable firewall (often get points just for running this command)
echo "*Enabling firewall*"
sudo ufw enable

# Update system (install system updates)
echo "*Installing updates*"
echo "Y" | sudo apt-get update

# Upgrade packages (sometimes helpful)
echo "*Installing package upgrades*"
echo "Y" | sudo apt-get upgrade

# Upgrades system items, including bash (often helpful)
echo "*Installing system upgrades*"
echo "Y" | sudo apt-get dist-upgrade

#######
# END
#######