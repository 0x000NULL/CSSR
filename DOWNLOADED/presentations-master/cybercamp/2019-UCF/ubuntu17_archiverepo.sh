#!/bin/bash

# Reference: https://help.ubuntu.com/community/EOLUpgrades
# Reference: https://ubuntuforums.org/showthread.php?t=2382832

# Backup original sources
sudo mv /etc/apt/sources.list /etc/apt/sources.list.bak

# Add archive repos
sudo bash -c 'echo "## EOL upgrade sources.list
# Required
deb http://old-releases.ubuntu.com/ubuntu/ zesty main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu/ zesty-updates main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu/ zesty-security main restricted universe multiverse" > /etc/apt/sources.list'

# Update list of available packages (test repo)
sudo apt-get update

# Upgrade packages
# sudo apt-get upgrade

