#!/bin/bash

# Reference: https://docs.docker.com/install/linux/docker-ce/ubuntu/

# Remove old versions
sudo apt-get remove docker docker-engine docker.io containerd runc

# Install packages to allow apt to use a repository over HTTPS:
sudo apt-get install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common

# Add Docker’s official GPG key:
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

# Add Docker Stable Repo
sudo add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"
   
# Update apt's package index
sudo apt-get update

# Install the latest version of Docker CE and container
sudo apt-get install -y docker-ce # docker-ce-cli containerd.io
