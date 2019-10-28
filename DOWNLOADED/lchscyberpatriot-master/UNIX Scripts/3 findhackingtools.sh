#!/bin/bash

# Searches for keywords common to hacking tools

dpkg --get-selections | grep john

dpkg --get-selections | grep crack
# NOTE: CRACKLIB IS GOOD

dpkg --get-selections | grep -i hydra

dpkg --get-selections | grep weplab

dpkg --get-selections | grep pyrit