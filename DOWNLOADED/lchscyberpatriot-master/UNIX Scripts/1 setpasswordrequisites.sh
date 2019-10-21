#!/bin/bash

sudo perl -pi -e 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/g' /etc/login.defs
sudo perl -pi -e 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   10/g' /etc/login.defs
sudo perl -pi -e 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/g' /etc/login.defs

