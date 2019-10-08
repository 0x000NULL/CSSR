#!/bin/bash
# With x.allow only users listed can use 'at' or 'cron'
# {where 'x' indicates either 'at' or 'cron'}
# Without x.allow then x.deny is checked, members of x.deny are excluded
# Without either (x.allow and x.deny), then only root can use 'at' and 'cron'
# At a minimum x.allow should exist and list root
echo "Attempting to list the following files for the 'before' picture."
echo "Any 'errors' are alright, as we are simply looking to see what exists."
ls -la /etc/at.allow /etc/at.deny /etc/cron.allow /etc/cron.deny
rm -f /etc/at.deny /etc/cron.deny
echo root > /etc/at.allow
echo root > /etc/cron.allow
chown root:root /etc/at.allow /etc/cron.allow
chmod 0400        /etc/at.allow /etc/cron.allow
if [ -e /etc/at.allow-preCIS ]; then
   echo "diff /etc/at.allow-preCIS /etc/at.allow"
   diff /etc/at.allow-preCIS         /etc/at.allow
fi
if [ -e /etc/cron.allow-preCIS ]; then
   echo "diff /etc/cron.allow-preCIS /etc/cron.allow"
   diff /etc/cron.allow-preCIS /etc/cron.allow
fi
echo "Listing the state of these AFTER imposing restrictions..."
echo "Missing file 'errors' are ok here too."
ls -la /etc/at.allow /etc/at.deny /etc/cron.allow /etc/cron.deny

