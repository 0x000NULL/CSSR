#!/bin/bash
awk '( $3 ~ /^ext[23]$/ && $2 != "/" ) { $4 = $4 ",nodev" };         \
     { printf "%-26s%-22s%-8s%-16s %-1s %-1s\n",$1,$2,$3,$4,$5,$6 }' \
     /etc/fstab > /tmp/cis/fstab.tmp2
#             Kept /tmp/cis/fstab.tmp2 as input to the next step (CIS 7.2).
chown root:root /etc/fstab
chmod 0644      /etc/fstab
# Note: the diff IS not for the same pair of files, as this step is treated
# as intermediary. But, we'll show the users the damage done so far and
# they see the progress.
echo "diff /etc/fstab-preCIS /etc/fstab"
      diff /etc/fstab          /tmp/cis/fstab.tmp2
chmod -R 0400 /tmp/cis/*
