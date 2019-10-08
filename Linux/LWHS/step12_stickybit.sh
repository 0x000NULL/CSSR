#!/bin/bash
echo "The following script should produce no results..."
for PART in `awk '( $3 ~ "ext[23]" ) { print $2 }' /etc/fstab`;
do
     find $PART -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print
done
echo $0 "DONE"
