#!/bin/bash
for DIR in `awk -F: '( $3 >= 500 ) { print $6 }' /etc/passwd`; do
     if [ $DIR != /var/lib/nfs ]; then
          chmod -R g-w   $DIR
          chmod -R o-rwx $DIR
     fi
done
