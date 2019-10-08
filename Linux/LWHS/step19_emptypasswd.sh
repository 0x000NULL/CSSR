#!/bin/bash
#
#
echo "Should produce no output"
awk -F: '( $2 == "" ) { print $1 }' /etc/shadow
