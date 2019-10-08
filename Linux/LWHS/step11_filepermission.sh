#!/bin/bash
echo "Before ..."
ls -la /etc/group /etc/gshadow /etc/passwd   /etc/shadow
chown root:root   /etc/group   /etc/gshadow  /etc/passwd  /etc/shadow
chmod 0644        /etc/group   /etc/passwd
chmod 0400                                   /etc/gshadow /etc/shadow
echo "After ..."
ls -la /etc/group /etc/gshadow /etc/passwd /etc/shadow
