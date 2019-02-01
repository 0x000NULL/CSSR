#!/bin/bash

#--------Removing Files----
	sudo apt-get purge netcat-*
	sudo apt-get purge aircrack-ng
	sudo apt-get purge airmon-ng
	sudo apt-get purge hydra-gtk
	sudo apt-get purge john
	sudo apt-get purge johnny
	sudo apt-get purge hive
	sudo apt-get purge burp
	sudo apt-get purge cainandable
	sudo apt-get purge myheritage
	sudo apt-get purge wireshark
	sudo apt-get purge nmap
	sudo apt-get purge john
  	sudo apt-get purge nikto
	sudo apt-get purge nmap
	sudo apt-get purge hashcat
	sudo apt-get purge etherape
	sudo apt-get purge kismet  
	sudo apt-get purge telnet
	sudo apt-get purge postfix
	sudo apt-get purge lcrack
	sudo apt-get purge ophcrack
	sudo apt-get purge sl



#Puring services
	sudo apt-get purge tomcat
	sudo apt-get purge tomcat6
	sudo apt-get purge postgresql
	sudo apt-get purge dnsmasq 
	sudo apt-get purge vncserver
	sudo apt-get purge tightvnc
	sudo apt-get purge tightvnc-common -y
	sudo apt-get purge tightvncserver
	sudo apt-get purge php5
	sudo apt-get purge vnc4server
	sudo apt-get purge telnet-server
	sudo apt-get purge nmdb
	sudo apt-get purge dhclient
	sudo apt-get purge 


	#removes leftover directories
	find . -name '*.mp3' -type f -delete
	find . -name '*.mov' -type f -delete
	find . -name '*.mp4' -type f -delete
	find . -name '*.avi' -type f -delete
	find . -name '*.mpg' -type f -delete
	find . -name '*.mpeg' -type f -delete
	find . -name '*.flac' -type f -delete
	find . -name '*.m4a' -type f -delete
	find . -name '*.flv' -type f -delete
	find . -name '*.ogg' -type f -delete
	find . -name '*.mov' -type f -delete
	find /home -name '*.gif' -type f -delete
	find /home -name '*.png' -type f -delete
	find /home -name '*.jpg' -type f -delete
	find /home -name '*.jpeg' -type f -delete
