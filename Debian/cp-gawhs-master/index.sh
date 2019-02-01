

#--------Updating Linux----
	#Making the linux sources.list open for updates
	sudo chattr -i /etc/apt/sources.list
	sudo chmod 777 /etc/apt/sources.list
	#updating
	sudo apt-get update
	sudo apt-get upgrade
	clear

#--------Running Misc. Automator Scripts-----
	sudo ./AntiVirus/automator.sh 
	sudo ./Purge/automator.sh
	sudo ./PW/automator.sh
	sudo ./UFW/automator.sh
	clear

#--------Running Service Scripts-------

##read cotyn 

##while [ "cotyn" != false || "cotyn" != exit]; do

##echo "What services are running? Choose samba, apache2 or ssh"

##while [exit ==! false ]
##read cotyn

##if [ "$contyn" = "ssh"]; then
/Services/sshScript.sh
echo "ssh secured. Modify anything else accordingly"
##fi

##if [ "$contyn" = "samba"]; then
/Services/sambaScript.sh
echo "samba secured. Modify anything accordingly"
#fi

./Services/apache2/apache2Script.sh

##done

#-------Unecessary services-------

read cotyn 

while [true]; do

	netstat -peanut | gedit
	netstat -tulpn | gedit
	echo "What services are not needed? (Please refrence Boot Up Manager, or BUM for refrence)"
