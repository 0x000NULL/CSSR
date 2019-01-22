#This script starts the linus scanner

	cd /usr/share/lynis/
	/usr/share/lynis/lynis update info
	/usr/share/lynis/lynis audit system
	cont