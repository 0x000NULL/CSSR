####  
#### This script will be removed as grsecurity is not free anymore.
####

## Setting up grsec
## License: GNU Free Documentation License - Version 1.3, 3 November 2008 (for details, see LICENSE.txt)
#
## Preparation
## https://en.wikibooks.org/wiki/Grsecurity/Obtaining_grsecurity
#
#echo "Check script and the comments before running!"
#sleep 9999
#
#
#GRSEC="grsecurity-3.1-4.5.7-201606080852.patch"
#GRSEC_SIGN="grsecurity-3.1-4.5.7-201606080852.patch.sig"
#
#GRADM="gradm-3.1-201603152148.tar.gz"
#GRADM_SIGN="gradm-3.1-201603152148.tar.gz.sig"
#
#KERNEL="linux-4.5.7.tar.gz"
#KERNEL_SIGN="linux-4.5.7.tar.sign"
#
## Create and use an empty folder for transparency.
#mkdir grsec_compile
#cd grsec_compile
#
## Download grsecurity
#wget http://grsecurity.net/stable/$GRSEC
#wget http://grsecurity.net/stable/$GRSEC_SIGN
#
## Download gradm
#wget http://grsecurity.net/stable/$GRADM
#wget http://grsecurity.net/stable/$GRADM_SIGN
#
## Download kernel source
#wget https://www.kernel.org/pub/linux/kernel/v4.x/$KERNEL
#wget https://www.kernel.org/pub/linux/kernel/v4.x/$KERNEL_SIGN
#
## Check the signatures (use tab for full filename)
#gpg --verify $GRSEC_SIGN
#gpg --verify $GRADM_SIGN
#gunzip $KERNEL
#gpg --verify $KERNEL_SIGN
#
#echo "Downloads and verifications finished."
#sleep 5
#
## Configure and make kernel
## https://en.wikibooks.org/wiki/Grsecurity/Configuring_and_Installing_grsecurity
##
## Note: for configuration and installing, additional packages are required. On debian 8 you can use the following:
## eg. apt-get update && apt-get install kernel-common linux-headers-amd64 gcc make libncurses5-dev fakeroot gcc-4.9-plugin-dev dpkg-dev
##
#tar -xf $KERNEL
#cd linux-*
#patch -p1 < ../$GRSEC
#
#
#echo '''
#Now we need to configure the kernel. Note the following:
#  - You need to turn on "grsecurity" in "Security" menu.
#  - You can use the automatic configuration of grsec (options are server and desktop).
#  - When ready, press enter'''
#read
#
#make menuconfig
#export CONCURRENCY_LEVEL=3  # Assuming you want to compile with 2 cores.
#fakeroot make deb-pkg -j 3  # Assuming you want to compile with 2 cores. If you have more, change the value of -j.
#
#
## RBAC
#cd ..
#tar xzf $GRADM
#cd gradm
#
#echo "Now you can run the make command."
#
## make  # with non-root user or use the next command to make it work. 
##make nopam  # without pam support
#
##make install
#
## In case of problem with shutdown subject: just comment the line out in rbac config. At least that worked last time.
