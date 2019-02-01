f [[ $EUID -ne 0 ]]
then
  echo "You must be root to run this script."
  exit 1
fi

cd 1 
chmod +x main.sh
./main.sh

cd ..
cd cp-gawhs-master
chmod +x index.sh
./index.sh

cd ..
cd cyberpatriot-master
chmod +x security.sh
./security.sh

cd ..
cd dofirst
chmod +x main.sh
./main.sh


cd ..
cd nixarmor-master
./debian_harden.sh

cd ..
cd lynis-master
./lynis

cd ..
clear
echo "FINISHED"
echo "Check Users and Questions!"
