f [[ $EUID -ne 0 ]]
then
  echo "You must be root to run this script."
  exit 1
fi

cd 1 
chmod +x main.sh
./main.sh

cd ..
cd 2
chmod +x ubuntu_16.04LTS.sh
./ubuntu_16.04LTS.sh
cd ..

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
./ubuntu_harden.sh

cd ..
cd lynis-master
./lynis

cd ..
clear
echo "FINISHED"
echo "Check Users and Questions!"
