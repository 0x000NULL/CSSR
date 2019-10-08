#!/bin/bash

#
# check whether /tmp/cis created
TEMP_DIR=/tmp/cis
LOG_DIR=`pwd`"/log-"`hostname`

echo -e "Checking $TEMP_DIR directory...\c"
if [ ! -d $TEMP_DIR ] 
    then
    echo -e "\nCreating $TEMP_DIR directory...\c"
    /bin/mkdir -p $TEMP_DIR || (echo -e "\nFailed to create $TEMP_DIR, Exiting... "; exit 1)
fi
echo -e "\tDONE"

#
# check whether any step files are in current dir
echo -e "Checking script library in" `pwd`"...\c"
for file in backup check step
do 
  (ls *sh | grep $file > /dev/null) || (echo -e "\nMissing $file script, Exiting ..."; exit 1)
done
echo -e "\tDONE"

echo -e "Checking $LOG_DIR directory...\c"
if [ ! -d $LOG_DIR ] 
    then
    echo -e "\nCreating $LOG_DIR directory...\c"
    /bin/mkdir -p $LOG_DIR || (echo -e "\nFailed to create $LOG_DIR, Exiting... "; exit 1)
fi
echo -e "\tDONE"

for file in ./do-backup.sh `/bin/ls ./step*sh`
do
  echo -e "\n***" Running $file "...\c";
  $file 1> $LOG_DIR/${file%sh}"log" 2>&1
  echo -e "\t\tDONE"

  while read -s -n1 -p "Continue or see log? [y|n|l]" key 
  do
    if [[ $key == 'n' || $key == 'N' ]]; then
	echo "Exiting..."; exit 0
    elif [[ $key == 'y' || $key == 'Y' ]]; then
	break;
    elif [[ $key == 'l' || $key == 'L' ]]; then
	echo "\n----------$file LOG---"
	cat $LOG_DIR/${file%sh}"log"
	echo "----------end of LOG----"
    else echo "wrong key";  fi
  done
done 

echo -e "\nRun Fingerprint script after you are done with"
echo "system modification"
