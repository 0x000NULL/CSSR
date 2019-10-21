#!/bin/bash

# First requires a list of users in a txt file called
# user_list.txt

	for i in `more user_list.txt `
	do
	echo -e “C0mpl3xPassw0rd\nC0mpl3xPassw0rd” | passwd $i
	
done
echo “*Changing passwords to C0mpl3xPassw0rd”
echo "*Command complete*"