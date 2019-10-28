:: This is a script for deleting all the users in badids.txt
:: Each user is on a single line in this file

FOR /F "delims==" %%G IN (badids.txt) DO net user %%G /del