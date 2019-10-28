:: This is a script for disabling all the services in disableServices.txt
:: Each service is on a single line in this file

FOR /F "delims==" %%G IN (disableServices.txt) DO net stop %%G
FOR /F "delims==" %%G IN (disableServices.txt) DO sc config %%G start= disabled