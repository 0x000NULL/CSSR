:: set standard windos account settings
net accounts /forcelogoff:60 /minpwlen:8 /maxpwage:90 /minpwage:1 /lockoutthreshold:4 /lockoutwindow:4 /lockoutduration:4

:: give every user a complex password
call ../mangleNetUser.cmd
FOR /F "delims==" %%G IN (del2.txt) DO net user %%G Compl3xPassw0rd!

:: deactivate Guest account
net user Guest /active:no