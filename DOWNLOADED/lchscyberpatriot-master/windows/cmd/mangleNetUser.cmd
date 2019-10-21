@echo off

del del.txt
net user > usernames.txt
findstr /v "The command completed" usernames.txt > usernames2.txt
FOR /F "tokens=1,2,3 skip=4" %%i in (usernames2.txt) do echo %%i >> del.txt & echo %%j >> del.txt & echo %%k >> del.txt
findstr /v "ECHO" del.txt > del2.txt
del usernames.txt
del usernames2.txt
del del.txt