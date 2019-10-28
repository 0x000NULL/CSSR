iex "reg add 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' /v AUOptions /t REG_DWORD /d 0 /f"
iex "NetSh Advfirewall set allprofiles state on"
Set-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost"

$formats = "mp3", "png", "jpg", "avi", "bmp", "mp4", "wav", "wmv"
Foreach($ending in $formats)
{
    Get-ChildItem -Path "C:\Users" -Filter *.$ending -Recurse -File -Name| ForEach-Object {
        if ((Split-Path -Path $_ -Parent) -notlike "*$env:USERNAME*") {
            $path = $_
            $path -replace "C:\Users\$env:USERNAME"
        
            Remove-Item -Path "C:\Users\$path"
        }
    }
}