# OSHardening

In computing, hardening is usually the process of securing a system by reducing its surface of vulnerability, which is larger when a system performs more functions; in principle a single-function system is more secure than a multipurpose one. Reducing available ways of attack typically includes changing default passwords, the removal of unnecessary software, unnecessary usernames or logins, and the disabling or removal of unnecessary services.
Clone repository

Source: Wikipedia

## Ubuntu 16.04 LTS
Give execution permission to the fille.
```
chmod +x ./ubuntu_16.04LTS.sh
```
Execute.
```
sudo ./ubuntu_16.04LTS.sh
```
Review cli and log filles and make your changes according to your preferences.

In this OS I did not cover the following steps:
* Closing open ports (iptables -A INPUT -p tcp --dport PORT_NUMBER -j DROP or UFW specific rules)
* Local encryption


## Ubuntu 16.10
Give execution permission to the fille.
```
chmod +x ./ubuntu_16.10.sh
```
Execute.
```
sudo ./ubuntu_16.10.sh
```
Review cli and log filles and make your changes according to your preferences.

In this OS I did not cover the following steps:
* Closing open ports (iptables -A INPUT -p tcp --dport PORT_NUMBER -j DROP or UFW specific rules)
* Local encryption
