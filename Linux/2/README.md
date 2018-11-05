# OSHardening

In computing, hardening is usually the process of securing a system by reducing its surface of vulnerability, which is larger when a system performs more functions; in principle a single-function system is more secure than a multipurpose one. Reducing available ways of attack typically includes changing default passwords, the removal of unnecessary software, unnecessary usernames or logins, and the disabling or removal of unnecessary services.
Clone repository

Source: Wikipedia

## How to:

```
git clone https://github.com/NitescuLucian/OSHardening.git
```
Navigate to the repository folder
```
cd OSHardening
```
Choose your OS from the following:
* [Kali Linux](#kali-linux)
* [Ubuntu 16.04 LTS](#ubuntu-1604-lts)
* [Ubuntu 16.10](#ubuntu-1610)

## Contributing

1. Fork it
2. Create your feature branch (```git checkout -b my-new-feature```)
3. Commit your changes (```git commit -am 'Add some feature'```)
4. Push to the branch (```git push origin my-new-feature```)
5. Create new Pull Request

Donations at: https://www.paypal.me/LNitescu

## Kali Linux
Give execution permission to the fille.
```
chmod +x ./kali.sh
```
Execute.

```
./kali.sh
```
Review cli and log filles and make your changes according to your preferences.

In this OS I did not cover the following steps:
* Adding a non-root user (for penetration testing purposes).
* Closing open ports (iptables -A INPUT -p tcp --dport PORT_NUMBER -j DROP or UFW specific rules)
* Local encryption

Problems might be caused by:
* UFW Firewall rules for specific tools within the Kali Linux

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
