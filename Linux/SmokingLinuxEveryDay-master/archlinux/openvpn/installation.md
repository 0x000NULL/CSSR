### OpenVPN installation
```bash
pacman -S openvpn easy-rsa
cp -R /usr/share/easy-rsa/ /etc/openvpn/easy-rsa
vim /etc/openvpn/easy-rsa/vars
```

* edit KEY_COUNTRY, KEY_PROVINCE, KEY_CITY, KEY_ORG, and KEY_EMAIL
```bash
source ./vars
./clean-all
```

```bash
./build-ca
```

```bash
Country Name (2 letter code) [US]:
State or Province Name (full name) [AT]:
Locality Name (eg, city) [City]:
Organization Name (eg, company) [Company]:
Organizational Unit Name (eg, section) [example]:
Common Name (eg, your name or your server's hostname) [example CA]: myname
Name [EasyRSA]:myname
Email Address [administration@example.com]:
```

```bash
./build-key-server server
```

* accept almost all defaults, care of common-name (set "server") and set password (optional)

```bash
./build-dh
```

```bash
./build-key-pass <username> (you may need to run 'source ./vars' first)
```

* accept almost all defaults, care of hostname, set password.
* cp the "ca.crt" and ALL the named to the client(s).

```bash
vim /etc/openvpn/vpnserver.conf
```

* ADD THESE AS CONTENTS:
```bash
### CONF FILE STARTS ###
port 1194
proto udp
dev tun0

ca /etc/openvpn/easy-rsa/keys/ca.crt
cert /etc/openvpn/easy-rsa/keys/certificate.crt
key /etc/openvpn/easy-rsa/keys/keyfile.key
dh /etc/openvpn/easy-rsa/keys/dh2048.pem

server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
keepalive 10 120
comp-lzo
user nobody
group nobody
persist-key
persist-tun
status /var/log/openvpn-status.log
verb 3

log-append /var/log/openvpn
status /tmp/vpn.status 10
### CONF FILE ENDS ###
```

```bash
systemctl start openvpn@vpnserver.service
systemctl enable openvpn@vpnserver.service
```

* At your client use something like this as conf:
* for WINDOWS: mind the whitespace at your path, you might
* want to use double quotes and backslashes.
e.g.: *key "C:\\Program Files\\OpenVPN\\config\\my-laptop.key"*

```bash
### CLIENT OPENVPN CONF FILE ###
client
remote <server> <port>
dev tun0
proto udp
resolv-retry infinite
nobind
persist-key
persist-tun
verb 2
ca /home/<username>/openvpn/certs/myca.crt
cert /home/<username>/openvpn/certs/mycrt.crt
key /home/<username>/openvpn/certs/mykey.key
comp-lzo
### CLIENT CONF FILE ENDS ###
```

* To tunnel all traffic through the VPN do the following:
```bash
vim /etc/sysctl.d/99-sysctl.conf
net.ipv4.ip_forward=1
vim /etc/openvpn/vpnserver.conf
push "redirect-gateway def1"
push "dhcp-option DNS 10.8.0.1"
```



