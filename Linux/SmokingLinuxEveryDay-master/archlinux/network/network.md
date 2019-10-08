### Static IP address with systemd

#### Create file at /etc/conf.d/net-conf-eth0
```bash
address=192.168.1.94
netmask=24
broadcast=192.168.1.255
gateway=192.168.1.254
```

#### Create script at /usr/local/bin/net-up.sh
```bash
#!/bin/bash
ip link set dev "$1" up
ip addr add ${address}/${netmask} broadcast ${broadcast} dev "$1"

[[ -z ${gateway} ]] || { 
  ip route add default via ${gateway}
}
```

#### Create script at /usr/local/bin/net-down.sh

```bash
#!/bin/bash
ip addr flush dev "$1"
ip route flush dev "$1"
ip link set dev "$1" down
```

#### Make them executable
```bash
chmod +x /usr/local/bin/net-{up,down}.sh
```

#### Create systemd service file at /etc/systemd/system/network@.service
```bash
[Unit]
Description=Network connectivity (%i)
Wants=network.target
Before=network.target
BindsTo=sys-subsystem-net-devices-%i.device
After=sys-subsystem-net-devices-%i.device

[Service]
Type=oneshot
RemainAfterExit=yes
EnvironmentFile=/etc/conf.d/net-conf-%i
ExecStart=/usr/local/bin/net-up.sh %i
ExecStop=/usr/local/bin/net-down.sh %i

[Install]
WantedBy=multi-user.target
```

#### Start and enable service
```bash
systemctl start network@eth0
systemctl enable network@eth0
```

### TCPDUMP

* Sniff HTTP traffic for a specific host

```bash
tcpdump -i tun0 -A -s 0 'src example.com and tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
```


