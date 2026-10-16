# Networking and Cisco

Some CyberPatriot divisions include a networking challenge: questions on networking concepts
plus a hands-on exercise in **Cisco Packet Tracer**, a free network simulator. Check the current
season's rules for what your division includes.

## Getting Packet Tracer

Packet Tracer and the free introductory courses come from the
[Cisco Networking Academy](https://www.netacad.com/). Create an account, enroll in a Packet
Tracer course, and download it from there.

## Topics to know

- **The OSI and TCP/IP models**, and which devices and protocols work at each layer
- **IPv4 addressing and subnetting**: CIDR notation, subnet masks, network and broadcast
  addresses, usable hosts. Practice until you can do it on paper.
- **IPv6 basics**: address format, link-local addresses
- **Switching**: MAC tables, VLANs, trunks, the spanning tree idea
- **Routing**: static routes, default routes, what a routing protocol does
- **Common ports and protocols**: SSH 22, Telnet 23, DNS 53, DHCP 67/68, HTTP 80, HTTPS 443,
  RDP 3389, SMB 445
- **Device security**: the commands below

## Securing a Cisco router or switch

The basics that come up again and again, in IOS configuration mode:

```text
enable
configure terminal
hostname R1
enable secret <strong-password>            ! hashed privileged-mode password (not "enable password")
service password-encryption                ! obscures any plain-text passwords in the config
security passwords min-length 10
banner motd ^Authorized access only^

username admin secret <strong-password>    ! local account for remote login
ip domain-name example.local
crypto key generate rsa modulus 2048       ! needed for SSH
ip ssh version 2

line console 0
 login local
 exec-timeout 5 0
line vty 0 4
 login local
 transport input ssh                        ! SSH only, no Telnet
 exec-timeout 5 0
end
copy running-config startup-config          ! save, or the changes are lost on reload
```

Also:

- Shut down unused switch ports (`interface range ...` then `shutdown`) and move them to an unused VLAN.
- Use `show running-config`, `show ip interface brief` and `show vlan brief` to check your work.

## Practice

- Packet Tracer activities in the Networking Academy courses
- Subnetting practice sites and worksheets: speed matters in a timed round
- Rebuild a small network from scratch (two routers, two switches, a few PCs), then secure it
  with the commands above
