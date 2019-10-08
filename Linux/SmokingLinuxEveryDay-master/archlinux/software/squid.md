### Squid
```bash
#allow specific (VPN) addresses to access it
acl ip_acl src 10.8.0.0/24
http_access allow ip_acl
http_access deny all
```

```bash
squid -k check
squid -z
systemctl start squid
```

* at your client's browser you may now use 10.8.0.1:3128 as proxy
* after you have successfully connected to the VPN

