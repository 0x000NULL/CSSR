### Installation

```bash
apt-get install apache2 -y
rm -f /var/www/html/index.html
touch /var/www/html/index.html
a2enmod ssl
a2ensite default-ssl
service apache2 restart
```

### Redirect to https

```bash
<VirtualHost *:80>
...
...
Redirect permanent / https://example.com/
..
</VirtualHost>
```

or

```bash
RewriteEngine on
RewriteCond %{HTTPS} !=on
RewriteRule ^.*$ https://%{SERVER_NAME}%{REQUEST_URI} [R,L]
```

### Redirect to folder

```bash
<IfModule mod_rewrite.c>
RewriteEngine on
Options +FollowSymLinks
RewriteRule ^$ /foldername [L]
</IfModule>
```

