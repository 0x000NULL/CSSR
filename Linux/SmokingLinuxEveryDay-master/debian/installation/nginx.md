## Laravel + nginx (LEMP)

```bash
sudo apt install nginx
```

### MySQL

```bash
sudo apt-get install mysql-server
```

### Init MySQL db

```bash
mysql_install_db
```

### Secure MySQL configuration

```bash
mysql_secure_installation
```

### PHP

```bash
sudo apt install php-fpm php-mysql
```

### index.php

```bash
sudo nano /etc/nginx/sites-available/default
index index.html index.php index.htm index.nginx-debian.html;
```

### run php

```bash
location ~ \.php$ {
    include snippets/fastcgi-php.conf;
    fastcgi_pass unix:/run/php/php7.0-fpm.sock;
}

location ~ /\.ht {
    deny all;
}
```

### PHPMyAdmin

```bash
apt install phpmyadmin
ln -s /usr/share/phpmyadmin /var/www/html/phpmyadmin
sudo php5enmod mcrypt
sudo nano /var/lib/phpmyadmin/blowfish_secret.inc.php
```

### Virtual blocks

```
sudo mkdir -p /var/www/example.com/html
sudo chown -R user:user /var/www/example.com/html
sudo chmod -R 755 /var/www
nano /var/www/dev.com/html/index.html
sudo cp /etc/nginx/sites-available/default /etc/nginx/sites-available/example.com
```

```
sudo nano /etc/nginx/sites-available/example.com
listen 80;
listen [::]:80;
server_name example.com www.example.com;
root /var/www/example.com/html;
```

```
sudo ln -s /etc/nginx/sites-available/example.com /etc/nginx/sites-enabled/
```

### hosts

```
127.0.0.1   example.com
```

### Memory

```
sudo nano /etc/nginx/nginx.conf
server_names_hash_bucket_size 64;
```

### Restart

```bash
sudo systemctl restart php7.0-fpm.service
sudo systemctl restart nginx.service
```

