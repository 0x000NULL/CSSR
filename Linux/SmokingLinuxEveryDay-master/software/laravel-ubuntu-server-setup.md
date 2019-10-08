## Laravel - Ubuntu Server 18.04

### Apache & PHP

```
sudo apt install apache2
sudo apt install php libapache2-mod-php
```

---

### PHP mbstring, xml and zip extensions

```
sudo nano /etc/apt/sources.list
```

```
deb http://archive.ubuntu.com/ubuntu bionic main universe
deb http://archive.ubuntu.com/ubuntu bionic-security main universe
deb http://archive.ubuntu.com/ubuntu bionic-updates main universe
```

```
sudo apt update
sudo apt install php-mbstring php-xml php-zip
```

---

### Composer

```
sudo apt install curl php-cli git unzip
sudo systemctl restart apache2
cd ~
curl -sS https://getcomposer.org/installer -o composer-setup.php
sudo php composer-setup.php --install-dir=/usr/local/bin --filename=composer
```

---

### Laravel

```
sudo chown -R $USER ~/.composer/
composer global require "laravel/installer"
```

**Add to $PATH - Temporary**

```
export PATH="$PATH:$HOME/.composer/vendor/bin"
```

**Add to $PATH - Permanently**

```
echo 'export PATH="$PATH:$HOME/.composer/vendor/bin"' >> ~/.bashrc
source ~/.bashrc
```

**New Application**

```
laravel new blog
```

### Server Configuration

**Web server's document / web root**

```
sudo nano /etc/apache2/sites-available/000-default.conf
```

```
DocumentRoot /home/user/blog/public
```


```
sudo nano /etc/apache2/apache2.conf
```

```
<Directory /home/user/blog/public/>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
</Directory>
```

**Permissions**

```
sudo chgrp -R www-data /home/user/blog/public
sudo chgrp -R www-data /home/user/blog/storage
sudo chgrp -R www-data /home/user/blog/bootstrap/cache

sudo chmod -R 775 /home/user/blog/storage
sudo chmod -R 775 /home/user/blog/bootstrap/cache
```

**Apache modules**

```
sudo a2enmod rewrite
sudo systemctl restart apache2
```

---
