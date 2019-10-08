### Installation

```bash
apt-get install mysql-server
mysql_install_db
mysql_secure_installation
```

### Init database and User

```bash
mysql -u root -p
create user 'username'@'%' identified by 'user-password';
create database mydatabase;
grant all privileges on mydatabase.* to 'username'@'%';
exit
```

### Reset mysql root password

```bash
systemctl stop mysql
mysqld_safe --skip-grant-tables --skip-networking &
mysql -u root
ALTER USER 'root'@'localhost' IDENTIFIED BY 'new_password';
FLUSH PRIVILEGES;
kill `cat /var/run/mysqld/mysqld.pid`
systemctl start mysql
```

