### MoinMoin
```bash
pacman -S nginx
pacman -S moinmoin uwsgi-plugin-python2
cp -R /usr/share/moin/data /usr/share/moin/underlay /usr/share/moin/config/wikiconfig.py /var/lib/moin/
chown -R http:http /var/lib/moin/
```

```bash
vim /var/lib/moin/uwsgi.ini
```

```bash
## CONF FILE STARTS ##
[uwsgi]
socket = /run/uwsgi/moin.sock
chmod-socket = 660
plugin = python2

chdir = /var/lib/moin/
wsgi-file = /usr/share/moin/server/moin.wsgi

master
workers = 3
max-requests = 200
harakiri = 60
die-on-term
## CONF FILE ENDS ##
```

```bash
uwsgi --uid 33 --gid 33 --ini /var/lib/moin/uwsgi.ini 
```

* You should check the output for errors. If no errors are found, ctrl-c
* uid and gid are the ones that correspond to the http user and group
* If you encounter permissions problems with this command, do a 
* "chown -R http:http /run/uwsgi/" and run it again

```bash
vim /etc/nginx/nginx.conf
```

### Add the following at the server field

```bash
## CONF FILE STARTS ##
server {
   listen       80;
   server_name  wiki.your.domain;

   location / {
      uwsgi_pass unix:/run/uwsgi/moin.sock;
      include /etc/nginx/uwsgi_params;
   }

   location /moin_static[0-9]+/(.*) {
      alias /usr/lib/python2.7/site-packages/MoinMoin/web/static/htdocs/$1;
   }

   location /favicon.ico {
      alias /usr/lib/python2.7/site-packages/MoinMoin/web/static/htdocs/favicon.ico;
   }
}
## CONF FILE ENDS ##
```

```bash
vim /etc/systemd/system/moinmoin.service
```

```bash
## CONF FILE STARTS ##
[Unit]
Description=Start uwsgi for moinmoin wiki
After=network.target

[Service]
Type=simple
User=http
ExecStart=/usr/bin/uwsgi --uid 33 --gid 33 --ini /var/lib/moin/uwsgi.ini

[Install]
WantedBy=multi-user.target
## CONF FILE ENDS ##
```

```bash
systemctl enable nginx
systemctl enable moinmoin
systemctl start nginx
systemctl start moinmoin
```

* browse at http://10.8.0.1/LanguageSetup?action=login
* create an account as "superuser" and passwd "0br3la"
* edit /var/lib/moin/wikiconfig.py and set superuser as superuser
* restart moinmoin service with 'systemctl restart moinmoin'
* login as superuser and follow the instructions to install
* page packages. Set language to english and install at least
* the essential category and restart the wiki again

```bash
vim /var/lib/moin/wikiconfig.py and uncomment page_front_page
```

