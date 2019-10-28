# A script to only be used by the Quinticorns, in Cyberpatriot XI or higher. If you use this script for Cyber Patriot, and your team is not the Quinticorns, you are breaking the rules... So don't...
echo "Starting Script"

# Enabling Firewall

echo "Attempting to Enable Firewall..."
apt-get install ufw
ufw enable
if (ufw status | grep -q Active)
then
  echo "Firewall Enabled."
else
  echo "ERROR: Firewall Not Enabled. Enable Manually."
fi

# Remove Telnet

echo "Attempting to remove Telnet..."
sudo apt-get remove --auto-remove telnet
echo "Removed Telnet, and it's dependancies."

# Update Bash

echo "Attempting to Update Bash..."
apt-get update
apt-get upgrade
apt-get install --only-upgrade bash
echo "Updated Bash (Double Check, because I really am not sure if it worked...)"

# Disabling Guest Account

echo "Attempting to disable Guest Account..."
cat << EOF > /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
greeter-session=unity-greeter
allow-guest=false
EOF
echo "Disabled Guest Account."

# Changing Password Policies

echo "Attempting to change Password Policies..."

cat << EOF > /etc/pam.d/common-password
password    [success=1 default=ignore]	pam_unix.so obscure sha512 remember=5 minlen=8 ocredit = -1 decredit = -1 lcredit = -1 ucredit = -1
password	requisite			pam_deny.so
password	required			pam_permit.so
password	optional	pam_gnome_keyring.so
EOF

cat << EOF > /etc/login.defs
FAILLOG_ENAB		yes
LOG_UNKFAIL_ENAB	no
LOG_OK_LOGINS		no
SYSLOG_SU_ENAB		yes
SYSLOG_SG_ENAB		yes
FTMP_FILE	/var/log/btmp
SU_NAME		su
HUSHLOGIN_FILE	.hushlogin
ENV_SUPATH	PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV_PATH	PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
TTYGROUP	tty
TTYPERM		0600
ERASECHAR	0177
KILLCHAR	025
UMASK		022
PASS_MAX_DAYS	30
PASS_MIN_DAYS	10
PASS_WARN_AGE	7
UID_MIN			 1000
UID_MAX			60000
GID_MIN			 1000
GID_MAX			60000
LOGIN_RETRIES		5
LOGIN_TIMEOUT		60
CHFN_RESTRICT		rwh
DEFAULT_HOME	yes
USERGROUPS_ENAB yes
ENCRYPT_METHOD SHA512
EOF

# Changing everyone's passwords

echo "Attempting to change every user password to 'B@NAn4S*RuL3'"
while IFS=: read u x nn rest; do  if [ $nn -ge 500 ]; then echo "B@NAn4S*RuL3" |passwd --stdin $u; fi  done < /etc/passwd
echo "Changed every user password to 'B@NAn4S*RuL3'"
