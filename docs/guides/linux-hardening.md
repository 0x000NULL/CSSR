# Linux hardening checklist

For Ubuntu 22.04/24.04; Debian and Linux Mint are very similar. Work top to bottom, check your
score after each section, and keep the README open. Bracketed IDs such as `[LNX-PWD-01]` match
the [audit script](../audit-scripts.md), so you can confirm each fix by re-running it.

!!! tip "Before you start"
    1. Read the README and write down users, admins and critical services.
    2. Answer the forensics questions.
    3. Open a terminal and keep a root shell open the whole time (`sudo -i`), especially while
       editing PAM or sudo settings. If you break authentication, you can still fix it from there.

## Accounts

- [ ] Remove users who aren't in the README: `sudo deluser NAME` `[LNX-USR-03]`
- [ ] Create authorized users who are missing, if the README asks: `sudo adduser NAME` `[LNX-USR-04]`
- [ ] No account besides root has UID 0: `awk -F: '$3==0' /etc/passwd` `[LNX-USR-01]`
- [ ] Only README admins are in `sudo` (and `admin`/`wheel`):
  `getent group sudo`, `sudo gpasswd -d NAME sudo` `[LNX-USR-05]`
- [ ] No `NOPASSWD` or `!authenticate` rules: `sudo visudo`, plus everything in `/etc/sudoers.d/` `[LNX-USR-06]`
- [ ] No empty passwords: `sudo awk -F: '$2==""' /etc/shadow` `[LNX-USR-02]`
- [ ] Every user except your own gets a strong password: `sudo passwd NAME`
- [ ] No guest session or automatic login `[LNX-USR-07]`:
    - LightDM (Mint, Xubuntu): `allow-guest=false` under `[Seat:*]` in `/etc/lightdm/lightdm.conf`, and no `autologin-user=`
    - GDM (Ubuntu): `AutomaticLoginEnable=false` in `/etc/gdm3/custom.conf`

See [Users and passwords](users-and-passwords.md) for details.

## Password policy

**Password aging** in `/etc/login.defs`. These only apply to *new* accounts:

```text
PASS_MAX_DAYS   90
PASS_MIN_DAYS   1
PASS_WARN_AGE   7
```

`[LNX-PWD-01]` `[LNX-PWD-02]` `[LNX-PWD-03]`. Apply the same values to existing users `[LNX-PWD-04]`:

```bash
for u in $(awk -F: '$3>=1000 && $7 !~ /(nologin|false)$/ {print $1}' /etc/passwd); do
  sudo chage -M 90 -m 1 -W 7 "$u"
done
```

**Length and complexity** with `pam_pwquality` `[LNX-PWD-05]` `[LNX-PWD-06]`:

```bash
sudo apt install libpam-pwquality     # adds pam_pwquality to /etc/pam.d/common-password
```

Then set in `/etc/security/pwquality.conf`:

```text
minlen = 14
minclass = 4
```

**History** `[LNX-PWD-07]`: add `remember=5` to the end of the `pam_unix.so` line in
`/etc/pam.d/common-password`. Alternatively, add the line
`password required pam_pwhistory.so remember=5 use_authtok` just above it.

**No empty passwords** `[LNX-PWD-08]`: remove `nullok` from the `pam_unix.so` line in
`/etc/pam.d/common-auth`.

**Account lockout** `[LNX-PWD-09]` with `pam_faillock`. On Ubuntu the safest way is two small
`pam-auth-update` profiles rather than hand-editing `common-auth`:

```text
# /usr/share/pam-configs/faillock
Name: Enable pam_faillock to deny access
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
	[default=die]	pam_faillock.so authfail
```

```text
# /usr/share/pam-configs/faillock_notify
Name: Notify of failed login attempts and reset count upon success
Default: yes
Priority: 1024
Auth-Type: Primary
Auth:
	requisite	pam_faillock.so preauth
Account-Type: Primary
Account:
	required	pam_faillock.so
```

```bash
sudo pam-auth-update --enable faillock faillock_notify
```

Then set in `/etc/security/faillock.conf`:

```text
deny = 5
unlock_time = 900
```

!!! warning
    Test in a **new** terminal (`su - someuser`) before closing your root shell. If logins break,
    run `sudo pam-auth-update` from the root shell and untick the profiles.

## SSH

Only if SSH is installed. Remove it if the README doesn't need it: `sudo apt purge openssh-server`.

In `/etc/ssh/sshd_config`, or a file in `/etc/ssh/sshd_config.d/` (those are read first, and the
first value found wins):

```text
PermitRootLogin no            # [LNX-SSH-01]
PermitEmptyPasswords no       # [LNX-SSH-02]
X11Forwarding no              # [LNX-SSH-03]
MaxAuthTries 4                # [LNX-SSH-04]
```

```bash
sudo sshd -t && sudo systemctl restart ssh    # -t checks the config before restarting
sudo sshd -T | grep -Ei 'permitrootlogin|permitemptypasswords|x11forwarding|maxauthtries'
```

Also look for unexpected keys in `~/.ssh/authorized_keys` for every user, root included:
`sudo find / -name authorized_keys 2>/dev/null`.

## Firewall

```bash
sudo apt install ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH        # only for critical services from the README, before enabling
sudo ufw enable
sudo ufw status verbose
```

`[LNX-FW-01]` `[LNX-FW-02]`

## Updates

```bash
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades     # creates /etc/apt/apt.conf.d/20auto-upgrades
sudo apt update && sudo apt upgrade
```

`[LNX-UPD-01]` `[LNX-UPD-02]` `[LNX-UPD-03]`. In the desktop, **Software & Updates > Updates**
does the same: check daily, and download and install security updates automatically. Look at
`/etc/apt/sources.list` and `/etc/apt/sources.list.d/` for unknown repositories first
`[LNX-NET-05]`.

## Kernel parameters

Create `/etc/sysctl.d/99-cssr.conf` `[LNX-KRN-01]`…`[LNX-KRN-09]`:

```text
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
kernel.randomize_va_space = 2
fs.suid_dumpable = 0
```

```bash
sudo sysctl --system
```

If the machine is a router or VPN server in the scenario, it needs `ip_forward = 1`. Check the README.

## Auditing

```bash
sudo apt install auditd && sudo systemctl enable --now auditd     # [LNX-AUD-01]
sudo aa-status                                                     # AppArmor [LNX-AUD-02]
```

## Services and software

- [ ] Disable services the README doesn't need `[LNX-SVC-01]`:
  `systemctl list-units --type=service --state=running`, then
  `sudo systemctl disable --now NAME` (and `sudo apt purge PACKAGE`).
  Usual suspects: telnet, FTP servers, Apache/nginx, Samba, NFS, SNMP, rsh, avahi.
- [ ] Remove hacking tools, games and torrent clients `[LNX-PKG-01]` `[LNX-PKG-02]`.
- [ ] Delete prohibited media files under `/home`, after the forensics questions `[LNX-FIL-01]`.

See [Services and software](services-and-software.md).

## File permissions

```bash
sudo chown root:shadow /etc/shadow && sudo chmod 640 /etc/shadow           # [LNX-FIL-02]
sudo chown root:root /etc/passwd /etc/group && sudo chmod 644 /etc/passwd /etc/group   # [LNX-FIL-03]
sudo find /etc -xdev -type f -perm -0002                                    # [LNX-FIL-04]
```

## Backdoors and persistence

- [ ] **Listening ports**: `sudo ss -tulpn` `[LNX-NET-01]`. A `nc`, `ncat` or `socat` listener is
  almost always a backdoor `[LNX-NET-02]`. Find what starts it before you kill it, or it comes back.
- [ ] **Cron**: `/etc/crontab`, `/etc/cron.d/`, `/etc/cron.{hourly,daily,weekly,monthly}/`, and
  every user's crontab: `sudo crontab -l -u NAME` `[LNX-NET-04]`.
- [ ] **systemd**: unknown units in `/etc/systemd/system/` and timers in `systemctl list-timers`.
- [ ] **Shell startup files**: odd lines in `/etc/profile`, `/etc/bash.bashrc`, `~/.bashrc` and
  `~/.profile`, and in `/etc/rc.local` if it exists.
- [ ] **hosts file**: surprise entries in `/etc/hosts` `[LNX-NET-03]`.
- [ ] **SUID programs**: `sudo find / -xdev -perm -4000 -type f 2>/dev/null`. Anything outside
  the usual system binaries (for example a SUID copy of a shell or an editor) is suspicious.

## Finally

- [ ] Re-run the [audit script](../audit-scripts.md) and work through what's left.
- [ ] Re-read the README for anything specific to this scenario.
