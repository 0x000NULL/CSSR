# Audit scripts

CSSR ships two **check-only** audit scripts, one for Linux and one for Windows. They look for the
kinds of problems CyberPatriot images are scored on and print the command that would fix each one.
They never change anything, so nothing breaks behind your back and you learn the fix by running it.

!!! warning "Check the competition rules"
    Check the current CyberPatriot rules about outside tools and downloads before using
    these during a round. Practice with them on practice images first.

## Running them

1. Copy the authorized users and administrators from the image's README into two text files,
   one name per line (`#` starts a comment). Put administrators in both files.
2. Answer the forensics questions first. Fixing things can destroy the evidence they ask about.
3. Run the audit, work through the `FAIL` lines, then the `WARN` lines, and run it again.

=== "Linux"

    ```bash
    curl -fsSLO https://raw.githubusercontent.com/0x000NULL/CSSR/master/audit/linux/cssr-audit.sh
    chmod +x cssr-audit.sh
    sudo ./cssr-audit.sh --users users.txt --admins admins.txt
    ```

=== "Windows"

    In an elevated PowerShell:

    ```powershell
    Invoke-WebRequest https://raw.githubusercontent.com/0x000NULL/CSSR/master/audit/windows/CSSR-Audit.ps1 -OutFile CSSR-Audit.ps1
    powershell -ExecutionPolicy Bypass -File .\CSSR-Audit.ps1 -UsersFile users.txt -AdminsFile admins.txt
    ```

Every finding has a status:

| Status | Meaning |
|---|---|
| `FAIL` | Almost always a scored vulnerability. Fix it unless the README says otherwise. |
| `WARN` | Probably a problem, but it depends on the scenario. Check the README. |
| `INFO` | Something to review by hand, such as listening ports or startup programs. |
| `PASS` | Looks right. |
| `SKIP` | Couldn't check: not elevated, the feature isn't installed, or no user list was given. |

The README always wins over the audit. If it says a service is critical or a program is
required, leave it alone.

Options, exit codes and JSON output are described in the
[audit README](https://github.com/0x000NULL/CSSR/tree/master/audit).

## Linux checks

These tables are generated from the scripts (`--list-checks --markdown`), and CI fails if they
drift.

<!-- BEGIN LINUX CHECKS -->
| ID | Category | Check |
|---|---|---|
| `LNX-USR-01` | Users | No account other than root has UID 0 |
| `LNX-USR-02` | Users | No account has an empty password |
| `LNX-USR-03` | Users | Every human account is an authorized user (--users) |
| `LNX-USR-04` | Users | Every authorized user exists (--users) |
| `LNX-USR-05` | Users | Only authorized admins are in sudo/admin/wheel (--admins) |
| `LNX-USR-06` | Users | sudoers has no NOPASSWD or !authenticate rules |
| `LNX-USR-07` | Users | No guest session or automatic login (LightDM/GDM) |
| `LNX-PWD-01` | Passwords | PASS_MAX_DAYS <= 90 in /etc/login.defs |
| `LNX-PWD-02` | Passwords | PASS_MIN_DAYS >= 1 in /etc/login.defs |
| `LNX-PWD-03` | Passwords | PASS_WARN_AGE >= 7 in /etc/login.defs |
| `LNX-PWD-04` | Passwords | Existing users' passwords expire within 90 days |
| `LNX-PWD-05` | Passwords | pam_pwquality is enabled with minlen >= 14 |
| `LNX-PWD-06` | Passwords | Password complexity requires several character classes |
| `LNX-PWD-07` | Passwords | Password history remembers >= 5 passwords |
| `LNX-PWD-08` | Passwords | pam_unix does not allow empty passwords (nullok) |
| `LNX-PWD-09` | Passwords | Account lockout (pam_faillock) after <= 5 failures |
| `LNX-SSH-01` | SSH | PermitRootLogin no |
| `LNX-SSH-02` | SSH | PermitEmptyPasswords no |
| `LNX-SSH-03` | SSH | X11Forwarding no |
| `LNX-SSH-04` | SSH | MaxAuthTries <= 4 |
| `LNX-FW-01` | Firewall | UFW is installed and active |
| `LNX-FW-02` | Firewall | UFW denies incoming traffic by default |
| `LNX-UPD-01` | Updates | Package lists are refreshed automatically |
| `LNX-UPD-02` | Updates | Unattended security upgrades are enabled |
| `LNX-UPD-03` | Updates | No upgradable packages in the local apt cache |
| `LNX-KRN-01` | Kernel | TCP SYN cookies on (net.ipv4.tcp_syncookies=1) |
| `LNX-KRN-02` | Kernel | IP forwarding off (net.ipv4.ip_forward=0) |
| `LNX-KRN-03` | Kernel | ICMP redirects ignored (accept_redirects=0) |
| `LNX-KRN-04` | Kernel | ICMP redirects not sent (send_redirects=0) |
| `LNX-KRN-05` | Kernel | Source-routed packets rejected (accept_source_route=0) |
| `LNX-KRN-06` | Kernel | Reverse path filtering on (rp_filter=1) |
| `LNX-KRN-07` | Kernel | Full ASLR (kernel.randomize_va_space=2) |
| `LNX-KRN-08` | Kernel | No core dumps from setuid programs (fs.suid_dumpable=0) |
| `LNX-KRN-09` | Kernel | Martian packets logged (log_martians=1) |
| `LNX-AUD-01` | Auditing | auditd is running |
| `LNX-AUD-02` | Auditing | AppArmor is enabled |
| `LNX-SVC-01` | Services | No commonly-unwanted network services are running |
| `LNX-PKG-01` | Software | No hacking tools are installed |
| `LNX-PKG-02` | Software | No games or torrent clients are installed |
| `LNX-FIL-01` | Files | No media files in /home |
| `LNX-FIL-02` | Files | /etc/shadow is owned by root and not world-readable |
| `LNX-FIL-03` | Files | /etc/passwd and /etc/group are root-owned and not writable by others |
| `LNX-FIL-04` | Files | No world-writable files in /etc |
| `LNX-NET-01` | Network | Listening ports (review against the README) |
| `LNX-NET-02` | Network | No netcat or socat listeners |
| `LNX-NET-03` | Network | /etc/hosts has only default entries |
| `LNX-NET-04` | Network | Cron jobs (review for persistence) |
| `LNX-NET-05` | Network | APT sources are official repositories |
<!-- END LINUX CHECKS -->

## Windows checks

<!-- BEGIN WINDOWS CHECKS -->
| ID | Category | Check |
|---|---|---|
| `WIN-ACC-01` | Accounts | Guest account is disabled |
| `WIN-ACC-02` | Accounts | Built-in Administrator account is disabled |
| `WIN-ACC-03` | Accounts | Every enabled local user is authorized (-UsersFile) |
| `WIN-ACC-04` | Accounts | Every authorized user exists (-UsersFile) |
| `WIN-ACC-05` | Accounts | Only authorized admins are in Administrators (-AdminsFile) |
| `WIN-ACC-06` | Accounts | No enabled user has a password that never expires |
| `WIN-ACC-07` | Accounts | Every enabled user is required to have a password |
| `WIN-POL-01` | Policy | Minimum password length >= 14 |
| `WIN-POL-02` | Policy | Password complexity is required |
| `WIN-POL-03` | Policy | Maximum password age is 1-90 days |
| `WIN-POL-04` | Policy | Minimum password age >= 1 day |
| `WIN-POL-05` | Policy | Password history remembers >= 24 passwords |
| `WIN-POL-06` | Policy | Passwords are not stored with reversible encryption |
| `WIN-POL-07` | Policy | Account lockout threshold is 1-5 attempts |
| `WIN-POL-08` | Policy | Account lockout duration >= 15 minutes |
| `WIN-POL-09` | Policy | Lockout counter resets after >= 15 minutes |
| `WIN-AUD-01` | Auditing | Key audit subcategories log success/failure |
| `WIN-SEC-01` | Security options | Blank passwords only work at the console |
| `WIN-SEC-02` | Security options | UAC is on and prompts administrators on the secure desktop |
| `WIN-SEC-03` | Security options | Anonymous users cannot enumerate accounts and shares |
| `WIN-SEC-04` | Security options | No LM hashes are stored and only NTLMv2 is sent |
| `WIN-SEC-05` | Security options | Logon screen hides the last user and requires Ctrl+Alt+Del |
| `WIN-SEC-06` | Security options | AutoRun is disabled for all drives |
| `WIN-NET-01` | Network | Windows Firewall is on for every profile |
| `WIN-NET-02` | Network | Windows Firewall blocks inbound connections by default |
| `WIN-NET-03` | Network | SMBv1 is disabled |
| `WIN-NET-04` | Network | Remote Desktop requires Network Level Authentication when on |
| `WIN-NET-05` | Network | No non-default file shares |
| `WIN-DEF-01` | Defender | Microsoft Defender real-time protection is on |
| `WIN-DEF-02` | Defender | Defender signatures are less than 7 days old |
| `WIN-DEF-03` | Defender | Defender has no exclusions |
| `WIN-UPD-01` | Updates | Windows Update is not disabled |
| `WIN-UPD-02` | Updates | An update was installed in the last 60 days |
| `WIN-SVC-01` | Services | No commonly-unwanted services are running |
| `WIN-SW-01` | Software | No hacking tools, P2P or remote-access programs installed |
| `WIN-FIL-01` | Files | No media files in user folders |
| `WIN-BKD-01` | Backdoors | Logon-screen accessibility programs are genuine |
| `WIN-BKD-02` | Backdoors | No debugger hijacks on accessibility programs (IFEO) |
| `WIN-BKD-03` | Backdoors | hosts file has only default entries |
| `WIN-INF-01` | Persistence | Startup programs (Run keys) for review |
| `WIN-INF-02` | Persistence | Non-Microsoft scheduled tasks for review |
<!-- END WINDOWS CHECKS -->
