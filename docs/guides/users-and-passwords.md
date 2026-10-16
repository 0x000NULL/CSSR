# Users and passwords

User problems are the most common vulnerabilities on an image, and the easiest points to get
wrong. Work from the README's lists (see [Reading the README](../getting-started/reading-the-readme.md)).

## 1. Find who is on the machine

=== "Windows"

    ```powershell
    Get-LocalUser | Format-Table Name, Enabled, PasswordRequired, PasswordExpires
    Get-LocalGroupMember Administrators
    ```

    Or open `lusrmgr.msc` (Local Users and Groups). On Home editions, use
    `netplwiz` or Settings > Accounts.

=== "Linux"

    ```bash
    # Human accounts: regular UIDs with a login shell
    awk -F: '$3 >= 1000 && $7 !~ /(nologin|false)$/ {print $1, $3, $7}' /etc/passwd
    # Anyone else with UID 0 is effectively root
    awk -F: '$3 == 0 {print $1}' /etc/passwd
    # Who can use sudo
    getent group sudo admin wheel
    ```

## 2. Remove or disable unauthorized accounts

Double-check the spelling against the README first. Deleting an authorized user is a penalty.

=== "Windows"

    ```powershell
    Remove-LocalUser -Name eve          # or: net user eve /delete
    Disable-LocalUser -Name Guest       # the Guest account should be disabled
    ```

=== "Linux"

    ```bash
    sudo deluser eve                    # add --remove-home only if the README allows it
    ```

    An extra account with UID 0 is a backdoor root account. Remove it, or give it a
    normal UID if the README says the person is authorized.

## 3. Fix administrator rights

Only the README's administrators should have admin rights. Everyone else becomes a standard
user. Change the group, not the account.

=== "Windows"

    ```powershell
    Remove-LocalGroupMember -Group Administrators -Member bob
    Add-LocalGroupMember -Group Administrators -Member alice
    ```

=== "Linux"

    ```bash
    sudo gpasswd -d bob sudo            # remove from sudo (also check admin/wheel)
    sudo usermod -aG sudo alice         # add to sudo
    sudo visudo                          # look for user-specific rules and NOPASSWD
    ls /etc/sudoers.d/                   # extra sudo rules can hide here
    ```

## 4. Give every user a strong password

Change the password of every authorized user except, usually, your own. Check the README;
some scenarios say not to change certain accounts.

=== "Windows"

    ```powershell
    net user bob *                      # prompts for the new password
    ```

=== "Linux"

    ```bash
    sudo passwd bob
    sudo passwd -l root                 # lock root's password if nobody should log in as root
    ```

## 5. Set the password and lockout policy

These values match the [audit scripts](../audit-scripts.md) and CIS Benchmark guidance.

| Setting | Value |
|---|---|
| Minimum length | 14 (10 is the bare minimum) |
| Complexity | Required (mix of upper, lower, digits, symbols) |
| Maximum age | 90 days |
| Minimum age | 1 day |
| History | Windows 24 passwords; Linux 5 |
| Lockout threshold | 5 failed attempts |
| Lockout duration / reset | 15 minutes |
| Reversible encryption (Windows) | Disabled |

The [Windows](windows-hardening.md#password-and-lockout-policy) and
[Linux](linux-hardening.md#password-policy) checklists show exactly where each setting lives.

## Things that hide

- **Windows:** accounts that don't appear on the logon screen, users whose password never
  expires or isn't required, and admin rights granted through nested groups.
- **Linux:** accounts with UID 0, users with an empty password field in `/etc/shadow`,
  `NOPASSWD` sudo rules, and users added to `sudo`, `adm` or other privileged groups.
