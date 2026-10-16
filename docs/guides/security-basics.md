# Security basics

Hardening an image is easier when you know *why* each fix matters. Almost every vulnerability
you'll fix threatens one of three things.

## The CIA triad

**Confidentiality**: only the right people can see information.
:   Threats: unauthorized accounts, weak or shared passwords, files readable by everyone,
    anonymous network access. Fixes: remove extra users, strong password policy, correct file
    permissions, encryption.

**Integrity**: information and programs aren't changed by the wrong people.
:   Threats: users with admin rights they don't need, writable system files, backdoored
    programs, malicious startup entries. Fixes: least privilege, file permissions, checking
    that system binaries are genuine, auditing.

**Availability**: systems and data are there when people need them.
:   Threats: malware, missing updates, misconfigured services, no backups. Fixes: updates,
    antivirus, keeping critical services running.

When you're unsure whether a change helps, ask which of the three it protects, and whether it
hurts availability for the services the README needs.

## Principles you'll use all the time

- **Least privilege.** Every user and program gets only the rights it needs. Standard users
  shouldn't be administrators, and services shouldn't run as root/SYSTEM if they don't have to.
- **Minimize attack surface.** Every installed program, open port and running service is
  something an attacker can use. Remove what the scenario doesn't need.
- **Defense in depth.** Use several layers (firewall, updates, antivirus, strong passwords) so
  one failure isn't fatal.
- **Secure defaults, then exceptions.** Block inbound traffic by default and allow only what's
  required. Deny by default, allow on purpose.
- **Logging and auditing.** You can't investigate what you didn't record. Turn on audit
  policies and keep logs.

## What an attacker leaves behind

Competition images are often "pre-compromised". Common signs:

| Sign | Where to look |
|---|---|
| Extra or hidden accounts, unexpected admins | User lists, admin groups, UID 0 on Linux |
| Programs that start automatically | Windows Run keys, scheduled tasks, services; Linux cron, systemd units |
| A program listening on an odd port | `netstat -ano` / `Get-NetTCPConnection`, `ss -tulpn` |
| Replaced system programs | Accessibility tools (sticky keys) on Windows, binaries in odd places on Linux |
| Changed name resolution | The `hosts` file |
| Weakened security settings | Firewall off, antivirus exclusions, UAC off, password policy blank |

## Passwords and password managers

Long passphrases beat short complex passwords. `correct-horse-battery-staple` is easier to
remember and harder to crack than `P@ssw0rd!`. In real life, use a password manager so every
account gets a unique random password, and turn on multi-factor authentication wherever you can.
In the competition, follow the README. It sometimes tells you exactly which passwords to keep.
