# Reading the README

Every image has a README, usually a shortcut on the desktop that opens a web page. It is the
**most important document in the round**: it tells you what "secure" means for this machine.
Read it twice before you change anything, and come back to it whenever you're unsure.

## What to pull out of it

Write these down. The [audit scripts](../audit-scripts.md) take the first two as input files.

| Item | Why it matters |
|---|---|
| **Authorized users** | Anyone else with an account probably shouldn't have one. Deleting an authorized user costs points. |
| **Administrators** | Only these users should have admin (Windows Administrators group, Linux `sudo`). Everyone else on the list stays as a standard user. |
| **Critical services** | Services the business depends on, such as a web server, file shares, SSH or remote desktop. Secure them, don't remove them. Breaking one is a penalty. |
| **Required software** | Programs that must stay installed, and sometimes must be updated. |
| **Forbidden things** | "No games", "no media files", "no hacking tools": the README often says what's against company policy. |
| **Special instructions** | Odd rules like a user who must keep a specific password, or a share that must stay open. |

## Common traps

- **A user is listed, but under a slightly different name.** Compare names carefully; a
  look-alike account (for example `jsmlth` next to `jsmith`) may be the unauthorized one.
- **A listed user is missing.** Sometimes you're expected to create them.
- **Someone is an administrator who shouldn't be,** or the other way around. Fix group
  membership, don't delete the account.
- **A "critical service" is installed but insecure.** Keep it running, but harden its
  configuration, for example SSH without root login.
- **A program is "required" but outdated.** Update it rather than uninstalling it.
- **Your own account.** The README usually says which account you're logged in as. Don't lock
  yourself out by changing its password or rights carelessly. Some READMEs say not to change it
  at all.

## Turning the README into lists

Make two text files, one name per line:

```text
# users.txt: every authorized user, administrators included
alice
bob
carol
```

```text
# admins.txt: just the administrators
alice
```

Then run the [audit script](../audit-scripts.md) with `--users users.txt --admins admins.txt`
(Linux) or `-UsersFile users.txt -AdminsFile admins.txt` (Windows) to compare the machine
against them.
