# Legacy toolkit (2018–2019)

> [!WARNING]
> **These scripts are not maintained, and they change your system without asking.** They were
> written for Ubuntu 16.04/16.10, Windows 7/8/10 and Server 2008/2016 images from CyberPatriot
> seasons X–XII. On a current image they can delete files you need, disable services the
> README requires, change every user's password, or lock you out.
>
> For current images, use the check-only audit scripts in [`audit/`](../audit/). They report
> problems and show the fix, and they change nothing.

They're kept as a record of what the team actually ran. If you run any of them anyway:

1. Read the whole script first.
2. Answer the forensics questions **before** running anything. These scripts delete media
   files and rewrite configs, and that can destroy the evidence.
3. Snapshot the VM so you can roll back.
4. Run the pieces one at a time, not the whole runner.

## What's here

| Path | Author | License | What it does |
|---|---|---|---|
| `linux/runme.sh` | Ethan Aldrich | MIT (repo license) | Runs `dofirst`, `nixarmor`, then `oshardening`, then sets security sysctls |
| `linux/dofirst/` | Ethan Perry, Andy Lyu ([Wellesley](https://github.com/BaiqingL/CyberPatriotScripts)) | MIT (`LICENSE`) | Ubuntu users, passwords, updates, SSH/LightDM configs from `referenceFiles/` |
| `linux/nixarmor/` | Emir Ozer ([nixarmor](https://github.com/emirozer/nixarmor)) | GPL-3.0 (`LICENSE`) | Debian/Ubuntu/CentOS/Fedora hardening |
| `linux/oshardening/` | Lucian Nitescu ([OSHardening](https://github.com/NitescuLucian/OSHardening)) | LGPL-3.0 (`COPYING`, `COPYING.LESSER`) | Ubuntu 16.04 / 16.10 hardening and log collection |
| `windows/RUNME.bat` | Ethan Aldrich | MIT (repo license) | Menu that runs the DOFIRST scripts, one Gucci script and two debloat scripts |
| `windows/*GucciScript.bat`, `windows/*CompFiles/` | Ethan Aldrich's team | MIT (repo license) | Menu-driven hardening per OS: security templates (`.inf`), audit policy, users, passwords, firewall (`.wfw`), services, media files, hosts file |
| `windows/OurGloriousChecklist2018_Windows.txt` | Ethan Aldrich's team | MIT (repo license) | The team's 2018 Windows checklist |
| `windows/ezscript-old.ps1` | Ethan Aldrich | MIT (repo license) | An unfinished PowerShell port of `RUNME.bat`. It doesn't run as-is. |
| `windows/files/DOFIRST/` | Wellesley team ([CyberPatriotScripts](https://github.com/BaiqingL/CyberPatriotScripts)) | MPL-2.0 (`LICENSE`) | `FirstRun.bat` and `Main.bat`: policies, registry, services, users |
| `windows/files/scripts/`, `windows/files/lib/` | W4RH4WK ([Debloat-Windows-10](https://github.com/W4RH4WK/Debloat-Windows-10)) | Beerware (`scripts/LICENSE`) | `block-telemetry.ps1`, `disable-services.ps1` (edit the list first) |

## Changes made in 2026

These changes make the scripts safer and keep the remaining paths working:

- **Removed a backdoor.** The Gucci scripts replaced `sethc.exe` with `cmd.exe` (the "sticky
  keys" trick), which gives anyone at the login screen a SYSTEM shell. That block is gone. The
  new audit script flags it if you find it on an image.
- **No shared passwords.** The Gucci scripts and the Wellesley `Main.bat` each set every user
  to the same hard-coded password, published right in the script. Both now ask for a
  password once per run.
- **Paths fixed.** The Gucci scripts now find their `*CompFiles` folder even when started from
  another folder or after they `cd` to the drive root. `RUNME.bat` jumped to labels that didn't
  exist and called `clear`, which isn't a cmd command. Both are fixed.
- **Media deletion is limited to `C:\Users`.** It used to delete every `.mp3`, `.mid`, `.wma`
  and so on across the whole drive, including Windows' own sound files.
- **Linux runner.** `runme.sh` had a syntax error and never finished. It also turned off TCP
  SACK and IPv6 and changed buffer sizes and swappiness, which is performance tuning, not
  hardening. Those lines were removed and the security sysctls kept.
- **Credit restored.** `dofirst/main.sh` had lost its copyright line, and it's back.
- **Bundled tools removed** (licensing and size). The scripts now print where to get them:

| Tool | Where to get it now |
|---|---|
| LGPO and Microsoft security baselines | [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319) |
| CIS-CAT Lite | [cisecurity.org](https://learn.cisecurity.org/cis-cat-lite) |
| hardentools | [securitywithoutborders/hardentools releases](https://github.com/securitywithoutborders/hardentools/releases) |
| Autoruns, Process Explorer | [Sysinternals](https://learn.microsoft.com/sysinternals/) |
| Microsoft Safety Scanner (`msert.exe`) | [Microsoft Learn](https://learn.microsoft.com/defender-endpoint/safety-scanner-download) |
| EMET, MBSA | Retired by Microsoft. Windows 10+ has Exploit Protection built in. |
| `ntrights.exe`, the bundled `Dism` copy | Not needed on current Windows. `Main.bat` reports errors for those steps. |

Everything else that used to sit next to these files is credited on the
[credits page](../docs/credits.md).
