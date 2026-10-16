# CSSR audit scripts

Check-only audits for CyberPatriot-style images. Each one lists what looks wrong and prints
the command that would fix it. **Neither script changes anything**, so you decide each fix
and learn what it does along the way.

| Script | Targets | Needs |
|---|---|---|
| [`linux/cssr-audit.sh`](linux/cssr-audit.sh) | Ubuntu 22.04/24.04. Debian 12 and Linux Mint work on a best-effort basis. | bash; run with `sudo` for every check |
| [`windows/CSSR-Audit.ps1`](windows/CSSR-Audit.ps1) | Windows 10/11, Server 2019/2022/2025 | Windows PowerShell 5.1+; run elevated for every check |

> Check the current CyberPatriot rules before using any outside tool or downloading files
> during a competition round. Practice with these on practice images first.

## Quick start

1. Copy the authorized users and administrators from the image's README into two text files,
   one name per line. [`examples/`](examples/) has a template. Put administrators in both
   files.
2. Run the audit.

**Linux**

```bash
curl -fsSLO https://raw.githubusercontent.com/0x000NULL/CSSR/master/audit/linux/cssr-audit.sh
chmod +x cssr-audit.sh
sudo ./cssr-audit.sh --users users.txt --admins admins.txt
```

**Windows** (in an elevated PowerShell)

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/0x000NULL/CSSR/master/audit/windows/CSSR-Audit.ps1 -OutFile CSSR-Audit.ps1
powershell -ExecutionPolicy Bypass -File .\CSSR-Audit.ps1 -UsersFile users.txt -AdminsFile admins.txt
```

## Reading the output

```
[FAIL] LNX-PWD-01  PASS_MAX_DAYS is 99999.
       fix: sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
```

| Status | Meaning |
|---|---|
| `FAIL` | Almost always a scored vulnerability. Fix it unless the README says otherwise. |
| `WARN` | Probably a problem, but it depends on the scenario. Check the README. |
| `INFO` | Something to review by hand, such as listening ports or startup programs. |
| `PASS` | Looks right. |
| `SKIP` | Couldn't check: not elevated, the feature isn't installed, or no user list was given. |

The README always wins. If it says a service is critical or a tool is required, leave it
alone even if the audit flags it.

## Options

| Linux | Windows | What it does |
|---|---|---|
| `--users FILE` | `-UsersFile FILE` | Authorized users (one per line, `#` comments allowed) |
| `--admins FILE` | `-AdminsFile FILE` | Authorized administrators |
| `--json FILE` | `-JsonPath FILE` | Also write a JSON report |
| `--list-checks [--markdown]` | `-ListChecks [-Markdown]` | Print every check and exit |
| `--no-color` | `-NoColor` | Plain output |

Exit codes: `0` no FAIL findings, `1` at least one FAIL, `2` bad arguments. On Windows, `3`
means a check crashed, which is a bug: please [report it](https://github.com/0x000NULL/CSSR/issues).

## What gets checked

The full list with IDs is on the [audit scripts page](../docs/audit-scripts.md), and
`--list-checks` prints it. In short: accounts and admin rights, password and lockout policy,
auditing, SSH/RDP, firewall, updates, kernel and security options, risky services, prohibited
software, media files, file permissions, and common backdoors and persistence (netcat
listeners, replaced accessibility programs, startup entries, cron jobs, scheduled tasks).

Thresholds follow CIS Benchmark-style values and are defined once at the top of each script.
The [hardening guides](../docs/guides/) use the same numbers.
