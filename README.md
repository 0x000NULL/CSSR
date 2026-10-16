# CSSR: Computer Security Scripts and Resources

[![CI](https://github.com/0x000NULL/CSSR/actions/workflows/ci.yml/badge.svg)](https://github.com/0x000NULL/CSSR/actions/workflows/ci.yml)
[![Docs](https://github.com/0x000NULL/CSSR/actions/workflows/docs.yml/badge.svg)](https://0x000null.github.io/CSSR/)
[![Code: MIT](https://img.shields.io/badge/code-MIT-blue)](LICENSE)
[![Docs: CC BY 4.0](https://img.shields.io/badge/docs-CC%20BY%204.0-lightgrey)](LICENSE-docs)

A free study kit for [CyberPatriot](https://www.uscyberpatriot.org/) and anyone learning to
secure Windows and Linux systems.

**Read it as a website: <https://0x000null.github.io/CSSR/>**

| | |
|---|---|
| **[Guides](docs/)** | How a round works, reading the README, Windows and Linux hardening checklists, forensics questions, networking |
| **[Audit scripts](audit/)** | Check-only scripts for Linux and Windows that list what's wrong and print the fix. They never change anything. |
| **[Practice](docs/practice.md)** | Official practice images and how to build your own scored images |
| **[Resources](docs/resources.md)** | Official hardening guides, tools and books |
| **[Legacy toolkit](legacy/)** | The 2018–2019 scripts, kept for reference with safety fixes. Not for current images. |
| **[Credits](docs/credits.md)** | The teams and authors whose public work this project learned from |

## Quick start: audit an image

Copy the authorized users and administrators from the image's README into `users.txt` and
`admins.txt` (one name per line), then:

**Linux**

```bash
curl -fsSLO https://raw.githubusercontent.com/0x000NULL/CSSR/master/audit/linux/cssr-audit.sh
chmod +x cssr-audit.sh
sudo ./cssr-audit.sh --users users.txt --admins admins.txt
```

**Windows** (elevated PowerShell)

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/0x000NULL/CSSR/master/audit/windows/CSSR-Audit.ps1 -OutFile CSSR-Audit.ps1
powershell -ExecutionPolicy Bypass -File .\CSSR-Audit.ps1 -UsersFile users.txt -AdminsFile admins.txt
```

Each finding comes with the command that fixes it. See [`audit/`](audit/) for options and
statuses. Check the current CyberPatriot rules before using outside tools during a round.

## Contributing

Fixes and new guides are welcome. [Open an issue](https://github.com/0x000NULL/CSSR/issues) or
send a pull request.

- **Docs:** edit the Markdown in [`docs/`](docs/). Preview with
  `pip install -r requirements-docs.txt && mkdocs serve`.
- **Audit scripts:** keep them check-only. After adding or renaming a check, regenerate the docs
  table:
  `audit/linux/cssr-audit.sh --list-checks --markdown | python3 tests/check_docs_tables.py linux --write`
  (and the same with `CSSR-Audit.ps1 -ListChecks -Markdown` and `windows`).
- **Tests:** `shellcheck`, `sudo tests/linux-readonly.sh`, PSScriptAnalyzer with
  `audit/windows/PSScriptAnalyzerSettings.psd1`, and `mkdocs build --strict`. CI runs all of
  them, plus the Windows audit on Windows Server 2022 and 2025.
- **No binaries, PDFs or copied repositories.** Link to the original instead and add it to
  [credits](docs/credits.md). CI enforces this.

## History

CSSR started in 2018 as Ethan Aldrich's team folder of CyberPatriot scripts and links, and grew
to over a gigabyte of other people's tools, books and repositories. In 2026 it was rebuilt:
copied material was removed and credited, the license was replaced, the old scripts were fixed
and moved to [`legacy/`](legacy/), and the guides and audit scripts were written new.

## License

- Code (audit scripts, tests, legacy scripts written for this repo): [MIT](LICENSE)
- Documentation in [`docs/`](docs/): [CC BY 4.0](LICENSE-docs)
- Third-party code in [`legacy/`](legacy/) keeps its own license. See the
  [legacy README](legacy/README.md).
