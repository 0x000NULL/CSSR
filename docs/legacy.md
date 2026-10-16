# Legacy toolkit

The [`legacy/`](https://github.com/0x000NULL/CSSR/tree/master/legacy) folder keeps the scripts
Ethan's team ran from 2018 to 2019, along with a few third-party scripts they called. Their
licenses allow redistribution, and their license files sit next to them.

!!! danger "Not for current images"
    These scripts were written for Ubuntu 16.04/16.10, Windows 7–10 and Server 2008/2016. They
    change the system without asking: they reset passwords, disable services, delete media
    files and rewrite configs. On a current image they can cost points or lock you out. Use the
    check-only [audit scripts](audit-scripts.md) instead.

They're kept because they're a record of how the project started and because they're useful
to read. Each one shows a team's idea of what to fix and how to script it. Read them like you'd
read old notes, not as something to run.

## What changed in 2026

Before the move to `legacy/`, the scripts were fixed so they're less dangerous to read and run:

- The "sticky keys" backdoor step (replacing `sethc.exe` with `cmd.exe`) was **removed**.
- Hard-coded shared passwords were replaced with a prompt.
- Broken paths, labels and a syntax error that kept the Linux runner from finishing were fixed.
- Media-file deletion was limited to user folders instead of the whole drive.
- Bundled third-party binaries were removed. The scripts now print where to download them.

The full list, a per-folder license table and a warning checklist are in the
[legacy README](https://github.com/0x000NULL/CSSR/blob/master/legacy/README.md).
