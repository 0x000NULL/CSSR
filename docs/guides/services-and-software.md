# Services and software

Every running service and installed program is something that can be attacked. The goal is to
keep exactly what the README needs, keep it updated and configured securely, and remove the
rest.

## Services

A **service** is a program that runs in the background, often listening on the network.

### Find what's running

=== "Windows"

    ```powershell
    Get-Service | Where-Object Status -eq Running | Sort-Object DisplayName
    Get-NetTCPConnection -State Listen | Sort-Object LocalPort |
        Select-Object LocalAddress, LocalPort, OwningProcess,
            @{n='Process'; e={(Get-Process -Id $_.OwningProcess).ProcessName}}
    ```

    Or `services.msc` for a GUI.

=== "Linux"

    ```bash
    systemctl list-units --type=service --state=running
    sudo ss -tulpn          # listening ports and the process behind each one
    ```

### Decide: keep, harden or remove

| Situation | What to do |
|---|---|
| The README names it as critical | **Keep it running.** Harden its configuration and update it. |
| Not mentioned, and you know what it does and nothing needs it | Stop and disable it. On Linux, consider removing the package. |
| Not mentioned, and you don't know what it does | Look it up before touching it. Disabling a core OS service can break the image. |

Services that are usually unwanted unless the README requires them: Telnet, FTP servers, a web
server (IIS, Apache, nginx), SNMP, Remote Registry, file sharing (SMB/Samba, NFS), remote
desktop or VNC, and UPnP/SSDP.

=== "Windows"

    ```powershell
    Stop-Service -Name RemoteRegistry
    Set-Service  -Name RemoteRegistry -StartupType Disabled
    ```

    For Windows features (IIS, Telnet, SMB1): **Turn Windows features on or off** in
    `optionalfeatures.exe`, or **Server Manager > Remove Roles and Features** on Server.

=== "Linux"

    ```bash
    sudo systemctl disable --now vsftpd
    sudo apt purge vsftpd               # if it isn't needed at all
    ```

### Harden the ones you keep

- Update them. Outdated server software is a common scored vulnerability.
- Turn off anonymous or guest access (FTP anonymous login, SMB guest shares).
- Require strong authentication. For SSH, see the [Linux checklist](linux-hardening.md#ssh). For
  RDP, require Network Level Authentication.
- Remove default or sample content (default web pages, sample shares).

## Software

### Remove what doesn't belong

Typical scored items:

- **Hacking and cracking tools**: password crackers, network scanners, packet sniffers, keyloggers.
- **Games** and **P2P / torrent clients**.
- **Remote-access tools** the README doesn't mention.
- **Unwanted media files** (music and video) in user folders, if the README or company policy
  forbids them. Answer the forensics questions first; a question may be about one of them.

=== "Windows"

    Settings > Apps > Installed apps, or `appwiz.cpl`. Also check `C:\Program Files`,
    `C:\Program Files (x86)` and user folders for portable programs that never installed.

    ```powershell
    Get-ChildItem C:\Users -Recurse -File -Force -ErrorAction SilentlyContinue |
        Where-Object Extension -in '.mp3', '.mp4', '.avi', '.mkv', '.wav', '.flac', '.mov' |
        Select-Object FullName
    ```

=== "Linux"

    ```bash
    apt list --installed 2>/dev/null | grep -Ei 'john|hydra|nmap|wireshark|aircrack|nikto|ophcrack'
    sudo apt purge john hydra             # use the exact package names you found
    sudo apt autoremove
    find /home -type f \( -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.avi' -o -iname '*.mkv' \
        -o -iname '*.wav' -o -iname '*.flac' -o -iname '*.mov' \) 2>/dev/null
    ```

### Update what stays

- Turn on automatic updates for the operating system (see the checklists).
- Update browsers and any application the README names. Many images score "Firefox is updated"
  or similar.
- On Linux, `sudo apt update && sudo apt upgrade` updates everything from the repositories.
  Check `/etc/apt/sources.list` and `/etc/apt/sources.list.d/` first: unknown repositories
  can be a vulnerability themselves.
