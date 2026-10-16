# Windows hardening checklist

For Windows 10/11 and Windows Server 2019/2022/2025. Work top to bottom, check your score after
each section, and keep the README open. Bracketed IDs such as `[WIN-POL-01]` match the
[audit script](../audit-scripts.md), so you can confirm each fix by re-running it.

!!! tip "Before you start"
    1. Read the README and write down users, admins and critical services.
    2. Answer the forensics questions.
    3. Open an elevated PowerShell: right-click Start > Terminal (Admin), or Windows PowerShell (Admin).

## Accounts

- [ ] Remove users who aren't in the README. `Remove-LocalUser -Name NAME` `[WIN-ACC-03]`
- [ ] Create authorized users who are missing, if the README asks. `New-LocalUser` `[WIN-ACC-04]`
- [ ] Only README administrators are in **Administrators**. `Get-LocalGroupMember Administrators` `[WIN-ACC-05]`
- [ ] Disable **Guest**. `Disable-LocalUser Guest` `[WIN-ACC-01]`
- [ ] Disable or rename the built-in **Administrator** unless the README uses it. `[WIN-ACC-02]`
- [ ] No account has *password never expires* or *password not required*. `[WIN-ACC-06]` `[WIN-ACC-07]`
- [ ] Give every user except your own a strong password: `net user NAME *`

See [Users and passwords](users-and-passwords.md) for details.

## Password and lockout policy

Open `secpol.msc` > **Account Policies**, or use `net accounts` for most values:

```powershell
net accounts /minpwlen:14 /maxpwage:90 /minpwage:1 /uniquepw:24
net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15
```

| Setting | Value | Audit ID |
|---|---|---|
| Minimum password length | 14 | `WIN-POL-01` |
| Password must meet complexity requirements | Enabled (`secpol.msc` only) | `WIN-POL-02` |
| Maximum password age | 90 days | `WIN-POL-03` |
| Minimum password age | 1 day | `WIN-POL-04` |
| Enforce password history | 24 | `WIN-POL-05` |
| Store passwords using reversible encryption | Disabled (`secpol.msc` only) | `WIN-POL-06` |
| Account lockout threshold | 5 | `WIN-POL-07` |
| Account lockout duration | 15 minutes | `WIN-POL-08` |
| Reset account lockout counter after | 15 minutes | `WIN-POL-09` |

!!! note
    On a domain controller, password policy comes from Group Policy (`gpmc.msc` > Default
    Domain Policy), not from the local policy.

## Audit policy

Turn on success and failure auditing so events get logged `[WIN-AUD-01]`:

```powershell
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"System" /success:enable /failure:enable
auditpol /get /category:*
```

## Security options

In `secpol.msc` > **Local Policies** > **Security Options**:

| Setting | Value | Audit ID |
|---|---|---|
| Accounts: Limit local account use of blank passwords to console logon only | Enabled | `WIN-SEC-01` |
| User Account Control: Run all administrators in Admin Approval Mode | Enabled | `WIN-SEC-02` |
| UAC: Behavior of the elevation prompt for administrators | Prompt for consent on the secure desktop | `WIN-SEC-02` |
| Network access: Do not allow anonymous enumeration of SAM accounts (and shares) | Enabled | `WIN-SEC-03` |
| Network security: Do not store LAN Manager hash value on next password change | Enabled | `WIN-SEC-04` |
| Network security: LAN Manager authentication level | Send NTLMv2 response only. Refuse LM & NTLM | `WIN-SEC-04` |
| Interactive logon: Don't display last signed-in | Enabled | `WIN-SEC-05` |
| Interactive logon: Do not require CTRL+ALT+DEL | Disabled | `WIN-SEC-05` |

Also turn off AutoRun for all drives: Group Policy (`gpedit.msc`) > Computer Configuration >
Administrative Templates > Windows Components > AutoPlay Policies > **Turn off AutoPlay:
All drives** `[WIN-SEC-06]`.

## Firewall and network

- [ ] Firewall on for every profile, inbound blocked by default `[WIN-NET-01]` `[WIN-NET-02]`:
  ```powershell
  Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block
  ```
- [ ] Remove inbound **allow** rules for programs or ports the README doesn't need (`wf.msc`).
- [ ] Disable SMBv1 `[WIN-NET-03]`:
  ```powershell
  Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
  Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
  ```
- [ ] Remote Desktop: off unless the README needs it. If it stays on, require Network Level
  Authentication: System Properties > Remote `[WIN-NET-04]`.
- [ ] Remove file shares the README doesn't need: `Get-SmbShare`, then `Remove-SmbShare -Name NAME` `[WIN-NET-05]`.

## Microsoft Defender

- [ ] Real-time protection on: Windows Security > Virus & threat protection `[WIN-DEF-01]`.
  Check `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` for a `DisableAntiSpyware` policy
  someone planted.
- [ ] Update signatures: `Update-MpSignature` `[WIN-DEF-02]`.
- [ ] Remove exclusions (an attacker's favorite): `Get-MpPreference | Select-Object Exclusion*` `[WIN-DEF-03]`.
- [ ] Run a quick scan: `Start-MpScan -ScanType QuickScan`.

## Updates

- [ ] The Windows Update service isn't disabled, and no policy blocks automatic updates `[WIN-UPD-01]`.
- [ ] Install updates: Settings > Windows Update > Check for updates `[WIN-UPD-02]`. Start early,
  because updates take a long time.
- [ ] Update the applications the README mentions, browsers included.

## Services and software

- [ ] Disable services the README doesn't need: Remote Registry, Telnet, FTP, SNMP, IIS (W3SVC),
  UPnP/SSDP, Routing and Remote Access, Internet Connection Sharing `[WIN-SVC-01]`.
  ```powershell
  Stop-Service NAME; Set-Service NAME -StartupType Disabled
  ```
- [ ] Uninstall hacking tools, games, P2P clients and unexpected remote-access tools `[WIN-SW-01]`.
- [ ] Delete prohibited media files in user folders, after the forensics questions `[WIN-FIL-01]`.

See [Services and software](services-and-software.md).

## Backdoors and persistence

- [ ] **Accessibility programs are genuine** `[WIN-BKD-01]` `[WIN-BKD-02]`. A well-known backdoor
  replaces `sethc.exe` (Sticky Keys), `utilman.exe` or similar with a copy of `cmd.exe`, or sets a
  "debugger" for them, so pressing Shift five times at the logon screen opens a SYSTEM prompt. The
  audit script detects both. To repair, run `sfc /scannow` (and DISM if SFC can't fix it), then
  remove any `Debugger` value under
  `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<program>.exe`.
- [ ] `hosts` file has no surprise entries: `C:\Windows\System32\drivers\etc\hosts` `[WIN-BKD-03]`.
- [ ] Review startup programs: Task Manager > Startup, plus the `Run`/`RunOnce` registry keys `[WIN-INF-01]`.
- [ ] Review scheduled tasks outside `\Microsoft\`: `taskschd.msc` `[WIN-INF-02]`.
- [ ] Check for programs listening on odd ports: `Get-NetTCPConnection -State Listen`.
- [ ] Look for suspicious services: `Get-CimInstance Win32_Service | Select Name, PathName, StartMode`.
  Watch for executables in user folders or `C:\Windows\Temp`.

## Finally

- [ ] Re-run the [audit script](../audit-scripts.md) and work through what's left.
- [ ] Re-read the README for anything specific to this scenario.
- [ ] If your score stalls, check the [Linux checklist](linux-hardening.md) too. The same ideas
  (users, policies, services, persistence) show up in different places.
