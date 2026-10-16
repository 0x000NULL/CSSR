# Forensics questions

Forensics questions are text files on the desktop (`Forensics Question 1.txt`, …). Each asks you
to find something on the machine and type the answer on its `ANSWER:` line. They're often worth
as much as several vulnerabilities, and the evidence they need can disappear once you start
fixing things. **Answer them first.**

## How to answer

- Open the file in a plain text editor (Notepad, `nano`, gedit). Don't change anything except
  the `ANSWER:` line.
- Copy the exact format the question asks for: full path or just a file name, upper or lower
  case, one answer or a comma-separated list.
- Save the file and check the scoring report. A correct answer shows up like any other point.
- If a question has several answers, it usually asks for one per `ANSWER:` line.

## Common question types

### "What is the hash of …?"

=== "Windows"

    ```powershell
    Get-FileHash 'C:\path\to\file' -Algorithm SHA256   # also MD5, SHA1
    ```

=== "Linux"

    ```bash
    sha256sum /path/to/file      # md5sum, sha1sum
    ```

### "Decode this message"

Look at the text to guess the encoding: `==` at the end suggests Base64, pairs of 0-9a-f
characters suggest hex, and letters that are shifted look like ROT13 or a Caesar cipher.
[CyberChef](https://gchq.github.io/CyberChef/) handles all of these. Its "Magic" operation can
guess the encoding.

=== "Windows"

    ```powershell
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('aGVsbG8='))
    ```

=== "Linux"

    ```bash
    echo 'aGVsbG8=' | base64 -d
    echo '68656c6c6f' | xxd -r -p
    echo 'uryyb' | tr 'A-Za-z' 'N-ZA-Mn-za-m'      # ROT13
    ```

### "Which user …?" / "What is the UID of …?"

=== "Windows"

    ```powershell
    Get-LocalUser | Select Name, SID, Enabled, LastLogon
    (Get-Acl 'C:\path\to\file').Owner               # who owns a file
    ```

=== "Linux"

    ```bash
    id NAME                                           # UID, GID, groups
    getent passwd NAME
    stat -c '%U %G %a' /path/to/file                  # owner, group, permissions
    last; lastlog                                     # who logged in, and when
    ```

### "Find the hidden / prohibited file"

=== "Windows"

    ```powershell
    Get-ChildItem C:\Users -Recurse -Force -File -ErrorAction SilentlyContinue |
        Where-Object Name -like '*secret*'
    Get-ChildItem C:\ -Recurse -Force -File -ErrorAction SilentlyContinue |
        Where-Object LastWriteTime -gt (Get-Date).AddDays(-30)     # recently changed files
    ```

    `Get-Item FILE -Stream *` shows alternate data streams, a common place to hide content.

=== "Linux"

    ```bash
    sudo find / -xdev -iname '*secret*' 2>/dev/null
    sudo find /home -name '.*' -type f                # hidden (dot) files
    sudo find / -xdev -newermt '2026-01-01' -type f 2>/dev/null | grep -v '^/proc'
    ```

### "What port / program is the backdoor using?"

=== "Windows"

    ```powershell
    Get-NetTCPConnection -State Listen |
        Select LocalPort, OwningProcess, @{n='Path'; e={(Get-Process -Id $_.OwningProcess).Path}}
    ```

=== "Linux"

    ```bash
    sudo ss -tulpn
    sudo ls -l /proc/PID/exe           # the program behind a process ID
    ps -fp PID
    ```

### "When did … happen?" / "What was installed?"

=== "Windows"

    Event Viewer (`eventvwr.msc`) > Windows Logs > Security/System. Useful event IDs:
    4624 (logon), 4625 (failed logon), 4720 (user created), 4732 (added to a group),
    7045 (service installed).

    ```powershell
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720} | Select TimeCreated, Message
    ```

=== "Linux"

    ```bash
    grep -E 'install|remove' /var/log/dpkg.log      # package history
    sudo grep -E 'useradd|usermod|passwd' /var/log/auth.log
    journalctl --since '2026-01-01' -u ssh          # service logs
    ```

## Tips

- Read every question before starting any of them. One answer is sometimes a clue for another.
- Keep notes of what you found. It helps if a later fix changes something you need.
- If a question mentions a file, don't open it in a program that might modify it. View it
  read-only, or copy it first.
