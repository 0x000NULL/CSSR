# How a round works

CyberPatriot is the Air & Space Forces Association's national youth cyber defense competition.
Teams of students, with a coach and often a technical mentor, defend virtual machines during
timed online rounds. Formats, divisions and rules change between seasons, so always check
[uscyberpatriot.org](https://www.uscyberpatriot.org/) and your coach's materials for the
current details. This page covers what stays the same.

## What you get

During a round your team downloads a set of **images**: virtual machines that run in a
hypervisor such as VMware. A season usually includes:

- **Windows** desktop images (for example Windows 10/11)
- **Windows Server** images
- **Linux** images (for example Ubuntu, Debian or Linux Mint)
- A **networking** challenge (Cisco Packet Tracer plus quiz questions), in divisions that
  include it

Each image has a **README** on the desktop. It describes a fictional company or user: who is
allowed on the machine, who is an administrator, which services the business depends on, and
any special rules. The [next page](reading-the-readme.md) covers how to read it.

## How scoring works

Each image runs a scoring engine that checks for a hidden list of **vulnerabilities**: an
unauthorized user, a weak password policy, a disabled firewall, a backdoor, a forbidden program,
an out-of-date package, and so on. When you fix one, your score goes up, usually within a minute
or two. A **scoring report** on the desktop shows your points and how many vulnerabilities are
left, but not which ones.

You can also **lose points** (penalties) by:

- breaking or removing a service the README says is critical,
- deleting an authorized user, or
- removing software the README says is required.

**Forensics questions** are text files on the desktop that ask you to find something on the
machine: a hidden file, a user's ID, a decoded message, the path of a malicious program. Each
correct answer is worth points. See [Forensics questions](../guides/forensics-questions.md).

## A good round, step by step

1. **Read the README twice.** Write down the authorized users, administrators, critical
   services and anything unusual.
2. **Snapshot the VM if the rules allow it**, so you can roll back a mistake.
3. **Answer the forensics questions** before changing anything. Fixes can erase evidence.
4. **Fix users and passwords**: remove unauthorized accounts, fix admin rights, set strong
   passwords and policies.
5. **Turn on the basics**: firewall, automatic updates, antivirus.
6. **Remove what doesn't belong**: hacking tools, games, media files, unneeded services.
7. **Hunt for backdoors**: unusual listening ports, startup entries, scheduled tasks, cron jobs.
8. **Update** the operating system and the applications the README cares about.
9. **Check the score after every change.** If it drops, undo what you just did.

The [Windows](../guides/windows-hardening.md) and [Linux](../guides/linux-hardening.md)
checklists cover steps 4–8 in detail.

## Working as a team

- Split by image, not by task, so two people never fight over the same settings.
- Keep a shared log of what you changed on each image and when. If the score drops, you'll
  know what to undo.
- Swap images partway through. A fresh pair of eyes finds what you stopped seeing.
