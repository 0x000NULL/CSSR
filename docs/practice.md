# Practice

The best preparation is fixing real images under time pressure, again and again.

## Official practice images

CyberPatriot provides practice images and training materials to registered teams. Your coach
gets them through the competitor resources on [uscyberpatriot.org](https://www.uscyberpatriot.org/).
They use the real scoring engine and are the closest thing to a competition round.

## Build your own scored images

When you've used up the official images, make your own:

1. Install a fresh VM: a Windows evaluation edition, or Ubuntu/Mint.
2. Have a teammate or coach introduce problems without telling you which ones. Use the
   [checklists](guides/windows-hardening.md) for ideas: extra users and admins, weak password
   policy, firewall off, a forbidden program, media files, a disabled update service, a
   suspicious startup entry, a forensics question or two.
3. Write a README for the scenario: authorized users, admins, critical services.
4. Snapshot it, then take turns fixing it against a timer.

A scoring engine makes this much better, because you see points appear the way you will in a
round:

- [**aeacus**](https://github.com/elysium-suite/aeacus): an open-source scoring engine for
  Windows and Linux modeled on the CyberPatriot experience. You describe each vulnerability as a
  check in a config file, and it produces a scoring report and can include a README and
  forensics questions. See its README for setup.
- Simple alternative: write your own checks as a script that prints a score. The
  [audit scripts](audit-scripts.md) are a good source of ideas for what to check.

!!! note "Credit"
    Early versions of this repository included Ryan Galligher's Easy, Medium and Hard Ubuntu
    practice images and bash scoring bots. They taught many teams. Those copies were removed
    because they had no license, and they're credited on the [credits page](credits.md).

## Drills that build speed

- **Ten-minute users drill:** someone creates a messy set of users and groups; you fix them
  against a README as fast as possible.
- **Policy from memory:** set the full password, lockout and audit policy without notes, then
  check yourself with the audit script.
- **Backdoor hunt:** a teammate leaves one persistence mechanism (a startup entry, a scheduled
  task, a cron job, a listener on an odd port); you find and remove it.
- **Forensics race:** practice the commands on the [forensics page](guides/forensics-questions.md)
  until you don't need to look them up.

## Learning beyond the competition

- Linux command line: [*The Linux Command Line*](https://linuxcommand.org/tlcl.php) (free book)
- Windows: [Microsoft Learn security docs](https://learn.microsoft.com/windows/security/)
- More in [Resources](resources.md)
