# CSSR: Computer Security Scripts and Resources

CSSR is a free study kit for [CyberPatriot](https://www.uscyberpatriot.org/) and for anyone
learning to secure Windows and Linux systems. It has three parts:

- **Guides**: how a round works, how to read the image README, and step-by-step hardening
  checklists for Windows and Linux, with the commands to run.
- **[Audit scripts](audit-scripts.md)**: check-only scripts that list what looks wrong on an
  image and print the fix. They never change anything.
- **Links**: [resources](resources.md) and [practice](practice.md) options, plus
  [credits](credits.md) for the many teams whose public work this project learned from.

## Where to start

New to CyberPatriot?

:   Read [How a round works](getting-started/competition-overview.md), set up a
    [virtual machine](getting-started/virtual-machines.md), and learn to
    [read the README](getting-started/reading-the-readme.md). Most lost points come from
    skipping that last step.

Preparing for a round?

:   Work through the [Windows](guides/windows-hardening.md) or [Linux](guides/linux-hardening.md)
    checklist on a practice image. Then run the [audit script](audit-scripts.md) to find
    what you missed.

Coaching a team?

:   Every guide is CC BY 4.0, so you can copy, adapt and hand them out as long as you give
    credit. The [practice page](practice.md) covers building your own scored images.

## The golden rules

1. **The README is the source of truth.** Authorized users, required services and allowed
   software all come from it. A "fix" that breaks a critical service costs points.
2. **Answer the forensics questions first.** Cleaning up an image can destroy the evidence
   they ask about.
3. **Understand every change before you make it.** Run commands by hand, one at a time. Don't
   run a script that changes things without reading it.
4. **Check your score after each change.** If it drops, undo the change you just made.

## About this project

CSSR started in 2018 as Ethan Aldrich's team folder of CyberPatriot scripts and links. It grew
into a 1 GB pile of other people's material. In 2026 it was rebuilt around original guides and
check-only audit scripts. Everything copied from elsewhere was removed and is now credited and
linked on the [credits page](credits.md). The old scripts are kept, with safety fixes, as the
[legacy toolkit](legacy.md).

Spotted a mistake or have an idea? [Open an issue](https://github.com/0x000NULL/CSSR/issues).
