# Virtual machines

A **virtual machine** (VM) is a whole computer simulated in software. A program called a
**hypervisor** runs it on your real machine (the **host**). CyberPatriot images are VMs, and
VMs are also the safest way to practice: if you break one, you delete it or roll it back.

## Setting up

1. **Install a hypervisor.** Competition images are built for VMware, so use the VMware
   product your coach or the current rules recommend (VMware Workstation Pro on Windows/Linux,
   or Fusion on Mac). VirtualBox is fine for building your own practice VMs.
2. **Check your hardware.** Running an image comfortably takes about 4 GB of free RAM and
   tens of GB of disk per image. Virtualization (Intel VT-x / AMD-V) must be enabled in the
   computer's BIOS/UEFI.
3. **Get practice images.** See [Practice](../practice.md).

## Snapshots

A **snapshot** saves the VM's exact state so you can return to it later.

- Take one right after you first boot an image, before you change anything.
- Take another after each big batch of fixes that raised your score.
- If a change breaks something, revert to the last good snapshot.

!!! warning
    Some rounds restrict what you may do with images, including snapshots and copying.
    Follow the current competition rules.

## Good habits

- **Keep the hypervisor and host OS updated.**
- **Shut the VM down from inside the guest**, or suspend it. A forced power-off can corrupt
  the image.
- **Learn the console shortcuts** (for example Ctrl+Alt+Insert instead of Ctrl+Alt+Delete in
  VMware), and how to release the mouse and keyboard from the VM.
- **Install VMware Tools / open-vm-tools** in your own practice VMs for copy-paste and display
  resizing. Competition images usually already have them.

## Practicing without competition images

Build your own: install a fresh Windows evaluation or Ubuntu VM, have a teammate quietly add
problems (an extra admin, a weak password policy, a forbidden program, a media file), then
take turns finding them. The [Practice](../practice.md) page has tools that score this for you.
