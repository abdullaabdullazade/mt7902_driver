# Testing a fix

A fix for this driver gets tried by the person whose adapter has the problem, before it goes to the kernel. That is what this repo is for. No developer skills are needed: install, test, report, go back.

## 1. Install

Open a terminal. The installer checks for the tools it needs and names any that are missing. The driver needs a kernel of 6.12 or newer; `uname -r` shows yours.

    git clone https://github.com/morrownr/mt76.git
    cd mt76
    sudo sh install-driver.sh

If you were asked to test a branch, say `some-fix`, check it out before installing:

    git checkout some-fix
    sudo sh install-driver.sh

Already have the clone? Run `git pull` first, then the same install command. On a system without sudo, log in as root and leave the `sudo` off.

Reboot when the installer offers. From then on the driver from this repo loads in place of the one built into your kernel, which is left as it was.

With Secure Boot on, the installer signs the driver and asks you for a one-time password, and the next boot asks you to enroll a key; the README's Secure Boot section walks through it.

If the installer stops with an error, copy everything it printed into your report and skip to step 3.

## 2. Test

After the reboot, confirm the repo's driver is the one running:

    ./check-driver.sh

Under "Loaded mt76 Modules" the names should end in `_git`. If it says an in-kernel module is loaded, stop there and report it. If the list is empty, the adapter was not detected; plug it in and run the check again.

Then do what the request asked. If it did not say, use the adapter the way that showed the problem: connect to your network, do what you normally do, and leave it running at least as long as the problem used to take to appear. Keep a few lines of notes on what you did and what happened.

## 3. Report

Save the diagnostic and paste it, whole, into the issue or pull request that asked you to test:

    ./check-driver.sh 2>&1 | tee mt76-diag.txt

Add your notes, even when nothing went wrong. "Two days, no drops" tells us as much as "same failure after twenty minutes".

## 4. Go back

To return to the driver built into your kernel:

    sudo sh uninstall-driver.sh

Reboot when it offers. After that your kernel's own driver is back and nothing from this repo is loaded.

## If you keep it installed

The driver you installed was built for the kernel you had that day. After a kernel update there is no build for the new kernel, and your kernel's own driver is still blocked, so the adapter has no driver at all until you run the install again:

    git pull
    sudo sh install-driver.sh

If dkms is installed, the rebuild happens on its own. Those two commands are also how you pick up newer fixes.
