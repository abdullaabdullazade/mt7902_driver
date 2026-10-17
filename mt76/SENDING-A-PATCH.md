# Sending a patch to the Linux kernel

## Who this is for

You have made a change to this driver and it works. Now you want it in Linux itself, not just in this repo.

To get it there you need a computer running Linux and a terminal. That is the entire list of requirements.

You do not need to be a programmer, and you do not need to have mastered the dark arts of DMA rings and firmware handshakes. Plenty of changes worth sending are three lines long and contain no programming at all. For example: a USB WiFi adapter does nothing when you plug it in, and the only reason is that nobody wrote its ID number down in the driver's list of known devices. Writing it down is a real change that helps real people.

This guide is about the sending, not the writing. How you arrived at your change is your business. Everything below is what happens afterwards, from an edit sitting on your disk to a commit in Linux.

## Where the pull request button should be

If you have contributed to anything on GitHub you know the shape of it. Fork, branch, edit, open a pull request, wait for someone to click merge.

The kernel does none of that. There is no fork, no pull request, and no button. There has never been a button.

Changes travel as email. You format your change as an email and send it to a mailing list. The people responsible for that part of Linux read it, and if they like it, one of them copies it into their own tree by hand. Weeks later it reaches everybody else.

Nothing you send is applied automatically. A human reads it and decides. So the realistic outcomes are that nobody replies, or somebody asks you to fix a detail and send it again.

## The words

**Kernel.** The core of Linux. The part that talks to your hardware.

**Driver.** Code that makes one piece of hardware work. `mt76` covers MediaTek WiFi chips.

**Tree.** A copy of the kernel source with its full history, managed by git. Many people keep their own.

**Mainline, or upstream.** The one official tree everybody else copies from. Getting a change in there is the goal.

**Patch.** One change written out as plain text: which lines come out, which go in.

**Commit.** A patch plus a description of why, saved into a tree.

**Maintainer.** The person responsible for one area. For mt76 that is mainly Felix Fietkau.

**Mailing list.** WiFi changes go to `linux-wireless@vger.kernel.org`.

**lore.** Public archive of every message sent to those lists, at `lore.kernel.org`.

**patchwork.** Tracks the status of each patch, at `patchwork.kernel.org/project/linux-wireless/list/`.

## The change used in this guide

Every step below uses the same small change, so that you are looking at one familiar thing at each stage rather than a fresh invention every time. It is real and it is in Linux now.

```
--- a/drivers/net/wireless/mediatek/mt76/mt7925/usb.c
+++ b/drivers/net/wireless/mediatek/mt76/mt7925/usb.c
@@ -12,6 +12,9 @@
 static const struct usb_device_id mt7925u_device_table[] = {
 	{ USB_DEVICE_AND_INTERFACE_INFO(0x0e8d, 0x7925, 0xff, 0xff, 0xff),
 		.driver_info = (kernel_ulong_t)MT7925_FIRMWARE_WM },
+	/* Netgear, Inc. A8500 */
+	{ USB_DEVICE_AND_INTERFACE_INFO(0x0846, 0x9050, 0xff, 0xff, 0xff),
+		.driver_info = (kernel_ulong_t)MT7925_FIRMWARE_WM },
 	/* Netgear, Inc. A9000 */
 	{ USB_DEVICE_AND_INTERFACE_INFO(0x0846, 0x9072, 0xff, 0xff, 0xff),
 		.driver_info = (kernel_ulong_t)MT7925_FIRMWARE_WM },
```

That format is a **diff**, and you will be looking at them for the rest of this. Three things to know and no more:

- Lines starting with `+` are being added.
- Lines starting with `-` are being removed.
- Lines starting with a space are neither. They are there so a reader can see the surroundings.

So this change adds three lines and removes nothing.

What it does, in one sentence: the Netgear A8500 is a USB WiFi adapter with a MediaTek MT7925 chip in it, the driver keeps a list of devices it recognises, the A8500 was not on that list, so Linux ignored the adapter even with the correct driver sitting right there on disk.

Three lines. No programming. Your own change will be different and it does not matter, because everything from here on is identical whatever you are sending.

## Step 1: Get the kernel source

Two trees matter for WiFi, and you send to one or the other:

- Fixing something that is broken: **wireless**
- Anything else, including support for new hardware: **wireless-next**

The example adds hardware support, so `wireless-next`.

```
git clone https://git.kernel.org/pub/scm/linux/kernel/git/wireless/wireless-next.git
cd wireless-next
```

That is a few gigabytes and it takes a while. Once only. After that `git pull` is seconds. The other tree is the same address ending `wireless.git`.

## Step 2: Tell git who you are

Git puts your name and address on everything you send, so set them before you start:

```
git config --global user.name "Your Real Name"
git config --global user.email "you@example.com"
```

**Use your real name**, not a handle. Sending a patch means formally stating that you have the right to contribute it, and that statement needs a real identity behind it. A patch signed with a handle gets sent back, and then you wait all over again for the second one to be looked at.

The address must be one you can send mail from and receive replies at.

## Step 3: Put your change in the kernel tree

If you have been working in this repo, your change is in the fork, not in a kernel tree, and the kernel tree is what you send from. The file contents match; only the paths differ. What is `mt7925/usb.c` here is `drivers/net/wireless/mediatek/mt76/mt7925/usb.c` there.

Make the same edit in the kernel tree, with whatever editor you like. Then ask git what you changed:

```
git diff
git diff --check
```

Read what the first one prints. That is your change written out as a diff, and it is very close to what you are about to send. The second prints nothing if you have not left any stray whitespace behind, and tells you where it is if you have.

**One change per patch.** If you fixed two unrelated things, that is two patches and they go out separately. A tidy-up riding along inside a bug fix is the most common reason a first patch gets sent back.

## Step 4: Prove it works

Building an entire kernel to test a small change takes a long time. There is a shortcut, and it is the repo this guide is sitting in.

This repo holds the same mt76 driver code, packaged so that it builds on its own against the kernel you are already running. About a minute, rather than the best part of an hour.

Get it, and make the same edit in `mt7925/usb.c` that you made in the kernel tree:

```
git clone https://github.com/morrownr/mt76.git
cd mt76
```

Then run the installer:

```
sudo sh install-driver.sh
```

That script is this repo's own, and it does the lot: checks you have what you need to build, compiles the driver, installs it and loads it. If you only want to know whether your change compiles, `make` on its own builds and stops there.

Now plug the adapter in, or do whatever it is your change was supposed to affect, and see whether it behaves. That is your test. If it works here it will work in the kernel, because it is the same code either way.

## Step 5: Commit it

```
git add drivers/net/wireless/mediatek/mt76/mt7925/usb.c
git commit -s
```

An editor opens. What you write here is permanent, and somebody will read it in ten years while trying to work out why their WiFi broke.

First line is the subject:

```
wifi: mt76: mt7925: add Netgear A8500 USB device ID
```

Read left to right through the colons it narrows down: WiFi, the mt76 driver, the mt7925 part of it, then what the change does. Three rules:

- Under about 70 characters.
- An instruction, not a report. "add", not "added" or "adds".
- Copy the prefixes already in use rather than inventing one: `git log --oneline drivers/net/wireless/mediatek/mt76/`

Blank line, then the body. Problem first, fix second, wrapped at about 72 characters:

```
Add USB device ID for the Netgear A8500 (0846:9050) which uses
the mt7925 chipset.
```

For a change this small that is enough.

The `-s` flag adds this line, filled in from what you set in step 2:

```
Signed-off-by: Your Real Name <you@example.com>
```

That is a legal statement called the Developer's Certificate of Origin. It says this is your work or you have the right to pass it on, published under the kernel's licence, permanently. Hence the real name. And you can never write one in somebody else's name, even if they ask you to.

## Step 6: Tags

These go under your description, above the sign-off. Most patches need one or two of them.

**`Fixes:`** names the commit that broke it:

```
Fixes: d9852ab2f362 ("mt76: mt7615: keep mcu_add_bss_info enabled till interface removal")
```

Put this in `~/.gitconfig` once and git will format the line for you:

```
[core]
	abbrev = 12
[pretty]
	fixes = Fixes: %h (\"%s\")
```

```
git log -1 --pretty=fixes d9852ab2f362
```

**The trap:** a commit gets a different hash in every tree it is copied into. A hash you found in this repo, or in openwrt/mt76, is not the hash mainline has for the same commit. Look it up in the mainline tree by its subject and take the hash from there:

```
git log --oneline --grep="keep mcu_add_bss_info enabled till interface removal"
```

You may get more than one hit, because the same fix often goes into several chips at once. Check the paths with `git show` and take the hash for the one you actually mean.

**`Cc: stable@vger.kernel.org`** asks for the change to be copied back into older kernels. Use it when you are fixing a real bug.

It belongs with a `Fixes:` tag. Without one, checkpatch warns and a reviewer will ask you which you meant.

A new device ID is the awkward case. The stable rules do accept device IDs, but the patch fixes no bug so it has no `Fixes:` tag to pair with, and the tag on its own trips that warning. Leave it off and take the other route: once the patch is in mainline, email `stable@vger.kernel.org` with the subject, the commit ID, why it matters and which versions you want.

**`Reported-by:`** and **`Tested-by:`** credit whoever found the problem or confirmed the fix:

```
Reported-by: Some Person <them@example.com>
```

`Tested-by:` needs that person's explicit agreement. `Reported-by:` does not, provided they reported it in public and you use the name and address they used themselves. Either way it is a real name and a real address. A GitHub username is not an email address.

`Reported-by:` should be followed by a `Closes:` tag pointing at the report.

**`Closes:`** points at the bug report:

```
Closes: https://github.com/morrownr/mt76/issues/79
```

**`Link:`** points at background: an earlier discussion, a thread that led to the change. You can add that yourself. Separately, when a maintainer applies your patch they add a `Link:` of their own pointing back at the email you sent. That second one is not yours to write.

## Step 7: Check it

```
./scripts/checkpatch.pl -g HEAD
```

That is a script in the kernel tree that reads your last commit and complains about it. Fix whatever it reports.

checkpatch is a pedant that never gets tired, which is exactly what you want reading your patch before a human does. Everything it catches is something a reviewer would otherwise have to spend their afternoon telling you.

You already know the change compiles and works from step 4. That is the bar for a driver change this size. The kernel's official checklist goes a great deal further, with cross-architecture builds and memory debugging, but that is aimed at people changing the heart of the kernel rather than adding a line to a list.

## Step 8: Turn it into an email

```
git format-patch -1 --subject-prefix="PATCH wireless-next"
```

You get a text file:

```
0001-wifi-mt76-mt7925-add-Netgear-A8500-USB-device-ID.patch
```

Open it and read it. Everything the list will see is in there apart from the `To` and `Cc` lines, which get added when you send it.

`--subject-prefix` tells people which tree you are aiming at. `"PATCH wireless"` for a fix, `"PATCH wireless-next"` for everything else, matching your choice in step 1.

Partway down there is a line of three dashes on its own:

```
---
```

Everything above it is permanent. Everything below it is written in disappearing ink and is thrown away when the patch is applied. That becomes useful shortly.

## Step 9: Work out who to send it to

There is a script for this too. Give it your patch file and it tells you who is responsible for the code you touched:

```
./scripts/get_maintainer.pl --nogit --nogit-fallback 0001-wifi-mt76-mt7925-add-Netgear-A8500-USB-device-ID.patch
```

```
Felix Fietkau <nbd@nbd.name> (maintainer:MEDIATEK MT76 WIRELESS LAN DRIVER)
Lorenzo Bianconi <lorenzo@kernel.org> (maintainer:MEDIATEK MT76 WIRELESS LAN DRIVER)
Ryder Lee <ryder.lee@mediatek.com> (maintainer:MEDIATEK MT76 WIRELESS LAN DRIVER)
Shayne Chen <shayne.chen@mediatek.com> (reviewer:MEDIATEK MT76 WIRELESS LAN DRIVER)
Sean Wang <sean.wang@mediatek.com> (reviewer:MEDIATEK MT76 WIRELESS LAN DRIVER)
Matthias Brugger <matthias.bgg@gmail.com> (maintainer:ARM/Mediatek SoC support)
AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com> (maintainer:ARM/Mediatek SoC support)
linux-wireless@vger.kernel.org (open list:MEDIATEK MT76 WIRELESS LAN DRIVER)
linux-kernel@vger.kernel.org (open list:ARM/Mediatek SoC support)
linux-arm-kernel@lists.infradead.org (moderated list:ARM/Mediatek SoC support)
linux-mediatek@lists.infradead.org (moderated list:ARM/Mediatek SoC support)
```

Read the labels in brackets. `MEDIATEK MT76 WIRELESS LAN DRIVER` is this driver. `ARM/Mediatek SoC support` is a different part of the kernel that happens to share a word, and does not need to hear about a USB WiFi adapter.

The mailing list goes in `To`, the driver's people go in `Cc`:

```
To:  linux-wireless@vger.kernel.org
Cc:  Felix Fietkau <nbd@nbd.name>,
     Lorenzo Bianconi <lorenzo@kernel.org>,
     Ryder Lee <ryder.lee@mediatek.com>,
     Shayne Chen <shayne.chen@mediatek.com>,
     Sean Wang <sean.wang@mediatek.com>,
     linux-mediatek@lists.infradead.org
```

That is every name the script gave for this driver, maintainers and reviewers alike. The remaining lists and the two ARM maintainers are dropped.

`linux-mediatek` is the judgement call. The script labels it as belonging to the ARM entry and it is not listed under the mt76 entry at all, but roughly half of mt76 patches copy it in anyway, including the one used in this guide.

Some of what the script prints will be out of date, because MAINTAINERS lags behind when people change jobs. Nothing to do about that in advance. Just reply to whatever address somebody actually writes to you from.

Run it without `--nogit` and it also mines the file's history for names. On this file that adds six more, including a graphics developer and two memory-management developers who have never once thought about your WiFi adapter. Mostly noise. But it is also where you find whoever added the entry sitting next to yours, and they are worth having on the Cc. So run it both ways: take the MAINTAINERS entries for the right subsystem, then read the extra names for anyone who has genuinely worked on the thing you are changing.

## Step 10: Send it

Plain text only, nothing attached, no formatting. A reviewer needs to be able to reply in between the lines of your change. Ordinary mail clients rewrap lines and turn tabs into spaces, which quietly corrupts a patch and wastes everyone's time. Use git's own tool:

```
git send-email --to=linux-wireless@vger.kernel.org \
  --cc="Felix Fietkau <nbd@nbd.name>" \
  --cc="Lorenzo Bianconi <lorenzo@kernel.org>" \
  --cc="Ryder Lee <ryder.lee@mediatek.com>" \
  --cc="Shayne Chen <shayne.chen@mediatek.com>" \
  --cc="Sean Wang <sean.wang@mediatek.com>" \
  --cc=linux-mediatek@lists.infradead.org \
  --dry-run \
  0001-wifi-mt76-mt7925-add-Netgear-A8500-USB-device-ID.patch
```

`--dry-run` prints what it would do without sending anything. Read the recipient list it prints, because that is the real one. When it looks right, run it again without that flag.

The first time, git asks for your mail server details. Gmail and similar want an app password rather than your normal one.

## Step 11: Wait

Your patch appears on lore within minutes and on patchwork shortly after. Patchwork has a dozen states; the four you care about are `New`, `Under Review`, `Changes Requested` and `Accepted`.

Silence is normal and it is not a verdict. Plenty of patches get no reply at all and are simply applied, and the state on patchwork can change without any mail landing in your inbox. When a reply does come it is often quick, but there is no schedule and nobody owes you one.

Wait weeks, not days. Do not repost within 24 hours. After a month of complete silence, a short reply on your own email asking whether anything more is needed is reasonable.

## If they ask for changes

This is the normal path, not a rejection. Most patches take a second round, and plenty of them are corrections to the message rather than to the code.

**Reply first.** Answer underneath the text you are answering, never above it, and trim the parts you are not responding to.

**Then send v2:**

```
git commit --amend
git format-patch -1 -v2 --subject-prefix="PATCH wireless-next"
```

Open the file, find the `---` line from step 8, and note what changed just below it:

```
Signed-off-by: Your Real Name <you@example.com>
---
v2: dropped the Cc: stable tag, this patch is not fixing a bug
    reworded the commit message as asked

 drivers/net/wireless/mediatek/mt76/mt7925/usb.c | 3 +++
 1 file changed, 3 insertions(+)
```

The reviewer sees that. Linux's history does not. Send it to the same people, plus anyone who replied to v1.

When it is finally taken, the maintainer adds a `Link:` back to your email and their own sign-off underneath yours, recording that it passed through their hands. Then it is in Linux.

## What a finished patch looks like

Every step above showed you one piece at a time. Here is a whole one, assembled, exactly as it would land in somebody's inbox.

The driver in it does not exist. The code is nonsense. Everything else about it is correct, and that is the part to copy.

```
From: Your Real Name <you@example.com>
To: linux-wireless@vger.kernel.org
Cc: Felix Fietkau <nbd@nbd.name>,
	Lorenzo Bianconi <lorenzo@kernel.org>,
	linux-mediatek@lists.infradead.org
Date: Wed, 12 Aug 2026 09:41:03 -0700
Subject: [PATCH wireless] wifi: clue: add missing entry to the clue table

The clue table has been empty since the driver was merged, so
clue_lookup() has never returned anything and every caller has had
to carry on without one.

Testing on affected hardware shows that a clue is in fact present
and can be read at probe time. Add it to the table so that lookups
succeed and the driver has a clue.

Fixes: deadbeefc0de ("wifi: clue: add the clue table")
Cc: stable@vger.kernel.org
Reported-by: Some Person <them@example.com>
Closes: https://lore.kernel.org/linux-wireless/20260801093344.2261-1-them@example.com/
Signed-off-by: Your Real Name <you@example.com>
---
 drivers/net/wireless/clue/clue.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/drivers/net/wireless/clue/clue.c b/drivers/net/wireless/clue/clue.c
index 5eaf00dc1a55..edc0dedbadc0 100644
--- a/drivers/net/wireless/clue/clue.c
+++ b/drivers/net/wireless/clue/clue.c
@@ -40,5 +40,6 @@ static const struct clue clue_table[] = {
 	{ .id = CLUE_NONE,   .desc = "no clue" },
 	{ .id = CLUE_VAGUE,  .desc = "some idea" },
 	{ .id = CLUE_STRONG, .desc = "pretty sure" },
+	{ .id = CLUE_FOUND,  .desc = "a clue" },
 	{ }
 };
-- 
2.55.0
```

Reading down it, and matching each part back to the step it came from:

**`Cc:`** is the driver's people, from step 9. The mailing list is in `To` on its own.

**`[PATCH wireless]`** says this is a fix and belongs in the `wireless` tree. It would be `[PATCH wireless-next]` for anything else, and a second version would say `[PATCH wireless v2]`.

**The subject** narrows left to right through the colons, and is an instruction: "add", not "adds" or "added".

**The body** says what was wrong first and what the change does second, wrapped at about 72 characters. It mentions that the change was tested, which is worth a sentence whenever it is true.

**`Fixes:`** names the commit that introduced the problem. That hash is invented. A real one is twelve hex characters, looked up in the mainline tree, never copied out of this repo or openwrt.

**`Cc: stable`** sits directly under a `Fixes:` tag, which is the only place it belongs.

**`Reported-by:`** credits whoever found it, followed by **`Closes:`** pointing at the report itself.

**`Signed-off-by:`** goes last, and is yours alone.

**The `---` line** is the boundary from step 8. A second version would list its changes just below it, and that note would be thrown away when the patch was applied.

**The diffstat** and the **`-- ` with the git version** underneath it are both added for you. You never type either.

## Do and do not

**Do**

- Use your real name and an address you can receive replies at.
- One change per patch.
- Run checkpatch every time.
- Test on the actual hardware.
- Name the target tree in the subject prefix.
- Read your own patch file before sending it.
- Reply underneath, not above.

**Do not**

- Attach the patch. It goes in the body of the mail.
- Send HTML mail.
- Send from a client that rewraps lines or converts tabs.
- Sign off in someone else's name, or add a `Tested-by:` they have not agreed to.
- Take a `Fixes:` hash from this repo or from openwrt. Look it up in mainline.
- Put `Cc: stable` on a patch with no `Fixes:` tag.
- Roll a tidy-up into a bug fix. You will be asked to separate them.
- Repost within 24 hours.

## Checklist

```
[ ] git config user.name is my real name
[ ] One logical change, nothing else riding along
[ ] Subject: wifi: mt76: <chip>: <what it does>, imperative, under 70 chars
[ ] Body says the problem, then the fix
[ ] Fixes: tag if this repairs something, hash taken from the mainline tree
[ ] Cc: stable only alongside a Fixes: tag
[ ] Tested-by only with explicit agreement; Reported-by paired with Closes
[ ] Signed-off-by is mine and only mine
[ ] git diff --check clean, before committing
[ ] ./scripts/checkpatch.pl -g HEAD clean
[ ] Builds, and works on the hardware
[ ] git format-patch --subject-prefix="PATCH wireless" or "PATCH wireless-next"
[ ] Opened the .patch file and read it
[ ] ./scripts/get_maintainer.pl --nogit --nogit-fallback, unrelated subsystems dropped
[ ] git send-email --dry-run, recipient list checked
[ ] Send
```

## Stuck?

Ask in the pinned issue on this repo.

## Sources

This is the kernel's own documentation cut down to the one path this repo uses. For the full story:

- `Documentation/process/submitting-patches.rst` is the main guide and the authority on anything here.
- `Documentation/process/submit-checklist.rst` is the official checklist.
- `Documentation/process/email-clients.rst` if you cannot use `git send-email`.
- `Documentation/process/stable-kernel-rules.rst` for getting fixes into older kernels.
- `Documentation/process/maintainer-netdev.rst` for networking conventions, much of which carries over.

All of them are in the tree you cloned in step 1, and online at `docs.kernel.org`.
