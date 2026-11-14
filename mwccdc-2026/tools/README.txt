================================================================================
 TRUSTED TOOLS  --  tmux, bash, and a package manager you can believe
================================================================================

READ THIS FIRST: THE BEST ANSWER IS USUALLY "DON'T"
--------------------------------------------------------------------------------
If you are worried about a backdoored tmux on a competition box, the simplest fix
is to not use the box's tmux at all.

  RUN TMUX ON YOUR OWN MACHINE, NOT ON THE BOX.

  On your VPN machine:        tmux new -s ccdc
  Inside that tmux:           ssh sysadmin@172.20.240.10
  Split the window, SSH to a different box in each pane.

Your tmux, your config, your machine. Nothing on any competition box can log your
keystrokes through a tmux you never ran there. This also solves your other problem:
the packet gives you ONE VPN device at a time, and a local tmux session is how your
team hands off a shared terminal without losing anyone's work.

Only install tools ON a box when you have to type a lot on that box directly.

--------------------------------------------------------------------------------
STEP 1 -- IS THE BOX'S COPY ACTUALLY BAD?    (do this first, it is free)
--------------------------------------------------------------------------------
    sudo sh tools/3-check.sh

Read only. It checks:
  * whether bash / tmux / ls / ps / find / grep still match their package checksums
  * whether any of them belong to no package at all (a hand-placed binary)
  * whether the package manager was told to SKIP SIGNATURE CHECKS
  * whether an install hook was added that runs curl/wget/nc as root
  * where packages are being downloaded from
  * whether PATH has been hijacked, or two copies of a command exist
  * whether a tmux config is mirroring your session (pipe-pane / run-shell)

If that comes back clean, the box's own tmux and bash are very likely fine and you
do not need any of the rest of this.

Caveat worth knowing: a deeply compromised box can lie to you here, because dpkg,
rpm and pacman are themselves programs on that box. Clean is reassuring, not proof.
Dirty is proof.

--------------------------------------------------------------------------------
STEP 2 -- FIX A TAMPERED PACKAGE MANAGER
--------------------------------------------------------------------------------
    sudo sh tools/4-fixrepo.sh

Asks before every change. Anything it removes is MOVED ASIDE (.disabled-<time>),
never deleted. It knows the difference between a stock Debian hook and a backdoor,
so it will not talk you into breaking apt.

It offers to: disable hooks that run network commands, re-enable gpgcheck /
SigLevel, and disable repository files you do not recognise.

If a repo or signing key was replaced and you cannot establish what the original
was, DO NOT install anything from it. File a ticket and work without the package
manager. Installing from an attacker's repo is how you hand them the box twice.

--------------------------------------------------------------------------------
STEP 3 -- BRING YOUR OWN BINARIES    (only if steps 1-2 say you must)
--------------------------------------------------------------------------------
You cannot safely download a trusted tool using a box you do not trust. Its curl,
its DNS and its certificate store could all be lying. So:

  BEFORE COMPETITION DAY, on your own clean machine:

    1. Edit  tools/urls.txt     (I could not verify these URLs -- check them)
    2. sh tools/1-fetch.sh      downloads into tools/bin/, writes SHA256SUMS
    3. Open each project's release page. Compare the hash 1-fetch printed against
       the hash THE PROJECT publishes. Not the one from the download. If they do
       not match, delete the file.
    4. Test each binary on your own machine:   ./tools/bin/bash --version
    5. Re-pack so the binaries travel with the kit:
           cd ../.. && tar czf mwccdc-2026.tgz ccdc

  ON COMPETITION DAY, on the box (no network needed):

    sudo sh tools/2-install.sh

  It re-verifies every hash and REFUSES to install if even one file changed.
  Then it copies them to /opt/ccdc-bin. It does not overwrite anything.

  To use them in a shell:
    export PATH=/opt/ccdc-bin:$PATH
    command -v bash ls          confirm you are getting /opt/ccdc-bin/...

  You have to run that export in each new shell. That is on purpose: editing
  /etc/profile to make it permanent is itself a persistence technique, and you do
  not want your own work to look like red team's.

--------------------------------------------------------------------------------
WHAT TO PUT IN urls.txt
--------------------------------------------------------------------------------
Static binaries carry their own libraries, so one file runs on any Linux of the
same CPU type. Check yours with:  uname -m   (x86_64 normal, aarch64 is ARM)

  busybox   One file, dozens of tools: sh, ls, ps, netstat, grep, find, vi, top.
            This is the highest-value single thing to bring. If you only bring
            one binary, bring busybox. 2-install.sh links its applets for you.

  bash      A full bash if busybox's smaller shell is not enough.

  tmux      Static tmux builds are less standard than the other two. If you cannot
            find one you trust, do not force it -- use the "run tmux on your own
            machine" approach at the top of this file instead. It is better anyway.

I have deliberately not shipped you any binaries. I have no network here, so I
could not fetch, build or verify any of them, and a root-level binary that arrives
from an AI tool with no provenance is exactly what you are trying to defend against.
Fetch them yourself from the upstream project and check the hashes.

--------------------------------------------------------------------------------
IF A SYSTEM BINARY IS CONFIRMED TAMPERED
--------------------------------------------------------------------------------
  Debian/Ubuntu   apt-get install --reinstall <package>
  Rocky           dnf reinstall <package>
  Arch            DO NOT use pacman -S, that is a partial upgrade. Restore the
                  file from the package you already have:
                      ls /var/cache/pacman/pkg/ | grep <name>
                      tar xf /var/cache/pacman/pkg/<file>.pkg.tar.zst -C /tmp/x
                  then copy the single file into place.

All of those need a package manager and repo you trust. Run 3-check.sh first, or
you may be reinstalling from the attacker.
================================================================================
