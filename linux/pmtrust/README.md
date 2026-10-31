# pmtrust: rebuild the package manager on every Linux/FreeBSD box from a verified trust chain

Team 37, Acme LLC (WCComps Invitational 2). Built from `/pm-reinstall`. It generalises
`reinstall-apt-trusted.py` (v1) into a shared core with one backend per package manager.

**Model.** The boxes are never trusted.

1. A static busybox **agent** takes a read-only **snapshot** of each box.
2. A trusted **staging laptop**, using its own `gpgv`, `gpg` and `openssl` and keys you pin, verifies the signatures, parses everything, audits, and writes a **plan**.
3. A POSIX `apply.sh` on the box carries out the plan. It runs no box binary until those binaries have been replaced with verified copies, and it backs up everything it changes.

Python is needed only on the staging laptop.

| Host | IP (.Y) | OS | Backend | Mode |
|---|---|---|---|---|
| marvin | .199 | Ubuntu 24.04 | apt | repair (tested on real Ubuntu data) |
| elmer | .77 | Ubuntu 22.04 | apt | repair (tested on real Ubuntu data) |
| daffy | .11 | Debian | apt | repair (same code, Debian mirrors not testable here) |
| taz | .169 | Debian 13 | apt | repair (same code, not testable here) |
| foghorn, sylvester | .13, .69 | Rocky Linux 9/10 | rpm | repair (synthetic test only) |
| porky | .67 | Arch | pacman | repair (synthetic test only) |
| ysam | .234 | NixOS 25.05 | nix | verify + store-file repair (synthetic test only) |
| roadrunner | .12 | Tiny Core | tce | **audit only**: Tiny Core has no signatures |
| tweety | .1 | OPNsense 26.7 | freebsd-pkg | **audit only**: a router reset costs 100 |

Addresses: internal `192.168.220.Y`; from outside the router `10.100.137.Y`
(`VIA=ext` in the helper).

## Before competition day: trust anchors (do this now, cross-check each through a second channel)

Never take keys from a box. Put them on the staging laptop:

| Backend | `--keyring` | Pins |
|---|---|---|
| Ubuntu | `/usr/share/keyrings/ubuntu-archive-keyring.gpg` from a trusted Ubuntu host | `--expect-fpr F6ECB3762474EDA9D21B7022871920D1991BC93C` (2018 archive key; it signed noble and jammy in testing) |
| Debian | `debian-archive-keyring.gpg` | the trixie/bookworm archive and security key fingerprints from https://ftp-master.debian.org/keys.html |
| Rocky | `RPM-GPG-KEY-Rocky-9` (or `-10`) from rockylinux.org | its fingerprint from https://rockylinux.org/resources/keys |
| Arch | the `/usr/share/pacman/keyrings` directory from a verified Arch ISO | the master key fingerprints from https://archlinux.org/master-keys/ (they must be listed in `archlinux-trusted`) |
| NixOS | none | `--nix-trusted-key cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=` (check it against the NixOS manual) |
| OPNsense | none | `--pkg-fingerprint <sha256>` from OPNsense's release notes or a verified image |
| Tiny Core | none | `--tce-baseline md5s.txt`: the `.tcz.md5.txt` files fetched over HTTPS from repo.tinycorelinux.net, or md5s taken from the pristine image |

Mirrors you will want reachable from the staging laptop: archive/security.ubuntu.com,
deb.debian.org, dl.rockylinux.org (+ /vault), archive.archlinux.org, cache.nixos.org.
Offline instead: `--repo file:///mnt/iso ...` / `--rpm-repo file:///mnt/dvd/BaseOS` (Rocky DVD) also
work, because signatures are checked either way. Use `--cache DIR` to avoid re-downloading.

Build the agent once (needs a static busybox, e.g. Debian/Ubuntu `busybox-static`):

```
python3 pmtrust.py agent --busybox /bin/busybox --out agent-build
```

## Competition day, per box

```
./pmtrust-box.sh collect marvin                       # 1. snapshot (read-only, ~2-30 s), pulled to snaps/
python3 pmtrust.py plan --snapshot snaps/snap-marvin-*.tar.gz \
    --keyring ubuntu-archive-keyring.gpg --expect-fpr F6ECB3762474EDA9D21B7022871920D1991BC93C
                                                      # 2. verify + audit -> plan-marvin-<time>/ + log
./pmtrust-box.sh apply marvin plan-marvin-<time>      # 3. dry run on the box (default)
./pmtrust-box.sh apply marvin plan-marvin-<time> --apply
./pmtrust-box.sh apply marvin plan-marvin-<time> --verify     # any time later: re-check verified files
./pmtrust-box.sh fetch-evidence marvin                # logs + manifests for the incident report
```

Backend-specific `plan` flags:

- **rpm:** `--rpm-repo URL` (repeatable). The default is Rocky BaseOS+AppStream for the box's release plus the vault.
- **pacman:** `--pacman-archive URL`. `--keyring` is the keyrings directory.
- **nix:** run `plan` once. It writes `need-hashes.txt`. Then run `./pmtrust-box.sh collect ysam --hash-list plan-.../need-hashes.txt` and `plan` again.
- **tce / tweety:** `plan` writes `report.txt` only.

`plan` exit codes: 0 clean, 2 critical findings, 1 refused (a verification failure stops everything).
Compare the **plan id** that `plan` prints with the one `apply.sh` prints on the box.

### What `--apply` does

1. It checks `MANIFEST.sha256`, the hostname, and the plan's age (48 h by default).
2. It backs up the package database and the loader/debconf caches.
3. It quarantines injection points:
   - `ld.so.preload` and the library it names
   - unverified `dpkg.cfg.d` files, apt hooks, transports and keys, and `trusted=yes` sources
   - `policy-rc.d`
   - rpm macros and plugins, Python start-up hooks, dnf plugins
   - unverified pacman hooks
4. It restores **verified** config files that were modified to weaken trust. Every other modified config file is kept.
5. It writes the verified files: libc and the package manager first.
6. It replaces the maintainer scripts the package manager would run from the old package.
7. It runs the now-verified package manager to repair its database. Neither old scriptlets nor other packages' triggers run:
   - **dpkg:** `--force-confold --no-triggers` with policy-rc.d set to 101, then triggers for verified packages only
   - **rpm:** `-U --replacepkgs --nopreun --nopostun --notriggers`
   - **pacman:** `-U --dbonly --noscriptlet` with both hook directories moved aside
8. It re-verifies every verified file.

Everything changed is listed in `/var/lib/pmtrust/run-<time>/manifest.tsv`, alongside the backups,
the quarantine and `apply.log` (timestamped).
`apply.sh --rollback /var/lib/pmtrust/run-<time>` restores it in reverse order. Rerunning `--apply` is a no-op.

**Report-only, by design.** These need a human decision:

- PATH and loader shadowing
- `LD_PRELOAD` in profiles and sudoers
- unowned files
- `gpgcheck` in repo files that pmtrust did not verify
- extra rpmdb keys
- nix.conf
- everything on roadrunner and tweety

**Uptime.** The plan lists the services package scripts may restart. libc6's postinst calls
`systemctl daemon-reexec` directly, which policy-rc.d cannot block. Apply one box at a time and watch
Quotient. A dry run never executes anything from the box.

## Tests (this session)

| Backend | Data | Result |
|---|---|---|
| apt | real Ubuntu 24.04 (updated, nginx) and 22.04 chroots, real archive | clean baselines 0/0; 23 planted attacks reported; apply fires none; verified files byte-identical to clean; `dpkg --verify` clean; idempotent; rollback exact: **37/37 each**. Trust chain: 10/10. Non-exact-version upgrade path OK |
| rpm | synthetic EL9: real rpmbuild/rpmsign/createrepo_c, rpm running in the chroot | 27/27 cycle (old %preun/%postun, triggers, file triggers, plugin, macro never fire), trust 10/10. rpm EVR compare 531/531 vs real rpm |
| pacman | synthetic Arch: makepkg-format packages, 3-master web of trust, real pacman in chroot | 25/25 cycle, trust 8/8. vercmp 400/400 vs real `vercmp` |
| nix | synthetic store + real `nix copy` signed cache | 17/17 (repair, idempotence, rollback, 5 signature/tamper refusals) |
| tce | synthetic Tiny Core layout | clean 0/0; all 9 plants reported |
| freebsd-pkg | synthetic OPNsense tree (Linux collector, os=FreeBSD) | clean 0/0; all 7 plants reported |

**Not tested:**

- real Debian, Rocky, Arch, NixOS, Tiny Core and OPNsense data (those mirrors were blocked in the build sandbox)
- the collector's FreeBSD branch (syntax-checked only)
- EL8 BerkeleyDB rpmdb (it is refused)
- SELinux relabelling on Rocky (rpm's selinux plugin relabels files at finalize)

Run `pmtrust plan` against one real box of each OS during practice before relying on it. Aim for 0 critical and 0 warnings on a clean box.

`tests/` has the fixture builders and `run_all.sh`.

## Limits

- Signatures prove origin, not honesty: the xz-utils backdoor would pass.
- The collector runs on the live box, so a kernel rootkit can lie to it.
- Logging in over SSH runs the box's own sshd, PAM and shell. An implant hooked into those (preload, PAM module,
  profile) fires on every login, whatever tool you use. pmtrust itself executes only the bundled busybox until
  the verified package manager is in place.
- Persistence outside package management is not covered: systemd units, cron, SSH keys, PAM, initramfs, bootloader, Kubernetes on roadrunner.
- On a confirmed compromise, image the box for evidence and rebuild. This is a stopgap.
- A 60-point scrub undoes everything: rerun collect → plan → apply.
