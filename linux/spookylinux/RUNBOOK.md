# WRCCDC 2026 Invitational 2 (Acme LLC) — Linux runbook

## Fast path
Run everything with `bash <script>` — no chmod needed.

    sudo bash ccdc/go          full guided run (asks before every change)
    sudo bash ccdc/go r        recon only, changes nothing
    sudo bash ccdc/go d        DRY RUN — walks every phase and prints what it would do

**Do the dry run first on each box.** You have no lab time, so this is your test.

## If the main kit fails
`plan-b/` holds five standalone `/bin/sh` scripts that share no code with the main kit and need nothing
but coreutils, so they also run on busybox/Tiny Core. See `plan-b/PLAN-B.txt`. They are deliberately
dumber: one password at a time, a firewall that undoes itself, a port watcher. Nothing clever to break.

## Network (from the packet)
- Internal: `192.168.220.0/24`. From outside, `10.100.1XX.Y` NATs to `192.168.220.Y`.
- VPN: NetBird, one shared team account, **one device at a time**. Access opens 9AM.
- Scoring: ~10 services, every 2–4 min. **SLA after 5 failed checks** → roughly 10–20 min of slack.
- Box credentials arrive at 9AM (Discord). Scored-service list comes from the scoring engine.

## Linux boxes
| IP | Host | OS | Service | Notes |
|---|---|---|---|---|
| .11 | daffy | Debian | Blog | web + probably a DB; run `web-harden.sh` |
| .169 | taz | Debian 13 | Photo Management | Debian 13 → likely **nftables**, no iptables |
| .67 | porky | Arch | Tracker | rolling release; **do not run `pacman -Syu`** mid-game |
| .13 | foghorn | Rocky | Wiki/Chat | firewalld + SELinux |
| .69 | sylvester | Rocky | Video Streamer | firewalld + SELinux |
| .77 | elmer | Ubuntu 22.04 | Forums | |
| .199 | marvin | Ubuntu | Database | do **not** expose the DB port externally |
| .12 | roadrunner | Tiny Core | K8S | not systemd — the kit mostly will not apply |
| .1/.2 | tweety | OPNsense | ROUTER | **see OPNSENSE.md — never run this kit there** |

## Order per box
1. `sudo bash ccdc/go d` — dry run, read what it plans.
2. `sudo bash ccdc/go` — recon + backup runs first and changes nothing. Read the RED FLAGS block.
3. Accounts → **submit every password change through the scoring engine**, not tickets.
4. Services phase → edit `/etc/ccdc/services.conf`, then start the watchdog.
5. Firewall **last**, after you know which ports are scored.

## Packet rules that change what you do
- **Passwords:** change requests go through `https://scoring.wccomps.org/`. Rotate, then submit.
- **SSH is in the scored-protocol list** and Orange Team may check it manually. Do **not** restrict SSH
  by source IP or change its port unless you have confirmed it is not scored on that box.
- **Telnet** appears in the protocol list but Orange Team says it is not manually scored. The automated
  engine may still check it. Confirm before you disable it.
- **Red team can reboot your boxes.** The watchdog (`services.sh watch`) is what gets services back up.
- **-50 points** if red team recovers credentials from a box. `users.sh` writes new passwords to a
  root-only file and shreds it at `reveal` — copy them to paper and never leave them on disk.
- **Router reset = -100.** Cutover windows at :00 and :30 only.

## Per-box service watchdog
    sudo bash ccdc/services.sh discover     # build the watch list
    sudo nano /etc/ccdc/services.conf       # delete non-scored ports, fix FIXME- names
    sudo bash ccdc/services.sh check        # one-shot
    sudo bash ccdc/services.sh watch 30 &   # auto-restart, max 3 per 15 min
    sudo bash ccdc/services.sh status       # what has been restarting

## Distro gotchas
- **Debian 13:** often ships nftables with no working iptables. `firewall.sh` detects this and builds its
  own `inet ccdc` table, leaving other tables alone. Rollback deletes just that table.
- **Arch:** `pacman -S <one package>` pulls the current repo version and a partial upgrade can break
  unrelated software. `pkgcheck.sh` asks twice before doing it. Prefer restoring from
  `/var/cache/pacman/pkg`. Arch usually has no cron — check `systemctl list-timers` instead.
- **Rocky:** firewalld + SELinux. Changing the SSH port needs `semanage`; `harden.sh` refuses rather than
  half-applying if `semanage` is missing.

## Safety properties (verified by test)
- firewall.sh never sets policy to DROP unless every allow rule applied; any failure restores the old
  ruleset. Auto-rollback at 300s unless you confirm.
- harden.sh restores sshd_config if `sshd -t` fails, if `semanage` is missing, or if the reload fails.
- users.sh records a password **before** changing it, refuses to lock the account you are logged in as,
  and never runs `pkill -u 0`.
- services.sh rate-limits restarts (3 per unit per 15 min) so a flapping service cannot loop forever.
- backup.sh aborts below 1 GB free and skips directories over MAX_MB (default 500).
- Nothing reboots, touches the bootloader, or loads kernel modules.
