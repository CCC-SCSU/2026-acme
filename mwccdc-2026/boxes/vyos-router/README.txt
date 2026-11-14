VyOS Router  --  VyOS 1.4.0  --  vyos / vyos  (CHANGE THIS)
  external 172.31.(20+team#).2/29   wkst 172.17.0.1/24   internal 172.16.0.254/24

*** DO NOT RUN THE MAIN KIT HERE. *** VyOS uses a commit-based config system;
the kit's iptables/systemd/package logic does not apply.

THE ONE SCRIPT THAT IS SAFE HERE (read-only, plus a config backup):
    bash ../../vyos-backup.sh

NO SNAPSHOTS, NO SCRUBS. Every scored service routes through this box. If you
break it there is no revert.

ORDER OF WORK
 1. bash ../../vyos-backup.sh          back up + list persistence spots
 2. Copy that backup off the router.
 3. Change the default password (everyone has the packet):
        configure
        set system login user vyos authentication plaintext-password <newpass>
        commit-confirm      <- auto-reverts in 10 min unless you type 'confirm'
        confirm
        save
    Submit it via Quotient PCR if anything scores against it.
 4. Hunt for red team:
        show configuration commands | match "system login user"   extra accounts
        cat /config/scripts/vyos-postconfig-bootup.script         boot persistence
        show configuration commands | match "nat"                 altered forwards
        show ip route                                             unexpected routes
        show interfaces                                           unexpected interfaces

ALWAYS USE commit-confirm, NOT commit. It auto-reverts if you lock yourself out.

WHAT NOT TO DO
 * No source-IP filtering on public services (rule 9 -- penalty if detected).
 * Never block ICMP (rule 12 -- Ping is scored).
 * Do not change interface addressing or system names (rule 7).
 * Do not touch NAT without knowing which scored service each rule carries.
