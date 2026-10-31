# tweety (.1/.2) -- OPNsense 26.7 -- DO NOT RUN THIS KIT ON IT

OPNsense is FreeBSD with pf. Every script here assumes Linux, systemd, and iptables/nft. Running them
there will not work and may break the firewall. A box reset costs **-100 points per reset**, and resets
only happen in cutover windows (:00 and :30).

## Order of work (web UI, https://192.168.220.1)
1. **Back up first:** System > Configuration > Backups > Download. Save it off-box. Do this before any change.
2. **Change the admin password** (System > Access > Users). The packet says you may change/disable/delete
   `admin` -- but if you lose it and there is no other admin, that is a reset. Create and TEST a second
   admin account before touching `admin`.
3. **Check for red-team persistence:** extra users, extra API keys (System > Access > Users > API),
   unexpected firewall/NAT rules, unknown VPN tunnels, scheduled cron jobs (System > Settings > Cron).
4. **Keep the 1:1 NAT intact.** 10.100.1XX.Y maps to 192.168.220.Y from outside only. Break it and every
   external check fails at once.
5. **Do not disable WAN management or syslog** unless your team has agreed on it -- the packet warns you
   may lose your own way in. Red team has access too, so that is a real trade-off, not a free win.
6. **Firewall rules:** add an explicit allow for the scoring engine and your VPN range BEFORE tightening
   anything. Apply changes, then immediately verify from a second session.

## If you lock yourself out
File a ticket. A credential will be provided in the ticket. Cutover windows are every 30 minutes.
