# MWCCDC 2026 Linux Kit

Defensive hardening, monitoring and cleanup scripts for the
**2026 Midwest Invitational CCDC** (14 November 2026).

**Start here:** [`GUIDE.txt`](GUIDE.txt) — then print [`FIELD-MANUAL.txt`](FIELD-MANUAL.txt).

## The three commands

From your machine's folder:

```sh
sudo bash harden.sh dry      # see the plan, change nothing
sudo bash harden.sh          # lock it down (asks before every change)
sudo bash watch.sh           # keep scored services alive + monitor
sudo bash clean.sh           # at the end: evidence bundle, then teardown
```

## Folders

| Folder | Machine | OS |
|---|---|---|
| `MY-BOX-debian-splunk/` | 172.20.240.20 | Debian 12 + Splunk 10 |
| `boxes/rocky-ecom/` | 172.20.240.10 | Rocky Linux 9 |
| `boxes/ubuntu-email/` | 172.20.240.15 | Ubuntu 22.04 |
| `boxes/ubuntu-wkst/` | dhcp | Ubuntu |
| `boxes/kali/` | 172.17.0.2 | Kali |
| `boxes/windows-*/` | — | notes only (this kit is bash) |
| `boxes/palo-alto/` | 172.20.240.200 | notes only (web UI) |
| `boxes/vyos-router/` | 172.16.0.254 | notes only (VyOS CLI) |

## Safety properties

- Every script has a read-only or `dry` mode. Run it first.
- The firewall applies a default-deny inbound ruleset that **auto-reverts in 5 minutes**
  unless you confirm — there are no VM snapshots in this environment.
- `harden.sh` validates `sshd_config` and restores the original if it fails.
- Source-IP filtering is **refused** (competition rule 9) and ICMP is always allowed (rule 12).
- `clean.sh` collects evidence *before* deleting anything.

Every script responds to `--help`.
