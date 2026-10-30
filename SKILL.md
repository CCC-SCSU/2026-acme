---
name: "ccdc"
description: "Competition context for the user's CCDC blue-team work (WCComps/WRCCDC Invitational 2, Acme LLC): network map, NAT, scoring, penalties, inject rules. Use on /ccdc or any CCDC, injects, Quotient, or Acme box-hostname mention."
---

# CCDC competition context — Acme LLC (WCComps 2026 Invitational 2)

The user is a cybersecurity student on a blue team. This skill is the team
packet turned into working context, so that anything you do for the competition
(hardening scripts, firewall rules, inventory, triage, incident reports, inject
prep, practice) fits the real environment and rules instead of generic advice.

**Source:** `WCComps-INV2-2027-TeamPacket.pdf` (15 pages; page header says
"WCComps 2026 Invitational 2"). WCComps runs the Western Regional (WRCCDC)
events — if the user is preparing for a Midwest (MWCCDC) event, the rules
below are a good approximation but the topology and costs are specific to this
packet. When a newer packet arrives, it supersedes this one.

## How to use this context

- Ground answers in the real hosts, IPs and OSes below. If the user says
  "harden porky", you already know it's Arch Linux running the tracker at .67.
- Always weigh the scoring trade-off: **uptime of scored services is points**.
  A fix that breaks a scored service, locks out the scoring engine, or forces a
  box reset can cost more than the red-team finding it prevents. Prefer
  changes that are reversible, tested one service at a time, and backed up first.
- The packet says the previous IT team left **no documentation** and "there may
  be other servers and services". Treat the table as a starting point and push
  for an inventory in the first minutes (see checklist below).
- Credentials for boxes arrive at **9 AM on competition day** (likely via
  Discord). Scored service list appears in Quotient that day. Don't invent
  credentials or claim to know the exact scored checks.
- Packet facts are marked as such; anything you infer (likely scored ports,
  likely red-team paths) should be labeled as inference.

## Environment

- **Company / theme:** Acme LLC (Looney Tunes theme). Domain: `acme.anvil`.
- **Internal network:** `192.168.220.0/24`.
- **External / 1:1 NAT:** `10.100.1XX.Y` → `192.168.220.Y`, where `XX` is the
  team number (example in packet: `10.100.102.10` → `192.168.220.10`). The NAT
  applies **only from outside the router**. Internal hosts talk to each other on
  192.168.220.Y; the scoring engine and red team come in via 10.100.1XX.Y.
  Firewall rules on tweety must allow scoring traffic through that NAT.

### Hosts

| IP (.Y) | Hostname | OS | Role / likely services |
|---|---|---|---|
| .1 / .2 | tweety | OPNsense 26.7 | Router / firewall (team-managed) |
| .10 | bugs | Windows Server 2025 | Domain controller — AD / DNS |
| .11 | daffy | Debian | Blog |
| .12 | roadrunner | Tiny Core + "???" | Kubernetes "Secure(?)" services — Git, SSH, IdP |
| .13 | foghorn | Rocky Linux | Wiki & chat |
| .46 | speedy | Windows Server Core 2022 | E-commerce (no GUI — PowerShell/sconfig) |
| .67 | porky | Arch Linux | Tracker |
| .69 | sylvester | Rocky Linux | Video streamer |
| .77 | elmer | Ubuntu 22.04 | Forums |
| .112 | wil.e | Windows 11 | Gallery |
| .169 | taz | Debian 13 | Photo management |
| .199 | marvin | Ubuntu (24.04 per diagram) | Database |
| .234 | ysam | NixOS 25.05 | dnsmasq PXE server, SSH — **on the topology diagram only, not in the table** |

Notes from the packet:
- ysam appearing only in the diagram is a hint that the table is incomplete.
  A PXE/dnsmasq box can also hand out DHCP/DNS/boot images — a juicy red-team
  persistence target and a possible source of rogue DNS.
- marvin (DB) likely backs the e-commerce site on speedy and maybe others;
  customer data/PII/credit cards there carry the largest penalties.
- roadrunner's OS is literally "???" — expect surprises (k3s/k8s on Tiny Core).
- Protocols the packet lists as in play: RDP, SSH, SNMP, SMTP, IMAP, POP3,
  VNC, OpenVPN, HTTP/HTTPS, Telnet, DNS, NFS, SMB, FTP. Box access is via SSH,
  VNC, Telnet or RDP depending on device.

### Router (tweety) — handle with care

- Teams have full control of the OPNsense firewall. Locking yourselves out or
  blocking the **scoring engine** = a very bad day.
- **Router box reset: −100 points each.** If black team loses access, they reset it.
- You may change, delete or disable the `admin` user — but if you lose the
  password and the admin, that's a reset.
- Packet recommends keeping **syslog** and **WAN-side config access** on so you
  can manage from outside — but red team will also have that access. Team's call:
  restrict WAN GUI/SSH to known source IPs rather than leaving it open.
- Router trouble: file a ticket; black team provides a full-admin credential in
  the ticket. **Cutover windows are every 30 minutes** (:00 / :30), including resets.
- Safe practice: export the config before every change; make one change at a
  time; keep a session open while testing a new rule.

## Access & logistics

- **SSO:** `auth.wccomps.org` — one team login for Proxmox, VPN, Quotient, etc.
  Credentials emailed beforehand.
- **VPN:** NetBird, management URL `https://vpn.wccomps.org:443`. One shared team
  account, **max 9 devices** (8 players + 1 coach observer), one device per person.
  Network access opens **promptly at 9 AM**.
- **Scoring / injects (Quotient):** `https://scoring.wccomps.org/` — "Sign in
  with SSO". Scored services, injects, announcements, and **password change
  requests** go here. Quotient is **out of scope for red team**.
- **Tickets:** `https://teams.wccomps.org` (SSO). Use for everything except
  password changes. **Incident reports are submitted here.** Be detailed —
  "router is broken" tickets get ignored. 4–6 staff for many teams.
- **Discord:** "WRCCDC-Competition" server. Join via SSO portal link → in
  `#general` type `/link` → "Click here to authenticate" → SSO. Team channels:
  `teamXX-chat`, `teamXX-voice` — **red team will not join these**; anyone in
  your voice channel is not red team. `#general` / `#memes` **are** visible to
  red team — never post creds/IPs/plans there. Ping `@blackteam` (infra),
  `@whiteteam` (judges). Best-effort, first-come service.

## Scoring

### Service uptime (scoring engine)
- ~10 services (±2) scored across most servers, checked **every 2–4 minutes**.
- **SLA violation after 5 consecutive failed checks.** So a broken service gives
  you roughly 10–20 minutes before an SLA hit — restore fast, change carefully.

### Orange team (manual scoring)
- Manually checks business-like apps: blogs, file services, calculators,
  spreadsheets, OWA, games. Legitimate = what a real business would expose
  (authenticated FTP yes, anonymous FTP no; SSH yes, telnet no).
- Contact via tickets or Discord chat/voice. They may ask for a **secret
  word/phrase** — the packet's is **"Free Birdseed"**.
- Scored by checks attempted; **≤10% of total points**. Promptly replying that a
  downed service is restored (and it really is) can win points back.
- Hint from packet: **monitor your team voice channel** for orange team.

### Injects (Quotient)
- First inject arrives within minutes of start. Timed; **late = not accepted**
  (close time usually = due time). Weighted by complexity; some are chained
  (e.g., choose software in one, deploy it in the next). One judge per inject,
  rubric-based, judging is final.
- **Submission rules (points deducted if broken):**
  - **PDF only.**
  - Filename: inject number first, team number only (**never the school
    name**), underscores, zero-padded single digit, all lowercase →
    `inject04_team13.pdf`
  - Cite any template/source you adapted — a URL is enough
    ("Our team was able to find a sample policy from the following site: <url>").
  - Read the inject fully twice before writing and once more before submitting —
    the packet says most points come from delivering *exactly* what's asked.
- **AI rule:** using AI (ChatGPT, Bard, etc.) on an inject = **0 points for that
  inject**; organizers run submissions through AI detectors and **≥20% flagged as
  AI-generated scores 0**. When the user asks for inject help, say this plainly
  once, then help in ways that keep the submission their own: break down what the
  inject asks for, build a requirements checklist from it, explain the technical
  topic, do the technical work (configs, commands, evidence gathering), review
  their draft against the prompt, and check filename/format. If they ask for
  finished submission prose, remind them of the risk and let them decide —
  it's their call, but they should make it knowingly.

### Support tickets (cost in points)
| Request | Cost | What you get |
|---|---|---|
| Service Scoring Validation | 0 | Verify a check you think is wrongly failing (abuse → must buy a Scoring Service Check) |
| Scoring Service Check | 10 | Black team explains why a check fails |
| Orange Team Verification/Questions | 10 | How a score/service check was performed |
| Service Reset / Scrub | 60 | Box restored to start-of-competition state |
| Black Team Phone Consultation | 100 | Diagnose over the phone |
| Black Team Hands-on Consultation | 200 | They log in and investigate/fix |
| Router (tweety) box reset | 100 | Router restored — avoid |

A 60-point scrub resets **all your hardening** on that box too — have a
re-hardening script ready.

### Red team penalties (national guidelines; may be adjusted)
| Finding | Penalty |
|---|---|
| Root / Administrator access | −100 |
| User-level access (shell or equivalent) | −25 |
| Standard user escalated to root/admin | additional −100 |
| User IDs + passwords recovered (hashes count: user list, AD hashes, SAM, /etc/shadow) | −50 |
| Sensitive files (configs, corporate data) | −25 |
| Customer credit card numbers | −50 |
| Customer PII (name, address, CC#) | −200 |
| Encrypted customer data / DB | −25, plus −25 if decrypted |

- Cumulative per incident; packet example chain = **−425**.
- Scored **per system per method** — the same vuln twice on one box counts once,
  a different vuln on the same box counts again. Only the highest access level per
  attack is scored.
- Red team may also deface sites, stop services, add/remove users, modify files,
  and reboot any server **including the router** — all legal, all hurt uptime.
- Red team must show proof with a timestamp. Incident reports (via tickets) are
  how blue teams document and respond — make them detailed: time, host, IOCs,
  what was accessed, how it was contained, remediation.

## Priorities that follow from the rules

1. **Biggest penalties live on bugs (AD hashes, domain admin) and marvin/speedy
   (customer PII + card data).** Protect those first.
2. **Default/shared credentials** are the fastest red-team win → rotate early.
   Domain/service passwords that the scoring engine uses go through **Quotient
   password change requests** — changing them silently can fail checks.
3. **Firewall on tweety:** default-deny inbound except scored services, but test
   from outside (10.100.1XX.Y) and keep a rollback.
4. Hunt for persistence the old team (red team) pre-staged: extra users, SSH
   keys, cron/systemd timers, scheduled tasks, services, web shells, k8s
   workloads on roadrunner, PXE/DHCP abuse on ysam.
5. Keep services up through every change; watch Quotient's service status.

## First-hour checklist (suggested)

1. Everyone on VPN, Discord `/link`ed, Quotient + ticket portal open, creds
   from 9 AM drop saved in a team-only place.
2. Inventory every box: hostname, IP, OS, listening ports/services, users,
   admins/sudoers, scheduled tasks/cron, running containers/pods. Nmap the /24
   for hosts not in the table (ysam proves the table is incomplete).
3. Snapshot/backup configs (tweety config export, web roots, DB dumps, `/etc`).
4. Rotate credentials (via Quotient where scored), remove unknown accounts/keys.
5. Firewall baseline on tweety and host firewalls; confirm scoring still green.
6. Assign an inject owner who watches Quotient constantly and tracks deadlines.
7. Someone sits in team voice for orange team.

## Things not in the packet (don't assume)

- Exact scored services/ports and box credentials (given on the day).
- Your team number (determines `10.100.1XX.Y`) — ask the user if needed.
- Injects' content. Everything above about likely attack paths is inference.