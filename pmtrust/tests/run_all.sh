#!/bin/bash
# Full regression matrix. Needs the fixtures under /srv/t (see the build_* scripts).
cd /home/claude/pmtrust/tests
cp ../agent/collect.sh ../agent/apply.sh /srv/t/agent/
run() { echo; echo "######## $*"; "$@" 2>&1 | grep -E '^(PASS|FAIL|==)|mismatches'; }
run python3 test_vercmp.py
run bash run_apt_cycle.sh /srv/t/noble-upd marvin
run bash run_apt_cycle.sh /srv/t/jammy-clean elmer
run bash run_apt_trust.sh "$(ls -t /srv/t/elmer/root/pmtrust/out/*.tar.gz | head -1)"
run bash run_rpm_cycle.sh foghorn
run bash run_rpm_trust.sh
run bash run_pacman_cycle.sh porky
run bash run_pacman_trust.sh
run bash run_nix_cycle.sh
echo; echo "######## audit-only backends"
. ./harness.sh
for t in tc-clean tc-atk; do rm -rf /srv/t/ra-$t; python3 $PM plan --agent $AGENT --snapshot "$(ls -t /srv/t/$t/root/pmtrust/out/*.tar.gz | head -1)" --out /srv/t/ra-$t --tce-baseline /srv/t/tc-baseline.md5 >/dev/null 2>&1; echo "$t: $(head -1 /srv/t/ra-$t/report.txt)"; done
for t in bsd-clean bsd-atk; do rm -rf /srv/t/ra-$t; python3 $PM plan --agent $AGENT --snapshot /srv/t/$t-freebsd.tar.gz --out /srv/t/ra-$t --pkg-fingerprint "$(cat /srv/t/bsd-fp)" >/dev/null 2>&1; echo "$t: $(head -1 /srv/t/ra-$t/report.txt)"; done
