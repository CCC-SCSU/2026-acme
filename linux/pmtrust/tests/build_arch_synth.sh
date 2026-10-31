#!/bin/bash
# Build a SYNTHETIC Arch-like system for testing the pacman backend when Arch
# mirrors are unreachable. Packages are assembled the way makepkg does it
# (.PKGINFO, bsdtar mtree .MTREE, zstd), from the host's own binaries so pacman
# really runs in the chroot; signed by a packager key that 3 test master keys
# certified (Arch web of trust); laid out like archive.archlinux.org.
#   /srv/t/arch/archive        ALA-style tree    /srv/t/arch/keyrings  archlinux-keyring dir
#   /srv/t/arch/masters        pinned master fprs
#   /srv/t/arch-clean          installed target root
set -euo pipefail
B=/srv/t/arch
rm -rf "$B" /srv/t/arch-clean; mkdir -p "$B"/{stage,pkgs,archive/packages,keyrings,gnupg}
chmod 700 "$B/gnupg"; export GNUPGHOME=$B/gnupg
for i in 1 2 3; do gpg --batch --quick-gen-key --passphrase '' "Arch Test Master $i <master$i@test.invalid>" rsa2048 sign never 2>/dev/null; done
gpg --batch --quick-gen-key --passphrase '' 'Arch Test Packager <packager@test.invalid>' rsa2048 sign never 2>/dev/null
gpg --batch --quick-gen-key --passphrase '' 'Rogue Packager <rogue@test.invalid>' rsa2048 sign never 2>/dev/null
fpr() { gpg --list-keys --with-colons "$1" | awk -F: '/^fpr/{print $10; exit}'; }
M1=$(fpr master1@); M2=$(fpr master2@); M3=$(fpr master3@); PK=$(fpr packager@); RG=$(fpr rogue@)
for m in $M1 $M2 $M3; do gpg --batch --yes --default-key $m --quick-sign-key $PK 2>/dev/null; done
gpg --batch --yes --default-key $M1 --quick-sign-key $RG 2>/dev/null      # rogue: only one master signature
gpg --batch --export $M1 $M2 $M3 $PK $RG > "$B/keyrings/archlinux.gpg"
printf '%s:4:\n%s:4:\n%s:4:\n' $M1 $M2 $M3 > "$B/keyrings/archlinux-trusted"; : > "$B/keyrings/archlinux-revoked"
printf '%s\n' $M1 $M2 $M3 > "$B/masters"; echo $PK > "$B/packager"; echo $RG > "$B/rogue"

ML=/usr/lib/x86_64-linux-gnu
BINS="/usr/bin/pacman /usr/bin/bash /usr/bin/touch /usr/bin/cat /usr/bin/ls /usr/bin/rm /usr/bin/mkdir /usr/bin/true /usr/bin/env"
ALL=$(ldd $BINS 2>/dev/null | awk '/=> \//{print $3} /^[ \t]*\/lib64/{print $1}' | xargs -n1 readlink -f | sort -u)
GLIBC_RE='/(libc|libm|libdl|libpthread|librt|libresolv|libutil|ld-linux-x86-64)[.-]'
stage() { local d=$B/stage/$1; mkdir -p "$d"; while read -r f; do [ -n "$f" ] || continue; mkdir -p "$d$(dirname "$f")"; cp -a "$f" "$d$f"; done; }
{ echo "$ALL" | grep -E "$GLIBC_RE"; for l in $(echo "$ALL" | grep -E "$GLIBC_RE"); do ls $ML/$(basename $l | sed 's/\.so.*//').so.* 2>/dev/null; done; } | sort -u | stage glibc
ln -s x86_64-linux-gnu/ld-linux-x86-64.so.2 $B/stage/glibc/usr/lib/ld-linux-x86-64.so.2
for l in $(echo "$ALL" | grep -vE "$GLIBC_RE"); do echo "$l"; ls $ML/$(basename $l | sed 's/\.so\..*//').so.* 2>/dev/null; done | sort -u | stage libarchive
echo /usr/bin/bash | stage bash; ln -s bash $B/stage/bash/usr/bin/sh
printf '%s\n' /usr/bin/touch /usr/bin/cat /usr/bin/ls /usr/bin/rm /usr/bin/mkdir /usr/bin/true /usr/bin/env | stage coreutils
echo /usr/bin/pacman | stage pacman
mkdir -p $B/stage/pacman/etc/pacman.d/hooks $B/stage/pacman/usr/share/libalpm/hooks $B/stage/pacman/usr/share/libalpm/scripts $B/stage/pacman/var/lib/pacman
printf '[options]\nHoldPkg = pacman glibc\nArchitecture = auto\nSigLevel = Required DatabaseOptional\nLocalFileSigLevel = Optional\n\n[core]\nInclude = /etc/pacman.d/mirrorlist\n' > $B/stage/pacman/etc/pacman.conf
mkdir -p $B/stage/pacman-mirrorlist/etc/pacman.d; echo 'Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch' > $B/stage/pacman-mirrorlist/etc/pacman.d/mirrorlist
mkdir -p $B/stage/archlinux-keyring/usr/share/pacman/keyrings; cp $B/keyrings/* $B/stage/archlinux-keyring/usr/share/pacman/keyrings/
mkdir -p $B/stage/gnupg/usr/share/doc/gnupg; echo synthetic > $B/stage/gnupg/usr/share/doc/gnupg/README
mkdir -p $B/stage/systemd/usr/share/libalpm/hooks $B/stage/systemd/usr/share/libalpm/scripts
printf '[Trigger]\nType = Path\nOperation = Install\nOperation = Upgrade\nTarget = usr/lib/sysusers.d/*.conf\n\n[Action]\nDescription = Creating system user accounts...\nWhen = PostTransaction\nExec = /usr/share/libalpm/scripts/systemd-hook sysusers\n' > $B/stage/systemd/usr/share/libalpm/hooks/20-systemd-sysusers.hook
printf '#!/bin/sh\nexit 0\n' > $B/stage/systemd/usr/share/libalpm/scripts/systemd-hook; chmod 755 $B/stage/systemd/usr/share/libalpm/scripts/systemd-hook
F=$B/stage/filesystem; mkdir -p $F/{etc,root,tmp,proc,dev,sys,run,var/lib,var/cache,usr/bin,usr/lib,usr/share} $F/etc/pacman.d/gnupg
ln -s usr/bin $F/bin; ln -s usr/bin $F/sbin; ln -s usr/lib $F/lib; ln -s usr/lib $F/lib64; ln -s bin $F/usr/sbin; ln -s lib $F/usr/lib64
chmod 1777 $F/tmp
printf 'root:x:0:0::/root:/bin/bash\n' > $F/etc/passwd; printf 'root:x:0:root\n' > $F/etc/group
printf 'NAME="Arch Linux"\nPRETTY_NAME="Arch Linux (synthetic test build)"\nID=arch\nBUILD_ID=rolling\n' > $F/usr/lib/os-release; ln -s ../usr/lib/os-release $F/etc/os-release
printf 'no-greeting\nno-permission-warning\nlock-never\nkeyserver-options timeout=10\n' > $F/etc/pacman.d/gnupg/gpg.conf

mkpkg() {  # mkpkg NAME VERSION "dep dep" [backup...]
    local n=$1 v=$2 deps=$3; shift 3
    local d=$B/stage/$n
    {   echo "# Generated by makepkg 6.0.2"; echo "pkgname = $n"; echo "pkgbase = $n"; echo "pkgver = $v"
        echo "pkgdesc = synthetic $n"; echo "url = https://example.invalid"; echo "builddate = 1730000000"
        echo "packager = Arch Test Packager <packager@test.invalid>"; echo "size = $(du -sb $d | cut -f1)"; echo "arch = x86_64"
        echo "license = GPL"; for x in $deps; do echo "depend = $x"; done; for b in "$@"; do echo "backup = $b"; done
    } > $d/.PKGINFO
    ( cd $d && LANG=C bsdtar -czf .MTREE --format=mtree --options='!all,use-set,type,uid,gid,mode,time,size,md5,sha256,link' .PKGINFO $(ls -A | grep -v -e '^\.PKGINFO$' -e '^\.MTREE$') \
      && LANG=C bsdtar -cf - --no-fflags --no-xattrs .MTREE .PKGINFO $(ls -A | grep -v -e '^\.PKGINFO$' -e '^\.MTREE$') ) | zstd -q -c -19 > "$B/pkgs/$n-$v-x86_64.pkg.tar.zst"
    gpg --batch --yes --default-key $PK --detach-sign -o "$B/pkgs/$n-$v-x86_64.pkg.tar.zst.sig" "$B/pkgs/$n-$v-x86_64.pkg.tar.zst" 2>/dev/null
    local a=$B/archive/packages/${n:0:1}/$n; mkdir -p $a; cp "$B/pkgs/$n-$v-x86_64.pkg.tar.zst"* $a/
}
mkpkg filesystem 2024.11.21-1 "" etc/passwd etc/group etc/pacman.d/gnupg/gpg.conf
mkpkg glibc 2.40+r16+gaa533d58ff-2 "filesystem"
mkpkg bash 5.2.037-1 "glibc"
mkpkg coreutils 9.5-2 "glibc"
mkpkg libarchive 3.7.7-1 "glibc"
mkpkg gnupg 2.4.7-1 "glibc"
mkpkg pacman-mirrorlist 20241119-1 "" etc/pacman.d/mirrorlist
mkpkg archlinux-keyring 20241203-1 ""
mkpkg pacman 7.0.0.r6.gc685ae6-2 "bash glibc libarchive coreutils gnupg pacman-mirrorlist archlinux-keyring" etc/pacman.conf
mkpkg systemd 256.10-1 "glibc"
# install the target with the host's real pacman (setup only: SigLevel Never here)
T=/srv/t/arch-clean; mkdir -p $T/var/lib/pacman $T/var/cache/pacman
printf '[options]\nArchitecture = auto\nSigLevel = Never\n' > $B/setup.conf
pacman -U --noconfirm --root $T --dbpath $T/var/lib/pacman/ --config $B/setup.conf --cachedir $T/var/cache/pacman \
    --hookdir $B/nohooks --logfile /dev/null --overwrite '*' $B/pkgs/*.pkg.tar.zst >/dev/null 2>$B/install.err || { cat $B/install.err; exit 1; }
echo "built: $(ls $B/pkgs/*.zst | wc -l) packages; masters $M1 $M2 $M3"
chroot $T /usr/bin/pacman -Q | head -20
