#!/bin/bash
# Build a SYNTHETIC Rocky-like rpm system for testing the rpm backend when real
# Rocky mirrors are unreachable. Packages are built with real rpmbuild from the
# host's own binaries (so rpm really runs inside the chroot), signed with a
# throwaway key using rpmsign, indexed with createrepo_c, and installed into a
# root with real rpm. Output:
#   /srv/t/rocky/repo            signed repository (repodata + rpms)
#   /srv/t/rocky/evil            same-NEVRA packages with malicious scriptlets (attack tests)
#   /srv/t/rocky/key.asc         public signing key   /srv/t/rocky/fpr   its fingerprint
#   /srv/t/rocky-clean           installed target root
set -euo pipefail
B=/srv/t/rocky
rm -rf "$B" /srv/t/rocky-clean; mkdir -p "$B"/{gnupg,stage,repo,evil,specs}
chmod 700 "$B/gnupg"
export GNUPGHOME=$B/gnupg
gpg --batch --quick-gen-key --passphrase '' 'Rocky Synthetic Test Key <test@rocky.invalid>' rsa2048 sign never 2>/dev/null
gpg --batch --armor --export > "$B/key.asc"
gpg --list-keys --with-colons | awk -F: '/^fpr/{print $10; exit}' > "$B/fpr"
mkdir -p "$B/evilgnupg"; chmod 700 "$B/evilgnupg"
GNUPGHOME=$B/evilgnupg gpg --batch --quick-gen-key --passphrase '' 'Evil <evil@example>' rsa2048 sign never 2>/dev/null
GNUPGHOME=$B/evilgnupg gpg --batch --armor --export > "$B/evilkey.asc"

ML=/usr/lib/x86_64-linux-gnu
libs_of() { ldd "$@" 2>/dev/null | awk '/=> \//{print $3} /^[ \t]*\/lib64/{print $1}' | sort -u; }
BINS="/usr/bin/rpm /usr/bin/rpmkeys /usr/bin/rpmdb /usr/bin/bash /usr/bin/touch /usr/bin/cat /usr/bin/ls /usr/bin/rm /usr/bin/mkdir /usr/bin/echo /usr/bin/true /usr/bin/id /usr/bin/env /usr/bin/sed"
ALLLIBS=$( (libs_of $BINS; ls $ML/rpm-plugins/*.so 2>/dev/null | xargs -r ldd 2>/dev/null | awk '/=> \//{print $3}') | xargs -n1 readlink -f | sort -u)
GLIBC_RE='/(libc|libm|libdl|libpthread|librt|libresolv|libutil|ld-linux-x86-64)[.-]'

# stage NAME : files listed on stdin are copied (with symlinks preserved) into stage/NAME
stage() { local d=$B/stage/$1; mkdir -p "$d"; while read -r f; do [ -n "$f" ] || continue; mkdir -p "$d$(dirname "$f")"; cp -a "$f" "$d$f"; done; }
{ echo "$ALLLIBS" | grep -E "$GLIBC_RE"; for l in $(echo "$ALLLIBS" | grep -E "$GLIBC_RE"); do ls $ML/$(basename $l | sed 's/\.so.*//').so.* 2>/dev/null; done; } | sort -u | stage glibc
mkdir -p $B/stage/glibc/usr/lib64; ln -s ../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 $B/stage/glibc/usr/lib64/ld-linux-x86-64.so.2
for l in $(echo "$ALLLIBS" | grep -vE "$GLIBC_RE"); do echo "$l"; ls $ML/$(basename $l | sed 's/\.so\..*//').so.* 2>/dev/null; done | sort -u | stage rpm-libs
printf '%s\n' /usr/bin/rpm /usr/bin/rpmkeys /usr/bin/rpmdb | stage rpm
mkdir -p $B/stage/rpm/usr/lib; cp -a /usr/lib/rpm $B/stage/rpm/usr/lib/rpm; rm -rf $B/stage/rpm/usr/lib/rpm/{*.prov,*.req,find-*,brp-*,check-*,*deps*,pythondist*,mkinstalldirs,ocaml*,elfdeps}
mkdir -p $B/stage/rpm/usr/lib/rpm/macros.d $B/stage/rpm/etc/rpm $B/stage/rpm/var/lib/rpm
printf '%%_dbpath /var/lib/rpm\n%%_db_backend sqlite\n' > $B/stage/rpm/usr/lib/rpm/macros.d/macros.dbpath
[ -d $ML/rpm-plugins ] && { mkdir -p $B/stage/rpm$ML; cp -a $ML/rpm-plugins $B/stage/rpm$ML/; }
printf '%s\n' /usr/bin/bash | stage bash; ln -s bash $B/stage/bash/usr/bin/sh
printf '%s\n' /usr/bin/touch /usr/bin/cat /usr/bin/ls /usr/bin/rm /usr/bin/mkdir /usr/bin/echo /usr/bin/true /usr/bin/id /usr/bin/env /usr/bin/sed | stage coreutils
mkdir -p $B/stage/filesystem/{etc,root,tmp,var/tmp,var/lib,usr/bin,usr/sbin,usr/lib,usr/lib64,etc/yum.repos.d,etc/pki/rpm-gpg,etc/dnf/plugins,proc,dev,sys,run}
ln -s usr/bin $B/stage/filesystem/bin; ln -s usr/sbin $B/stage/filesystem/sbin; ln -s usr/lib $B/stage/filesystem/lib; ln -s usr/lib64 $B/stage/filesystem/lib64
printf 'root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534::/:/sbin/nologin\n' > $B/stage/filesystem/etc/passwd
printf 'root:x:0:\nnobody:x:65534:\n' > $B/stage/filesystem/etc/group
mkdir -p $B/stage/python3-libs/usr/lib64/python3.9/site-packages/dnf-plugins $B/stage/python3-libs/usr/lib64/python3.9/site-packages/dnf
echo '# synthetic dnf package' > $B/stage/python3-libs/usr/lib64/python3.9/site-packages/dnf/__init__.py
echo '# synthetic dnf plugin' > $B/stage/python3-libs/usr/lib64/python3.9/site-packages/dnf-plugins/builddep.py
mkdir -p $B/stage/dnf/usr/bin $B/stage/dnf/etc/dnf; printf '#!/bin/sh\necho "synthetic dnf"\n' > $B/stage/dnf/usr/bin/dnf; chmod 755 $B/stage/dnf/usr/bin/dnf
printf '[main]\ngpgcheck=1\ninstallonly_limit=3\nclean_requirements_on_remove=True\nbest=True\nskip_if_unavailable=False\n' > $B/stage/dnf/etc/dnf/dnf.conf
mkdir -p $B/stage/rocky-gpg-keys/etc/pki/rpm-gpg; cp $B/key.asc $B/stage/rocky-gpg-keys/etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9
mkdir -p $B/stage/rocky-repos/etc/yum.repos.d
printf '[baseos]\nname=Rocky Linux $releasever - BaseOS\nbaseurl=file:///srv/t/rocky/repo\ngpgcheck=1\nenabled=1\ngpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9\n' > $B/stage/rocky-repos/etc/yum.repos.d/rocky.repo
mkdir -p $B/stage/rocky-release/etc $B/stage/rocky-release/usr/lib
printf 'NAME="Rocky Linux"\nVERSION="9.4 (Synthetic)"\nID="rocky"\nVERSION_ID="9.4"\nPRETTY_NAME="Rocky Linux 9.4 (synthetic test build)"\n' > $B/stage/rocky-release/usr/lib/os-release
ln -s ../usr/lib/os-release $B/stage/rocky-release/etc/os-release; echo 'Rocky Linux release 9.4 (synthetic)' > $B/stage/rocky-release/etc/rocky-release
mkdir -p $B/stage/systemd-ft/usr/lib/systemd; echo 'synthetic' > $B/stage/systemd-ft/usr/lib/systemd/README

# spec writer: name version release [scriptlets...]
spec() {
    local n=$1 v=$2 r=$3 extra=${4:-} payload=${5:-w2.xzdio} pre=""
    case "$n" in
        glibc) pre=$'Provides: rtld(GNU_HASH)\nProvides: ld-linux-x86-64.so.2()(64bit)\nProvides: ld-linux-x86-64.so.2(GLIBC_2.2.5)(64bit)\nProvides: ld-linux-x86-64.so.2(GLIBC_2.3)(64bit)\nProvides: ld-linux-x86-64.so.2(GLIBC_PRIVATE)(64bit)' ;;
        python3-libs) pre='Provides: python(abi) = 3.9' ;;
    esac
    cat > "$B/specs/$n-$r.spec" <<EOF
Name: $n
Version: $v
Release: $r
Summary: synthetic $n
License: GPL
BuildArch: x86_64
AutoReqProv: yes
$pre
%define _binary_payload $payload
%define _build_id_links none
%define __strip /bin/true
%define __brp_strip /bin/true
%define __os_install_post %{nil}
%define _unpackaged_files_terminate_build 0
%description
synthetic $n for pmtrust tests
%install
mkdir -p %{buildroot}
cp -a $B/stage/$n/. %{buildroot}/
%files
$(cd $B/stage/$n && find . -mindepth 1 \( -type f -o -type l \) | sed 's|^\.||' | while read -r f; do case "$f" in /etc/yum.repos.d/*|/etc/dnf/dnf.conf|/etc/passwd|/etc/group) echo "%config(noreplace) $f";; *) echo "$f";; esac; done)
$(cd $B/stage/$n && find . -mindepth 1 -type d | sed 's|^\.||' | grep -vE '^/(usr|usr/bin|usr/lib|usr/lib64|usr/sbin|etc|var|var/lib)$' | while read -r d; do [ "$n" = filesystem ] && echo "%dir $d" || { case "$d" in /usr/lib/rpm*|/usr/lib64/python3.9*|/etc/rpm|/var/lib/rpm|/etc/dnf*|$ML/rpm-plugins) echo "%dir $d";; esac; }; done)
$( [ "$n" = filesystem ] && printf '%%attr(1777,root,root) %%dir /tmp\n%%attr(1777,root,root) %%dir /var/tmp\n%%dir /usr\n%%dir /usr/bin\n%%dir /usr/lib\n%%dir /usr/lib64\n%%dir /usr/sbin\n%%dir /etc\n%%dir /var\n%%dir /var/lib\n')
$extra
EOF
}
spec filesystem 3.16 2.el9
spec glibc 2.34 100.el9_4.2 "" w19.zstdio
spec bash 5.1.8 9.el9
spec coreutils 8.32 35.el9
spec rpm-libs 4.16.1.3 29.el9 "" w19.zstdio
spec rpm 4.16.1.3 29.el9 $'%post\n/usr/bin/touch /var/lib/rpm/.post-ran\n%preun\nexit 0'
spec python3-libs 3.9.18 3.el9_4.6
spec dnf 4.14.0 9.el9 "" w19.zstdio
spec rocky-gpg-keys 9.4 1.7.el9
spec rocky-repos 9.4 1.7.el9
spec rocky-release 9.4 1.7.el9
spec systemd-ft 252 32.el9 $'%filetriggerin -- /usr/lib/systemd\nexit 0'
for s in "$B"/specs/*.spec; do
    rpmbuild -bb --define "_topdir $B/build" --define "_rpmdir $B/repo" --define '_build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm' "$s" >/dev/null 2>"$B/build.err" || { cat "$B/build.err"; exit 1; }
done
# evil variants: same NEVRA, malicious scriptlets (simulate a tampered rpmdb)
spec rpm 4.16.1.3 29.el9 $'%post\n/usr/bin/touch /var/lib/rpm/.post-ran\n%preun\n/usr/bin/touch /PWNED_preun\n%postun\n/usr/bin/touch /PWNED_postun'
mv "$B/specs/rpm-29.el9.spec" "$B/specs/evil-rpm.spec"
spec systemd-ft 252 32.el9 $'%filetriggerin -- /usr/bin\n/usr/bin/touch /PWNED_filetrigger\n%triggerin -- rpm\n/usr/bin/touch /PWNED_triggerin'
mv "$B/specs/systemd-ft-32.el9.spec" "$B/specs/evil-systemd-ft.spec"
for s in "$B"/specs/evil-*.spec; do
    rpmbuild -bb --define "_topdir $B/build" --define "_rpmdir $B/evil" --define '_build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm' "$s" >/dev/null 2>"$B/build.err" || { cat "$B/build.err"; exit 1; }
done
FPR=$(cat $B/fpr)
GNUPGHOME=$B/gnupg rpmsign --addsign --define "_gpg_name $FPR" --define "_gpg_path $B/gnupg" "$B"/repo/*.rpm >/dev/null
GNUPGHOME=$B/evilgnupg rpmsign --addsign --define "_gpg_name Evil" --define "_gpg_path $B/evilgnupg" "$B"/evil/*.rpm >/dev/null
createrepo_c -q "$B/repo"
# install the target with real rpm
mkdir -p /srv/t/rocky-clean
rpm --root /srv/t/rocky-clean --dbpath /var/lib/rpm --define '_db_backend sqlite' --import "$B/key.asc"
rpm --root /srv/t/rocky-clean --dbpath /var/lib/rpm --define '_db_backend sqlite' -i "$B"/repo/*.rpm
echo "built: $(ls "$B"/repo/*.rpm | wc -l) packages, key $FPR"
rpm --root /srv/t/rocky-clean --dbpath /var/lib/rpm -qa | sort
