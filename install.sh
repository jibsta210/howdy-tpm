#!/bin/bash
# ===========================================================================
# pam_howdy_tpm installer
#
#   sudo ./install.sh              # build + install, NO PAM changes
#   sudo ./install.sh --uninstall
#
# Deliberately does NOT edit your PAM stacks. Getting that wrong locks you out
# of your own machine, and it depends on which greeter and which keyring you
# actually run. `howdy-tpm doctor` tells you exactly which lines to add, and
# you add them, having read them.
# ===========================================================================
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root: sudo $0"; exit 1; }

PREFIX=${PREFIX:-/usr}
SECDIR=${SECDIR:-$PREFIX/lib/security}

if [[ ${1:-} == --uninstall ]]; then
  rm -f "$SECDIR/pam_howdy_tpm.so" "$PREFIX/bin/howdy-tpm-enroll" "$PREFIX/bin/howdy-tpm"
  echo "removed. NOTE: your PAM files still reference pam_howdy_tpm.so --"
  echo "remove those lines BEFORE rebooting, or auth will log a missing module."
  echo "  grep -rn pam_howdy_tpm /etc/pam.d/"
  exit 0
fi

for c in gcc systemd-creds; do
  command -v $c >/dev/null || { echo "missing: $c"; exit 1; }
done
[[ -e /usr/include/security/pam_modules.h ]] || {
  echo "missing PAM headers (Arch: pam, Debian: libpam0g-dev, Fedora: pam-devel)"
  exit 1; }

if ! systemd-analyze has-tpm2 >/dev/null 2>&1; then
  echo "No usable TPM 2.0 -- 'systemd-analyze has-tpm2' says no."
  echo "This module has nothing to unseal from without one."
  exit 1
fi

make clean >/dev/null 2>&1 || true
make
install -Dm755 pam_howdy_tpm.so "$SECDIR/pam_howdy_tpm.so"
install -Dm755 scripts/howdy-tpm-enroll "$PREFIX/bin/howdy-tpm-enroll"
install -Dm755 scripts/howdy-tpm "$PREFIX/bin/howdy-tpm"
install -dm700 /etc/howdy-tpm

cat <<'MSG'

Installed. Nothing is active yet -- the module is not in any PAM stack.

Next:
  1. sudo howdy-tpm doctor     what to add, and where, for THIS machine
  2. sudo howdy-tpm-enroll     seal the secret
  3. add the lines doctor printed
  4. sudo howdy-tpm test       verify WITHOUT rebooting
MSG
