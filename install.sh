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

MAKE_ARGS=()
for setting in PREFIX SECDIR LIBEXECDIR; do
  if [[ -n ${!setting:-} ]]; then MAKE_ARGS+=("$setting=${!setting}"); fi
done

if [[ ${1:-} == --uninstall ]]; then
  make uninstall "${MAKE_ARGS[@]}"
  echo "removed. NOTE: your PAM files still reference pam_howdy_tpm.so --"
  echo "remove those lines BEFORE rebooting, or auth will log a missing module."
  echo "  grep -rn pam_howdy_tpm /etc/pam.d/"
  exit 0
fi

for c in cc make pkg-config; do
  command -v $c >/dev/null || { echo "missing: $c"; exit 1; }
done
[[ -e /usr/include/security/pam_modules.h ]] || {
  echo "missing PAM headers (Arch: pam, Debian: libpam0g-dev, Fedora: pam-devel)"
  exit 1; }

make install "${MAKE_ARGS[@]}"

cat <<'MSG'

Installed. Nothing is active yet -- the module is not in any PAM stack.

Next:
  1. howdy-tpm doctor --service YOUR_SERVICE --user YOUR_USER --keyring kwallet
  2. sudo howdy-tpm-enroll     seal the secret
  3. add the lines doctor printed
  4. sudo howdy-tpm test --service YOUR_SERVICE --user YOUR_USER
MSG
