#!/bin/bash
# Report whether the credential unseals -- WITHOUT printing it.
#
# Written after the author echoed a real account password to a terminal by
# running `systemd-creds decrypt ... -` directly. There is never a reason to
# print the secret; only whether it unseals and how long it is.
set -uo pipefail
CRED=${1:-/etc/howdy-tpm/secret.cred}
NAME=${2:-howdy-tpm}

[[ -f $CRED ]] || { echo "  no credential at $CRED"; exit 1; }
printf '  file      %s (%s, %s bytes)\n' "$CRED" \
  "$(stat -c '%U:%G %a' "$CRED")" "$(stat -c %s "$CRED")"

# Length only. Piped to wc; the value never reaches a terminal or a log.
if LEN=$(systemd-creds decrypt --name="$NAME" "$CRED" - 2>/dev/null | wc -c); then
  if [[ ${LEN:-0} -gt 0 ]]; then
    printf '  unseals   yes (%s bytes)\n' "$LEN"
    exit 0
  fi
fi
echo "  unseals   NO -- TPM state changed, or wrong --name"
exit 1
