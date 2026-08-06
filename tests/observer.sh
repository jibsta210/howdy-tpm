#!/bin/bash
# pam_exec with expose_authtok feeds PAM_AUTHTOK on stdin. Record only whether
# it matched -- never write the secret itself anywhere.
read -r -s TOK
if [ "$TOK" = "correct-horse-battery-staple" ]; then
	echo "AUTHTOK-MATCHED" > /tmp/authtok-result
else
	printf 'AUTHTOK-WRONG len=%s\n' "${#TOK}" > /tmp/authtok-result
fi
exit 0
