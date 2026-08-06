# pam_howdy_tpm

Release a TPM-sealed secret when your face unlocks the machine.

Face auth proves who you are but produces no password. Anything downstream that
needs one — KDE Wallet, GNOME Keyring, an encrypted home — finds
`PAM_AUTHTOK` empty and prompts anyway. You get recognised by your face and
then asked for a password, which rather defeats the point.

This module fixes that: the face match authorises the TPM to release a real
secret, which is handed to the rest of the PAM stack as if you had typed it.

---

## Why the face can't just *be* the key

The obvious idea — hash the face encoding, use it as an encryption key — does
not work, and it is worth knowing why before dismissing it.

Face encodings are **fuzzy**. Six enrolments of the same face, captured seconds
apart on the same camera, measured on the author's own model:

```
encoding 0 vs 1 :  0.0829
encoding 0 vs 4 :  0.3609
encoding 1 vs 4 :  0.3846
encoding 2 vs 5 :  0.3166        (identical vectors would be 0.0000)
```

That is why matching uses a distance threshold rather than equality. A hash of
one encoding is unrelated to a hash of the next, so there is nothing stable to
derive a key from. And a face is not secret in the first place — your model
file sits on disk next to the data it would be protecting.

So the biometric authorises; the TPM holds. This is the same split Windows
Hello uses to unlock BitLocker, and it is the only arrangement where "unlock
with your face" is not a synonym for "keep the password in a file".

---

## What it protects, and what it doesn't

**Protects against drive theft.** The TPM will not unseal on other hardware.
Pull the SSD, put it in another machine, get nothing. If your disk is not
otherwise encrypted, this is the difference between "my browser passwords are
readable by anyone who picks up the laptop" and "they are not".

**Optionally protects against boot tampering** — bind to PCR 7 and the secret
stops unsealing if Secure Boot state changes.

**Does not protect against** anyone using your machine while it is running and
logged in, or anyone who can already run code as root. Nothing at this layer
does.

**Not a substitute for full-disk encryption.** If you can encrypt the disk, do
that — `systemd-cryptenroll --tpm2-device=auto` gives unattended boot with no
passphrase and protects everything, not just one secret. This module is for
when you can't or won't.

**Howdy is not presentation-attack-resistant.** An IR sensor raises the bar
over an RGB webcam, but this is not a certified biometric stack. Decide what
you seal accordingly.

---

## Requirements

- A TPM 2.0 — check with `systemd-analyze has-tpm2`
- systemd built with TPM2 support (provides `systemd-creds`)
- [Howdy](https://github.com/boltgolt/howdy), or any PAM module that
  authenticates without producing a password
- `libpam` headers to build

No `tpm2-tools` needed.

---

## Install

```bash
make
sudo make install
```

Installs `pam_howdy_tpm.so` to `/usr/lib/security/` and `howdy-tpm-enroll` to
`/usr/bin/`. **Installing does nothing on its own** — the module is inert until
you add it to a PAM stack.

## Enrol a secret

```bash
sudo howdy-tpm-enroll
```

Prompts twice, hidden. The secret goes straight to `systemd-creds` — never to a
file, never into argv, never into shell history. Sealed to
`/etc/howdy-tpm/secret.cred`, `root:root 600`, and read back before success is
reported.

```bash
sudo howdy-tpm-enroll --show      # status; never prints the secret
sudo howdy-tpm-enroll --remove    # delete it; PAM falls back to prompting
sudo howdy-tpm-enroll --pcrs 7    # additionally bind to Secure Boot state
```

Multiple secrets are fine — give each its own name and path:

```bash
sudo howdy-tpm-enroll --name ssh-key --cred /etc/howdy-tpm/ssh.cred
```

## Wire it into PAM

**Placement matters, and the obvious placement is wrong.**

Put it where the auth modules *converge on success* — the target of
`pam_howdy`'s `success=N` jump — and before whatever consumes the token:

```
auth  requisite                   pam_faillock.so preauth
auth  [success=N default=ignore]  pam_howdy.so
auth  [success=1 default=bad]     pam_unix.so try_first_pass nullok
auth  [default=die]               pam_faillock.so authfail
auth  optional                    pam_permit.so
auth  optional                    pam_howdy_tpm.so      <-- here
auth  required                    pam_faillock.so authsucc
auth  optional                    pam_kwallet5.so
```

Immediately **after** `pam_howdy` would be wrong: on success Howdy *jumps over*
the following modules, so a module placed there runs only when face auth
**failed** — exactly backwards.

Adding a module shifts every `success=N` below it. Recount them; do not eyeball
it. `tools/flatten-pam.py` prints the flattened stack with the jump targets
resolved.

### Module options

| option | default | meaning |
|---|---|---|
| `cred=PATH` | `/etc/howdy-tpm/secret.cred` | sealed credential |
| `name=NAME` | `howdy-tpm` | credential name (must match enrolment) |
| `debug` | off | log decisions to syslog — never the secret |

---

## Testing without rebooting

Iterating on an auth stack by rebooting is how people lock themselves out.
Don't.

`tests/pamtest.c` runs a real PAM conversation against any service and answers
no prompts, so a stack that still needs a password fails visibly:

```bash
gcc -o pamtest tests/pamtest.c -lpam
sudo ./pamtest login "$USER"
```

A working face-only stack prints the Howdy messages and `Success` with **no**
`Password:` prompt. If `Password:` appears, something downstream still wants
one.

To prove the token is actually delivered, use `pam_exec` as an observer — see
`tests/`.

**Failed tests increment faillock.** Reset between batches:

```bash
sudo faillock --user "$USER" --reset
```

---

## Design notes

**It never authenticates.** `pam_sm_authenticate` returns `PAM_IGNORE` on every
path, including success. It supplies a token; it does not decide who may log
in. Returning `PAM_SUCCESS` would let a readable credential file substitute for
authentication.

**It never overwrites an existing token.** If `PAM_AUTHTOK` is already set —
normally by `pam_unix` on the password path — it does nothing. One placement
therefore serves both paths without knowing which ran.

**It refuses an unsafe credential.** Not root-owned, or any group/other
permission bits, and it declines and logs. The file's contents become an
authentication token downstream; if a non-root user can write it, that user
chooses your wallet password.

**It strips exactly one trailing newline.** `systemd-creds` is byte-exact, so a
credential sealed with `echo` carries a `\n` that would travel into
`PAM_AUTHTOK` and make every unlock fail while looking exactly like a wrong
password. `howdy-tpm-enroll` uses `printf '%s'` for the same reason.

**It shells out to `systemd-creds`** rather than linking libsystemd: one
well-defined binary, the secret crosses a pipe we control, no in-process crypto
state. Buffers are wiped with `explicit_bzero` after use.

---

## ⚠ Before you seal anything

A TPM-sealed secret is recoverable **only by this TPM, on this machine**. Clear
the TPM — firmware update, BIOS reset, "Clear TPM" in setup, moving the drive —
and the blob is permanently undecryptable.

That is the entire security value, and the entire risk.

**Write down whatever you seal and keep it somewhere that is not this laptop.**

`sudo howdy-tpm-enroll --show` reports whether the credential still unseals, so
you can find out deliberately rather than at a login screen.

---

## Status

Working and tested on a Dell XPS 16 (Panther Lake, STMicro TPM 2.0), Howdy with
an IR sensor, KDE Wallet.

Verified: secret delivered on the face path; existing token preserved on the
password path; missing, world-readable and non-root-owned credentials each
refused without setting a token or crashing.

Not yet done: an installer that edits PAM stacks for you. Deliberately —
that is the part that can lock you out, and it should be done deliberately with
a restore command to hand.

## Licence

MIT.
