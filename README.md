# pam_howdy_tpm

Release a TPM-sealed secret when your face unlocks the machine.

Face auth proves who you are but produces no password. Anything downstream that
needs one — KDE Wallet, GNOME Keyring, an encrypted home — finds
`PAM_AUTHTOK` empty and prompts anyway. You get recognised by your face and
then asked for a password, which rather defeats the point.

This module provides a TPM-encrypted secret to downstream PAM modules. The PAM
configuration must route a successful face match to it; the TPM itself does
not check Howdy's result. Each module rule requires an explicit user and service.

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

Biometrics control the PAM path; the TPM protects the stored secret. This is
not a Windows Hello implementation. TPM-backed disk encryption and session
keyring unlock are separate operations.

---

## What it protects, and what it doesn't

**Protects against drive theft.** The TPM will not unseal on other hardware.
Pull the SSD, put it in another machine, get nothing. If your disk is not
otherwise encrypted, this is the difference between "my browser passwords are
readable by anyone who picks up the laptop" and "they are not".

**Optionally protects against boot tampering** — bind to PCR 7 and the secret
stops unsealing if Secure Boot state changes.
The default binds to no PCRs. PCR 7 alone does not identify a particular OS or
measure every file on the root filesystem.

**Does not protect against** anyone using your machine while it is running and
logged in, or anyone who can already run code as root. Nothing at this layer
does.

**Not a substitute for full-disk encryption**, and not competing with it. FDE
protects far more, and if you can run it you should — the two compose fine.

The honest difference is cost of adoption, not safety:

|  | TPM-backed FDE | this module |
|---|---|---|
| protects | the whole disk at rest | one secret |
| to adopt on an existing unencrypted system | backup + reinstall, or an involved in-place conversion | install, enrol, two PAM lines |
| if the TPM is cleared | you type your existing passphrase at boot | you type your password at the keyring prompt |

Both are recoverable when the TPM is cleared. `systemd-cryptenroll
--tpm2-device=auto` *adds* a keyslot; your passphrase slot survives unless you
explicitly `--wipe-slot=password`. (Windows does the same — BitLocker keeps a
recovery key, escrowed to your account, and Windows Update suspends protection
around firmware updates so PCRs can change without stranding you.)

So this is not "safer than FDE". It is cheap, additive, and solves a different
problem: session secrets, not the disk. If your root is already unencrypted and
you are not about to reinstall, this gets you face-unlocked keyrings today.

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
- C compiler, make, pkg-config; Python 3 for the read-only configuration helper

No `tpm2-tools` needed.

---

## Install

```bash
make
sudo make install
```

The PAM directory is derived from Linux-PAM's pkg-config `libdir`, for example
`/usr/lib64/security` on Fedora. Both `howdy-tpm` and `howdy-tpm-enroll` are
installed, along with the inspection and authentication helpers. For a custom
PAM installation, set `SECDIR=/absolute/module/directory`. `PREFIX`,
`LIBEXECDIR`, and staging with `DESTDIR` are also supported. `install.sh` uses
the same make targets.
For a nondefault `LIBEXECDIR`, set `HOWDY_TPM_LIBEXECDIR` when invoking the CLI.

On Fedora, the build dependencies include `gcc`, `make`, `pkgconf-pkg-config`,
and `pam-devel`. Installation does not edit PAM or enroll any secret.

## Enrol a secret

```bash
sudo howdy-tpm-enroll
```

Prompts twice, hidden. The secret goes straight to `systemd-creds` — never to a
file, never into argv, never into shell history. Sealed to
`/etc/howdy-tpm/secret.cred`, `root:root 600`, and read back before success is
reported.
Leading and trailing spaces are preserved. Replacement is verified in a
temporary file before an atomic rename; a failed replacement keeps the old
credential.

The root-only credential directory can hide metadata from an unprivileged
`doctor`; this does not establish that enrollment failed. Use
`sudo howdy-tpm status` for an explicit decryption check.

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

Start with the actual login service and intended user, for example:

```bash
howdy-tpm doctor --service sddm --user "$USER" --keyring kwallet
```

To get copyable setup commands instead of manually applying the diff:

```bash
howdy-tpm doctor --service sddm --user "$USER" --keyring kwallet --emit-shell > /tmp/howdy-tpm-setup.sh
less /tmp/howdy-tpm-setup.sh
bash /tmp/howdy-tpm-setup.sh
```

Generation remains read-only; stack inspection goes to stderr and only the
script goes to stdout. Execute the script after reviewing it. It refuses a
changed service file or existing fragment, verifies the credential without
printing it, backs up the original service under `/var/backups/howdy-tpm`,
and prints a rollback command before installing the two files. Rollback restores
the service file, then removes the generated fragment so setup can be repeated.
It restores SELinux file labels when `restorecon` is available; TPM-access policy remains
a separate administrator decision. The default doctor output remains a diff.

`doctor` is read-only and does not decrypt credentials. It displays the actual
authentication files, including repeated includes and substack boundaries. It
does not pretend to simulate arbitrary PAM control flow. Use `--module-dir`
when PAM's build metadata is unavailable, and `--cred`/`--name` for a custom
credential.

The first supported plan is a direct `auth sufficient pam_howdy.so`, immediately
followed by a password-authentication `substack`, with existing optional keyring
auth and `auto_start` session hooks. This covers the Fedora SDDM layout. The
plan is a diff that creates a separate face-auth fragment and replaces just
the Howdy rule with an `include`. If the usual Fedora `pam_selinux_permit`
guard precedes Howdy, the plan also changes its failure action from `bad` to
`die`: a denied login stops before any secret is released. Other authentication
prefixes require manual review and receive no generated plan.

- Face success runs the scoped credential module and the selected keyring auth
  hook before returning success, just as the original sufficient rule did.
- Face failure skips credential release and returns to the original password
  substack. Password handling and session hooks are not rewritten.

Review and apply both parts of the diff together. Keep an administrator session
open and verify face success, password login, and rejected authentication before
rebooting. The helper refuses to generate a plan for unsupported structures,
parent numeric jumps, existing generated fragments, or authselect-managed entry
files. It identifies authselect-managed included files without modifying them.
It never guesses a `system-auth` insertion point.

For an existing custom successful-authentication branch, the module rule needs
both `user=YOUR_USER` and `service=YOUR_SERVICE`. Without both, it deliberately
releases nothing. **Existing installations must add these options when upgrading.**
Place it before the keyring consumer and after successful authentication;
returning `PAM_IGNORE` does not make an incorrect placement safe.

### Module options

| option | default | meaning |
|---|---|---|
| `cred=PATH` | `/etc/howdy-tpm/secret.cred` | sealed credential |
| `name=NAME` | `howdy-tpm` | credential name (must match enrolment) |
| `user=USER` | required | only this PAM user may receive the credential |
| `service=NAME` | required | only this PAM service may receive the credential |
| `debug` | off | log decisions to syslog — never the secret |

---

## Testing without rebooting

Iterating on an auth stack by rebooting is how people lock themselves out.
Don't.

The installed authentication helper runs a PAM conversation and supplies no
password. The command preserves its failure status:

```bash
sudo howdy-tpm test --service sddm --user "$USER"
```

A working face-only stack prints the Howdy messages and `Success` with **no**
`Password:` prompt. If `Password:` appears, something downstream still wants
one. This checks authentication only, not account policy, session startup, or
the resulting state of a new desktop's keyring.

For a separate read-only check of a wallet in the **current** KDE session:

```bash
sudo howdy-tpm test --service sddm --user "$USER" --wallet kdewallet
```

An already-open wallet is not proof that the tested login opened it. This check
does not start the wallet daemon or ask it to unlock. A closed wallet or a
failed D-Bus query causes a nonzero exit status. To inspect files without
authenticating, use `howdy-tpm test --service sddm --user "$USER" --show-stack`.

To prove the token is actually delivered, use `pam_exec` as an observer — see
`tests/`.

**Failed tests increment faillock.** Reset between batches:

```bash
sudo faillock --user "$USER" --reset
```

### SELinux with SDDM

On an enforcing system, a terminal authentication test can run in
`unconfined_t`, while the actual SDDM helper runs in `xdm_t`. Terminal success
therefore does not prove that the login screen can access the TPM. A denial
for `systemd-creds` reading/writing `tpmrm0` with source type `xdm_t` and target
type `tpm_device_t` prevents credential release; the keyring then receives no
password. Inspect the real login's logs:

```bash
sudo journalctl -b --no-pager | grep -Ei 'pam_howdy_tpm|pam_kwallet5|systemd-creds|avc:'
```

For that verified denial, an administrator can review this optional local
policy, saved as `howdy_tpm_sddm.te`:

```text
module howdy_tpm_sddm 1.0;
require {
    type xdm_t;
    type tpm_device_t;
    class chr_file { getattr open read write };
}
allow xdm_t tpm_device_t:chr_file { getattr open read write };
```

This grants TPM access to the **whole `xdm_t` domain**, not just this PAM
module or `systemd-creds`. It is not installed automatically. Compile and
install it with the SELinux policy tools:

```bash
checkmodule -M -m -o howdy_tpm_sddm.mod howdy_tpm_sddm.te
semodule_package -o howdy_tpm_sddm.pp -m howdy_tpm_sddm.mod
sudo semodule -X 300 -i howdy_tpm_sddm.pp
```

Remove it with `sudo semodule -X 300 -r howdy_tpm_sddm`. After installation,
verify a fresh SDDM login and first application launch without manually
unlocking the wallet. Other AVCs require their own diagnosis.

---

## Design notes

**It does not supply an authentication result.** `pam_sm_authenticate` returns
`PAM_IGNORE` on every path. It still modifies `PAM_AUTHTOK`, which downstream
modules can consume. Safe release depends on a successful-authentication path;
user/service restrictions are checked before accessing the credential.

**It never overwrites an existing token.** If `PAM_AUTHTOK` is already set —
normally by `pam_unix` on the password path — it does nothing. The configuration
must still prevent failed authentication from reaching credential release;
an empty token does not establish success.

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

Working. Verified on a Dell XPS 16 (Panther Lake, STMicro TPM 2.0, kernel
7.2-rc6) with Howdy on an IR sensor, cosmic-greeter, and the GNOME login
keyring.

A real boot, from the journal:

```
pam_howdy: Login approved
gkr-pam: stashed password to try later in open session
pam_unix(login:session): session opened for user jakes
```

`stashed password` is the keyring receiving the token. On every boot before
this, that line was `pam_kwallet5: Couldn't get password (it is empty)` and the
greeter sat waiting for a password it had already been told it did not need.

Face at the greeter, straight to the desktop, keyring unlocked, nothing typed.

Also verified, in an isolated PAM service rather than by guessing:

| case | result |
|---|---|
| no existing token | secret delivered, correct length |
| token already set | left alone — `already set, doing nothing` |
| credential mode 0644 | refused, no token set |
| credential owned non-root | refused |
| credential missing | no token, no crash |

The supported configuration plan has isolated real-libpam regression tests for
face success, password success, authentication failure, and user/service scope.
TPM decryption and face recognition are mocked in these tests; they do not
establish hardware, SELinux, or a real desktop cold-login result. Run `make check`
with `uv` and PAM development files installed.

## Licence

MIT.
