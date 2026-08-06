# Reddit draft — r/linux (crosspost r/archlinux, r/kde)

**Title:**
I got Howdy face unlock to also unlock my keyring, using the TPM — because a face can't be an encryption key

---

Howdy gives you face login on Linux. What it doesn't give you is a password —
and gnome-keyring, KWallet and friends want one. So you get recognised by your
face, and then asked for your password anyway. Which rather defeats the point.

I spent a while trying to fix this the obvious way and it can't work, so I want
to explain why before the actual solution, because the why is the interesting
part.

## Why you can't just hash your face

The obvious idea is: take the face encoding, hash it, use that as the key.

Face encodings are fuzzy. Here are six enrolments of my *own face*, captured
seconds apart on the same camera, compared pairwise:

```
encoding 0 vs 1 :  0.0829
encoding 0 vs 4 :  0.3609
encoding 1 vs 4 :  0.3846
encoding 2 vs 5 :  0.3166      (identical vectors would be 0.0000)
```

Every capture is a different 128-float vector. That's why face matching uses a
*distance threshold* rather than equality — Howdy accepts anything under ~0.57.
A hash of one encoding is unrelated to a hash of the next, so there's nothing
stable to derive a key from.

And even if you solved the noise: your face isn't secret, and the model file
sits on disk right next to whatever it would be protecting.

## What actually works

The biometric doesn't *become* the key. It authorises the TPM to *release* one.

```
face match  ->  authorises  ->  TPM unseals  ->  a real, stable secret
  (fuzzy)                        (hardware)         (exact)
```

Seal your keyring password to the TPM, and have a PAM module unseal it after
Howdy authenticates and hand it to the stack as `PAM_AUTHTOK`. gnome-keyring
picks it up and unlocks. No prompt.

That's it. ~250 lines of C.

**https://github.com/jibsta210/howdy-tpm**

Face at the greeter, straight to desktop, keyring unlocked, nothing typed.

---

## The part that actually took the time

The module was the easy bit. Three things fail *silently* and I got all three
wrong:

**1. Both keyrings were running, and I wired the wrong one.** `kwalletd6` and
`gnome-keyring-daemon` were both alive on my KDE box. Only gnome-keyring
actually owned `org.freedesktop.secrets`. I spent an hour on `pam_kwallet5`,
which was never the thing asking me for a password.

**2. The keyring module was in the wrong PAM file.** My distro wired
`pam_gnome_keyring` into `/etc/pam.d/sddm`. I use cosmic-greeter, which reads
`login`. So it had *never run*, on any boot, and my login keyring had never
been unlocked — completely independent of Howdy.

**3. PAM's `success=N` is a jump, and the obvious placement is backwards.** If
you put your module right after `pam_howdy`, it runs only when face auth
**failed** — because on success Howdy *jumps over* the next N modules. It has
to go at the jump target.

So the repo ships a `doctor` that reads the D-Bus owner, resolves your greeter's
actual PAM service from its config, tells you which password that store wants,
and prints the exact lines for your machine. That's the bit that saves you a
day, not the module.

There's also a `pamtest` harness, because iterating on an auth stack by
rebooting is how people lock themselves out of their own machines. It runs a
real PAM conversation and answers no prompts, so a stack that still wants a
password fails visibly. I never rebooted to test this until it already worked.

---

## Objections, pre-empted

**"Just use full-disk encryption."** Correct, and I'd tell you the same. FDE
protects far more and the two compose — if you run FDE, add this anyway.

I originally wrote a whole argument here about blast radius, then checked it
and it was wrong, so here is the accurate version: `systemd-cryptenroll
--tpm2-device=auto` *adds* a TPM keyslot and leaves your passphrase slot alone
unless you explicitly `--wipe-slot=password`. So a cleared TPM means you type
your passphrase at boot, not that your disk is gone. Windows is the same —
BitLocker keeps an escrowed recovery key and Windows Update suspends protection
around firmware updates so the PCRs can change safely.

The real difference is adoption cost. FDE on an already-unencrypted root means
a backup and reinstall, or an involved conversion. This is two PAM lines. If
you're not about to reinstall, this gets you face-unlocked keyrings today, and
it's solving a different problem anyway — session secrets, not the disk at
rest.

And no, `--tpm2-device=auto` does not add a preboot password. That objection
comes up a lot and it isn't true.

**"This is less secure than a password."** For the threat it targets, no. The
TPM won't unseal on other hardware — pull the drive, put it in another machine,
get nothing. If your disk isn't otherwise encrypted, that's the difference
between your browser passwords being readable by anyone who picks up the laptop
and not.

It does nothing against someone at your unlocked, running machine. Neither does
anything else at this layer.

**"Howdy can be fooled by a photo."** An IR sensor raises the bar over an RGB
webcam, but this is not a certified presentation-attack-detection stack, and I
don't claim otherwise. Decide what you seal accordingly. If face auth isn't
good enough for your threat model, this module inherits that — it's a delivery
mechanism, not an authenticator. It returns `PAM_IGNORE` on every path,
including success, so it can never grant access on its own.

**"So the secret is just sitting there for root."** Yes. Root can unseal it,
same as root can read anything else. The credential is `root:root 0600` and the
module refuses to read it if that's not true.

**"Isn't this just `pam_exec` with extra steps?"** `pam_exec` can't hand an
authtok back to the stack. It has to be a real module.

---

## Caveats, honestly

Tested on **one machine**: Dell XPS 16, Panther Lake, STMicro TPM 2.0, Arch
(CachyOS), kernel 7.2-rc6, cosmic-greeter, gnome-keyring, Howdy on an IR
sensor.

That's one distro, one greeter, one keyring. The design is store-agnostic — it
only sets `PAM_AUTHTOK`, so anything consuming a token should work — but if
you're on GDM or Debian you may be the first. Issues welcome; `doctor` output
is the useful thing to paste.

Requires a TPM 2.0 and `systemd-creds`. No `tpm2-tools`.

MIT. Written for my own laptop; it seemed worth cleaning up.
