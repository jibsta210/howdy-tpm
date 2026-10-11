#!/usr/bin/env python3
"""Inspect PAM files and print a review-only plan for sufficient-Howdy stacks.

This preserves include/substack boundaries; it does not simulate PAM execution.
"""
import argparse
import contextlib
from dataclasses import dataclass
import difflib
import hashlib
from pathlib import Path
import re
import shlex
import sys


@dataclass
class Rule:
    line: int
    phase: str
    control: str
    module: str
    args: str


RULE = re.compile(r"^(-?\w+)\s+(\[[^\]]*\]|\S+)\s+(\S+)(.*)$")
SERVICE = re.compile(r"[a-zA-Z0-9_-]+")


def read_service(directory, service):
    if not SERVICE.fullmatch(service):
        raise ValueError("invalid PAM service name")
    path = directory / service
    with path.open(encoding="utf-8", newline="") as source:
        lines = source.read().splitlines(keepends=True)
    rules = []
    for number, line in enumerate(lines, 1):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        match = RULE.fullmatch(text)
        if not match or text.endswith("\\"):
            raise ValueError(f"{path}:{number}: unsupported PAM syntax; no plan generated")
        phase, control, module, args = match.groups()
        rules.append(Rule(number, phase.lstrip("-"), control, module, args.strip()))
    return path, lines, rules


def show_stack(directory, service, parents=(), indent=""):
    if service in parents:
        raise ValueError(f"recursive PAM include: {' -> '.join((*parents, service))}")
    path, _, rules = read_service(directory, service)
    managed = path.is_symlink() and "authselect" in str(path.resolve())
    print(f"{indent}{path}" + (" [authselect-managed: do not edit directly]" if managed else ""))
    for rule in rules:
        if rule.phase != "auth":
            continue
        print(f"{indent}  {rule.line}: {rule.control} {rule.module} {rule.args}".rstrip())
        if rule.control in ("include", "substack"):
            show_stack(directory, rule.module, (*parents, service), indent + "    ")


def shell_plan(path, original, fragment_path, fragment, changed, cred, name):
    if path.is_symlink():
        raise ValueError("shell output requires a regular service file, not a symlink")
    expected = hashlib.sha256("".join(original).encode()).hexdigest()
    return f"""# Review before running; keep an administrator session open.
# This configures PAM only. SELinux TPM access may need a separately reviewed rule.
sudo bash <<'HOWDY_TPM_APPLY'
set -euo pipefail
pam={shlex.quote(str(path.absolute()))}
fragment={shlex.quote(str(fragment_path.absolute()))}

[[ -f $pam && ! -L $pam ]] || {{ echo 'Service file is missing or a symlink.' >&2; exit 1; }}
[[ $(sha256sum "$pam" | cut -d ' ' -f 1) == {expected} ]] || {{
  echo 'Service configuration changed; run doctor again.' >&2; exit 1;
}}
[[ ! -e $fragment && ! -L $fragment ]] || {{ echo 'Fragment already exists; refusing to overwrite.' >&2; exit 1; }}
length=$(systemd-creds decrypt --name={shlex.quote(name)} {shlex.quote(cred)} - | wc -c)
[[ $length -gt 0 ]] || {{ echo 'Credential is empty; enroll it first.' >&2; exit 1; }}

install -dm700 /var/backups/howdy-tpm
backup=$(mktemp /var/backups/howdy-tpm/{path.name}.XXXXXX)
cp -a -- "$pam" "$backup"
printf 'Backup: %s\\nRollback: sudo cp -a -- %q %q && sudo rm -f -- %q\\n' "$backup" "$backup" "$pam" "$fragment"

work=$(mktemp -d "$(dirname "$pam")/.howdy-tpm.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
printf '%s' {shlex.quote("".join(fragment))} > "$work/fragment"
chmod 644 "$work/fragment"
cp -a -- "$pam" "$work/service"
printf '%s' {shlex.quote("".join(changed))} > "$work/service"
mv -- "$work/fragment" "$fragment"
mv -- "$work/service" "$pam"
if command -v restorecon >/dev/null 2>&1; then
  restorecon -v "$fragment" "$pam"
fi
echo 'PAM configuration installed. Verify face and password login before rebooting.'
HOWDY_TPM_APPLY
"""


def configuration_plan(directory, service, user, keyring, module_dir, cred, name, emit_shell=False):
    if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_.-]*\$?", user):
        raise ValueError("invalid user name for a PAM configuration fragment")
    if not Path(cred).is_absolute() or re.search(r"[\s#\\]", cred):
        raise ValueError("--cred must be an absolute path without whitespace, # or backslashes")
    if not re.fullmatch(r"[a-zA-Z0-9_.-]+", name):
        raise ValueError("invalid credential name for a PAM configuration fragment")
    if not module_dir.is_absolute() or re.search(r"[\s#\\]", str(module_dir)):
        raise ValueError("--module-dir must be an absolute path without whitespace, # or backslashes")
    path, lines, rules = read_service(directory, service)
    if path.is_symlink() and "authselect" in str(path.resolve()):
        raise ValueError("selected service is authselect-managed; edit a custom profile instead")
    auth = [rule for rule in rules if rule.phase == "auth"]
    if any(re.search(r"=\d+", rule.control) for rule in auth):
        raise ValueError("parent stack contains numeric jumps; no automatic plan for this structure")
    howdy = [rule for rule in auth if Path(rule.module).name == "pam_howdy.so"]
    if len(howdy) != 1 or howdy[0].control != "sufficient":
        raise ValueError("plan supports one direct 'auth sufficient pam_howdy.so' rule only")
    face = howdy[0]
    # The Fedora SDDM guard can retain a failure and still reach Howdy.
    # Stop that failure before releasing any token; do not infer other prefixes.
    prefix = auth[:auth.index(face)]
    guard = None
    if prefix:
        if (len(prefix) != 1 or Path(prefix[0].module).name != "pam_selinux_permit.so"
                or " ".join(prefix[0].control.split()) != "[success=done ignore=ignore default=bad]"):
            raise ValueError("unsupported auth rules before Howdy; no safe release plan inferred")
        guard = prefix[0]
    following = auth[auth.index(face) + 1:]
    if not following or following[0].control != "substack":
        raise ValueError("plan requires a password-authentication substack immediately after Howdy")
    consumer_name = {"kwallet": "pam_kwallet5.so", "gnome": "pam_gnome_keyring.so"}[keyring]
    consumers = [rule for rule in following if Path(rule.module).name == consumer_name]
    if len(consumers) != 1 or consumers[0].control != "optional":
        raise ValueError(f"plan requires one existing optional auth rule for {consumer_name}")
    consumer = consumers[0]
    sessions = [rule for rule in rules if rule.phase == "session"
                and Path(rule.module).name == consumer_name and rule.control == "optional"
                and "auto_start" in rule.args.split()]
    if not sessions:
        raise ValueError(f"missing optional session rule for {consumer_name} auto_start")
    for module in ("pam_howdy_tpm.so", "pam_permit.so", Path(face.module).name, consumer_name):
        if not (module_dir / module).is_file():
            raise ValueError(f"required module missing: {module_dir / module}")
    fragment_name = f"howdy-tpm-face-{service}"
    fragment_path = directory / fragment_name
    if fragment_path.exists() or fragment_path.is_symlink():
        raise ValueError(f"{fragment_path} already exists; inspect it before changing the service")
    # On failure, skip only release, keyring auth, and the success return.
    # With include, this lands back in the unchanged parent password substack.
    fragment = [
        "# Howdy failure returns to the parent password substack.\n",
        f"auth [success=1 default=ignore] {face.module} {face.args}\n".replace(" \n", "\n"),
        f"auth [default=3] {module_dir}/pam_permit.so\n",
        f"auth optional {module_dir}/pam_howdy_tpm.so user={user} service={service} cred={cred} name={name}\n",
        f"-auth optional {consumer.module} {consumer.args}\n".replace(" \n", "\n"),
        f"auth sufficient {module_dir}/pam_permit.so\n",
    ]
    changed = lines.copy()
    changed[face.line - 1] = f"auth include {fragment_name}\n"
    if guard:
        changed[guard.line - 1] = changed[guard.line - 1].replace("default=bad", "default=die", 1)
    if emit_shell:
        print(shell_plan(path, lines, fragment_path, fragment, changed, cred, name), end="")
    else:
        print("\nReview-only plan: create the fragment and replace the Howdy rule together.")
        print("The password substack and session hooks remain in the selected service.")
        if guard:
            print("The SELinux guard stops immediately on failure, before any credential release.")
        print("Keep an administrator session open; test face, password, and failed authentication before rebooting.\n")
        print("".join(difflib.unified_diff([], fragment, fromfile="/dev/null", tofile=str(fragment_path))), end="")
        print("".join(difflib.unified_diff(lines, changed, fromfile=str(path), tofile=str(path))), end="")
    return fragment_name, fragment, changed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("service")
    parser.add_argument("--pam-dir", type=Path, default=Path("/etc/pam.d"))
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--emit-shell", action="store_true", help="print copyable commands instead of a diff")
    parser.add_argument("--user")
    parser.add_argument("--keyring", choices=("kwallet", "gnome"))
    parser.add_argument("--module-dir", type=Path)
    parser.add_argument("--cred", default="/etc/howdy-tpm/secret.cred")
    parser.add_argument("--name", default="howdy-tpm")
    args = parser.parse_args(argv)
    try:
        with contextlib.redirect_stdout(sys.stderr if args.emit_shell else sys.stdout):
            print("Authentication files (include/substack boundaries preserved; no jump simulation):")
            show_stack(args.pam_dir, args.service)
        if args.plan or args.emit_shell:
            if not args.user or not args.keyring or not args.module_dir:
                parser.error("planning requires --user, --keyring and --module-dir")
            configuration_plan(args.pam_dir, args.service, args.user, args.keyring,
                               args.module_dir, args.cred, args.name, args.emit_shell)
    except (OSError, ValueError) as error:
        print(f"No configuration changes made: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
