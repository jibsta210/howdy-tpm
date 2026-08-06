#!/usr/bin/env python3
"""Flatten a PAM service's auth stack and resolve every success=N jump target.

Adding or removing a module shifts every jump below it, and a jump that lands
one line off fails silently -- it does not error, it just runs the wrong
modules. This prints the resolved stack so the arithmetic is checked rather
than eyeballed.

    ./flatten-pam.py login
"""
import os, re, sys

def flatten(svc, seen=None):
    seen = seen or set()
    path = "/etc/pam.d/" + svc
    if svc in seen or not os.path.exists(path):
        return []
    seen.add(svc)
    out = []
    for line in open(path):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Control may be a bracketed expression with spaces: [success=4 default=ignore]
        m = re.match(r'^(-?)(\w+)\s+(\[[^\]]*\]|\S+)\s+(\S+)(.*)$', line)
        if not m:
            continue
        _, phase, ctl, mod, args = m.groups()
        if phase != "auth":
            continue
        if ctl == "include":
            out += flatten(mod, seen)
        else:
            out.append((ctl, mod, args.strip(), svc))
    return out

def main():
    svc = sys.argv[1] if len(sys.argv) > 1 else "login"
    st = flatten(svc)
    if not st:
        print("no auth stack for service %r" % svc); return 1
    print("auth stack for service %r (%d modules)\n" % (svc, len(st)))
    for i, (ctl, mod, args, src) in enumerate(st):
        print("  %2d  %-30s %-28s [%s]" % (i, ctl, mod, src))
        if args:
            print("      args: %s" % args)
        j = re.search(r'success=(\d+)', ctl)
        if j:
            n = int(j.group(1)); tgt = i + 1 + n
            if tgt < len(st):
                print("      success=%d -> skips %d, lands on %d (%s)"
                      % (n, n, tgt, st[tgt][1]))
            else:
                print("      success=%d -> lands PAST THE END (stack has %d)"
                      % (n, len(st)))
    return 0

if __name__ == "__main__":
    sys.exit(main())
