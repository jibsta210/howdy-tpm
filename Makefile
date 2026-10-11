CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -fPIC -fstack-protector-strong -D_GNU_SOURCE
LDFLAGS ?= -shared
LIBS    ?= -lpam
PREFIX  ?= /usr
PAM_LIBDIR := $(shell pkg-config --variable=libdir pam 2>/dev/null)
SECDIR  ?= $(if $(PAM_LIBDIR),$(PAM_LIBDIR)/security)
LIBEXECDIR ?= $(PREFIX)/libexec/howdy-tpm

all: pam_howdy_tpm.so pamtest

pam_howdy_tpm.so: src/pam_howdy_tpm.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

pamtest: tests/pamtest.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LIBS)

check-secdir:
	@test -n "$(SECDIR)" || { echo 'PAM directory unavailable: install PAM development files and pkg-config, or set SECDIR explicitly.' >&2; exit 1; }

install: all check-secdir
	install -Dm755 pam_howdy_tpm.so "$(DESTDIR)$(SECDIR)/pam_howdy_tpm.so"
	install -Dm755 scripts/howdy-tpm-enroll "$(DESTDIR)$(PREFIX)/bin/howdy-tpm-enroll"
	install -Dm755 scripts/howdy-tpm "$(DESTDIR)$(PREFIX)/bin/howdy-tpm"
	install -Dm644 tools/flatten-pam.py "$(DESTDIR)$(LIBEXECDIR)/flatten-pam.py"
	install -Dm755 pamtest "$(DESTDIR)$(LIBEXECDIR)/pamtest"
	install -dm700 "$(DESTDIR)/etc/howdy-tpm"

uninstall: check-secdir
	rm -f "$(DESTDIR)$(SECDIR)/pam_howdy_tpm.so"
	rm -f "$(DESTDIR)$(PREFIX)/bin/howdy-tpm-enroll" "$(DESTDIR)$(PREFIX)/bin/howdy-tpm"
	rm -f "$(DESTDIR)$(LIBEXECDIR)/flatten-pam.py" "$(DESTDIR)$(LIBEXECDIR)/pamtest"

clean:
	rm -f pam_howdy_tpm.so pamtest

check:
	PYTHONDONTWRITEBYTECODE=1 uv run --no-project --no-config tests/test_integration.py

.PHONY: all install uninstall clean check check-secdir
