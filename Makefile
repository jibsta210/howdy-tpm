CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -fPIC -fstack-protector-strong -D_GNU_SOURCE
LDFLAGS ?= -shared
LIBS     = -lpam
PREFIX  ?= /usr
SECDIR  ?= $(PREFIX)/lib/security

all: pam_howdy_tpm.so

pam_howdy_tpm.so: src/pam_howdy_tpm.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

install: pam_howdy_tpm.so
	install -Dm755 pam_howdy_tpm.so $(DESTDIR)$(SECDIR)/pam_howdy_tpm.so
	install -Dm755 scripts/howdy-tpm-enroll $(DESTDIR)$(PREFIX)/bin/howdy-tpm-enroll
	install -dm700 $(DESTDIR)/etc/howdy-tpm

uninstall:
	rm -f $(DESTDIR)$(SECDIR)/pam_howdy_tpm.so
	rm -f $(DESTDIR)$(PREFIX)/bin/howdy-tpm-enroll

clean:
	rm -f pam_howdy_tpm.so

.PHONY: all install uninstall clean
