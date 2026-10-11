/*
 * pam_howdy_tpm — release a TPM-sealed secret as PAM_AUTHTOK.
 *
 * THE PROBLEM
 *   Biometric auth (Howdy) proves who you are but produces no password. Any
 *   later module that needs one -- pam_kwallet5, pam_gnome_keyring -- finds
 *   PAM_AUTHTOK empty and prompts. The user has just been identified by face
 *   and is then asked for a password anyway, which defeats the point.
 *
 *   A face cannot supply the password itself. Face encodings are fuzzy: two
 *   captures of the same face differ (measured 0.08-0.38 Euclidean distance on
 *   the author's own enrolment), which is why matching uses a distance
 *   threshold rather than equality. There is nothing stable to derive a key
 *   from.
 *
 * THE APPROACH
 *   TPM-bound encryption protects the stored secret. PAM configuration must
 *   route only a successful authentication to this module; the TPM does not
 *   verify Howdy's result.
 *
 * WHERE IT GOES IN THE STACK
 *   On an explicitly successful authentication branch, before the modules
 *   that consume PAM_AUTHTOK. Failed authentication must not reach it, even
 *   if an earlier required module retained a failure. The doctor command
 *   prints a review-only fragment for the supported Howdy stack structure.
 *
 * WHY IT IS SAFE ON THE PASSWORD PATH
 *   It only acts when PAM_AUTHTOK is unset or empty. If the user typed a
 *   password, pam_unix has already stored it and this module does nothing.
 *   This token check is not proof of successful authentication.
 *
 * WHAT IT DOES NOT DO
 *   It returns PAM_IGNORE in every path, but setting PAM_AUTHTOK still affects
 *   downstream consumers. Do not place it before password authentication.
 *
 * Options:
 *   cred=PATH     sealed credential          (default /etc/howdy-tpm/secret.cred)
 *   name=NAME     credential name            (default howdy-tpm)
 *   user=USER     permitted PAM user         (required)
 *   service=NAME  permitted PAM service      (required)
 *   debug         log decisions (never the secret)
 *
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <fcntl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <syslog.h>        /* LOG_* priorities for pam_syslog */
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define DEFAULT_CRED "/etc/howdy-tpm/secret.cred"
#define DEFAULT_NAME "howdy-tpm"
#define SYSTEMD_CREDS "/usr/bin/systemd-creds"
#define MAX_SECRET 4096

struct opts {
	const char *cred;
	const char *name;
	const char *user;
	const char *service;
	int debug;
};

static void parse_opts(struct opts *o, int argc, const char **argv)
{
	o->cred = DEFAULT_CRED;
	o->name = DEFAULT_NAME;
	o->user = NULL;
	o->service = NULL;
	o->debug = 0;

	for (int i = 0; i < argc; i++) {
		if (!strncmp(argv[i], "cred=", 5))
			o->cred = argv[i] + 5;
		else if (!strncmp(argv[i], "name=", 5))
			o->name = argv[i] + 5;
		else if (!strncmp(argv[i], "user=", 5))
			o->user = argv[i] + 5;
		else if (!strncmp(argv[i], "service=", 8))
			o->service = argv[i] + 8;
		else if (!strcmp(argv[i], "debug"))
			o->debug = 1;
	}
}

/*
 * Refuse to read a credential that is not root-owned and not 0600.
 *
 * Not paranoia: this file's contents become the authentication token for
 * whatever consumes it downstream. If a non-root user can write it, that user
 * chooses your wallet password. Checking here rather than trusting the
 * installer means a later chmod cannot silently widen the hole.
 */
static int cred_file_sane(pam_handle_t *pamh, const struct opts *o)
{
	struct stat st;

	if (stat(o->cred, &st) != 0) {
		if (o->debug)
			pam_syslog(pamh, LOG_DEBUG, "no credential at %s (%m)", o->cred);
		return 0;
	}
	if (!S_ISREG(st.st_mode)) {
		pam_syslog(pamh, LOG_WARNING, "%s is not a regular file", o->cred);
		return 0;
	}
	if (st.st_uid != 0) {
		pam_syslog(pamh, LOG_WARNING,
			   "%s is owned by uid %u, refusing (must be root)",
			   o->cred, (unsigned)st.st_uid);
		return 0;
	}
	if (st.st_mode & (S_IRWXG | S_IRWXO)) {
		pam_syslog(pamh, LOG_WARNING,
			   "%s is mode %04o, refusing (must be 0600)",
			   o->cred, st.st_mode & 07777);
		return 0;
	}
	return 1;
}

/*
 * Unseal via systemd-creds. Fork/exec rather than linking libsystemd: the
 * surface is one well-defined binary, the secret crosses a pipe we control,
 * and there is no in-process crypto state to leak.
 */
static char *unseal(pam_handle_t *pamh, const struct opts *o)
{
	int fds[2];
	pid_t pid;
	char *buf = NULL;
	size_t len = 0;
	int status = 0;

	if (pipe(fds) != 0) {
		pam_syslog(pamh, LOG_ERR, "pipe: %m");
		return NULL;
	}

	pid = fork();
	if (pid < 0) {
		pam_syslog(pamh, LOG_ERR, "fork: %m");
		close(fds[0]); close(fds[1]);
		return NULL;
	}

	if (pid == 0) {
		int devnull = open("/dev/null", O_RDWR);
		close(fds[0]);
		if (dup2(fds[1], STDOUT_FILENO) < 0) _exit(127);
		if (devnull >= 0) {
			dup2(devnull, STDIN_FILENO);
			/* stderr to /dev/null: systemd-creds is chatty on
			 * failure and PAM stderr can reach the login screen. */
			dup2(devnull, STDERR_FILENO);
			if (devnull > STDERR_FILENO) close(devnull);
		}
		close(fds[1]);
		execl(SYSTEMD_CREDS, "systemd-creds", "decrypt",
		      "--name", o->name, o->cred, "-", (char *)NULL);
		_exit(127);
	}

	close(fds[1]);

	buf = calloc(1, MAX_SECRET + 1);
	if (buf) {
		ssize_t n;
		while (len < MAX_SECRET &&
		       (n = read(fds[0], buf + len, MAX_SECRET - len)) > 0)
			len += (size_t)n;
	}
	close(fds[0]);

	if (waitpid(pid, &status, 0) < 0 ||
	    !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		pam_syslog(pamh, LOG_NOTICE,
			   "systemd-creds could not unseal %s; check the credential, TPM access and SELinux audit logs",
			   o->cred);
		if (buf) { explicit_bzero(buf, MAX_SECRET); free(buf); }
		return NULL;
	}

	if (!buf || len == 0) {
		if (buf) { explicit_bzero(buf, MAX_SECRET); free(buf); }
		return NULL;
	}

	/*
	 * Strip ONE trailing newline. systemd-creds is byte-exact, so a
	 * credential sealed from `echo` carries a \n that would be handed to
	 * pam_kwallet5 as part of the password and fail to unlock -- silently,
	 * and looking exactly like a wrong password.
	 */
	if (buf[len - 1] == '\n')
		buf[--len] = '\0';

	return buf;
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct opts o;
	const void *existing = NULL;
	const void *user = NULL, *service = NULL;
	char *secret;
	int rc;

	(void)flags;
	parse_opts(&o, argc, argv);

	if (!o.user || !*o.user || !o.service || !*o.service) {
		pam_syslog(pamh, LOG_ERR, "user= and service= are required; refusing to release a credential");
		return PAM_IGNORE;
	}
	if (pam_get_item(pamh, PAM_USER, &user) != PAM_SUCCESS || !user ||
	    strcmp(user, o.user) != 0 ||
	    pam_get_item(pamh, PAM_SERVICE, &service) != PAM_SUCCESS || !service ||
	    strcmp(service, o.service) != 0)
		return PAM_IGNORE;

	/*
	 * If something already established a token -- normally pam_unix on the
	 * password path -- leave it alone. Overwriting it would replace the
	 * password the user actually typed.
	 */
	if (pam_get_item(pamh, PAM_AUTHTOK, &existing) == PAM_SUCCESS &&
	    existing && *(const char *)existing) {
		if (o.debug)
			pam_syslog(pamh, LOG_DEBUG,
				   "PAM_AUTHTOK already set, doing nothing");
		return PAM_IGNORE;
	}

	if (!cred_file_sane(pamh, &o))
		return PAM_IGNORE;

	secret = unseal(pamh, &o);
	if (!secret)
		return PAM_IGNORE;

	rc = pam_set_item(pamh, PAM_AUTHTOK, secret);

	/* pam_set_item copies; wipe ours rather than leaving it in the heap. */
	explicit_bzero(secret, strlen(secret));
	free(secret);

	if (rc != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR, "pam_set_item(PAM_AUTHTOK): %s",
			   pam_strerror(pamh, rc));
		return PAM_IGNORE;
	}

	if (o.debug)
		pam_syslog(pamh, LOG_DEBUG,
			   "released TPM-sealed secret as PAM_AUTHTOK");

	/*
	 * PAM_IGNORE, always. This module supplies a token; it does not decide
	 * whether anyone may log in. Returning PAM_SUCCESS here would let a
	 * readable credential file substitute for authentication.
	 */
	return PAM_IGNORE;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	(void)pamh; (void)flags; (void)argc; (void)argv;
	return PAM_IGNORE;
}
