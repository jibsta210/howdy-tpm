/* Minimal PAM auth test. Answers NO prompts -- if the stack needs a password
 * it fails, if howdy alone satisfies it we get PAM_SUCCESS. That is exactly
 * the question: does service "login" authenticate this user with face only? */
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int conv(int n, const struct pam_message **m,
                struct pam_response **r, void *d)
{
	(void)d;
	*r = calloc(n, sizeof(struct pam_response));
	if (!*r) return PAM_BUF_ERR;
	for (int i = 0; i < n; i++) {
		printf("  PAM prompt [style=%d]: %s\n",
		       m[i]->msg_style, m[i]->msg ? m[i]->msg : "");
		/* Refuse to supply anything. A stack that needs a password
		 * must fail here rather than silently pass because the test
		 * handed it one. */
		(*r)[i].resp = NULL;
		(*r)[i].resp_retcode = 0;
	}
	return PAM_SUCCESS;
}

int main(int argc, char **argv)
{
	const char *svc = argc > 1 ? argv[1] : "login";
	const char *usr = argc > 2 ? argv[2] : "jakes";
	struct pam_conv c = { conv, NULL };
	pam_handle_t *h = NULL;
	int rc = pam_start(svc, usr, &c, &h);
	if (rc != PAM_SUCCESS) { printf("  pam_start: %d\n", rc); return 2; }
	rc = pam_authenticate(h, 0);
	printf("  pam_authenticate(%s, %s) = %d (%s)\n",
	       svc, usr, rc, pam_strerror(h, rc));
	pam_end(h, rc);
	return rc == PAM_SUCCESS ? 0 : 1;
}
