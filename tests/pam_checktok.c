/* Test observer: report whether PAM_AUTHTOK is set, and its length.
 * Never logs the secret itself -- only presence and length, which is enough
 * to prove delivery without putting a password in the journal. */
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <syslog.h>
#include <string.h>

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const void *tok = NULL;
	(void)flags; (void)argc; (void)argv;
	if (pam_get_item(pamh, PAM_AUTHTOK, &tok) == PAM_SUCCESS && tok)
		pam_syslog(pamh, LOG_NOTICE, "CHECKTOK: AUTHTOK set, len=%zu",
			   strlen((const char *)tok));
	else
		pam_syslog(pamh, LOG_NOTICE, "CHECKTOK: AUTHTOK is NOT set");
	return PAM_IGNORE;
}
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{ (void)pamh;(void)flags;(void)argc;(void)argv; return PAM_IGNORE; }
