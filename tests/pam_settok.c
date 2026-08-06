/* Test scaffolding only: sets PAM_AUTHTOK to a known value so we can prove
 * pam_howdy_tpm leaves an existing token alone. Never installed by `make
 * install`. */
#include <security/pam_modules.h>
#include <security/pam_ext.h>
int pam_sm_authenticate(pam_handle_t *pamh, int f, int c, const char **v)
{ (void)f;(void)c;(void)v; pam_set_item(pamh, PAM_AUTHTOK, "typed-by-the-user"); return PAM_IGNORE; }
int pam_sm_setcred(pam_handle_t *pamh, int f, int c, const char **v)
{ (void)pamh;(void)f;(void)c;(void)v; return PAM_IGNORE; }
