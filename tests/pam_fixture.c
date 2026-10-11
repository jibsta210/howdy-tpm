/* Isolated PAM fixtures. Never installed: no real account/face authentication. */
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int pam_sm_authenticate(pam_handle_t *h, int flags, int argc, const char **argv)
{
    (void)flags;
    if (!argc) return PAM_SERVICE_ERR;
    if (!strcmp(argv[0], "guard"))
        return getenv("GUARD_OK") ? PAM_IGNORE : PAM_AUTH_ERR;
    if (!strcmp(argv[0], "face"))
        return getenv("FACE_OK") && !strcmp(getenv("FACE_OK"), "1") ? PAM_SUCCESS : PAM_AUTH_ERR;
    if (!strcmp(argv[0], "password")) {
        if (!getenv("PASSWORD_OK") || strcmp(getenv("PASSWORD_OK"), "1")) return PAM_AUTH_ERR;
        pam_set_item(h, PAM_AUTHTOK, "typed-by-the-user");
        return PAM_SUCCESS;
    }
    if (!strcmp(argv[0], "observe")) {
        const void *token = NULL;
        pam_get_item(h, PAM_AUTHTOK, &token);
        FILE *log = fopen(getenv("OBSERVER_LOG"), "a");
        if (!log) return PAM_SERVICE_ERR;
        fprintf(log, "present=%d fixture=%d typed=%d\n", token != NULL,
                token && !strcmp(token, "audit-only-secret"),
                token && !strcmp(token, "typed-by-the-user"));
        fclose(log);
        return PAM_IGNORE;
    }
    return PAM_SERVICE_ERR;
}

int pam_sm_setcred(pam_handle_t *h, int f, int c, const char **v)
{ (void)h; (void)f; (void)c; (void)v; return PAM_IGNORE; }
