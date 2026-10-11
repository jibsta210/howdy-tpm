/* Link wrappers for tests only: fake credential ownership and decryption. */
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int __real_stat(const char *, struct stat *);
int __wrap_stat(const char *path, struct stat *st)
{
    int rc = __real_stat(path, st);
    const char *fixture = getenv("FIXTURE_CRED");
    if (rc == 0 && fixture && !strcmp(path, fixture))
        st->st_uid = getenv("BAD_OWNER") ? 1234 : 0;
    return rc;
}

int __wrap_execl(const char *file, const char *arg, ...)
{
    (void)file; (void)arg;
    const char *mock = getenv("MOCK_DECRYPT");
    char *const argv[] = {(char *)mock, NULL};
    if (!mock) return -1;
    return execv(mock, argv);
}
