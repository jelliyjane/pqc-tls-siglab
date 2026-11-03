#ifndef CATS_CTI_POLICY_H
#define CATS_CTI_POLICY_H

/* CATS runtime format, NOT STIX. Compiled from STIX + operator rules.
 * Header: CATS-CTI-1<TAB>expires_epoch<TAB>row_count<TAB>sha256_revision\n
 * Rows: exact OpenSSL algorithm names. END\n terminates the snapshot.
 * Reload on every certificate selection; never fall back on an invalid policy.
 */
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CATS_CTI_MAX_ALGORITHMS 512
#define CATS_CTI_NAME_BYTES 512

struct cats_cti_policy {
    char algorithms[CATS_CTI_MAX_ALGORITHMS][CATS_CTI_NAME_BYTES];
    char revision[65];
    size_t count;
    int enabled;
};

/* Bounded byte reader rejects NUL, CR, partial lines and overlong input. */
static int cats_cti_line(FILE *file, char *line, size_t size)
{
    size_t n = 0;
    int c;
    while ((c = fgetc(file)) != EOF) {
        if (c == '\n') { line[n] = '\0'; return 1; }
        if (c == 0 || c == '\r' || n + 1 >= size) return 0;
        line[n++] = (char)c;
    }
    return 0;
}

static int cats_cti_uint(const char *s, unsigned long long *value)
{
    char *end;
    if (!*s) return 0;
    for (const char *p = s; *p; p++) if (*p < '0' || *p > '9') return 0;
    errno = 0;
    *value = strtoull(s, &end, 10);
    return !errno && !*end;
}

static int cats_cti_load(const char *path, time_t now, struct cats_cti_policy *policy)
{
    FILE *file;
    char line[1024], *expires, *count, *revision;
    unsigned long long expiry, rows;
    int ok = 0;
    memset(policy, 0, sizeof(*policy));
    if (!path) return 1; /* Only an unset variable disables enforcement. */
    policy->enabled = 1;
    if (!*path || now < 0 || !(file = fopen(path, "rb"))) return 0;
    if (!cats_cti_line(file, line, sizeof(line)) || strncmp(line, "CATS-CTI-1\t", 11)) goto done;
    expires = line + 11;
    if (!(count = strchr(expires, '\t'))) goto done;
    *count++ = '\0';
    if (!(revision = strchr(count, '\t'))) goto done;
    *revision++ = '\0';
    if (!cats_cti_uint(expires, &expiry) || expiry <= (unsigned long long)now ||
        !cats_cti_uint(count, &rows) || rows > CATS_CTI_MAX_ALGORITHMS || strlen(revision) != 64) goto done;
    for (size_t i = 0; i < 64; i++)
        if (!((revision[i] >= '0' && revision[i] <= '9') || (revision[i] >= 'a' && revision[i] <= 'f'))) goto done;
    memcpy(policy->revision, revision, 65);
    for (size_t i = 0; i < (size_t)rows; i++) {
        if (!cats_cti_line(file, line, CATS_CTI_NAME_BYTES) || !line[0]) goto done;
        for (const char *p = line; *p; p++)
            if (!( (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                   (*p >= '0' && *p <= '9') || *p == '_' || *p == '-' || *p == '+' || *p == '.')) goto done;
        for (size_t j = 0; j < i; j++) if (!strcmp(line, policy->algorithms[j])) goto done;
        strcpy(policy->algorithms[i], line);
    }
    if (!cats_cti_line(file, line, sizeof(line)) || strcmp(line, "END") || fgetc(file) != EOF || ferror(file)) goto done;
    policy->count = (size_t)rows;
    ok = 1;
done:
    fclose(file);
    return ok;
}

static int cats_cti_allows(const struct cats_cti_policy *policy, const char *algorithm)
{
    if (!policy->enabled) return 1;
    for (size_t i = 0; i < policy->count; i++)
        if (!strcmp(algorithm, policy->algorithms[i])) return 1;
    return 0;
}
#endif
