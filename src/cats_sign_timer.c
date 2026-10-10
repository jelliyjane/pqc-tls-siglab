#define _GNU_SOURCE
#include <dlfcn.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

/* Linux shared-OpenSSL integration. Enable only around a synchronous TLS
 * handshake on this thread. Never substitute message-callback phase timing.
 * Static linking, async sign operations and thread migration are unsupported. */
static _Thread_local int enabled;
static _Thread_local uint64_t elapsed_ns, calls;
static pthread_once_t once = PTHREAD_ONCE_INIT;
static int (*real_sign)(EVP_MD_CTX *, unsigned char *, size_t *, const unsigned char *, size_t);

static uint64_t now_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ULL + t.tv_nsec;
}

static void resolve(void)
{
    *(void **)(&real_sign) = dlsym(RTLD_NEXT, "EVP_DigestSign");
    if (!real_sign) _exit(127); /* Instrumentation cannot silently skip signing. */
}

void cats_sign_timer_begin(void)
{
    pthread_once(&once, resolve);
    elapsed_ns = calls = 0;
    enabled = 1;
}

uint64_t cats_sign_timer_end(uint64_t *count)
{
    enabled = 0;
    *count = calls;
    return elapsed_ns;
}

int EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *len,
                   const unsigned char *data, size_t size)
{
    pthread_once(&once, resolve);
    if (!enabled || !sig) return real_sign(ctx, sig, len, data, size);
    uint64_t start = now_ns();
    int ok = real_sign(ctx, sig, len, data, size);
    uint64_t stop = now_ns();
    if (ok > 0) { elapsed_ns += stop - start; calls++; }
    return ok;
}
