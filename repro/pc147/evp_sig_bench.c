/* Pure and composite: identical in-process EVP timing, no CLI-time fallback.
 * argv: key.pem provider-directory provider-name warmup iterations delay-ms
 * Use '-' for provider-directory/name when testing only the default provider.
 * stdout: one CSV row per sample, flushed immediately. Metadata is on stderr.
 */
#define _POSIX_C_SOURCE 200809L
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

static uint64_t now_ns(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) { perror("clock"); exit(2); }
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}

static long number(const char *s) {
    char *end = NULL;
    errno = 0;
    long n = strtol(s, &end, 10);
    if (errno || !*s || *end || n < 0 || n > 1000000) return -1;
    return n;
}

int main(int argc, char **argv) {
    if (argc != 7) {
        fprintf(stderr, "usage: %s key.pem provider-dir provider warmup iterations delay-ms\n", argv[0]);
        return 2;
    }
    long warmup = number(argv[4]), iterations = number(argv[5]), delay = number(argv[6]);
    if (warmup < 0 || iterations <= 0 || delay < 0) return 2;
    int rc = 1;
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *def = NULL, *custom = NULL;
    EVP_PKEY *key = NULL, *pub = NULL;
    EVP_MD_CTX *sign = NULL, *verify = NULL;
    BIO *keybio = NULL, *pubbio = NULL;
    unsigned char *sig = NULL;
    if (!libctx) goto done;
    if (strcmp(argv[2], "-") && !OSSL_PROVIDER_set_default_search_path(libctx, argv[2])) goto done;
    if (!(def = OSSL_PROVIDER_load(libctx, "default"))) goto done;
    if (strcmp(argv[3], "-") && !(custom = OSSL_PROVIDER_load(libctx, argv[3]))) goto done;
    if (!(keybio = BIO_new_file(argv[1], "r"))) goto done;
    key = PEM_read_bio_PrivateKey_ex(keybio, NULL, NULL, NULL, libctx, NULL);
    if (!key || !(pubbio = BIO_new(BIO_s_mem())) || !PEM_write_bio_PUBKEY(pubbio, key)) goto done;
    pub = PEM_read_bio_PUBKEY_ex(pubbio, NULL, NULL, NULL, libctx, NULL);
    if (!pub || !(sign = EVP_MD_CTX_new()) || !(verify = EVP_MD_CTX_new())) goto done;

    /* TLS 1.3 server CertificateVerify input for a SHA-256 transcript.
     * Fixed public test digest. 64 spaces || context || 0 || 32-byte digest.
     * This is not certificate-chain verification or end-to-end TLS timing.
     */
    const char context[] = "TLS 1.3, server CertificateVerify";
    unsigned char message[64 + sizeof(context) + 32];
    memset(message, 0, sizeof(message));
    memset(message, 0x20, 64);
    memcpy(message + 64, context, sizeof(context));
    memset(message + 64 + sizeof(context), 0xa5, 32);
    size_t capacity = 0;
    if (EVP_DigestSignInit_ex(sign, NULL, NULL, libctx, NULL, key, NULL) != 1 ||
        EVP_DigestSign(sign, NULL, &capacity, message, sizeof(message)) != 1 ||
        capacity == 0 || !(sig = OPENSSL_malloc(capacity))) goto done;
    fprintf(stderr, "protocol=evp_cv_sha256_init_oneshot_v1\nopenssl=%s\nkey_type=%s\nkey_provider=%s\nmessage_bytes=%zu\n",
            OpenSSL_version(OPENSSL_VERSION), EVP_PKEY_get0_type_name(key),
            OSSL_PROVIDER_get0_name(EVP_PKEY_get0_provider(key)), sizeof(message));
    puts("run,sign_ms,verify_ms,signature_bytes");
    fflush(stdout);
    for (long i = -warmup; i < iterations; ++i) {
        /* Allocate/load/reset outside timing. Include Init + actual operation
         * identically for every algorithm, not subprocess or key import time.
         */
        if (EVP_MD_CTX_reset(sign) != 1 || EVP_MD_CTX_reset(verify) != 1) goto done;
        size_t siglen = capacity;
        uint64_t start = now_ns();
        if (EVP_DigestSignInit_ex(sign, NULL, NULL, libctx, NULL, key, NULL) != 1 ||
            EVP_DigestSign(sign, sig, &siglen, message, sizeof(message)) != 1) goto done;
        uint64_t sign_ns = now_ns() - start;
        start = now_ns();
        if (EVP_DigestVerifyInit_ex(verify, NULL, NULL, libctx, NULL, pub, NULL) != 1 ||
            EVP_DigestVerify(verify, sig, siglen, message, sizeof(message)) != 1) goto done;
        uint64_t verify_ns = now_ns() - start;
        if (i >= 0) {
            printf("%ld,%.9f,%.9f,%zu\n", i + 1, (double)sign_ns / 1e6,
                   (double)verify_ns / 1e6, siglen);
            fflush(stdout);
        }
        if (delay) {
            struct timespec pause = {delay / 1000, (delay % 1000) * 1000000};
            while (nanosleep(&pause, &pause) && errno == EINTR) {}
        }
    }
    rc = 0;
done:
    if (rc) ERR_print_errors_fp(stderr);
    OPENSSL_free(sig);
    EVP_MD_CTX_free(sign); EVP_MD_CTX_free(verify);
    EVP_PKEY_free(key); EVP_PKEY_free(pub);
    BIO_free(keybio); BIO_free(pubbio);
    OSSL_PROVIDER_unload(custom); OSSL_PROVIDER_unload(def);
    OSSL_LIB_CTX_free(libctx);
    return rc;
}
