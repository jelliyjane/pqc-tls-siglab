#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

static int tcp_connect(const char *host, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *p;
    int fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &res) != 0)
        return -1;

    for (p = res; p != NULL; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

int main(int argc, char **argv)
{
    const char *host;
    const char *port;
    const char *sigalg;
    const char *provider_path;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    X509 *cert = NULL;
    OSSL_PROVIDER *oqsprov = NULL;
    OSSL_PROVIDER *defprov = NULL;
    int fd = -1;
    int rc = 1;
    double start, end;
    int sig_nid = NID_undef;

    if (argc != 5) {
        fprintf(stderr, "usage: %s <host> <port> <sigalg> <provider_path>\n", argv[0]);
        return 2;
    }

    host = argv[1];
    port = argv[2];
    sigalg = argv[3];
    provider_path = argv[4];

    if (!OSSL_PROVIDER_set_default_search_path(NULL, provider_path)) {
        fprintf(stderr, "failed to set provider path\n");
        goto out;
    }
    oqsprov = OSSL_PROVIDER_load(NULL, "oqsprovider");
    defprov = OSSL_PROVIDER_load(NULL, "default");
    if (oqsprov == NULL || defprov == NULL) {
        fprintf(stderr, "failed to load providers\n");
        ERR_print_errors_fp(stderr);
        goto out;
    }

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL)
        goto out;

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_max_cert_list(ctx, 512 * 1024);

    if (!SSL_CTX_set1_sigalgs_list(ctx, sigalg)) {
        fprintf(stderr, "failed to set sigalgs: %s\n", sigalg);
        ERR_print_errors_fp(stderr);
        goto out;
    }

    fd = tcp_connect(host, port);
    if (fd < 0) {
        perror("connect");
        goto out;
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL)
        goto out;
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);

    start = now_ms();
    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "SSL_connect failed\n");
        ERR_print_errors_fp(stderr);
        goto out;
    }
    end = now_ms();

    cert = SSL_get1_peer_certificate(ssl);
    printf("status ok\n");
    printf("tls_version %s\n", SSL_get_version(ssl));
    printf("cipher %s\n", SSL_get_cipher(ssl));
    printf("handshake_ms %.2f\n", end - start);
    printf("max_cert_list %ld\n", SSL_get_max_cert_list(ssl));
    printf("peer_cert %s\n", cert != NULL ? "present" : "missing");
    if (SSL_get_peer_signature_type_nid(ssl, &sig_nid) == 1)
        printf("peer_signature %s\n", OBJ_nid2sn(sig_nid));

    rc = 0;

out:
    X509_free(cert);
    SSL_free(ssl);
    if (fd >= 0)
        close(fd);
    SSL_CTX_free(ctx);
    OSSL_PROVIDER_unload(oqsprov);
    OSSL_PROVIDER_unload(defprov);
    return rc;
}
