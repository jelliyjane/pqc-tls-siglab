#define _GNU_SOURCE

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

#ifdef __linux__
#include <netinet/tcp.h>
#endif

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

static int tcp_connect(const char *host, const char *port, double *connect_ms)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *p;
    int fd = -1;
    double start;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &res) != 0)
        return -1;

    start = now_ms();
    for (p = res; p != NULL; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    *connect_ms = now_ms() - start;

    freeaddrinfo(res);
    return fd;
}

static int is_default_group(const char *group)
{
    return strcmp(group, "OPENSSL_DEFAULT") == 0 || strcmp(group, "DEFAULT") == 0 || strcmp(group, "-") == 0;
}

static int is_no_cafile(const char *cafile)
{
    return strcmp(cafile, "none") == 0 || strcmp(cafile, "NONE") == 0 || strcmp(cafile, "-") == 0;
}

static int require_oqsprovider(void)
{
    const char *value = getenv("TLS_REQUIRE_OQSPROVIDER");
    return value == NULL || strcmp(value, "0") != 0;
}

static void print_tcp_info(int fd, const char *prefix)
{
#ifdef __linux__
    struct tcp_info ti;
    socklen_t len = sizeof(ti);
    unsigned long long client_send_cwnd_bytes;

    memset(&ti, 0, sizeof(ti));
    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &len) != 0) {
        printf("%s_tcp_info ok=0\n", prefix);
        return;
    }

    client_send_cwnd_bytes = (unsigned long long)ti.tcpi_snd_cwnd * (unsigned long long)ti.tcpi_snd_mss;
    printf("%s_tcp_info ok=1\n", prefix);
    printf("%s_tcpi_rtt_us %u\n", prefix, ti.tcpi_rtt);
    printf("%s_snd_mss_bytes %u\n", prefix, ti.tcpi_snd_mss);
    printf("%s_snd_cwnd_segments %u\n", prefix, ti.tcpi_snd_cwnd);
    printf("%s_client_send_cwnd_bytes %llu\n", prefix, client_send_cwnd_bytes);
    printf("%s_rcv_space_bytes %u\n", prefix, ti.tcpi_rcv_space);
#else
    (void)fd;
    printf("%s_tcp_info ok=0\n", prefix);
#endif
}

int main(int argc, char **argv)
{
    const char *host;
    const char *port;
    const char *sigalg;
    const char *provider_path;
    const char *cafile;
    const char *group;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    X509 *cert = NULL;
    OSSL_PROVIDER *oqsprov = NULL;
    OSSL_PROVIDER *defprov = NULL;
    int fd = -1;
    int rc = 1;
    double tcp_ms = 0.0;
    double tls_start;
    double tls_end;
    int sig_nid = NID_undef;
    int group_nid = NID_undef;

    if (argc != 7) {
        fprintf(stderr, "usage: %s <host> <port> <sigalg> <provider_path> <cafile|none> <groups|OPENSSL_DEFAULT>\n", argv[0]);
        return 2;
    }

    host = argv[1];
    port = argv[2];
    sigalg = argv[3];
    provider_path = argv[4];
    cafile = argv[5];
    group = argv[6];

    if (!OSSL_PROVIDER_set_default_search_path(NULL, provider_path)) {
        fprintf(stderr, "failed to set provider path\n");
        goto out;
    }
    defprov = OSSL_PROVIDER_load(NULL, "default");
    oqsprov = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if (defprov == NULL || (oqsprov == NULL && require_oqsprovider())) {
        fprintf(stderr, "failed to load providers\n");
        ERR_print_errors_fp(stderr);
        goto out;
    }
    if (oqsprov == NULL)
        ERR_clear_error();

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL)
        goto out;

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_cert_list(ctx, 512 * 1024);

    if (is_no_cafile(cafile)) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        if (!SSL_CTX_load_verify_locations(ctx, cafile, NULL)) {
            fprintf(stderr, "failed to load CA file: %s\n", cafile);
            ERR_print_errors_fp(stderr);
            goto out;
        }
    }

    if (!SSL_CTX_set1_sigalgs_list(ctx, sigalg)) {
        fprintf(stderr, "failed to set sigalgs: %s\n", sigalg);
        ERR_print_errors_fp(stderr);
        goto out;
    }

    if (!is_default_group(group) && !SSL_CTX_set1_groups_list(ctx, group)) {
        fprintf(stderr, "failed to set groups: %s\n", group);
        ERR_print_errors_fp(stderr);
        goto out;
    }

    fd = tcp_connect(host, port, &tcp_ms);
    if (fd < 0) {
        perror("connect");
        goto out;
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL)
        goto out;
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);

    printf("status starting\n");
    printf("tcp_connect_ms %.3f\n", tcp_ms);
    print_tcp_info(fd, "before_tls");

    tls_start = now_ms();
    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "SSL_connect failed\n");
        ERR_print_errors_fp(stderr);
        goto out;
    }
    tls_end = now_ms();

    cert = SSL_get1_peer_certificate(ssl);
    printf("status ok\n");
    printf("tls_version %s\n", SSL_get_version(ssl));
    printf("cipher %s\n", SSL_get_cipher(ssl));
    printf("handshake_ms %.3f\n", tls_end - tls_start);
    printf("peer_cert %s\n", cert != NULL ? "present" : "missing");
    if (SSL_get_peer_signature_type_nid(ssl, &sig_nid) == 1)
        printf("peer_signature %s\n", OBJ_nid2sn(sig_nid));
    group_nid = SSL_get_negotiated_group(ssl);
    if (group_nid != NID_undef) {
        const char *group_name = SSL_group_to_name(ssl, group_nid);
        if (group_name == NULL)
            group_name = OBJ_nid2sn(group_nid);
        if (group_name != NULL)
            printf("negotiated_group %s\n", group_name);
        else
            printf("negotiated_group_nid %d\n", group_nid);
    }
    print_tcp_info(fd, "after_tls");

    rc = 0;

out:
    X509_free(cert);
    SSL_free(ssl);
    if (fd >= 0)
        close(fd);
    SSL_CTX_free(ctx);
    if (oqsprov != NULL)
        OSSL_PROVIDER_unload(oqsprov);
    if (defprov != NULL)
        OSSL_PROVIDER_unload(defprov);
    return rc;
}
