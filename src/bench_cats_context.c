#define _GNU_SOURCE
#include "cats_context.h"
#include <arpa/inet.h>
#include <assert.h>
#include <dlfcn.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct benchmark {
    struct cats_context *ctx;
    SSL_CTX *client;
    int port, iterations, warmup, profiles;
    uint64_t acquisition_ns;
    struct cats_values values;
};

static void fail(const char *message)
{
    fprintf(stderr, "%s\n", message); ERR_print_errors_fp(stderr); exit(1);
}

static int acquire(SSL *ssl, void *arg)
{
    struct benchmark *b = arg;
    double signs[CATS_MAX_ALGORITHMS];
    uint64_t start = cats_now_ns();
    int ok = cats_collect(b->ctx, SSL_get_fd(ssl), time(NULL), &b->values,
                          signs, b->profiles);
    b->acquisition_ns = cats_now_ns() - start;
    return ok == 0 && b->values.tcp.rtt_valid && b->values.tcp.window_valid;
}

static void *client_worker(void *arg)
{
    struct benchmark *b = arg;
    for (int i = 0; i < b->iterations + b->warmup; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr = {.sin_family=AF_INET, .sin_port=htons(b->port),
                                   .sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr))) fail("client connect");
        SSL *s=SSL_new(b->client); SSL_set_fd(s, fd);
        if (SSL_connect(s) != 1) fail("SSL_connect");
        /* Test-only application response, not traffic emitted by the collector. */
        char data[4096]; size_t total=0;
        while (total < 65536) {
            int n=SSL_read(s, data, sizeof(data));
            if (n<=0) fail("SSL_read application response");
            total += n;
        }
        if (SSL_write(s, "x", 1) != 1) fail("client application confirmation");
        /* Complete TLS shutdown so closing sockets does not discard traffic. */
        int rc=SSL_shutdown(s); if (rc == 0) SSL_shutdown(s);
        SSL_free(s); close(fd);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc != 4) { fprintf(stderr, "usage: %s ECDSA|ML-DSA-44 iterations profile-count\n", argv[0]); return 2; }
    int iterations=atoi(argv[2]), profiles=atoi(argv[3]);
    if (iterations<1 || profiles<1 || profiles>CATS_MAX_ALGORITHMS) return 2;
    signal(SIGPIPE, SIG_IGN);
    void (*begin)(void) = dlsym(RTLD_DEFAULT, "cats_sign_timer_begin");
    uint64_t (*end)(uint64_t *) = dlsym(RTLD_DEFAULT, "cats_sign_timer_end");
    if (!begin || !end) fail("Load libcats_sign_timer.so with LD_PRELOAD");
    begin(); uint64_t unused; end(&unused); /* resolve symbols outside measurements */
    EVP_PKEY *key = !strcmp(argv[1], "ECDSA") ? EVP_PKEY_Q_keygen(NULL,NULL,"EC","prime256v1")
                                             : EVP_PKEY_Q_keygen(NULL,NULL,argv[1]);
    if (!key) fail("keygen");
    X509 *cert=X509_new(); X509_set_version(cert,2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert),1);
    X509_gmtime_adj(X509_getm_notBefore(cert),-60);
    X509_gmtime_adj(X509_getm_notAfter(cert),3600);
    X509_set_pubkey(cert,key);
    X509_NAME *name=X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name,"CN",MBSTRING_ASC,(const unsigned char *)"localhost",-1,-1,0);
    X509_set_issuer_name(cert,name);
    if (!X509_sign(cert,key,!strcmp(argv[1],"ECDSA") ? EVP_sha256() : NULL)) fail("X509_sign");
    SSL_CTX *server=SSL_CTX_new(TLS_server_method()), *client=SSL_CTX_new(TLS_client_method());
    if (!server || !client || !SSL_CTX_use_certificate(server,cert) || !SSL_CTX_use_PrivateKey(server,key)) fail("server credential");
    SSL_CTX_set_min_proto_version(server,TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(server,TLS1_3_VERSION);
    SSL_CTX_set_min_proto_version(client,TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(client,TLS1_3_VERSION);
    SSL_CTX_set_num_tickets(server,0);
    SSL_CTX_set_session_cache_mode(client,SSL_SESS_CACHE_OFF);
    if (!SSL_CTX_set1_groups_list(server,"X25519") || !SSL_CTX_set1_groups_list(client,"X25519")) fail("X25519");
    X509_STORE_add_cert(SSL_CTX_get_cert_store(client),cert);
    SSL_CTX_set_verify(client,SSL_VERIFY_PEER,NULL);
    struct cats_config config=cats_default_config();
    struct cats_context *ctx=cats_context_new(config);
    if (!ctx) fail("context init");
    for (int i=0;i<profiles;i++) cats_sign_init(ctx,i,1.0);
    if (cats_sampler_start(ctx)) fail("sampler");
    int listen_fd=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in addr={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    socklen_t len=sizeof(addr);
    if (bind(listen_fd,(struct sockaddr *)&addr,len) || listen(listen_fd,16) ||
        getsockname(listen_fd,(struct sockaddr *)&addr,&len)) fail("listener");
    struct benchmark b={.ctx=ctx,.client=client,.port=ntohs(addr.sin_port),
                        .iterations=iterations,.warmup=100,.profiles=profiles};
    SSL_CTX_set_cert_cb(server,acquire,&b);
    printf("{\"kind\":\"metadata\",\"algorithm\":\"%s\",\"openssl\":\"%s\",\"iterations\":%d,\"warmup\":100,\"profiles\":%d,\"context_bytes\":%zu,\"sample_interval_ms\":%u}\n",
           argv[1],OpenSSL_version(OPENSSL_VERSION),iterations,profiles,cats_context_size(),config.sample_interval_ms);
    pthread_t worker;
    if (pthread_create(&worker,NULL,client_worker,&b)) fail("client thread");
    char payload[65536]; memset(payload,'a',sizeof(payload));
    for (int i=0;i<iterations+100;i++) {
        int fd=accept(listen_fd,NULL,NULL); if (fd<0) fail("accept");
        uint64_t start=cats_now_ns();
        if (cats_track(ctx,fd)) fail("track");
        uint64_t track_ns=cats_now_ns()-start;
        SSL *s=SSL_new(server); SSL_set_fd(s,fd);
        begin();
        int ok=SSL_accept(s);
        uint64_t count=0, sign_ns=end(&count);
        if (ok!=1 || count!=1) fail("TLS handshake / expected one real signature");
        start=cats_now_ns();
        if (cats_sign_update(ctx,0,sign_ns/1000000.0)) fail("sign update");
        uint64_t update_ns=cats_now_ns()-start;
        if (i==100) {
            /* Steady-state syscall/query benchmark. No SSL/network writes. */
            struct cats_tcp before,after; cats_tcp_read(fd,&before);
            for (int j=0;j<10000;j++) {
                start=cats_now_ns(); struct cats_values v; double signs[CATS_MAX_ALGORITHMS];
                if (cats_collect(ctx,fd,time(NULL),&v,signs,profiles)) fail("micro collect");
                uint64_t elapsed=cats_now_ns()-start;
                printf("{\"kind\":\"micro\",\"ns\":%llu}\n",(unsigned long long)elapsed);
            }
            cats_tcp_read(fd,&after);
            if (after.data_segs_out != before.data_segs_out) fail("collector sent TCP data");
            printf("{\"kind\":\"no_probe_check\",\"data_segments_added\":%u}\n", after.data_segs_out-before.data_segs_out);
        }
        if (SSL_write(s,payload,sizeof(payload)) != sizeof(payload)) fail("server application response");
        char done; if (SSL_read(s,&done,1) != 1) fail("server application confirmation");
        start=cats_now_ns(); cats_untrack(ctx,fd);
        uint64_t untrack_ns=cats_now_ns()-start;
        if (i>=100) printf("{\"kind\":\"handshake\",\"index\":%d,\"acquisition_ns\":%llu,\"track_ns\":%llu,\"untrack_ns\":%llu,\"ewma_ns\":%llu,\"sign_ns\":%llu,\"sign_calls\":%llu,\"rtt_ms\":%.6f,\"window_bytes\":%llu,\"bw_history\":%d,\"loss_history\":%d,\"loss_sent\":%llu,\"loss_retrans\":%llu,\"bw_mbps\":%.6f}\n",
            i-100,(unsigned long long)b.acquisition_ns,(unsigned long long)track_ns,
            (unsigned long long)untrack_ns,(unsigned long long)update_ns,
            (unsigned long long)sign_ns,(unsigned long long)count,b.values.tcp.rtt_ms,
            (unsigned long long)b.values.tcp.window_bytes,b.values.bw_from_history,
            b.values.loss_from_history,(unsigned long long)b.values.loss_sent,
            (unsigned long long)b.values.loss_retrans,b.values.bw_mbps);
        int rc=SSL_shutdown(s); if (rc==0) SSL_shutdown(s);
        SSL_free(s); close(fd);
    }
    pthread_join(worker,NULL); close(listen_fd);
    cats_sampler_stop(ctx);
    struct cats_sampler_stats stats=cats_sampler_statistics(ctx);
    printf("{\"kind\":\"sampler\",\"batches\":%llu,\"socket_reads\":%llu,\"elapsed_ns\":%llu,\"max_batch_ns\":%llu}\n",
           (unsigned long long)stats.batches,(unsigned long long)stats.socket_reads,
           (unsigned long long)stats.elapsed_ns,(unsigned long long)stats.max_batch_ns);
    for (int i=0;i<10000;i++) {
        uint64_t start=cats_now_ns(), stop=cats_now_ns();
        printf("{\"kind\":\"clock_pair\",\"ns\":%llu}\n",(unsigned long long)(stop-start));
    }
    cats_context_free(ctx); SSL_CTX_free(server); SSL_CTX_free(client);
    X509_free(cert); EVP_PKEY_free(key);
    return 0;
}
