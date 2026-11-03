#define _GNU_SOURCE
#include "cats_context.h"
#include <arpa/inet.h>
#include <assert.h>
#include <dlfcn.h>
#include <netinet/tcp.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static _Thread_local uint64_t starts[2], spans[2];
static _Thread_local unsigned marks;
/* Exported by -rdynamic. Called by the timing-only OpenSSL build on the
 * server thread; no printing or allocation in the hooks. */
void cats_selection_mark(int stage)
{
    uint64_t ns=cats_now_ns();
    if (stage < 0 || stage > 3) abort();
    if (!(stage & 1)) starts[stage/2]=ns;
    else spans[stage/2]=ns-starts[stage/2];
    marks++;
}

struct bench {
    struct cats_context *ctx;
    SSL_CTX *client;
    X509 *cert[2]; EVP_PKEY *key[2];
    unsigned code[2];
    int port, count, cats, sidecar, selected, arm;
    uint64_t acquire_ns, policy_ns, model_ns, install_ns;
    double flight[2];
    struct cats_values values;
};

static void fail(const char *s) { fprintf(stderr,"FAIL: %s\n",s); ERR_print_errors_fp(stderr); exit(1); }
static int candidate_index(const EVP_PKEY *key)
{
    if (EVP_PKEY_is_a(key,"ML-DSA-44")) return 0;
    if (EVP_PKEY_is_a(key,"falcon512")) return 1;
    return -1;
}
static int cap_cb(const OSSL_PARAM params[], void *arg)
{
    struct bench *b=arg; const char *name=NULL; unsigned code=0;
    const OSSL_PARAM *n=OSSL_PARAM_locate_const(params,OSSL_CAPABILITY_TLS_SIGALG_NAME);
    const OSSL_PARAM *v=OSSL_PARAM_locate_const(params,OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT);
    if (n && v && OSSL_PARAM_get_utf8_string_ptr(n,&name) && OSSL_PARAM_get_uint(v,&code) &&
        name && !strcmp(name,"falcon512")) b->code[1]=code;
    return 1;
}
static int acquire_and_select(SSL *ssl, void *arg)
{
    struct bench *b=arg; double signs[2];
    uint64_t start=cats_now_ns();
    if (cats_collect(b->ctx,SSL_get_fd(ssl),time(NULL),&b->values,signs,2) ||
        !b->values.tcp.rtt_valid || !b->values.tcp.window_valid || !b->values.tcp.window_bytes)
        fail("collect");
    b->acquire_ns=cats_now_ns()-start;
    start=cats_now_ns();
    /* Same two preapproved credentials in both modes. The OpenSSL shared-list
     * stage already applies its TLS security policy; repeat compatibility here
     * to construct the model's actual candidate mask. */
    int allowed=0, count=SSL_get_shared_sigalgs(ssl,0,NULL,NULL,NULL,NULL,NULL);
    for (int i=0;i<count;i++) {
        unsigned char sig=0, hash=0;
        if (!SSL_get_shared_sigalgs(ssl,i,NULL,NULL,NULL,&sig,&hash)) fail("shared sigalg");
        unsigned code=((unsigned)hash<<8)|sig;
        for (int j=0;j<2;j++) if (code==b->code[j]) allowed |= 1<<j;
    }
    if (allowed!=3) fail("both candidates must be compatible");
    char request[1024], response[128];
    int len=snprintf(request,sizeof(request),"%.17g %.17g %.17g %llu %.17g %.17g %.17g %.17g %d\n",
        b->values.tcp.rtt_ms,b->values.bw_mbps,b->values.loss_probability,
        (unsigned long long)b->values.tcp.window_bytes,signs[0],signs[1],b->flight[0],b->flight[1],allowed);
    for (int sent=0;sent<len;) {
        ssize_t n=write(b->sidecar,request+sent,(size_t)(len-sent));
        if (n<=0) fail("sidecar send");
        sent+=(int)n;
    }
    size_t used=0;
    while (used+1<sizeof(response)) {
        ssize_t n=read(b->sidecar,response+used,sizeof(response)-used-1);
        if (n<=0) fail("sidecar receive");
        used+=(size_t)n;
        if (response[used-1]=='\n') break;
    }
    response[used]=0; unsigned long long model_ns;
    if (sscanf(response,"%d %d %llu",&b->selected,&b->arm,&model_ns)!=3 ||
        b->selected<0 || b->selected>1) fail("sidecar result");
    b->model_ns=model_ns; b->policy_ns=cats_now_ns()-start;
    start=cats_now_ns();
    SSL_certs_clear(ssl);
    if (!SSL_use_cert_and_key(ssl,b->cert[b->selected],b->key[b->selected],NULL,1)) fail("install selected credential");
    b->install_ns=cats_now_ns()-start;
    return 1;
}
static void no_delay(int fd) { int one=1; if (setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one))) fail("TCP_NODELAY"); }
static void *client_worker(void *arg)
{
    struct bench *b=arg;
    for (int i=0;i<b->count+100;i++) {
        int fd=socket(AF_INET,SOCK_STREAM,0); no_delay(fd);
        struct sockaddr_in addr={.sin_family=AF_INET,.sin_port=htons(b->port),.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
        if (connect(fd,(struct sockaddr *)&addr,sizeof(addr))) fail("connect");
        SSL *s=SSL_new(b->client); SSL_set_fd(s,fd);
        if (SSL_connect(s)!=1 || SSL_get_verify_result(s)!=X509_V_OK) fail("authenticated TLS");
        int rc=SSL_shutdown(s); if (!rc) SSL_shutdown(s);
        SSL_free(s); close(fd);
    }
    return NULL;
}
int main(int argc,char **argv)
{
    if (argc!=5) { fprintf(stderr,"usage: %s stock|cats mldsa-first|falcon-first iterations sidecar-socket\n",argv[0]); return 2; }
    struct bench b={.cats=!strcmp(argv[1],"cats"),.count=atoi(argv[3]),.sidecar=-1,.code={0x0904,0}};
    if (b.count<1 || (strcmp(argv[1],"stock") && strcmp(argv[1],"cats"))) return 2;
    int falcon_first=!strcmp(argv[2],"falcon-first");
    signal(SIGPIPE,SIG_IGN);
    void (*begin)(void)=dlsym(RTLD_DEFAULT,"cats_sign_timer_begin");
    uint64_t (*end)(uint64_t *)=dlsym(RTLD_DEFAULT,"cats_sign_timer_end");
    if (!begin || !end) fail("sign hook missing");
    begin(); uint64_t unused; end(&unused);
    OSSL_PROVIDER *def=OSSL_PROVIDER_load(NULL,"default"), *oqs=OSSL_PROVIDER_load(NULL,"oqsprovider");
    if (!def || !oqs) fail("providers");
    OSSL_PROVIDER_get_capabilities(oqs,"TLS-SIGALG",cap_cb,&b);
    if (!b.code[1]) fail("Falcon code point");
    SSL_CTX *server=SSL_CTX_new(TLS_server_method()); b.client=SSL_CTX_new(TLS_client_method());
    SSL_CTX *contexts[]={server,b.client};
    for (int j=0;j<2;j++) {
        SSL_CTX_set_min_proto_version(contexts[j],TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(contexts[j],TLS1_3_VERSION);
        SSL_CTX_set_session_cache_mode(contexts[j],SSL_SESS_CACHE_OFF);
        if (!SSL_CTX_set1_groups_list(contexts[j],"X25519")) fail("groups");
    }
    SSL_CTX_set_options(server,SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_num_tickets(server,0);
    if (!SSL_CTX_set1_sigalgs_list(server,falcon_first ? "falcon512:mldsa44" : "mldsa44:falcon512") ||
        !SSL_CTX_set1_sigalgs_list(b.client,"mldsa44:falcon512")) fail("sigalgs");
    SSL_CTX_set_verify(b.client,SSL_VERIFY_PEER,NULL);
    const char *names[]={"mldsa44","falcon512"};
    const char *directory=getenv("SELECT_CERT_DIR");
    if (!directory) fail("SELECT_CERT_DIR missing");
    for (int j=0;j<2;j++) {
        char path[1024];
        snprintf(path,sizeof(path),"%s/%s.key",directory,names[j]);
        FILE *f=fopen(path,"r"); if (!f) fail("open key");
        b.key[j]=PEM_read_PrivateKey(f,NULL,NULL,NULL); fclose(f);
        snprintf(path,sizeof(path),"%s/%s.crt",directory,names[j]);
        f=fopen(path,"r"); if (!f) fail("open cert");
        X509 *cert=b.cert[j]=PEM_read_X509(f,NULL,NULL,NULL); fclose(f);
        if (!b.key[j] || !cert || candidate_index(b.key[j])!=j) fail("load credential");
        if (!X509_STORE_add_cert(SSL_CTX_get_cert_store(b.client),cert) ||
            !SSL_CTX_use_cert_and_key(server,cert,b.key[j],NULL,1)) fail("credential setup");
        /* One-certificate test flight estimate: DER + signature upper bound +
         * fixed 200-byte framing estimate. Identical profiles across modes.
         * This benchmark establishes runtime, not handshake prediction accuracy. */
        b.flight[j]=i2d_X509(cert,NULL)+EVP_PKEY_get_size(b.key[j])+200;
    }
    if (b.cats) {
        struct cats_config cfg=cats_default_config(); b.ctx=cats_context_new(cfg);
        if (!b.ctx || cats_sign_init(b.ctx,0,.71714122) || cats_sign_init(b.ctx,1,1.00602308) || cats_sampler_start(b.ctx)) fail("context init");
        struct sockaddr_un address={.sun_family=AF_UNIX};
        if (strlen(argv[4])>=sizeof(address.sun_path)) fail("sidecar path too long");
        strcpy(address.sun_path,argv[4]); b.sidecar=socket(AF_UNIX,SOCK_STREAM,0);
        if (connect(b.sidecar,(struct sockaddr *)&address,sizeof(address))) fail("sidecar connect");
        SSL_CTX_set_cert_cb(server,acquire_and_select,&b);
    }
    int listener=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in addr={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    socklen_t len=sizeof(addr);
    if (bind(listener,(struct sockaddr *)&addr,len) || listen(listener,16) || getsockname(listener,(struct sockaddr *)&addr,&len)) fail("listen");
    b.port=ntohs(addr.sin_port);
    printf("{\"kind\":\"metadata\",\"mode\":\"%s\",\"order\":\"%s\",\"iterations\":%d,\"warmup\":100,\"candidates\":2,\"openssl\":\"%s\",\"flight_bytes\":[%.0f,%.0f]}\n",argv[1],argv[2],b.count,OpenSSL_version(OPENSSL_VERSION),b.flight[0],b.flight[1]);
    pthread_t thread; if (pthread_create(&thread,NULL,client_worker,&b)) fail("pthread");
    for (int i=0;i<b.count+100;i++) {
        int fd=accept(listener,NULL,NULL); if (fd<0) fail("accept"); no_delay(fd);
        if (b.cats && cats_track(b.ctx,fd)) fail("track");
        SSL *s=SSL_new(server); SSL_set_fd(s,fd);
        spans[0]=spans[1]=marks=0; begin();
        if (SSL_accept(s)!=1) fail("SSL_accept");
        uint64_t sign_count=0, sign_ns=end(&sign_count);
        if (marks!=4 || !spans[0] || !spans[1] || sign_count!=1) fail("timing/sign hooks");
        int chosen=candidate_index(X509_get0_pubkey(SSL_get_certificate(s)));
        if (chosen<0 || chosen!=(b.cats ? b.selected : falcon_first)) fail("selected credential mismatch");
        if (b.cats && cats_sign_update(b.ctx,(size_t)chosen,sign_ns/1e6)) fail("EWMA");
        if (i>=100) printf("{\"kind\":\"selection\",\"index\":%d,\"shared_ns\":%llu,\"decision_ns\":%llu,\"total_ns\":%llu,\"acquisition_ns\":%llu,\"policy_ipc_ns\":%llu,\"model_ns\":%llu,\"install_ns\":%llu,\"selected\":%d,\"arm\":%d,\"bw_history\":%d,\"loss_history\":%d}\n",
            i-100,(unsigned long long)spans[0],(unsigned long long)spans[1],(unsigned long long)(spans[0]+spans[1]),
            (unsigned long long)b.acquire_ns,(unsigned long long)b.policy_ns,(unsigned long long)b.model_ns,
            (unsigned long long)b.install_ns,chosen,b.cats ? b.arm : -1,b.values.bw_from_history,b.values.loss_from_history);
        if (b.cats) cats_untrack(b.ctx,fd);
        int rc=SSL_shutdown(s); if (!rc) SSL_shutdown(s); SSL_free(s); close(fd);
    }
    pthread_join(thread,NULL); close(listener);
    if (b.cats) { close(b.sidecar); cats_context_free(b.ctx); }
    for (int i=0;i<10000;i++) { uint64_t a=cats_now_ns(), z=cats_now_ns(); printf("{\"kind\":\"clock\",\"ns\":%llu}\n",(unsigned long long)(z-a)); }
    SSL_CTX_free(server); SSL_CTX_free(b.client);
    for (int j=0;j<2;j++) { X509_free(b.cert[j]); EVP_PKEY_free(b.key[j]); }
    OSSL_PROVIDER_unload(oqs); OSSL_PROVIDER_unload(def);
    return 0;
}
