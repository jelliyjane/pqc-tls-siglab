#define _POSIX_C_SOURCE 200809L
#include "cats_context.h"
#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct query { struct cats_context *ctx; int fd; };
static void *query_worker(void *arg)
{
    struct query *q=arg;
    for (int i=0;i<10000;i++) {
        struct cats_values v; double signs[150];
        assert(!cats_collect(q->ctx,q->fd,time(NULL),&v,signs,150));
        assert(v.tcp.window_valid && v.tcp.rtt_valid);
        assert(v.tcp.window_bytes <= v.tcp.cwnd_bytes);
        assert(v.tcp.window_bytes <= v.tcp.rwnd_bytes);
        assert(signs[149] == 1.0);
    }
    return NULL;
}

int main(void)
{
    struct cats_config cfg=cats_default_config(); cfg.sample_interval_ms=10;
    struct cats_context *ctx=cats_context_new(cfg); assert(ctx);
    for (int i=0;i<150;i++) assert(!cats_sign_init(ctx,i,1));
    int listener=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in a={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    socklen_t n=sizeof(a);
    assert(!bind(listener,(struct sockaddr *)&a,n)); assert(!listen(listener,128));
    assert(!getsockname(listener,(struct sockaddr *)&a,&n));
    int clients[128],servers[128];
    for (int i=0;i<128;i++) {
        clients[i]=socket(AF_INET,SOCK_STREAM,0);
        assert(!connect(clients[i],(struct sockaddr *)&a,n));
        servers[i]=accept(listener,NULL,NULL); assert(servers[i]>=0);
        assert(!cats_track(ctx,servers[i]));
        assert(cats_track(ctx,servers[i]) == -1);
    }
    assert(!cats_sampler_start(ctx));
    char payload[4096]; memset(payload,'x',sizeof(payload));
    for (int i=0;i<128;i++) {
        assert(send(servers[i],payload,sizeof(payload),0)==sizeof(payload));
        assert(recv(clients[i],payload,sizeof(payload),MSG_WAITALL)==sizeof(payload));
    }
    pthread_t threads[4]; struct query queries[4];
    for (int i=0;i<4;i++) {
        queries[i]=(struct query){ctx,servers[i]};
        assert(!pthread_create(&threads[i],NULL,query_worker,&queries[i]));
    }
    for (int i=0;i<4;i++) pthread_join(threads[i],NULL);
    struct timespec pause={0,30000000}; nanosleep(&pause,NULL);
    struct cats_values v={0}; cats_cached(ctx,cats_now_ns(),time(NULL),&v);
    assert(v.loss_from_history && v.loss_sent>=128);
    struct cats_sampler_stats stats=cats_sampler_statistics(ctx);
    assert(stats.batches>0 && stats.socket_reads>=128);
    for (int i=0;i<128;i++) {
        cats_untrack(ctx,servers[i]); close(servers[i]); close(clients[i]);
    }
    close(listener); cats_context_free(ctx);
    puts("PASS: 128 real TCP sockets, periodic sampler, 4 concurrent readers / 40000 queries, unregister-before-close");
    return 0;
}
