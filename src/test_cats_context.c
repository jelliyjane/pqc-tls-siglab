#define _POSIX_C_SOURCE 200809L
#include "cats_context.h"
#include <assert.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void *cycle(void *arg)
{
    struct cats_context *ctx = arg;
    for (int i=0; i<20; i++) { cats_sampler_start(ctx); cats_sampler_stop(ctx); }
    return NULL;
}

int main(void)
{
    struct cats_config cfg = cats_default_config();
    struct cats_context *c = cats_context_new(cfg);
    assert(c);
    struct cats_values v = {0};
    time_t wall = 1700000000;
    uint64_t ns = 100000000000ULL;
    cats_cached(c, ns, wall, &v);
    assert(!v.bw_from_history && !v.loss_from_history);
    assert(v.bw_mbps == 1000 && v.loss_probability == 0);
    struct cats_cursor a = {0}, b = {0};
    struct cats_tcp s = {.counters_valid=1, .rate_valid=1,
        .data_segs_out=10, .retrans=1, .bytes_acked=100,
        .delivery_bytes_per_sec=12500000};
    cats_observe(c, &a, &s, ns, wall); /* baseline, not historical traffic */
    s.data_segs_out += 100; s.retrans += 5; s.bytes_acked += 1000;
    cats_observe(c, &a, &s, ns, wall);
    cats_observe(c, &a, &s, ns, wall); /* unchanged sample must not double-count */
    cats_cached(c, ns, wall, &v);
    assert(v.loss_sent == 100 && v.loss_retrans == 5);
    assert(fabs(v.loss_probability - .05) < 1e-12 && v.bw_mbps == 100);
    s.data_segs_out += 50; s.bytes_acked += 1000;
    s.app_limited=1; s.delivery_bytes_per_sec=125;
    cats_observe(c, &a, &s, ns, wall);
    cats_cached(c, ns, wall, &v);
    assert(v.loss_sent == 150 && v.bw_mbps == 100);
    s.app_limited=0; s.delivery_bytes_per_sec=25000000;
    cats_observe(c, &a, &s, ns, wall); /* no fresh ACK, no BW update */
    cats_cached(c, ns, wall, &v); assert(v.bw_mbps == 100);
    s.bytes_acked++;
    cats_observe(c, &a, &s, ns, wall);
    cats_cached(c, ns, wall, &v); assert(v.bw_mbps == 120);
    struct cats_tcp t = {.counters_valid=1, .data_segs_out=UINT32_MAX-2,
                         .retrans=UINT32_MAX};
    cats_observe(c, &b, &t, ns, wall);
    t.data_segs_out=2; t.retrans=1;
    cats_observe(c, &b, &t, ns, wall); /* unsigned wrap */
    cats_cached(c, ns, wall, &v);
    assert(v.loss_sent == 155 && v.loss_retrans == 7);
    cats_cached(c, ns + 600000000000ULL, wall, &v);
    assert(!v.loss_from_history);
    s.data_segs_out += 100;
    cats_observe(c, &a, &s, ns + 600000000000ULL, wall);
    cats_cached(c, ns + 600000000000ULL, wall, &v);
    assert(!v.loss_from_history); /* old traffic cannot revive after a long gap */
    cats_cached(c, ns, wall + 3600, &v); assert(!v.bw_from_history);
    cats_cached(c, ns, wall + 21 * 86400, &v); assert(!v.bw_from_history);
    cats_cached(c, ns, wall - 7 * 86400, &v); assert(!v.bw_from_history);
    assert(!cats_sign_init(c, 0, 10));
    assert(!cats_sign_update(c, 0, 20));
    assert(cats_sign_update(c, 0, NAN) == -1);
    assert(cats_sign_update(c, CATS_MAX_ALGORITHMS, 1) == -1);
    double signs[2];
    assert(cats_collect(c, -1, wall, &v, signs, 2) == -1);
    assert(!v.tcp.window_valid && !v.tcp.rtt_valid);
    assert(signs[0] == 12 && isnan(signs[1]));
    assert(cats_collect(c, -1, wall, &v, NULL, 1) == -1);
    char path[] = "/tmp/cats-bw-test-XXXXXX";
    int fd=mkstemp(path); assert(fd>=0); close(fd);
    assert(!cats_bw_save(c, path));
    struct cats_context *d=cats_context_new(cfg); assert(d);
    assert(!cats_bw_load(d, path));
    cats_cached(d, ns, wall, &v); assert(v.bw_mbps == 120);
    unlink(path);
    assert(cats_track(c, -1) == -1);
    assert(!cats_sampler_start(c));
    pthread_t threads[4];
    for (int i=0;i<4;i++) assert(!pthread_create(&threads[i],NULL,cycle,c));
    for (int i=0;i<4;i++) pthread_join(threads[i],NULL);
    assert(!cats_sampler_start(c));
    assert(cats_sampler_start(c) == -1);
    cats_sampler_stop(c);
    assert(!cats_sampler_start(c));
    cats_context_free(c); cats_context_free(d);
    cfg.ewma_alpha = NAN; assert(!cats_context_new(cfg));
    puts("PASS: aggregation, duplicate/ACK filtering, expiry, rollover, EWMA, persistence, lifecycle, missing telemetry");
    return 0;
}
