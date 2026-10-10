#define _POSIX_C_SOURCE 200809L
#include "cats_context.h"
#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/tcp.h>
#endif

struct loss_bucket { uint64_t epoch, sent, retrans; int valid; };
struct bw_slot { double mbps; time_t updated; uint64_t samples; };
struct tracked { int fd; struct cats_cursor cursor; };
struct cats_context {
    struct cats_config config;
    pthread_mutex_t lock;
    pthread_mutex_t registry, lifecycle;
    pthread_cond_t wake;
    pthread_t worker;
    int running, stopping;
    struct loss_bucket loss[CATS_LOSS_BUCKETS];
    struct bw_slot bw[CATS_BW_SLOTS];
    double sign_ms[CATS_MAX_ALGORITHMS];
    unsigned char sign_valid[CATS_MAX_ALGORITHMS];
    struct tracked active[CATS_MAX_CONNECTIONS];
    size_t active_count;
    struct cats_sampler_stats sampler_stats;
};

uint64_t cats_now_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ULL + t.tv_nsec;
}

int cats_tcp_read(int fd, struct cats_tcp *out)
{
    memset(out, 0, sizeof(*out));
#ifdef __linux__
    struct tcp_info t;
    socklen_t n = sizeof(t);
    memset(&t, 0, sizeof(t));
    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &t, &n) != 0)
        return -1;
#define HAS(field) (n >= offsetof(struct tcp_info, field) + sizeof(t.field))
    if (HAS(tcpi_rtt) && t.tcpi_rtt) {
        out->rtt_ms = t.tcpi_rtt / 1000.0;
        out->rtt_valid = 1;
    }
    if (HAS(tcpi_snd_wnd) && t.tcpi_snd_cwnd && t.tcpi_snd_mss) {
        out->cwnd_bytes = (uint64_t)t.tcpi_snd_cwnd * t.tcpi_snd_mss;
        out->rwnd_bytes = t.tcpi_snd_wnd; /* Already window-scaled. */
        out->window_bytes = out->cwnd_bytes < out->rwnd_bytes
                         ? out->cwnd_bytes : out->rwnd_bytes;
        out->window_valid = 1;
    }
    if (HAS(tcpi_data_segs_out) && HAS(tcpi_bytes_acked)) {
        out->data_segs_out = t.tcpi_data_segs_out;
        out->retrans = t.tcpi_total_retrans;
        out->bytes_acked = t.tcpi_bytes_acked;
        out->counters_valid = 1;
    }
    if (HAS(tcpi_delivery_rate)) {
        out->delivery_bytes_per_sec = t.tcpi_delivery_rate;
        out->app_limited = t.tcpi_delivery_rate_app_limited;
        out->rate_valid = 1;
    }
#undef HAS
    return 0;
#else
    (void)fd;
    errno = ENOTSUP;
    return -1;
#endif
}

struct cats_config cats_default_config(void)
{
    /* Engineering defaults, not experimentally optimized constants. */
    return (struct cats_config){1000.0, 0.0, 0.2, 10, 1000, 14 * 86400};
}

struct cats_context *cats_context_new(struct cats_config c)
{
    if (!isfinite(c.default_bw_mbps) || c.default_bw_mbps <= 0 ||
        !isfinite(c.default_loss) || c.default_loss < 0 || c.default_loss > 1 ||
        !isfinite(c.ewma_alpha) || c.ewma_alpha <= 0 || c.ewma_alpha > 1 ||
        !c.loss_bucket_seconds || !c.sample_interval_ms || !c.bw_max_age_seconds) {
        errno = EINVAL;
        return NULL;
    }
    struct cats_context *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;
    ctx->config = c;
    if (pthread_mutex_init(&ctx->lock, NULL)) { free(ctx); return NULL; }
    if (pthread_mutex_init(&ctx->registry, NULL)) {
        pthread_mutex_destroy(&ctx->lock); free(ctx); return NULL;
    }
    if (pthread_mutex_init(&ctx->lifecycle, NULL)) {
        pthread_mutex_destroy(&ctx->registry); pthread_mutex_destroy(&ctx->lock); free(ctx); return NULL;
    }
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    int error = pthread_cond_init(&ctx->wake, &attr);
    pthread_condattr_destroy(&attr);
    if (error) {
        pthread_mutex_destroy(&ctx->lifecycle); pthread_mutex_destroy(&ctx->registry);
        pthread_mutex_destroy(&ctx->lock); free(ctx); return NULL;
    }
    return ctx;
}

static int slot_index(time_t wall)
{
    struct tm t;
    if (!gmtime_r(&wall, &t)) return -1;
    return t.tm_wday * 24 + t.tm_hour;
}

static void observe_locked(struct cats_context *ctx, struct cats_cursor *c,
                           const struct cats_tcp *s, uint64_t ns, time_t wall)
{
    if (!s->counters_valid) { c->initialized = 0; return; }
    uint64_t retention_ns = (uint64_t)ctx->config.loss_bucket_seconds * CATS_LOSS_BUCKETS * 1000000000ULL;
    if (c->initialized && ns >= c->last_ns && ns - c->last_ns < retention_ns) {
        /* TCP counters are unsigned and may wrap. Registration after accept
         * excludes SYN retransmissions; counters must belong to the same fd lifetime. */
        uint32_t sent = s->data_segs_out - c->previous.data_segs_out;
        uint32_t retrans = s->retrans - c->previous.retrans;
        uint64_t epoch = ns / 1000000000ULL / ctx->config.loss_bucket_seconds;
        struct loss_bucket *b = &ctx->loss[epoch % CATS_LOSS_BUCKETS];
        if (!b->valid || b->epoch != epoch)
            *b = (struct loss_bucket){.epoch = epoch, .valid = 1};
        b->sent += sent;
        b->retrans += retrans;
        int slot = slot_index(wall);
        if (slot >= 0 && s->bytes_acked > c->previous.bytes_acked &&
            s->rate_valid && !s->app_limited && s->delivery_bytes_per_sec) {
            struct bw_slot *bw = &ctx->bw[slot];
            double sample = s->delivery_bytes_per_sec * 8.0 / 1000000.0;
            if (!bw->samples || wall < bw->updated ||
                difftime(wall, bw->updated) > ctx->config.bw_max_age_seconds)
                bw->mbps = sample;
            else
                bw->mbps += ctx->config.ewma_alpha * (sample - bw->mbps);
            bw->updated = wall;
            bw->samples++;
        }
    }
    c->previous = *s;
    c->last_ns = ns;
    c->initialized = 1;
}

void cats_observe(struct cats_context *ctx, struct cats_cursor *c,
                  const struct cats_tcp *s, uint64_t ns, time_t wall)
{
    pthread_mutex_lock(&ctx->lock);
    observe_locked(ctx, c, s, ns, wall);
    pthread_mutex_unlock(&ctx->lock);
}

static void cached_locked(struct cats_context *ctx, uint64_t ns, time_t wall,
                          struct cats_values *out)
{
    out->bw_mbps = ctx->config.default_bw_mbps;
    out->loss_probability = ctx->config.default_loss;
    out->bw_from_history = out->loss_from_history = 0;
    out->loss_sent = out->loss_retrans = 0;
    uint64_t epoch = ns / 1000000000ULL / ctx->config.loss_bucket_seconds;
    for (size_t i = 0; i < CATS_LOSS_BUCKETS; i++) {
        struct loss_bucket *b = &ctx->loss[i];
        if (b->valid && b->epoch <= epoch && epoch - b->epoch < CATS_LOSS_BUCKETS) {
            out->loss_sent += b->sent;
            out->loss_retrans += b->retrans;
        }
    }
    if (out->loss_sent) {
        out->loss_probability = fmin(1., (double)out->loss_retrans / out->loss_sent);
        out->loss_from_history = 1;
    }
    int slot = slot_index(wall);
    if (slot >= 0) {
        struct bw_slot *bw = &ctx->bw[slot];
        if (bw->samples && wall >= bw->updated &&
            difftime(wall, bw->updated) <= ctx->config.bw_max_age_seconds) {
            out->bw_mbps = bw->mbps;
            out->bw_from_history = 1;
        }
    }
}

void cats_cached(struct cats_context *ctx, uint64_t ns, time_t wall, struct cats_values *out)
{
    pthread_mutex_lock(&ctx->lock);
    cached_locked(ctx, ns, wall, out);
    pthread_mutex_unlock(&ctx->lock);
}

int cats_collect(struct cats_context *ctx, int fd, time_t wall,
                 struct cats_values *out, double *sign, size_t count)
{
    if (count > CATS_MAX_ALGORITHMS || (count && !sign)) { errno = EINVAL; return -1; }
    memset(out, 0, sizeof(*out));
    int rc = cats_tcp_read(fd, &out->tcp);
    pthread_mutex_lock(&ctx->lock);
    cached_locked(ctx, cats_now_ns(), wall, out);
    for (size_t i = 0; i < count; i++)
        sign[i] = ctx->sign_valid[i] ? ctx->sign_ms[i] : NAN;
    pthread_mutex_unlock(&ctx->lock);
    return rc;
}

int cats_sign_init(struct cats_context *ctx, size_t i, double ms)
{
    if (i >= CATS_MAX_ALGORITHMS || !isfinite(ms) || ms < 0) return -1;
    pthread_mutex_lock(&ctx->lock);
    ctx->sign_ms[i] = ms;
    ctx->sign_valid[i] = 1;
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

int cats_sign_update(struct cats_context *ctx, size_t i, double ms)
{
    if (i >= CATS_MAX_ALGORITHMS || !isfinite(ms) || ms < 0) return -1;
    pthread_mutex_lock(&ctx->lock);
    if (ctx->sign_valid[i]) ctx->sign_ms[i] += ctx->config.ewma_alpha * (ms - ctx->sign_ms[i]);
    else ctx->sign_ms[i] = ms;
    ctx->sign_valid[i] = 1;
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

int cats_track(struct cats_context *ctx, int fd)
{
    pthread_mutex_lock(&ctx->registry);
    for (size_t i = 0; i < ctx->active_count; i++) {
        if (ctx->active[i].fd == fd) { pthread_mutex_unlock(&ctx->registry); return -1; }
    }
    if (ctx->active_count == CATS_MAX_CONNECTIONS) {
        pthread_mutex_unlock(&ctx->registry); errno = ENOSPC; return -1;
    }
    struct cats_tcp s;
    if (cats_tcp_read(fd, &s) || !s.counters_valid) {
        pthread_mutex_unlock(&ctx->registry); return -1;
    }
    struct tracked *t = &ctx->active[ctx->active_count++];
    *t = (struct tracked){.fd = fd};
    cats_observe(ctx, &t->cursor, &s, cats_now_ns(), time(NULL));
    pthread_mutex_unlock(&ctx->registry);
    return 0;
}

void cats_untrack(struct cats_context *ctx, int fd)
{
    pthread_mutex_lock(&ctx->registry);
    for (size_t i = 0; i < ctx->active_count; i++) {
        if (ctx->active[i].fd != fd) continue;
        struct cats_tcp s;
        if (!cats_tcp_read(fd, &s))
            cats_observe(ctx, &ctx->active[i].cursor, &s, cats_now_ns(), time(NULL));
        ctx->active[i] = ctx->active[--ctx->active_count];
        break;
    }
    pthread_mutex_unlock(&ctx->registry);
}

static void *sample_worker(void *arg)
{
    struct cats_context *ctx = arg;
    pthread_mutex_lock(&ctx->lock);
    while (!ctx->stopping) {
        uint64_t ns = cats_now_ns() + (uint64_t)ctx->config.sample_interval_ms * 1000000;
        struct timespec deadline = {(time_t)(ns / 1000000000), (long)(ns % 1000000000)};
        int wait_rc = 0;
        while (!ctx->stopping && wait_rc != ETIMEDOUT)
            wait_rc = pthread_cond_timedwait(&ctx->wake, &ctx->lock, &deadline);
        if (ctx->stopping) break;
        pthread_mutex_unlock(&ctx->lock);
        pthread_mutex_lock(&ctx->registry);
        uint64_t start = cats_now_ns();
        size_t sampled = ctx->active_count;
        for (size_t i = 0; i < ctx->active_count; i++) {
            struct cats_tcp s;
            if (!cats_tcp_read(ctx->active[i].fd, &s))
                cats_observe(ctx, &ctx->active[i].cursor, &s, cats_now_ns(), time(NULL));
        }
        uint64_t elapsed = cats_now_ns() - start;
        pthread_mutex_unlock(&ctx->registry);
        pthread_mutex_lock(&ctx->lock);
        if (sampled) {
            ctx->sampler_stats.batches++;
            ctx->sampler_stats.socket_reads += sampled;
            ctx->sampler_stats.elapsed_ns += elapsed;
            if (elapsed > ctx->sampler_stats.max_batch_ns) ctx->sampler_stats.max_batch_ns = elapsed;
        }
    }
    pthread_mutex_unlock(&ctx->lock);
    return NULL;
}

int cats_sampler_start(struct cats_context *ctx)
{
    pthread_mutex_lock(&ctx->lifecycle);
    pthread_mutex_lock(&ctx->lock);
    if (ctx->running) {
        pthread_mutex_unlock(&ctx->lock); pthread_mutex_unlock(&ctx->lifecycle); return -1;
    }
    ctx->stopping = 0;
    int rc = pthread_create(&ctx->worker, NULL, sample_worker, ctx);
    if (!rc) ctx->running = 1;
    pthread_mutex_unlock(&ctx->lock);
    pthread_mutex_unlock(&ctx->lifecycle);
    return rc ? -1 : 0;
}

void cats_sampler_stop(struct cats_context *ctx)
{
    pthread_mutex_lock(&ctx->lifecycle);
    pthread_mutex_lock(&ctx->lock);
    int join = ctx->running;
    ctx->stopping = 1;
    pthread_cond_broadcast(&ctx->wake);
    pthread_mutex_unlock(&ctx->lock);
    if (join) pthread_join(ctx->worker, NULL);
    pthread_mutex_lock(&ctx->lock);
    ctx->running = 0;
    pthread_mutex_unlock(&ctx->lock);
    pthread_mutex_unlock(&ctx->lifecycle);
}

void cats_context_free(struct cats_context *ctx)
{
    if (!ctx) return;
    cats_sampler_stop(ctx);
    pthread_cond_destroy(&ctx->wake);
    pthread_mutex_destroy(&ctx->lock);
    pthread_mutex_destroy(&ctx->registry);
    pthread_mutex_destroy(&ctx->lifecycle);
    free(ctx);
}

struct cats_sampler_stats cats_sampler_statistics(struct cats_context *ctx)
{
    pthread_mutex_lock(&ctx->lock);
    struct cats_sampler_stats stats = ctx->sampler_stats;
    pthread_mutex_unlock(&ctx->lock);
    return stats;
}

int cats_bw_save(struct cats_context *ctx, const char *path)
{
    struct bw_slot slots[CATS_BW_SLOTS];
    pthread_mutex_lock(&ctx->lock);
    memcpy(slots, ctx->bw, sizeof(slots));
    pthread_mutex_unlock(&ctx->lock);
    char *tmp = malloc(strlen(path) + 12);
    if (!tmp) return -1;
    sprintf(tmp, "%s.XXXXXX", path);
    int fd = mkstemp(tmp);
    if (fd < 0) { free(tmp); return -1; }
    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); unlink(tmp); free(tmp); return -1; }
    fprintf(f, "CATS_BW_UTC_V1\n");
    for (size_t i = 0; i < CATS_BW_SLOTS; i++)
        fprintf(f, "%zu %.17g %lld %llu\n", i, slots[i].mbps,
                (long long)slots[i].updated, (unsigned long long)slots[i].samples);
    int rc = ferror(f) ? -1 : 0;
    if (fclose(f)) rc = -1;
    if (!rc && rename(tmp, path)) rc = -1;
    if (rc) unlink(tmp);
    free(tmp);
    return rc;
}

int cats_bw_load(struct cats_context *ctx, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    struct bw_slot slots[CATS_BW_SLOTS] = {{0}};
    char header[64];
    int rc = -1;
    if (!fgets(header, sizeof(header), f) || strcmp(header, "CATS_BW_UTC_V1\n")) goto done;
    for (size_t i = 0; i < CATS_BW_SLOTS; i++) {
        size_t index;
        long long updated;
        unsigned long long samples;
        double mbps;
        if (fscanf(f, "%zu %lf %lld %llu", &index, &mbps, &updated, &samples) != 4 ||
            index != i || !isfinite(mbps) || mbps < 0 || (samples && mbps == 0) || updated < 0)
            goto done;
        slots[i] = (struct bw_slot){mbps, (time_t)updated, samples};
    }
    pthread_mutex_lock(&ctx->lock);
    memcpy(ctx->bw, slots, sizeof(slots));
    pthread_mutex_unlock(&ctx->lock);
    rc = 0;
done:
    fclose(f);
    return rc;
}

size_t cats_context_size(void) { return sizeof(struct cats_context); }
