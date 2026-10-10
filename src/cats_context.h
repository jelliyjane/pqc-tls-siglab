#ifndef CATS_CONTEXT_H
#define CATS_CONTEXT_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define CATS_MAX_ALGORITHMS 512
#define CATS_LOSS_BUCKETS 60
#define CATS_BW_SLOTS (7 * 24)
#define CATS_MAX_CONNECTIONS 4096

/* All times are monotonic except wall_time (UTC weekday/hour lookup). */
struct cats_tcp {
    double rtt_ms;
    uint64_t cwnd_bytes, rwnd_bytes, window_bytes, bytes_acked;
    uint64_t delivery_bytes_per_sec;
    uint32_t data_segs_out, retrans;
    int rtt_valid, window_valid, counters_valid, rate_valid, app_limited;
};
struct cats_cursor { struct cats_tcp previous; uint64_t last_ns; int initialized; };
struct cats_config {
    double default_bw_mbps, default_loss, ewma_alpha;
    unsigned loss_bucket_seconds, sample_interval_ms, bw_max_age_seconds;
};
struct cats_values {
    struct cats_tcp tcp;
    double bw_mbps, loss_probability;
    int bw_from_history, loss_from_history;
    uint64_t loss_sent, loss_retrans;
};
struct cats_context;
struct cats_sampler_stats { uint64_t batches, socket_reads, elapsed_ns, max_batch_ns; };

uint64_t cats_now_ns(void);
int cats_tcp_read(int fd, struct cats_tcp *out);
struct cats_config cats_default_config(void);
struct cats_context *cats_context_new(struct cats_config config);
void cats_context_free(struct cats_context *ctx); /* caller first joins all API users */
int cats_sign_init(struct cats_context *ctx, size_t algorithm, double profile_ms);
int cats_sign_update(struct cats_context *ctx, size_t algorithm, double measured_ms);
/* Exactly one TCP_INFO call plus bounded cached lookups, no network writes.
 * Missing RTT/window are explicitly invalid; zero rwnd stays zero.
 * sign_ms may be NULL only if count is zero. */
int cats_collect(struct cats_context *ctx, int fd, time_t wall_time,
                 struct cats_values *out, double *sign_ms, size_t count);
/* An event loop may call observe periodically, or use the background service.
 * Cursor belongs to one socket lifetime. First observation is a baseline.
 * Supplied snapshots also support deterministic tests without fake sockets. */
void cats_observe(struct cats_context *ctx, struct cats_cursor *cursor,
                  const struct cats_tcp *snapshot, uint64_t mono_ns, time_t wall_time);
void cats_cached(struct cats_context *ctx, uint64_t mono_ns, time_t wall_time,
                 struct cats_values *out);
int cats_track(struct cats_context *ctx, int fd);
void cats_untrack(struct cats_context *ctx, int fd); /* call BEFORE close(fd) */
int cats_sampler_start(struct cats_context *ctx);
void cats_sampler_stop(struct cats_context *ctx);
struct cats_sampler_stats cats_sampler_statistics(struct cats_context *ctx);
/* Explicit maintenance, outside the selection path. Persists only 168
 * aggregated BW slots, never client addresses or connection histories. */
int cats_bw_save(struct cats_context *ctx, const char *path);
int cats_bw_load(struct cats_context *ctx, const char *path);
size_t cats_context_size(void);

#endif
