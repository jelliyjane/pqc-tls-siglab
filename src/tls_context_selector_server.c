#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/tcp.h>
#endif
#include "tcp_selection_window.h"
#ifdef CATS_CONTEXT_ACQUISITION
#include "cats_context.h"
#include <dlfcn.h>
#endif

#define MAX_CANDIDATES 512
#define MAX_LINE 4096
#define MAX_FIELD 512

struct candidate {
    char algorithm[MAX_FIELD];
    char level[16];
    char certificate_mode[32];
    char cert_path[MAX_FIELD];
    char key_path[MAX_FIELD];
    char chain_path[MAX_FIELD];
    long chain_bytes;
    long signature_bytes;
    int sent_cert_count;
    double sign_ms;
    double verify_ms;
    unsigned int sigalg_code_point;
    int has_sigalg_code_point;
};

struct selector_state {
    struct candidate candidates[MAX_CANDIDATES];
    int count;
    double fallback_rtt_ms;
    double bandwidth_mbps;
    long fallback_window_size;
    int server_hello_keyshare_bytes;
    int encrypted_extensions_bytes;
    int finished_bytes;
    int record_overhead_bytes;
    int tls_plaintext_fragment_bytes;
    int bio_buffer_bytes;
    const struct candidate *last_selected;
    double last_score_ms;
    long last_server_flight_bytes;
    int last_extra_rounds;
    int last_i_tail;
    long last_certificate_tail_bytes;
    long last_certificate_start_offset;
    long last_certificate_message_bytes;
    double last_tail_delay_ms;
    double last_certificate_message_ms;
    double last_sign_phase_ms;
    long last_wbio_pending_before_certificate;
    long last_wbio_pending_before_certverify;
    long last_observed_server_hello_bytes;
    long last_observed_encrypted_extensions_bytes;
    long last_observed_certificate_bytes;
    int auto_calibrate_message_sizes;
    char rl_socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    char rl_protocol[32];
    char rl_security_level[16];
    char last_decision_id[64];
    char last_arm[32];
    long connection_serial;
#ifdef CATS_CONTEXT_ACQUISITION
    struct cats_context *acquisition;
    struct cats_values acquired;
    uint64_t acquisition_ns;
    int acquisition_valid;
    void (*sign_timer_begin)(void);
    uint64_t (*sign_timer_end)(uint64_t *);
#endif
};

static int require_client_sigalg_match(void);
static int split_tsv(char *line, char **fields, int max_fields);

static unsigned int builtin_sigalg_code_point(const char *algorithm)
{
    struct builtin_sigalg {
        const char *name;
        unsigned int code_point;
    };
    static const struct builtin_sigalg values[] = {
        {"ecdsa_secp256r1_sha256", 0x0403},
        {"ecdsa_secp384r1_sha384", 0x0503},
        {"ecdsa_secp521r1_sha512", 0x0603},
        {"rsa_pss_rsae_sha256", 0x0804},
        {"rsa_pss_rsae_sha384", 0x0805},
        {"rsa_pss_rsae_sha512", 0x0806},
        {"ed25519", 0x0807},
        {"ed448", 0x0808},
        {"rsa_pss_pss_sha256", 0x0809},
        {"rsa_pss_pss_sha384", 0x080a},
        {"rsa_pss_pss_sha512", 0x080b},
        /* Native OpenSSL 3.5 TLS signature schemes (ssl_local.h). */
        {"mldsa44", 0x0904},
        {"mldsa65", 0x0905},
        {"mldsa87", 0x0906},
        {"ML-DSA-44", 0x0904},
        {"ML-DSA-65", 0x0905},
        {"ML-DSA-87", 0x0906},
    };
    size_t i;
    for (i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        if (strcasecmp(values[i].name, algorithm) == 0)
            return values[i].code_point;
    }
    return 0;
}

static int sigalg_capability_cb(const OSSL_PARAM params[], void *arg)
{
    struct selector_state *state = (struct selector_state *)arg;
    const OSSL_PARAM *name_param;
    const OSSL_PARAM *code_param;
    const char *name = NULL;
    unsigned int code_point = 0;
    int i;

    name_param = OSSL_PARAM_locate_const(params, OSSL_CAPABILITY_TLS_SIGALG_NAME);
    code_param = OSSL_PARAM_locate_const(params, OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT);
    if (name_param == NULL || code_param == NULL
        || !OSSL_PARAM_get_utf8_string_ptr(name_param, &name)
        || !OSSL_PARAM_get_uint(code_param, &code_point)
        || name == NULL)
        return 1;
    for (i = 0; i < state->count; i++) {
        if (strcasecmp(state->candidates[i].algorithm, name) == 0) {
            state->candidates[i].sigalg_code_point = code_point;
            state->candidates[i].has_sigalg_code_point = 1;
        }
    }
    return 1;
}

static void populate_sigalg_codepoints(struct selector_state *state, OSSL_PROVIDER *provider)
{
    int i;
    if (provider != NULL)
        OSSL_PROVIDER_get_capabilities(provider, "TLS-SIGALG", sigalg_capability_cb, state);
    for (i = 0; i < state->count; i++) {
        unsigned int code_point;
        if (state->candidates[i].has_sigalg_code_point)
            continue;
        code_point = builtin_sigalg_code_point(state->candidates[i].algorithm);
        if (code_point != 0) {
            state->candidates[i].sigalg_code_point = code_point;
            state->candidates[i].has_sigalg_code_point = 1;
        }
    }
}

static int client_offers_candidate(
    SSL *ssl,
    const struct selector_state *state,
    const char *algorithm)
{
    int sig_count;
    int sig_index;
    if (!require_client_sigalg_match())
        return 1;
    sig_count = SSL_get_sigalgs(ssl, -1, NULL, NULL, NULL, NULL, NULL);
    if (sig_count <= 0)
        return 1;
    for (sig_index = 0; sig_index < sig_count; sig_index++) {
        int sign = NID_undef;
        int hash = NID_undef;
        int signhash = NID_undef;
        const char *sn;
        const char *ln;
        unsigned char raw_signature = 0;
        unsigned char raw_hash = 0;
        unsigned int raw_code_point;
        if (!SSL_get_sigalgs(
                ssl, sig_index, &sign, &hash, &signhash,
                &raw_signature, &raw_hash))
            continue;
        /* OpenSSL exposes the two wire bytes through the historical rsig/rhash
         * parameters in low-byte/high-byte order for TLS 1.3 schemes. */
        raw_code_point = ((unsigned int)raw_hash << 8) | (unsigned int)raw_signature;
        if (getenv("TLS_SELECTOR_DEBUG_SIGALGS") != NULL) {
            fprintf(stderr,
                "SIGALG peer_index=%d raw_signature=%u raw_hash=%u code_point=0x%04x sign_nid=%d hash_nid=%d signhash_nid=%d sn=%s ln=%s\n",
                sig_index, (unsigned int)raw_signature, (unsigned int)raw_hash,
                raw_code_point, sign, hash, signhash,
                OBJ_nid2sn(signhash) ? OBJ_nid2sn(signhash) : "",
                OBJ_nid2ln(signhash) ? OBJ_nid2ln(signhash) : "");
        }
        {
            int candidate_index;
            for (candidate_index = 0; candidate_index < state->count; candidate_index++) {
                const struct candidate *candidate = &state->candidates[candidate_index];
                if (strcasecmp(candidate->algorithm, algorithm) == 0
                    && candidate->has_sigalg_code_point
                    && candidate->sigalg_code_point == raw_code_point)
                    return 1;
            }
        }
        sn = OBJ_nid2sn(signhash);
        ln = OBJ_nid2ln(signhash);
        if ((sn != NULL && strcasecmp(sn, algorithm) == 0)
            || (ln != NULL && strcasecmp(ln, algorithm) == 0))
            return 1;
    }
    return 0;
}

static int rl_exchange(const char *socket_path, const char *request, char *response, size_t response_size)
{
    int fd;
    struct sockaddr_un address;
    size_t request_len;
    ssize_t written;
    ssize_t received;
    if (socket_path == NULL || socket_path[0] == '\0')
        return 0;
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return 0;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", socket_path);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return 0;
    }
    request_len = strlen(request);
    written = write(fd, request, request_len);
    if (written != (ssize_t)request_len) {
        close(fd);
        return 0;
    }
    received = read(fd, response, response_size - 1);
    close(fd);
    if (received <= 0)
        return 0;
    response[received] = '\0';
    response[strcspn(response, "\r\n")] = '\0';
    return 1;
}

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

static void tls_message_cb(
    int write_p,
    int version,
    int content_type,
    const void *buf,
    size_t len,
    SSL *ssl,
    void *arg)
{
    struct selector_state *state = (struct selector_state *)arg;
    const unsigned char *message = (const unsigned char *)buf;
    int handshake_type;
    (void)version;
    (void)ssl;
    if (!write_p || content_type != SSL3_RT_HANDSHAKE || len < 1)
        return;
    handshake_type = message[0];
    if (handshake_type == SSL3_MT_SERVER_HELLO) {
        state->last_observed_server_hello_bytes = (long)len;
        if (state->auto_calibrate_message_sizes)
            state->server_hello_keyshare_bytes = (int)len;
    } else if (handshake_type == SSL3_MT_ENCRYPTED_EXTENSIONS) {
        state->last_observed_encrypted_extensions_bytes = (long)len;
        if (state->auto_calibrate_message_sizes)
            state->encrypted_extensions_bytes = len > 4 ? (int)len - 4 : (int)len;
    } else if (handshake_type == SSL3_MT_CERTIFICATE) {
        BIO *wbio = SSL_get_wbio(ssl);
        state->last_observed_certificate_bytes = (long)len;
        state->last_wbio_pending_before_certificate = wbio != NULL ? BIO_wpending(wbio) : 0;
        state->last_certificate_message_ms = now_ms();
    } else if (handshake_type == SSL3_MT_CERTIFICATE_VERIFY && state->last_certificate_message_ms > 0.0) {
        BIO *wbio = SSL_get_wbio(ssl);
        state->last_wbio_pending_before_certverify = wbio != NULL ? BIO_wpending(wbio) : 0;
        /* This is an observable server-side approximation: certificate
         * serialization plus CertificateVerify generation/signing phase. */
        state->last_sign_phase_ms = now_ms() - state->last_certificate_message_ms;
    }
}

static double env_double(const char *name, double fallback)
{
    const char *value = getenv(name);
    if (value == NULL || value[0] == '\0')
        return fallback;
    return atof(value);
}

static long env_long(const char *name, long fallback)
{
    const char *value = getenv(name);
    if (value == NULL || value[0] == '\0')
        return fallback;
    return atol(value);
}

static int env_int(const char *name, int fallback)
{
    return (int)env_long(name, fallback);
}

static long record_overhead(long bytes, int per_record_overhead)
{
    long records;
    if (bytes <= 0)
        return 0;
    records = (bytes + 16383) / 16384;
    return records * per_record_overhead;
}

static void certificate_tail_state(
    long chain_bytes,
    int sent_cert_count,
    int encrypted_extensions_bytes,
    int fragment_bytes,
    int bio_buffer_bytes,
    int *i_tail,
    long *tail_bytes,
    long *certificate_start_offset,
    long *certificate_message_bytes)
{
    const int handshake_header_bytes = 4;
    const int certificate_context_length_bytes = 1;
    const int certificate_list_length_bytes = 3;
    const int certificate_entry_overhead_bytes = 5;
    long encrypted_extensions_message_bytes;
    long certificate_end;
    if (fragment_bytes <= 0)
        fragment_bytes = 16384;
    if (bio_buffer_bytes <= 0)
        bio_buffer_bytes = 4096;
    *i_tail = 0;
    *tail_bytes = 0;
    encrypted_extensions_message_bytes = handshake_header_bytes + encrypted_extensions_bytes;
    *certificate_start_offset = encrypted_extensions_message_bytes % fragment_bytes;
    *certificate_message_bytes = handshake_header_bytes
        + certificate_context_length_bytes
        + certificate_list_length_bytes
        + chain_bytes
        + (sent_cert_count > 0 ? sent_cert_count : 1) * certificate_entry_overhead_bytes;
    certificate_end = *certificate_start_offset + *certificate_message_bytes;
    if (certificate_end <= fragment_bytes)
        return;
    *tail_bytes = certificate_end % fragment_bytes;
    if (*tail_bytes > 0 && *tail_bytes < bio_buffer_bytes)
        *i_tail = 1;
}

static void tcp_context(
    int fd,
    double fallback_rtt_ms,
    long fallback_window,
    double *rtt_ms,
    long *window_size,
    double *loss_percent)
{
    *rtt_ms = fallback_rtt_ms;
    *window_size = fallback_window;
    *loss_percent = -1.0;
#ifdef __linux__
    {
        struct tcp_info ti;
        socklen_t len = sizeof(ti);
        memset(&ti, 0, sizeof(ti));
        if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &len) == 0) {
            if (ti.tcpi_rtt > 0)
                *rtt_ms = (double)ti.tcpi_rtt / 1000.0;
            /* Old kernels can return a shorter TCP_INFO. Never substitute
             * rcv_space: that is the server's receive direction, not rwnd. */
            if (len >= offsetof(struct tcp_info, tcpi_snd_wnd) + sizeof(ti.tcpi_snd_wnd))
                *window_size = tcp_selection_window(ti.tcpi_snd_cwnd,
                    ti.tcpi_snd_mss, ti.tcpi_snd_wnd);
            if (len >= offsetof(struct tcp_info, tcpi_segs_out) + sizeof(ti.tcpi_segs_out)
                    && ti.tcpi_segs_out > 0)
                *loss_percent = 100.0 * (double)ti.tcpi_total_retrans / (double)ti.tcpi_segs_out;
        }
    }
#else
    (void)fd;
#endif
}

static double candidate_score(
    const struct candidate *c,
    const struct selector_state *state,
    double rtt_ms,
    long window_size,
    long *server_flight_bytes,
    int *extra_rounds,
    int *i_tail,
    long *certificate_tail_bytes,
    long *certificate_start_offset,
    long *certificate_message_bytes,
    double *tail_delay_ms)
{
    long without_records = state->server_hello_keyshare_bytes
        + state->encrypted_extensions_bytes
        + c->chain_bytes
        + c->signature_bytes
        + state->finished_bytes;
    double serialization_ms;
    double network_penalty_ms;
    double verify_chain_ms;
    double overlap_ms;

    *server_flight_bytes = without_records + record_overhead(without_records, state->record_overhead_bytes);
    /* The certificate callback rejects unavailable/closed windows first. */
    *extra_rounds = (int)((*server_flight_bytes + window_size - 1) / window_size) - 1;
    if (*extra_rounds < 0)
        *extra_rounds = 0;
    serialization_ms = ((double)(*server_flight_bytes) * 8.0) / (state->bandwidth_mbps * 1000000.0) * 1000.0;
    network_penalty_ms = (double)(*extra_rounds) * rtt_ms + serialization_ms;
    certificate_tail_state(
        c->chain_bytes,
        c->sent_cert_count,
        state->encrypted_extensions_bytes,
        state->tls_plaintext_fragment_bytes,
        state->bio_buffer_bytes,
        i_tail,
        certificate_tail_bytes,
        certificate_start_offset,
        certificate_message_bytes);
    *tail_delay_ms = *i_tail ? c->sign_ms : 0.0;
    verify_chain_ms = c->verify_ms * (double)c->sent_cert_count;
    overlap_ms = *extra_rounds == 0 && !*i_tail && c->sign_ms < verify_chain_ms ? c->sign_ms : 0.0;
    if (*extra_rounds == 0 && !*i_tail && verify_chain_ms <= c->sign_ms)
        overlap_ms = verify_chain_ms;
    return rtt_ms + c->sign_ms + network_penalty_ms + *tail_delay_ms + verify_chain_ms - overlap_ms;
}

static int load_chain(SSL *ssl, const char *path)
{
    BIO *bio;
    X509 *cert;
    int loaded = 0;

    if (strcmp(path, "-") == 0 || path[0] == '\0')
        return 1;

    bio = BIO_new_file(path, "r");
    if (bio == NULL)
        return 0;
    SSL_clear_chain_certs(ssl);
    while ((cert = PEM_read_bio_X509(bio, NULL, 0, NULL)) != NULL) {
        if (!SSL_add1_chain_cert(ssl, cert)) {
            X509_free(cert);
            BIO_free(bio);
            return 0;
        }
        X509_free(cert);
        loaded++;
    }
    BIO_free(bio);
    ERR_clear_error();
    return loaded > 0;
}

static int cert_cb(SSL *ssl, void *arg)
{
    struct selector_state *state = (struct selector_state *)arg;
    const struct candidate *best = NULL;
    double best_score = 0.0;
    double rtt_ms;
    double loss_percent;
    long window_size;
    int i;
    char rl_algorithm[MAX_FIELD];
    char request[16384];
    char response[4096];
    char candidate_names[12000];

    rl_algorithm[0] = '\0';
    state->last_decision_id[0] = '\0';
    state->last_arm[0] = '\0';

#ifdef CATS_CONTEXT_ACQUISITION
    {
        double signs[MAX_CANDIDATES];
        uint64_t start = cats_now_ns();
        if (cats_collect(state->acquisition, SSL_get_fd(ssl), time(NULL),
                         &state->acquired, signs, (size_t)state->count) != 0 ||
            !state->acquired.tcp.rtt_valid || !state->acquired.tcp.window_valid)
            return 0;
        rtt_ms = state->acquired.tcp.rtt_ms;
        window_size = (long)state->acquired.tcp.window_bytes;
        loss_percent = state->acquired.loss_probability * 100.0; /* DECIDE2 uses percent */
        state->bandwidth_mbps = state->acquired.bw_mbps;
        for (i = 0; i < state->count; i++) state->candidates[i].sign_ms = signs[i];
        state->acquisition_ns = cats_now_ns() - start;
        state->acquisition_valid = 1;
    }
#else
    tcp_context(
        SSL_get_fd(ssl), state->fallback_rtt_ms, state->fallback_window_size,
        &rtt_ms, &window_size, &loss_percent);
#endif
    if (window_size <= 0) {
        fprintf(stderr, "SELECT unavailable: TCP window missing or closed (%ld); no fixed-window scoring\n", window_size);
        return 0;
    }
    if (state->rl_socket_path[0] != '\0') {
        char *fields[8];
        int field_count;
        size_t used = 0;
        candidate_names[0] = '\0';
        for (i = 0; i < state->count; i++) {
            if (!client_offers_candidate(ssl, state, state->candidates[i].algorithm))
                continue;
            int appended = snprintf(candidate_names + used, sizeof(candidate_names) - used, "%s%s", used ? "," : "", state->candidates[i].algorithm);
            if (appended < 0 || (size_t)appended >= sizeof(candidate_names) - used)
                break;
            used += (size_t)appended;
        }
        if (strcmp(state->rl_protocol, "linucb-v2") == 0) {
            snprintf(request, sizeof(request), "DECIDE2\ttls-%ld\t%.6f\t%.6f\t%.6f\t%ld\t%s\t%s\n",
                state->connection_serial, rtt_ms, state->bandwidth_mbps, loss_percent,
                window_size, state->rl_security_level, candidate_names);
        } else {
            snprintf(request, sizeof(request), "DECIDE\ttls-%ld\t%.6f\t%.6f\t%s\t%s\n",
                state->connection_serial, rtt_ms, state->bandwidth_mbps, state->rl_security_level, candidate_names);
        }
        if (rl_exchange(state->rl_socket_path, request, response, sizeof(response))) {
            field_count = split_tsv(response, fields, 8);
            if (field_count >= 8 && strcmp(fields[0], "OK") == 0) {
                snprintf(state->last_decision_id, sizeof(state->last_decision_id), "%s", fields[1]);
                snprintf(state->last_arm, sizeof(state->last_arm), "%s", fields[2]);
                snprintf(rl_algorithm, sizeof(rl_algorithm), "%s", fields[3]);
            }
        }
        if (rl_algorithm[0] == '\0')
            fprintf(stderr, "RL fallback: updater unavailable or invalid response; using deterministic selector\n");
    }
    for (i = 0; i < state->count; i++) {
        long flight = 0;
        int rounds = 0;
        int i_tail = 0;
        long tail_bytes = 0;
        long certificate_start_offset = 0;
        long certificate_message_bytes = 0;
        double tail_delay_ms = 0.0;
        double score = candidate_score(
            &state->candidates[i], state, rtt_ms, window_size,
            &flight, &rounds, &i_tail, &tail_bytes,
            &certificate_start_offset, &certificate_message_bytes, &tail_delay_ms);
        if (rl_algorithm[0] != '\0' && strcmp(rl_algorithm, state->candidates[i].algorithm) != 0)
            continue;
        if (!client_offers_candidate(ssl, state, state->candidates[i].algorithm))
            continue;
        if (best == NULL || score < best_score) {
            best = &state->candidates[i];
            best_score = score;
            state->last_server_flight_bytes = flight;
            state->last_extra_rounds = rounds;
            state->last_i_tail = i_tail;
            state->last_certificate_tail_bytes = tail_bytes;
            state->last_certificate_start_offset = certificate_start_offset;
            state->last_certificate_message_bytes = certificate_message_bytes;
            state->last_tail_delay_ms = tail_delay_ms;
        }
    }

    if (best == NULL) {
        fprintf(stderr, "SELECT failed: no candidate after client signature_algorithms filter\n");
        return 0;
    }

    if (!SSL_use_certificate_file(ssl, best->cert_path, SSL_FILETYPE_PEM)) {
        fprintf(stderr, "SELECT failed: cannot load cert %s\n", best->cert_path);
        ERR_print_errors_fp(stderr);
        return 0;
    }
    if (!SSL_use_PrivateKey_file(ssl, best->key_path, SSL_FILETYPE_PEM)) {
        fprintf(stderr, "SELECT failed: cannot load key %s\n", best->key_path);
        ERR_print_errors_fp(stderr);
        return 0;
    }
    if (!SSL_check_private_key(ssl)) {
        fprintf(stderr, "SELECT failed: private key mismatch %s\n", best->algorithm);
        ERR_print_errors_fp(stderr);
        return 0;
    }
    if (!load_chain(ssl, best->chain_path)) {
        fprintf(stderr, "SELECT failed: cannot load chain %s\n", best->chain_path);
        ERR_print_errors_fp(stderr);
        return 0;
    }
    if (!SSL_set1_sigalgs_list(ssl, best->algorithm)) {
        fprintf(stderr, "SELECT failed: cannot set sigalgs %s\n", best->algorithm);
        ERR_print_errors_fp(stderr);
        return 0;
    }

    state->last_selected = best;
    state->last_score_ms = best_score;
    fprintf(stderr,
        "SELECT algorithm=%s arm=%s decision_id=%s estimated_tls_ms=%.3f rtt_ms=%.3f window_size=%ld server_hello_keyshare_bytes=%d server_hello_flush_boundary=1 server_flight_bytes=%ld extra_rounds=%d I_tail=%d certificate_start_offset=%ld certificate_message_bytes=%ld certificate_tail_bytes=%ld tail_delay_ms=%.3f\n",
        best->algorithm, state->last_arm[0] ? state->last_arm : "deterministic-local",
        state->last_decision_id, best_score, rtt_ms, window_size, state->server_hello_keyshare_bytes,
        state->last_server_flight_bytes, state->last_extra_rounds,
        state->last_i_tail, state->last_certificate_start_offset, state->last_certificate_message_bytes,
        state->last_certificate_tail_bytes, state->last_tail_delay_ms);
    return 1;
}

static void rl_observe(
    struct selector_state *state,
    int success,
    double handshake_ms,
    double sign_phase_ms,
    double loss_percent)
{
    char request[512];
    char response[512];
    if (state->rl_socket_path[0] == '\0' || state->last_decision_id[0] == '\0')
        return;
    if (strcmp(state->rl_protocol, "linucb-v2") == 0) {
        snprintf(request, sizeof(request), "OBSERVE2\t%s\t%d\t%.6f\t%.6f\t%.6f\n",
            state->last_decision_id, success, handshake_ms, sign_phase_ms, loss_percent);
    } else {
        snprintf(request, sizeof(request), "OBSERVE\t%s\t%d\t%.6f\t%.6f\n",
            state->last_decision_id, success, handshake_ms, sign_phase_ms);
    }
    if (!rl_exchange(state->rl_socket_path, request, response, sizeof(response)) || strncmp(response, "OK", 2) != 0)
        fprintf(stderr, "RL observe failed decision_id=%s\n", state->last_decision_id);
}

static int split_tsv(char *line, char **fields, int max_fields)
{
    int count = 0;
    char *p = line;
    while (count < max_fields) {
        fields[count++] = p;
        p = strchr(p, '\t');
        if (p == NULL)
            break;
        *p = '\0';
        p++;
    }
    return count;
}

static int load_manifest(const char *path, struct selector_state *state)
{
    FILE *f = fopen(path, "r");
    char line[MAX_LINE];
    if (f == NULL)
        return 0;
    if (fgets(line, sizeof(line), f) == NULL) {
        fclose(f);
        return 0;
    }
    while (fgets(line, sizeof(line), f) != NULL) {
        char *fields[11];
        struct candidate *c;
        int n;
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0')
            continue;
        if (state->count >= MAX_CANDIDATES)
            break;
        n = split_tsv(line, fields, 11);
        if (n < 11)
            continue;
        c = &state->candidates[state->count++];
        snprintf(c->algorithm, sizeof(c->algorithm), "%s", fields[0]);
        snprintf(c->level, sizeof(c->level), "%s", fields[1]);
        snprintf(c->certificate_mode, sizeof(c->certificate_mode), "%s", fields[2]);
        snprintf(c->cert_path, sizeof(c->cert_path), "%s", fields[3]);
        snprintf(c->key_path, sizeof(c->key_path), "%s", fields[4]);
        snprintf(c->chain_path, sizeof(c->chain_path), "%s", fields[5]);
        c->chain_bytes = atol(fields[6]);
        c->signature_bytes = atol(fields[7]);
        c->sent_cert_count = atoi(fields[8]);
        c->sign_ms = atof(fields[9]);
        c->verify_ms = atof(fields[10]);
    }
    fclose(f);
    return state->count > 0;
}

static int make_listen_socket(const char *port)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *p;
    int fd = -1;
    int one = 1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(getenv("TLS_SELECTOR_LISTEN_HOST"), port, &hints, &res) != 0)
        return -1;
    for (p = res; p != NULL; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0)
            continue;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (bind(fd, p->ai_addr, p->ai_addrlen) == 0 && listen(fd, 32) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int is_default_group(const char *group)
{
    return strcmp(group, "OPENSSL_DEFAULT") == 0 || strcmp(group, "DEFAULT") == 0 || strcmp(group, "-") == 0;
}

static int require_oqsprovider(void)
{
    const char *value = getenv("TLS_REQUIRE_OQSPROVIDER");
    return value == NULL || strcmp(value, "0") != 0;
}

static int require_client_sigalg_match(void)
{
    const char *value = getenv("TLS_SELECTOR_REQUIRE_CLIENT_SIGALG_MATCH");
    return value != NULL && strcmp(value, "1") == 0;
}

int main(int argc, char **argv)
{
    const char *port;
    const char *manifest;
    const char *provider_path;
    const char *group;
    int naccept;
    int listen_fd = -1;
    int accepted = 0;
    SSL_CTX *ctx = NULL;
    OSSL_PROVIDER *oqsprov = NULL;
    OSSL_PROVIDER *defprov = NULL;
    struct selector_state state;
    int rc = 1;

    if (argc != 6) {
        fprintf(stderr, "usage: %s <port> <manifest.tsv> <provider_path> <groups|OPENSSL_DEFAULT> <naccept>\n", argv[0]);
        return 2;
    }
    port = argv[1];
    manifest = argv[2];
    provider_path = argv[3];
    group = argv[4];
    naccept = atoi(argv[5]);

    memset(&state, 0, sizeof(state));
    state.fallback_rtt_ms = env_double("TLS_SELECTOR_FALLBACK_RTT_MS", 1.0);
    state.bandwidth_mbps = env_double("TLS_SELECTOR_BANDWIDTH_MBPS", 1000.0);
    /* Explicit input for dry runs/unsupported TCP_INFO only; no silent 16 KiB. */
    state.fallback_window_size = env_long("TLS_SELECTOR_WINDOW_SIZE_BYTES", -1);
    if (state.fallback_window_size > 0)
        fprintf(stderr, "TCP window fallback explicitly configured: %ld bytes (not measured)\n", state.fallback_window_size);
    state.server_hello_keyshare_bytes = env_int("TLS_SELECTOR_SERVER_HELLO_KEYSHARE_BYTES", 160);
    state.encrypted_extensions_bytes = env_int("TLS_SELECTOR_ENCRYPTED_EXTENSIONS_BYTES", 80);
    state.finished_bytes = env_int("TLS_SELECTOR_FINISHED_BYTES", 64);
    state.record_overhead_bytes = env_int("TLS_SELECTOR_RECORD_OVERHEAD_BYTES", 22);
    state.tls_plaintext_fragment_bytes = env_int("TLS_SELECTOR_TLS_PLAINTEXT_FRAGMENT_BYTES", 16384);
    state.bio_buffer_bytes = env_int("TLS_SELECTOR_BIO_BUFFER_BYTES", 4096);
    state.auto_calibrate_message_sizes = env_int("TLS_SELECTOR_AUTO_CALIBRATE_MESSAGE_SIZES", 1);
    snprintf(state.rl_socket_path, sizeof(state.rl_socket_path), "%s", getenv("TLS_RL_SOCKET") ? getenv("TLS_RL_SOCKET") : "");
    snprintf(state.rl_protocol, sizeof(state.rl_protocol), "%s", getenv("TLS_RL_PROTOCOL") ? getenv("TLS_RL_PROTOCOL") : "legacy-v1");
    snprintf(state.rl_security_level, sizeof(state.rl_security_level), "%s", getenv("TLS_RL_SECURITY_LEVEL") ? getenv("TLS_RL_SECURITY_LEVEL") : "L1");

    if (!load_manifest(manifest, &state)) {
        fprintf(stderr, "failed to load manifest: %s\n", manifest);
        goto out;
    }
#ifdef CATS_CONTEXT_ACQUISITION
    {
        struct cats_config config = cats_default_config();
        config.default_bw_mbps = state.bandwidth_mbps;
        config.default_loss = env_double("CATS_DEFAULT_LOSS", 0.0);
        config.ewma_alpha = env_double("CATS_EWMA_ALPHA", 0.2);
        state.acquisition = cats_context_new(config);
        if (!state.acquisition) goto out;
        for (int i = 0; i < state.count; i++)
            if (cats_sign_init(state.acquisition, i, state.candidates[i].sign_ms)) goto out;
        const char *history = getenv("CATS_BW_HISTORY");
        if (history && cats_bw_load(state.acquisition, history))
            fprintf(stderr, "BW history unavailable; using explicit default until valid observations arrive\n");
        if (cats_sampler_start(state.acquisition)) goto out;
        *(void **)(&state.sign_timer_begin) = dlsym(RTLD_DEFAULT, "cats_sign_timer_begin");
        *(void **)(&state.sign_timer_end) = dlsym(RTLD_DEFAULT, "cats_sign_timer_end");
        if (!state.sign_timer_begin || !state.sign_timer_end) {
            fprintf(stderr, "Acquisition build requires LD_PRELOAD=libcats_sign_timer.so\n");
            goto out;
        }
        state.sign_timer_begin();
        uint64_t count;
        state.sign_timer_end(&count); /* resolve hooks before accepting connections */
    }
#endif
    if (!OSSL_PROVIDER_set_default_search_path(NULL, provider_path))
        goto out;
    defprov = OSSL_PROVIDER_load(NULL, "default");
    oqsprov = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if (defprov == NULL || (oqsprov == NULL && require_oqsprovider()))
        goto out;
    if (oqsprov == NULL)
        ERR_clear_error();
    populate_sigalg_codepoints(&state, defprov);
    populate_sigalg_codepoints(&state, oqsprov);

    ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL)
        goto out;
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_cert_list(ctx, 512 * 1024);
    if (!is_default_group(group) && !SSL_CTX_set1_groups_list(ctx, group))
        goto out;
    SSL_CTX_set_cert_cb(ctx, cert_cb, &state);
    SSL_CTX_set_msg_callback(ctx, tls_message_cb);
    SSL_CTX_set_msg_callback_arg(ctx, &state);

    listen_fd = make_listen_socket(port);
    if (listen_fd < 0) {
        perror("listen");
        goto out;
    }
    fprintf(stderr, "READY port=%s candidates=%d\n", port, state.count);
    while (naccept <= 0 || accepted < naccept) {
        int fd = accept(listen_fd, NULL, NULL);
        SSL *ssl;
        double start;
        double end;
        double observed_rtt_ms;
        double observed_loss_percent;
        long observed_window_size;
        if (fd < 0) {
            if (errno == EINTR)
                continue;
            perror("accept");
            goto out;
        }
        state.last_selected = NULL;
#ifdef CATS_CONTEXT_ACQUISITION
        state.acquisition_ns = 0;
        state.acquisition_valid = 0;
        memset(&state.acquired, 0, sizeof(state.acquired));
#endif
        state.connection_serial++;
        state.last_certificate_message_ms = 0.0;
        state.last_sign_phase_ms = 0.0;
        state.last_wbio_pending_before_certificate = 0;
        state.last_wbio_pending_before_certverify = 0;
        state.last_observed_server_hello_bytes = 0;
        state.last_observed_encrypted_extensions_bytes = 0;
        state.last_observed_certificate_bytes = 0;
        ssl = SSL_new(ctx);
        if (ssl == NULL) {
            close(fd);
            goto out;
        }
        SSL_set_fd(ssl, fd);
#ifdef CATS_CONTEXT_ACQUISITION
        if (cats_track(state.acquisition, fd)) {
            SSL_free(ssl); close(fd); goto out;
        }
        state.sign_timer_begin();
#endif
        start = now_ms();
        if (SSL_accept(ssl) == 1) {
            end = now_ms();
            tcp_context(
                fd, state.fallback_rtt_ms, state.fallback_window_size,
                &observed_rtt_ms, &observed_window_size, &observed_loss_percent);
            printf("status ok algorithm=%s handshake_ms=%.3f sign_phase_ms=%.3f loss_percent=%.6f estimated_tls_ms=%.3f server_flight_bytes=%ld extra_rounds=%d I_tail=%d certificate_start_offset=%ld certificate_message_bytes=%ld certificate_tail_bytes=%ld observed_server_hello_bytes=%ld observed_encrypted_extensions_bytes=%ld observed_certificate_bytes=%ld wbio_pending_before_certificate=%ld wbio_pending_before_certverify=%ld tail_delay_ms=%.3f\n",
                state.last_selected ? state.last_selected->algorithm : "",
                end - start,
                state.last_sign_phase_ms,
                observed_loss_percent,
                state.last_score_ms,
                state.last_server_flight_bytes,
                state.last_extra_rounds,
                state.last_i_tail,
                state.last_certificate_start_offset,
                state.last_certificate_message_bytes,
                state.last_certificate_tail_bytes,
                state.last_observed_server_hello_bytes,
                state.last_observed_encrypted_extensions_bytes,
                state.last_observed_certificate_bytes,
                state.last_wbio_pending_before_certificate,
                state.last_wbio_pending_before_certverify,
                state.last_tail_delay_ms);
            fflush(stdout);
            rl_observe(&state, 1, end - start, state.last_sign_phase_ms, observed_loss_percent);
        } else {
            fprintf(stderr, "SSL_accept failed\n");
            ERR_print_errors_fp(stderr);
            tcp_context(
                fd, state.fallback_rtt_ms, state.fallback_window_size,
                &observed_rtt_ms, &observed_window_size, &observed_loss_percent);
            rl_observe(&state, 0, 0.0, state.last_sign_phase_ms, observed_loss_percent);
        }
#ifdef CATS_CONTEXT_ACQUISITION
        {
            uint64_t count = 0;
            uint64_t sign_ns = state.sign_timer_end(&count);
            /* Resumed/failed handshakes must not insert a zero observation. */
            if (state.last_selected && count == 1)
                cats_sign_update(state.acquisition,
                    (size_t)(state.last_selected - state.candidates), sign_ns / 1000000.0);
            cats_untrack(state.acquisition, fd);
            printf("CONTEXT acquisition_valid=%d acquisition_ns=%llu actual_sign_ns=%llu sign_calls=%llu bw_mbps=%.6f bw_history=%d loss_probability=%.9f loss_history=%d selected_sign_estimate_ms=%.9f\n",
                state.acquisition_valid, (unsigned long long)state.acquisition_ns, (unsigned long long)sign_ns,
                (unsigned long long)count, state.acquired.bw_mbps,
                state.acquired.bw_from_history, state.acquired.loss_probability,
                state.acquired.loss_from_history,
                state.last_selected ? state.last_selected->sign_ms : -1.0);
            fflush(stdout);
        }
#endif
        SSL_free(ssl);
        close(fd);
        accepted++;
    }
    rc = 0;

out:
#ifdef CATS_CONTEXT_ACQUISITION
    if (state.acquisition) {
        const char *history = getenv("CATS_BW_HISTORY");
        if (history && cats_bw_save(state.acquisition, history))
            fprintf(stderr, "BW history checkpoint failed\n");
        cats_context_free(state.acquisition);
    }
#endif
    if (listen_fd >= 0)
        close(listen_fd);
    SSL_CTX_free(ctx);
    if (oqsprov != NULL)
        OSSL_PROVIDER_unload(oqsprov);
    if (defprov != NULL)
        OSSL_PROVIDER_unload(defprov);
    return rc;
}
