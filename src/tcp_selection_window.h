#ifndef TCP_SELECTION_WINDOW_H
#define TCP_SELECTION_WINDOW_H

#include <limits.h>
#include <stdint.h>

/* Linux snd_cwnd is in segments; snd_wnd is already scaled bytes.
 * Zero rwnd is a closed window, not missing telemetry or a 16-KiB fallback.
 * This is an outstanding-data limit, not remaining send credit. */
static inline long tcp_selection_window(uint32_t cwnd_segments,
                                        uint32_t snd_mss,
                                        uint32_t peer_rwnd_bytes)
{
    uint64_t cwnd = (uint64_t)cwnd_segments * snd_mss;
    uint64_t window;
    if (cwnd == 0)
        return -1;
    window = cwnd < peer_rwnd_bytes ? cwnd : peer_rwnd_bytes;
    return window <= LONG_MAX ? (long)window : -1;
}

#endif
