"""Connection-supplied TCP window, in bytes (not TLS record size).

The window is an outstanding-data limit, not the remaining send allowance.
Round counts freeze the selection-time window and remain a size-based proxy.
"""
from numbers import Integral


def positive_window(value):
    if isinstance(value, bool) or not isinstance(value, Integral) or value <= 0:
        raise ValueError('TCP window must be a positive integer in bytes; no fixed fallback')
    return int(value)


def resolve_window(*, window_size_bytes=None, cwnd_bytes=None, rwnd_bytes=None):
    if window_size_bytes is not None:
        if cwnd_bytes is not None or rwnd_bytes is not None:
            raise ValueError('Supply W or both cwnd/rwnd, not both representations')
        return positive_window(window_size_bytes)
    # rwnd must already include negotiated TCP window scaling. Linux cwnd
    # must be converted from segments with snd_cwnd * snd_mss by the caller.
    return min(positive_window(cwnd_bytes), positive_window(rwnd_bytes))


def additional_rounds(flight_bytes, window_size_bytes):
    window = positive_window(window_size_bytes)
    if isinstance(flight_bytes, bool) or not isinstance(flight_bytes, Integral) or flight_bytes < 0:
        raise ValueError('Flight size must be a nonnegative integer in bytes')
    return max(0, (int(flight_bytes) + window - 1) // window - 1)

