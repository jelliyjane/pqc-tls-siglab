#!/usr/bin/env python3
"""Mechanical timing-only instrumentation of a DISPOSABLE OpenSSL 3.5.7 copy.

No installed library is modified. Four weak hook calls bracket signature-list
preparation and the certificate-callback/native selection block, identically
for the stock-order and CATS experiments. Fails if source anchors differ.
"""
import argparse
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('source', type=Path)
a = p.parse_args()
f = a.source / 'ssl/statem/statem_srvr.c'
s = f.read_text()
pairs = [
    ('#include <stdio.h>', '#include <stdio.h>\nextern void cats_selection_mark(int) __attribute__((weak));'),
    ('    if (!s->hit && !tls1_set_server_sigalgs(s)) {',
     '    if (cats_selection_mark) cats_selection_mark(0);\n    if (!s->hit && !tls1_set_server_sigalgs(s)) {'),
    ('    if (!s->hit\n        && s->version >= TLS1_VERSION',
     '    if (cats_selection_mark) cats_selection_mark(1);\n\n    if (!s->hit\n        && s->version >= TLS1_VERSION'),
    ('            /* Let cert callback update server certificates if required */',
     '            if (cats_selection_mark) cats_selection_mark(2);\n            /* Let cert callback update server certificates if required */'),
    ('                /* check whether we should disable session resumption */',
     '                if (cats_selection_mark) cats_selection_mark(3);\n                /* check whether we should disable session resumption */'),
]
for old, new in pairs:
    if s.count(old) != 1:
        raise SystemExit(f'Expected exactly one unmodified source anchor: {old}')
    s = s.replace(old, new)
f.write_text(s)
print('Instrumented five anchors in disposable OpenSSL statem_srvr.c')
