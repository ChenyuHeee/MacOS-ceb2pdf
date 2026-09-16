#!/usr/bin/env python3
"""CEB -> PDF proof of concept.  Verified against samples/ceb/*.ceb.

Pipeline:  container -> Founder-RC4 (whole body) -> RSA-unwrap 3DES key
           -> 3DES-OFB per stream -> strip /Encrypt -> PDF

Status: container/RC4/RSA/3DES all verified.  Image (ImageMask) streams
decrypt perfectly.  FlateDecode page-content streams still do not inflate
-- see FINDINGS.md "Open problem".
"""
import struct, re, sys, zlib
from Crypto.Cipher import DES3

# RSA-512 constants lifted from Chingliu/ceb2pdf (little-endian BIGNUM limbs)
KEY_N = bytes.fromhex('91437cd83d0722ce410bd96ca80cff34895a315e25128bc32529d5f614e45097'
                      'e12e450c68daf1ad8d8e740ab708564f4f317b8012c44856de567d58522497db')
KEY_E = bytes.fromhex('f384ff17a8165a0eceb0a526f54412a99a88ec6968b5e14faf7a08bee92ffde3'
                      '5b18c54697d86ecc639700e642bc91757e522dc5ef4c95ccd746d2d259db00c5')

SEC_PDF, SEC_RC4KEY, SEC_WRAPPEDKEY, SEC_ALGO = 3, 4, 5, 16


def parse_container(data):
    assert data[:12] == b'Founder CEB\0', 'not a Founder CEB file'
    count = struct.unpack_from('<H', data, 0x14)[0]
    secs = {}
    for i in range(count):
        p = 0x1F + i * 17
        off, ln = struct.unpack_from('<II', data, p)
        secs[data[p + 8]] = (off, ln)
    return secs


class FounderRC4:
    """RC4 as shipped by Founder -- note the swapped-assignment bug on the
    third line of the PRGA (`S[y] = S[t]` instead of `S[y] = t`).  It
    collapses the permutation, so ~97% of keystream bytes come out 0x45."""

    def __init__(self, key):
        seed = [b | 0xAA for b in key]
        st = list(range(256))
        i2 = 0
        for c in range(256):
            i2 = (seed[c % len(key)] + st[c] + i2) & 0xFF
            st[c], st[i2] = st[i2], st[c]
        self.st, self.x, self.y = st, 0, 0

    def crypt(self, buf):
        st, x, y = self.st, self.x, self.y
        for n in range(len(buf)):
            x = (x + 1) & 0xFF
            y = (st[x] + y) & 0xFF
            t = st[x]
            st[x] = st[y]
            st[y] = st[t]              # <- the bug, reproduced faithfully
            buf[n] ^= st[(st[x] + st[y]) & 0xFF]
        self.x, self.y = x, y


def unwrap_3des_key(wrapped):
    n = int.from_bytes(KEY_N, 'little')
    e = int.from_bytes(KEY_E, 'little')
    c = int.from_bytes(wrapped, 'little')
    m = pow(c, e, n).to_bytes(64, 'little')
    ln = int.from_bytes(m[:4], 'little')
    assert 0 < ln <= 32, f'implausible key length {ln}'
    return m[4:4 + ln]


def convert(path, out):
    data = open(path, 'rb').read()
    secs = parse_container(data)
    off, ln = secs[SEC_PDF]
    pdf = bytearray(data[off:off + ln])

    rc4_key = data[slice(*_span(secs[SEC_RC4KEY]))]
    for p in range(0, len(pdf), 65536):          # state reset every 64 KiB
        blk = pdf[p:p + 65536]
        FounderRC4(rc4_key).crypt(blk)
        pdf[p:p + 65536] = blk
    assert pdf[:5] == b'%PDF-', 'RC4 layer failed'

    algo = int.from_bytes(data[slice(*_span(secs[SEC_ALGO]))], 'little')
    key = data[slice(*_span(secs[SEC_WRAPPEDKEY]))]
    key = unwrap_3des_key(key) if algo & 0x80000000 else key

    for start, length in _streams(bytes(pdf)):
        buf = bytearray()
        for p in range(0, length, 256):          # fresh IV every 256 bytes
            chunk = bytes(pdf[start + p:start + min(p + 256, length)])
            buf += DES3.new(key, DES3.MODE_OFB, iv=key[:8]).decrypt(chunk)
        pdf[start:start + length] = buf

    i = bytes(pdf).rfind(b'/Encrypt')            # blank it out, same width,
    j = bytes(pdf).find(b'R', i) + 1             # so every xref offset holds
    pdf[i:j] = b' ' * (j - i)
    open(out, 'wb').write(bytes(pdf))
    return bytes(pdf)


def _span(sec):
    off, ln = sec
    return off, off + ln


def _streams(pdf):
    """Reproduce the reference implementation's naive keyword scan."""
    pos = 0
    while True:
        i = pdf.find(b'stream', pos)
        if i < 0:
            break
        if pdf[i - 1:i] == b'd':                 # skip "endstream"
            pos = i + 6
            continue
        end = pdf.find(b'endstream', i)
        if end < 0:
            break
        s = i + 6
        while pdf[s:s + 1] in (b'\r', b'\n'):
            s += 1
        yield s, end - s
        pos = end + 9


if __name__ == '__main__':
    convert(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else 'out.pdf')
    print('wrote', sys.argv[2] if len(sys.argv) > 2 else 'out.pdf')
