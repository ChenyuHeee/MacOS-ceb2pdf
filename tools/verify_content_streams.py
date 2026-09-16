#!/usr/bin/env python3
"""Evidence harness for the CEB per-stream cipher.

Establishes, on a real sample, that the second encryption layer is
3DES-CFB with 64-bit segments re-keyed every 256 bytes -- and that the
previously assumed 3DES-OFB is wrong but *unfalsifiable* by the test that
was originally used to confirm it.

    python3 tools/verify_content_streams.py samples/ceb/<file>.ceb

Sections printed:
  [1] mode sweep       -- inflate success rate per (mode, chunk size)
  [2] why OFB "passed" -- the two modes are provably equal on a prefix
  [3] per-stream table -- every /FlateDecode object, both modes
  [4] glyph render     -- an ImageMask bitmap under both modes
  [5] end-to-end       -- rebuild the PDF and pull text out of page 1

Requires pycryptodome.  Section 5 prints extracted text only if pypdf or
PyMuPDF is importable; the inflate evidence in [1]-[4] needs neither.
"""
import re
import sys
import zlib

from Crypto.Cipher import DES3

sys.path.insert(0, __file__.rsplit('/', 1)[0])
import ceb_poc as P

CHUNK = 256


def modes():
    """The candidate stream ciphers, as (label, factory) pairs."""
    return [
        ('OFB', lambda k: DES3.new(k, DES3.MODE_OFB, iv=k[:8])),
        ('CFB64', lambda k: DES3.new(k, DES3.MODE_CFB, iv=k[:8], segment_size=64)),
        ('CFB8', lambda k: DES3.new(k, DES3.MODE_CFB, iv=k[:8], segment_size=8)),
    ]


def decrypt(ct, factory, key, chunk=CHUNK):
    """Decrypt with the cipher state reset every `chunk` bytes."""
    out = bytearray()
    for p in range(0, len(ct), chunk):
        out += factory(key).decrypt(ct[p:p + chunk])
    return bytes(out)


def rc4_layer(path):
    """Strip the container and undo the Founder-RC4 layer.  Returns (body, key)."""
    data = open(path, 'rb').read()
    secs = P.parse_container(data)
    off, ln = secs[P.SEC_PDF]
    body = bytearray(data[off:off + ln])
    ko, kl = secs[P.SEC_RC4KEY]
    for p in range(0, len(body), 65536):
        blk = body[p:p + 65536]
        P.FounderRC4(data[ko:ko + kl]).crypt(blk)
        body[p:p + 65536] = blk
    assert body[:5] == b'%PDF-', 'RC4 layer failed'

    ao, al = secs[P.SEC_ALGO]
    algo = int.from_bytes(data[ao:ao + al], 'little')
    wo, wl = secs[P.SEC_WRAPPEDKEY]
    key = data[wo:wo + wl]
    key = P.unwrap_3des_key(key) if algo & 0x80000000 else key
    print('algorithm id  0x%08x   (high bit = RSA-wrapped key, low word = mode)' % algo)
    print('3DES key      %s' % key.hex())
    return bytes(body), key


def streams(pdf):
    """Yield (objnum, start, length, dict_bytes) for every stream object."""
    for m in re.finditer(rb'(?<![0-9])(\d+)\s+(\d+)\s+obj\b', pdf):
        endobj = pdf.find(b'endobj', m.end())
        si = pdf.find(b'stream', m.end())
        if si < 0 or (0 <= endobj < si):
            continue
        d = pdf[m.end():si]
        s = si + 6
        while pdf[s:s + 1] in (b'\r', b'\n'):
            s += 1
        yield int(m.group(1)), s, pdf.find(b'endstream', s) - s, d


def inflates(pt):
    try:
        return len(zlib.decompress(pt))
    except zlib.error:
        return None


def main(path):
    pdf, key = rc4_layer(path)
    all_streams = list(streams(pdf))
    flate = [s for s in all_streams if b'/FlateDecode' in s[3]]
    masks = [s for s in all_streams if b'ImageMask' in s[3]]
    print('streams %d   /FlateDecode %d   /ImageMask %d\n'
          % (len(all_streams), len(flate), len(masks)))

    print('[1] mode sweep -- /FlateDecode streams that inflate')
    for label, factory in modes():
        row = []
        for chunk in (8, 16, 32, 64, 128, 256, 512, 1 << 30):
            ok = sum(1 for _, s, n, _ in flate
                     if inflates(decrypt(pdf[s:s + n], factory, key, chunk)))
            row.append('%s:%d' % ('all' if chunk >> 20 else chunk, ok))
        print('    %-6s %s   / %d' % (label, '  '.join(row), len(flate)))

    print('\n[2] why the OFB hypothesis survived its own test')
    table = dict(modes())
    ofb, cfb = table['OFB'], table['CFB64']
    _, s, n, _ = flate[0]
    a, b = decrypt(pdf[s:s + n], ofb, key), decrypt(pdf[s:s + n], cfb, key)
    firsts = sorted({next((i for i in range(len(x)) if x[i] != y[i]), None)
                     for x, y in ((a[p:p + CHUNK], b[p:p + CHUNK])
                                  for p in range(0, len(a), CHUNK))})
    print('    OFB and CFB64 decrypt block 1 of every chunk identically,')
    print('    because both compute P1 = C1 ^ E(IV).  They diverge only at')
    print('    byte 8.  First differing offset within each 256-byte chunk: %s' % firsts)
    print('    A zlib header is 2 bytes, so `78 9c` appears under both modes.')
    print('    The deflate dynamic-Huffman code-length table straddles byte 8,')
    print('    which is exactly where "invalid code lengths set" comes from.')
    same = [(num, n2) for num, s2, n2, _ in masks
            if decrypt(pdf[s2:s2 + n2], ofb, key) == decrypt(pdf[s2:s2 + n2], cfb, key)]
    print('    The modes also agree while the plaintext stays zero: C_i = E(C_{i-1})')
    print('    = O_i whenever P_1..P_{i-1} = 0.  So a bitmap with blank leading')
    print('    rows decrypts the same either way -- it cannot tell them apart.')
    print('    %d of %d ImageMask streams are mode-ambiguous: %s'
          % (len(same), len(masks), ['obj%d(%dB)' % (o, l) for o, l in same[:6]]))

    print('\n[3] per-stream table')
    contents = {int(x) for x in re.findall(rb'/Contents (\d+) 0 R', pdf)}
    fontfile = {int(x) for g in (rb'/FontFile', rb'/FontFile2', rb'/FontFile3')
                for x in re.findall(g + rb' (\d+) 0 R', pdf)}
    for num, s, n, d in flate:
        kind = 'page' if num in contents else 'font' if num in fontfile else 'misc'
        r = {lb: inflates(decrypt(pdf[s:s + n], f, key)) for lb, f in modes()}
        note = ''
        m = re.search(rb'/Length1 (\d+)', d)
        if m:
            note = '  /Length1=%s %s' % (m.group(1).decode(),
                                         'MATCHES' if r['CFB64'] == int(m.group(1)) else 'differs')
        print('    obj %-5d %-4s len=%-6d OFB=%-6s CFB64=%-6s%s'
              % (num, kind, n, r['OFB'] or 'fail', r['CFB64'] or 'fail', note))

    print('\n[4] glyph render (ImageMask, both modes)')
    for num, s, n, d in masks:
        w = int(re.search(rb'/Width (\d+)', d).group(1))
        h = int(re.search(rb'/Height (\d+)', d).group(1))
        if not (40 <= w <= 60 and h >= 60):
            continue
        rowb = (w + 7) // 8
        for label, factory in (('OFB', ofb), ('CFB64', cfb)):
            data = decrypt(pdf[s:s + n], factory, key)
            print('    obj %d  %dx%d  %s' % (num, w, h, label))
            for r in range(h - 18, h, 2):
                row = data[r * rowb:(r + 1) * rowb]
                bits = ''.join('#' if (byte >> (7 - i)) & 1 else '.'
                               for byte in row for i in range(8))
                print('      ' + bits[:w])
        break

    print('\n[5] end-to-end')
    out = path.rsplit('/', 1)[-1] + '.verify.pdf'
    P.convert(path, out)
    print('    wrote %s' % out)
    try:
        import pypdf
        txt = pypdf.PdfReader(out).pages[0].extract_text()
    except Exception:
        try:
            import fitz
            txt = fitz.open(out)[0].get_text()
        except Exception as e:
            print('    (no PDF text extractor available: %s)' % e)
            return
    print('    page 1 text: %s' % ' '.join(txt.split())[:120])


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1])
