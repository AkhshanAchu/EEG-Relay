"""egi_relay.py - read EEG from the Mac relay and decode it.

The client must be on the 10.10.10.x network.

    from egi_relay import read_eeg
    data = read_eeg(seconds=10)
    data['eeg_uV']        # (n_samples, 128) float32, microvolts
    data['fs']            # samples per second

Continuous use:

    from egi_relay import stream_eeg
    for chunk in stream_eeg(chunk_seconds=1):
        process(chunk['eeg_uV'])

Output (a dict):
    eeg_uV           float32 (n, 128)  EEG in microvolts, columns E1..E128
    counter          int64   (n,)      amp sample counter (+1 per sample)
    status           uint32  (n,)      status / digital-input word (0xFFFF1F00 = idle)
    aux              int32   (n, 7)    aux / monitor channels, raw counts
    fs               float             sample rate in Hz (from the counter, e.g. 250.0)
    ch_names         list of str       ['E1', ..., 'E128']
    start_time       float             Unix time of the first sample (Mac capture clock)
    missing_samples  int               samples lost in transit (counter gaps)
"""
import socket
import struct
import time

import numpy as np

HOST, PORT = '10.10.10.41', 9000      # Mac relay
AMP_IP, AMP_PORT = '10.10.10.51', 9879
UV_PER_COUNT = 0.00015522042          # tentative NA400 scale; confirm against an .mff export
CH_NAMES = ['E%d' % i for i in range(1, 129)]
_REC = 1264
_MARK = b'\x87\x65\x43\x21'


class _Decoder:
    """pcap byte stream -> amp TCP stream -> 1264-byte sample records."""

    def __init__(self):
        self.buf = bytearray()          # unparsed pcap bytes
        self.stream = bytearray()       # reassembled amp data not yet framed
        self.e = None
        self.next_seq = None
        self.last_ts = None             # capture time of the newest amp packet
        self.amp_ip = bytes(int(x) for x in AMP_IP.split('.'))

    def feed(self, data):
        self.buf += data
        b, pos = self.buf, 0
        if self.e is None:
            if len(b) < 24:
                return []
            magic = bytes(b[:4])
            if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'):
                self.e = '<'
            elif magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'):
                self.e = '>'
            else:
                raise ValueError('relay did not send a pcap stream')
            pos = 24
        while pos + 16 <= len(b):
            sec, usec, incl = struct.unpack(self.e + 'III', b[pos:pos + 12])
            if pos + 16 + incl > len(b):
                break
            self._packet(bytes(b[pos + 16:pos + 16 + incl]), sec + usec / 1e6)
            pos += 16 + incl
        del b[:pos]
        return self._frame()

    def _packet(self, f, ts):
        if len(f) < 54 or f[12:14] != b'\x08\x00':          # Ethernet + IPv4 only
            return
        ip = f[14:]
        if ip[9] != 6 or ip[12:16] != self.amp_ip:          # TCP from the amp
            return
        ihl = (ip[0] & 15) * 4
        tcp = ip[ihl:struct.unpack('!H', ip[2:4])[0]]
        sport, seq = struct.unpack('!H2xI', tcp[:8])
        payload = tcp[(tcp[12] >> 4) * 4:]
        if sport != AMP_PORT or not payload:
            return
        if self.next_seq is None:
            self.next_seq = seq
        ahead = (seq - self.next_seq) & 0xFFFFFFFF
        if ahead >= 1 << 31:                                # already have (part of) it
            overlap = (self.next_seq - seq) & 0xFFFFFFFF
            if overlap >= len(payload):
                return
            payload = payload[overlap:]
        self.stream += payload                              # a hole is resynced by _frame
        self.next_seq = (seq + len(tcp) - (tcp[12] >> 4) * 4) & 0xFFFFFFFF
        self.last_ts = ts

    def _frame(self):
        s, pos, out = self.stream, 0, []
        ok = lambda p: s[p + 42:p + 46] == _MARK and s[p + 69:p + 73] == _MARK
        while pos + _REC <= len(s):
            if ok(pos):                                     # a sample record
                out.append(bytes(s[pos:pos + _REC]))
                pos += _REC
            elif pos + 16 + _REC > len(s):
                break
            elif ok(pos + 16):                              # 16-byte block header
                pos += 16
            else:                                           # lost alignment: find next record
                i = s.find(_MARK, pos + 1)
                while i != -1 and not (i - 42 > pos and s[i + 27:i + 31] == _MARK):
                    i = s.find(_MARK, i + 1)
                if i == -1:
                    pos = max(pos, len(s) - _REC - 16)
                    break
                pos = i - 42
        del s[:pos]
        return out


def _decode(records, t_first, t_last, dedupe=True, prev=None):
    """prev = last counter of the previous chunk (so chunks neither overlap nor hide gaps)."""
    a = np.frombuffer(b''.join(records), np.uint8).reshape(-1, _REC)
    counter = a[:, 25:29].copy().view('<u4').ravel().astype(np.int64)
    if dedupe:                                  # amp repeats records at lower sample rates
        keep = np.diff(np.r_[counter[0] - 1 if prev is None else prev, counter]) != 0
        a, counter = a[keep], counter[keep]
    steps = np.diff(counter if prev is None else np.r_[prev, counter])
    span = t_last - t_first
    fs = float((counter[-1] - counter[0]) / span) if span > 0.5 and len(counter) > 1 else float('nan')
    for std in (250, 500, 1000, 2000, 4000, 8000):             # snap to a standard rate
        if abs(fs - std) < 0.1 * std:
            fs = float(std)
    return {
        'eeg_uV': (a[:, 80:592].copy().view('<i4') * UV_PER_COUNT).astype(np.float32),
        'counter': counter,
        'status': a[:, 0:4].copy().view('>u4').ravel().astype(np.uint32),
        'aux': a[:, 1104:1136].copy().view('<i4')[:, [0, 1, 2, 3, 4, 5, 7]] >> 8,
        'fs': fs,
        'ch_names': CH_NAMES,
        'start_time': t_first,
        'missing_samples': int((steps[steps > 1] - 1).sum()),
    }


def stream_eeg(chunk_seconds=1.0, host=HOST, port=PORT, warmup=1.0, dedupe=True):
    """Yield a decoded dict (same keys as read_eeg) every `chunk_seconds`, forever.
    The first `warmup` seconds are dropped: on connect the relay sends some old data first."""
    sock = socket.create_connection((host, port), timeout=5)
    sock.settimeout(5)
    dec, recs, t_conn, t_first, t_chunk, prev = _Decoder(), [], time.time(), None, None, None
    try:
        while True:
            data = sock.recv(262144)
            if not data:
                raise ConnectionError('relay closed the connection')
            new = dec.feed(data)
            now = time.time()
            if now - t_conn < warmup or not new:
                continue
            if t_first is None:
                t_first, t_chunk = dec.last_ts, now
            recs += new
            if now - t_chunk >= chunk_seconds:
                chunk = _decode(recs, t_first, dec.last_ts, dedupe, prev)
                recs, t_first, t_chunk = [], dec.last_ts, now
                if len(chunk['counter']):
                    prev = chunk['counter'][-1]
                    yield chunk
    except socket.timeout:
        raise TimeoutError('no data from %s:%d for 5 s - is the relay running and the amp '
                           'acquiring? (the relay serves one client at a time)' % (host, port))
    finally:
        sock.close()


def read_eeg(seconds=10.0, host=HOST, port=PORT, warmup=1.0, dedupe=True):
    """Read `seconds` of EEG from the relay and return it decoded (output keys: see top of file)."""
    for chunk in stream_eeg(seconds, host, port, warmup, dedupe):
        return chunk


if __name__ == '__main__':
    import sys
    secs = float(sys.argv[1]) if len(sys.argv) > 1 else 10
    d = read_eeg(secs)
    print('samples:', d['eeg_uV'].shape, ' fs:', d['fs'], 'Hz  missing:', d['missing_samples'],
          ' counter:', d['counter'][0], '->', d['counter'][-1])
    np.savez('eeg.npz', **{k: np.asarray(v) for k, v in d.items()})
    print('saved eeg.npz')
