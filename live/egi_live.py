"""EGI Live - realtime viewer / recorder for the EGI amp TCP data stream.

Run:        python egi_live.py
Convert:    python egi_live.py --convert recordings/egi_XXXX.raw      (raw -> .npz)
Self-test:  python egi_live.py --selftest ../abba.pcap OUTDIR SECONDS  (offscreen screenshots)

Stream format (decoded from abba.pcap):
  block  = 8-byte amp id + 8-byte length (BE) + N x 1264-byte records, one record per sample @ 1000 Hz
  record [0:4] status/DIN (BE u32) | [25:29] counter (LE u32) | sync 87 65 43 21 at 42 and 69
         [80:592] 128 x LE int32 EEG (E1..E128) | [1104:1136] 8 x LE int32 aux (24-bit << 8)
"""
import sys, os, socket, struct, threading, queue, time, json
from collections import deque
import numpy as np
from scipy import signal
if os.name == 'nt':
    # Conda envs ship their own icuuc.dll on PATH; Qt6 needs Windows' ICU. Preload the system one.
    import ctypes
    for _dll in ('icuuc.dll', 'icuin.dll'):
        try: ctypes.WinDLL(os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', _dll))
        except OSError: pass
from PyQt6 import QtCore, QtWidgets, QtGui
import pyqtgraph as pg

FS = 1000
NCH = 128
REC = 1264
MARK = b'\x87\x65\x43\x21'
DEFAULT_UV = 0.00015522042          # tentative NA400-series uV/count - verify against an .mff export
CH = [f'E{i}' for i in range(1, NCH + 1)]
AUX_SLOTS = [0, 1, 2, 3, 4, 5, 7]
# Approximate HydroCel-128 regions (used only for the heuristic inferences)
EYE_ABOVE, EYE_BELOW = [25, 8], [127, 126]
POSTERIOR = [70, 71, 75, 76, 83]
BANDS = [('delta', 1, 4), ('theta', 4, 8), ('alpha', 8, 13), ('beta', 13, 30), ('gamma', 30, 45)]
GROUPS = {
    'All 128': list(range(NCH)),
    'E1-E32': list(range(0, 32)), 'E33-E64': list(range(32, 64)),
    'E65-E96': list(range(64, 96)), 'E97-E128': list(range(96, 128)),
    'Eye / frontal': [c - 1 for c in (8, 14, 21, 25, 126, 127)],
    'Posterior': [c - 1 for c in POSTERIOR],
}
COLORS = {'ok': '#2e7d32', 'line': '#c9a400', 'noisy': '#ef6c00', 'flat': '#c62828'}
BP_SOS = signal.butter(4, [1, 40], 'bandpass', fs=FS, output='sos')
VEOG_SOS = signal.butter(2, [0.5, 10], 'bandpass', fs=FS, output='sos')


# ----------------------------------------------------------------------------- stream parsing
class Framer:
    """Turns an arbitrary byte stream into 1264-byte records (resyncs on the sync markers)."""
    def __init__(self):
        self.buf = bytearray(); self.resyncs = 0

    @staticmethod
    def _is_rec(b, p):
        return b[p + 42:p + 46] == MARK and b[p + 69:p + 73] == MARK

    def feed(self, data):
        self.buf += data
        b, n, pos, out = self.buf, len(self.buf), 0, []
        while pos + REC <= n:
            if self._is_rec(b, pos):
                out.append(bytes(b[pos:pos + REC])); pos += REC; continue
            if pos + 16 + REC > n:
                break                                    # need more bytes to decide
            if self._is_rec(b, pos + 16):
                pos += 16; continue                      # block header
            i, found = b.find(MARK, pos + 1), None       # lost framing -> search
            while i != -1:
                s = i - 42
                if s > pos and s + 73 <= n and b[s + 69:s + 73] == MARK:
                    found = s; break
                i = b.find(MARK, i + 1)
            self.resyncs += 1
            if found is None:
                pos = max(pos, n - REC - 16); break
            pos = found
        del self.buf[:pos]
        return np.frombuffer(b''.join(out), np.uint8).reshape(-1, REC) if out else None


def decode(A):
    counter = np.frombuffer(A[:, 25:29].tobytes(), '<u4').astype(np.int64)
    status = np.frombuffer(A[:, 0:4].tobytes(), '>u4')
    eeg = np.frombuffer(A[:, 80:80 + 4 * NCH].tobytes(), '<i4').reshape(-1, NCH)
    aux = (np.frombuffer(A[:, 1104:1136].tobytes(), '<i4').reshape(-1, 8) >> 8)[:, AUX_SLOTS]
    return counter, status, eeg, aux


def pcap_stream_bytes(path, sport=None):
    """Reassemble the largest TCP flow (optionally from source port `sport`) of a classic pcap."""
    d = memoryview(open(path, 'rb').read())
    magic = bytes(d[:4])
    if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'): e = '<'
    elif magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'): e = '>'
    else: raise ValueError('Only classic .pcap is supported (in Wireshark: Save As -> pcap)')
    link = struct.unpack(e + 'I', d[20:24])[0]
    if link not in (0, 1, 113): raise ValueError(f'Unsupported link type {link}')
    pos, flows = 24, {}
    while pos + 16 <= len(d):
        incl = struct.unpack(e + 'I', d[pos + 8:pos + 12])[0]
        pkt = d[pos + 16:pos + 16 + incl]; pos += 16 + incl
        if link == 1:
            et, off = struct.unpack('!H', pkt[12:14])[0], 14
            if et == 0x8100: et, off = struct.unpack('!H', pkt[16:18])[0], 18
        elif link == 113: et, off = struct.unpack('!H', pkt[14:16])[0], 16
        else: et, off = 0x0800, 4
        if et != 0x0800: continue
        ip = pkt[off:]
        if len(ip) < 20 or ip[9] != 6: continue
        ihl = (ip[0] & 15) * 4; tot = struct.unpack('!H', ip[2:4])[0]
        tcp = ip[ihl:tot]
        sp, dp, seq = struct.unpack('!HHI', tcp[:8])
        thl, flags = (tcp[12] >> 4) * 4, tcp[13]
        pl = tcp[thl:]
        fl = flows.setdefault((bytes(ip[12:16]), sp, bytes(ip[16:20]), dp), {'isn': None, 'segs': {}, 'n': 0})
        if flags & 2: fl['isn'] = seq + 1
        if not len(pl): continue
        if fl['isn'] is None: fl['isn'] = seq
        rel = (seq - fl['isn']) & 0xFFFFFFFF
        if rel not in fl['segs']: fl['segs'][rel] = bytes(pl); fl['n'] += len(pl)
    cands = [k for k in flows if sport is None or k[1] == sport]
    if not cands: raise ValueError('No TCP data flow found in capture')
    fl = flows[max(cands, key=lambda k: flows[k]['n'])]
    out, p = bytearray(), 0
    for rel in sorted(fl['segs']):
        s = fl['segs'][rel]
        if rel + len(s) <= p: continue
        out += s[max(0, p - rel):]; p = rel + len(s)
    return bytes(out)


def _tcp_from_frame(pkt, link):
    """-> (sport, seq, payload) for a TCP/IPv4 frame, else None."""
    try:
        if link == 1:
            et, off = struct.unpack('!H', pkt[12:14])[0], 14
            if et == 0x8100: et, off = struct.unpack('!H', pkt[16:18])[0], 18
        elif link == 113: et, off = struct.unpack('!H', pkt[14:16])[0], 16
        elif link == 0: et, off = 0x0800, 4
        else: return None
        if et != 0x0800: return None
        ip = pkt[off:]
        if len(ip) < 20 or ip[9] != 6: return None
        ihl = (ip[0] & 15) * 4; tot = struct.unpack('!H', ip[2:4])[0]
        tcp = ip[ihl:tot]
        sp, _, seq = struct.unpack('!HHI', tcp[:8])
        return sp, seq, tcp[(tcp[12] >> 4) * 4:]
    except (struct.error, IndexError):
        return None


class PcapStream:
    """Incrementally parses a live pcap byte stream (e.g. `tcpdump -w -` relayed over TCP) and
    returns the in-order TCP payload of the amp's data flow (source port `sport`)."""
    def __init__(self, sport=9879):
        self.buf = bytearray(); self.e = None; self.link = None; self.next_seq = None
        self.sport = sport; self.gaps = 0; self.gap_bytes = 0; self.packets = 0

    def feed(self, data):
        self.buf += data; b = self.buf; pos = 0; out = bytearray()
        if self.e is None:
            if len(b) < 24: return b''
            magic = bytes(b[:4])
            if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'): self.e = '<'
            elif magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'): self.e = '>'
            else: raise ValueError(f'relay is not sending pcap (first bytes {magic.hex()})')
            self.link = struct.unpack(self.e + 'I', b[20:24])[0]; pos = 24
        while pos + 16 <= len(b):
            incl = struct.unpack(self.e + 'I', b[pos + 8:pos + 12])[0]
            if incl > 1 << 20: raise ValueError('pcap stream corrupt (bad record length)')
            if pos + 16 + incl > len(b): break
            r = _tcp_from_frame(bytes(b[pos + 16:pos + 16 + incl]), self.link); pos += 16 + incl
            if not r or r[0] != self.sport or not r[2]: continue
            self.packets += 1
            seq, pl = r[1], r[2]; end = (seq + len(pl)) & 0xFFFFFFFF
            if self.next_seq is None: self.next_seq = seq
            ahead = (seq - self.next_seq) & 0xFFFFFFFF
            if ahead >= 1 << 31:                       # starts before what we already have
                back = (self.next_seq - seq) & 0xFFFFFFFF
                if back >= len(pl): continue           # pure duplicate / retransmission
                pl = pl[back:]
            elif ahead:                                # bytes missing (relay dropped packets)
                self.gaps += 1; self.gap_bytes += ahead
            out += pl; self.next_seq = end
        del b[:pos]
        return bytes(out)


def convert_raw_to_npz(raw_path, uv=DEFAULT_UV, notch=50):
    fr = Framer(); A = fr.feed(open(raw_path, 'rb').read())
    if A is None: raise ValueError('no records found')
    counter, status, eeg, aux = decode(A)
    out = os.path.splitext(raw_path)[0] + '.npz'
    x = eeg * uv
    extra = {}
    if notch:   # zero-phase notch (f0 + 2nd harmonic) on the DC-removed signal; raw kept alongside
        extra['eeg_uV_notched'] = (signal.sosfiltfilt(notch_sos(notch), x - x.mean(0), axis=0)).astype(np.float32)
    np.savez_compressed(out, eeg_uV=x, eeg_counts=eeg, aux_counts=aux, counter=counter, status=status,
                        fs=FS, ch_names=np.array(CH), uv_per_count=uv, notch_hz=notch or 0, **extra)
    return out, len(A), int((np.diff(counter) != 1).sum())


# ----------------------------------------------------------------------------- acquisition thread
class Acquisition(threading.Thread):
    def __init__(self, cfg, q):
        super().__init__(daemon=True)
        self.cfg, self.q = cfg, q
        self.stop_ev = threading.Event()
        self.framer = Framer()
        self.rec_lock = threading.Lock(); self.rec_file = None; self.rec_bytes = 0
        self.bytes_in = 0

    def msg(self, kind, val=None): self.q.put((kind, val))

    def start_recording(self, path):
        with self.rec_lock: self.rec_file = open(path, 'wb'); self.rec_bytes = 0

    def stop_recording(self):
        with self.rec_lock:
            f, self.rec_file = self.rec_file, None
        if f: f.close()

    def _on_bytes(self, data):
        self.bytes_in += len(data)
        with self.rec_lock:
            if self.rec_file: self.rec_file.write(data); self.rec_bytes += len(data)
        A = self.framer.feed(data)
        if A is not None: self.msg('data', A)

    def run(self):
        try:
            {'tcp': self._run_tcp, 'replay': self._run_replay, 'relay': self._run_relay}[self.cfg['mode']]()
        except Exception as ex:
            self.msg('error', f'{type(ex).__name__}: {ex}')
        finally:
            self.stop_recording(); self.msg('stopped')

    def _run_tcp(self):
        c = self.cfg
        self.msg('status', f"Connecting to {c['host']}:{c['port']} ...")
        s = socket.create_connection((c['host'], c['port']), timeout=5)
        s.settimeout(1.0); cmd_sock = None
        if c['send_cmd'] and c['cmd_text'].strip():
            txt = c['cmd_text'].strip().encode() + b'\n'
            if c['cmd_port'] == c['port']:
                s.sendall(txt); self.msg('status', 'Listen command sent on data socket')
            else:
                try:
                    cmd_sock = socket.create_connection((c['host'], c['cmd_port']), timeout=5)
                    cmd_sock.sendall(txt); cmd_sock.settimeout(2)
                    try: rep = cmd_sock.recv(4096)
                    except socket.timeout: rep = b''
                    self.msg('status', f"Command sent on port {c['cmd_port']}, reply: {rep[:120]!r}")
                except OSError as ex:
                    self.msg('status', f"Command port {c['cmd_port']} failed: {ex}")
        self.msg('connected', f"{c['host']}:{c['port']}")
        last, warned = time.time(), False
        ps, first = None, True
        try:
            while not self.stop_ev.is_set():
                try:
                    data = s.recv(262144)
                except socket.timeout:
                    if time.time() - last > 3 and not warned:
                        self.msg('status', 'Connected but no data for 3 s - is the amp acquiring? '
                                           'Try enabling "send listen command".')
                        warned = True
                    continue
                if not data: raise ConnectionError('amp closed the connection')
                last, warned = time.time(), False
                if first:
                    first = False
                    if data[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'):
                        ps = PcapStream(sport=9879); self.pcap = ps
                        self.msg('status', 'This port sends a pcap capture (Mac relay) - decoding it as relay '
                                           'automatically. Next time choose "Mac relay (pcap stream)".')
                if ps is not None:
                    data = ps.feed(data)
                    if not data: continue
                self._on_bytes(data)
        finally:
            s.close()
            if cmd_sock: cmd_sock.close()

    def _run_replay(self):
        c = self.cfg; path = c['file']
        self.msg('status', f'Loading {os.path.basename(path)} ...')
        data = open(path, 'rb').read() if path.lower().endswith(('.raw', '.bin')) else pcap_stream_bytes(path)
        nrec = max(1, data.count(MARK) // 2)
        bps = len(data) / (nrec / FS) * c['speed']
        step = 0.02; chunk = max(REC, int(bps * step))
        self.msg('connected', f'replay {os.path.basename(path)} x{c["speed"]:g}')
        while not self.stop_ev.is_set():
            t0 = time.perf_counter()
            for k, i in enumerate(range(0, len(data), chunk)):
                if self.stop_ev.is_set(): return
                self._on_bytes(data[i:i + chunk])
                dt = t0 + (k + 1) * step - time.perf_counter()
                if dt > 0: time.sleep(dt)
            if not c['loop']: self.msg('status', 'Replay finished'); return
            self.framer = Framer()

    def _run_relay(self):
        """Read the Mac's pcap relay (amp_read.sh equivalent) and extract the amp data flow."""
        c = self.cfg
        self.msg('status', f"Connecting to relay {c['relay_host']}:{c['relay_port']} ...")
        s = socket.create_connection((c['relay_host'], c['relay_port']), timeout=5); s.settimeout(1.0)
        ps = PcapStream(sport=c['port']); self.pcap = ps
        self.msg('connected', f"relay {c['relay_host']}:{c['relay_port']} (amp port {c['port']})")
        last, warned, gaps_seen = time.time(), False, 0
        t_conn = time.time()
        try:
            while not self.stop_ev.is_set():
                try:
                    data = s.recv(262144)
                except socket.timeout:
                    if time.time() - last > 3 and not warned:
                        self.msg('status', 'Relay connected but silent for 3 s - is the relay running and the amp acquiring?')
                        warned = True
                    continue
                if not data: raise ConnectionError('relay closed the connection')
                last, warned = time.time(), False
                payload = ps.feed(data)
                if time.time() - t_conn < 3:          # backlog -> live jump on connect is not data loss
                    ps.gaps = ps.gap_bytes = 0
                elif ps.gaps > gaps_seen:
                    self.msg('status', f'Relay dropped packets: {ps.gap_bytes / 1e6:.2f} MB missing so far '
                                       f'({ps.gaps} holes) - the Mac capture cannot keep up')
                    gaps_seen = ps.gaps
                if payload: self._on_bytes(payload)
        finally:
            s.close()


# ----------------------------------------------------------------------------- DSP helpers
class Ring:
    def __init__(self, cap, ch):
        self.buf = np.zeros((cap, ch), np.float32); self.cap = cap; self.i = 0; self.n = 0

    def clear(self): self.i = self.n = 0

    def push(self, x):
        k = len(x)
        if k >= self.cap:
            self.buf[:] = x[-self.cap:]; self.i = 0; self.n = self.cap; return
        e = self.i + k
        if e <= self.cap: self.buf[self.i:e] = x
        else:
            f = self.cap - self.i; self.buf[self.i:] = x[:f]; self.buf[:k - f] = x[f:]
        self.i = e % self.cap; self.n = min(self.cap, self.n + k)

    def last(self, k):
        k = min(k, self.n); s = (self.i - k) % self.cap
        if s + k <= self.cap: return self.buf[s:s + k]
        return np.concatenate([self.buf[s:], self.buf[:s + k - self.cap]])


class FilterChain:
    def __init__(self): self.sos = None; self.zi = None

    def configure(self, hp, notch, lp):
        parts = []
        if hp: parts.append(signal.butter(2, hp, 'highpass', fs=FS, output='sos'))
        if notch: parts.append(notch_sos(notch))
        if lp: parts.append(signal.butter(4, lp, 'lowpass', fs=FS, output='sos'))
        self.sos = np.vstack(parts) if parts else None; self.zi = None

    def process(self, x):
        if self.sos is None or not len(x): return x
        x = x.astype(np.float64)
        if self.zi is None:
            self.zi = signal.sosfilt_zi(self.sos)[:, :, None] * x[0][None, None, :]
        y, self.zi = signal.sosfilt(self.sos, x, axis=0, zi=self.zi)
        return y


_NOTCH_CACHE = {}
def notch_sos(f0):
    """Notch at f0 and its 2nd harmonic (Q=30)."""
    if f0 not in _NOTCH_CACHE:
        _NOTCH_CACHE[f0] = np.vstack([signal.tf2sos(*signal.iirnotch(f, 30, fs=FS)) for f in (f0, 2 * f0)])
    return _NOTCH_CACHE[f0]


def compute_metrics(raw, total, notch=50):
    """raw: (n, 128) uV incl. DC. Metrics use the notched signal; mains pickup is measured before the notch."""
    n = len(raw)
    x0 = raw.astype(np.float64); dc = x0.mean(0); x0 -= dc
    x = signal.sosfiltfilt(notch_sos(notch), x0, axis=0) if notch else x0
    bp = signal.sosfiltfilt(BP_SOS, x, axis=0)
    rms = bp.std(0)
    nper = min(2 * FS, n)
    f, P0 = signal.welch(x0, fs=FS, nperseg=nper, axis=0)           # un-notched: for mains measurement
    P = signal.welch(x, fs=FS, nperseg=nper, axis=0)[1] if notch else P0
    def band0(lo, hi): m = (f >= lo) & (f < hi); return P0[m].mean(0)
    def band(lo, hi): m = (f >= lo) & (f < hi); return P[m].mean(0)
    line50 = band0(49, 51) / (0.5 * (band0(44, 48) + band0(52, 56)) + 1e-12)
    line60 = band0(59, 61) / (0.5 * (band0(54, 58) + band0(62, 66)) + 1e-12)
    total_pw = sum(band(lo, hi) * (hi - lo) for _, lo, hi in BANDS)
    rel = {nm: band(lo, hi) * (hi - lo) / (total_pw + 1e-12) for nm, lo, hi in BANDS}
    med = np.median(rms)
    state = np.array(['ok'] * NCH, dtype=object)
    lr = np.maximum(line50, line60)
    state[lr > max(50, 5 * np.median(lr))] = 'line'      # relative: a global mains problem isn't a per-electrode one
    state[rms > 4 * med] = 'noisy'
    state[(rms < 0.5) | (rms < 0.1 * med)] = 'flat'
    good = state == 'ok'
    if good.sum() < 10: good[:] = True
    post = [c - 1 for c in POSTERIOR]
    # VEOG from eye channels that are not flagged bad (blinks: 50-500 ms wide, well above background)
    above = [c - 1 for c in EYE_ABOVE if state[c - 1] in ('ok', 'line')]
    below = [c - 1 for c in EYE_BELOW if state[c - 1] in ('ok', 'line')]
    pk = np.array([], int)
    if above and below:
        veog = signal.sosfiltfilt(VEOG_SOS, x[:, above].mean(1) - x[:, below].mean(1))
        mad = 1.4826 * np.median(np.abs(veog - np.median(veog)))
        thr = max(100.0, 6 * mad)
        for sgn in (1, -1):                                   # polarity depends on referencing
            p, _ = signal.find_peaks(sgn * veog, height=thr, distance=int(0.3 * FS),
                                     width=(int(0.05 * FS), int(0.5 * FS)))
            if len(p) > len(pk): pk = p
    last1 = bp[-FS:]
    move_frac = float((np.abs(last1) > 200).any(0)[good].mean())
    return dict(
        f=f, P=P, P0=P0, notch=notch, rms=rms, dc=dc, line50=line50, line60=line60, rel=rel, state=state, good=good,
        med_rms=float(med), mains=50 if np.median(line50) >= np.median(line60) else 60,
        mains_ratio=float(max(np.median(line50), np.median(line60))),
        alpha_post=float(np.mean([rel['alpha'][c] for c in post])),
        alpha_glob=float(np.median(rel['alpha'][good])),
        gamma_glob=float(np.median(rel['gamma'][good])),
        rel_glob={k: float(np.median(v[good])) for k, v in rel.items()},
        rel_post={k: float(np.mean(v[post])) for k, v in rel.items()},
        blink_abs=[int(total - n + p) for p in pk], move_frac=move_frac)


# ----------------------------------------------------------------------------- GUI
def card(title):
    w = QtWidgets.QGroupBox(title)
    lab = QtWidgets.QLabel('—'); lab.setWordWrap(True); lab.setTextFormat(QtCore.Qt.TextFormat.RichText)
    lab.setStyleSheet('font-size: 13px;')
    QtWidgets.QVBoxLayout(w).addWidget(lab)
    return w, lab


class Main(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('EGI Live'); self.resize(1500, 950)
        pg.setConfigOptions(antialias=False, background='w', foreground='k')
        self.q = queue.Queue(); self.acq = None
        self.raw = Ring(60 * FS, NCH); self.filt = Ring(60 * FS, NCH); self.aux = Ring(60 * FS, len(AUX_SLOTS))
        self.counts_peak = np.zeros(NCH)
        self.fc = FilterChain()
        self.total = 0; self.last_counter = None; self.dropped = 0; self.discont = 0
        self.last_status = None; self.rate_hist = deque(maxlen=50); self.t_connect = None
        self.repeats = 0; self.uniq = 0; self.repeat_noted = False
        self.blinks = deque(); self.metrics = None
        self.trend_t, self.trend_alpha, self.trend_blink, self.trend_rms = (deque(maxlen=600) for _ in range(4))
        self.rec_path = None; self.rec_t0 = None
        self.paused = False
        self._build_ui()
        self._apply_filters()
        self.t_fast = QtCore.QTimer(self, interval=50, timeout=self.tick_fast); self.t_fast.start()
        self.t_slow = QtCore.QTimer(self, interval=1000, timeout=self.tick_slow); self.t_slow.start()

    # ---------------- UI construction
    def _build_ui(self):
        cw = QtWidgets.QWidget(); self.setCentralWidget(cw); v = QtWidgets.QVBoxLayout(cw)
        # connection bar
        conn = QtWidgets.QGroupBox('Source'); h = QtWidgets.QHBoxLayout(conn)
        self.mode = QtWidgets.QComboBox(); self.mode.addItems(['Live amp (TCP)', 'Replay file (.pcap/.raw)', 'Mac relay (pcap stream)'])
        self.relay_host = QtWidgets.QLineEdit('10.10.10.41'); self.relay_host.setFixedWidth(110)
        self.relay_port = QtWidgets.QSpinBox(maximum=65535, value=9000)
        self.relay_w = [QtWidgets.QLabel('Relay'), self.relay_host, QtWidgets.QLabel('Port'), self.relay_port]
        self.host = QtWidgets.QLineEdit('10.10.10.51'); self.host.setFixedWidth(110)
        self.port = QtWidgets.QSpinBox(maximum=65535, value=9879)
        self.send_cmd = QtWidgets.QCheckBox('send listen command')
        self.send_cmd.setToolTip('Only if the amp sends nothing after connecting. Sends the text below to the '
                                 'command port (set it equal to the data port to send on the data socket).\n'
                                 'No start/stop/power commands are ever sent.')
        self.cmd_port = QtWidgets.QSpinBox(maximum=65535, value=9877)
        self.cmd_text = QtWidgets.QLineEdit('(sendCommand cmd_ListenToAmp 0 0 0)'); self.cmd_text.setFixedWidth(230)
        self.file = QtWidgets.QLineEdit(''); self.file.setPlaceholderText('capture.pcap or recording.raw')
        self.browse = QtWidgets.QPushButton('…'); self.browse.setFixedWidth(28); self.browse.clicked.connect(self._browse)
        self.speed = QtWidgets.QDoubleSpinBox(minimum=0.25, maximum=8, value=1, singleStep=0.25, suffix='x')
        self.loop = QtWidgets.QCheckBox('loop'); self.loop.setChecked(True)
        self.uv = QtWidgets.QDoubleSpinBox(decimals=11, minimum=1e-9, maximum=10, value=DEFAULT_UV, singleStep=1e-6)
        self.uv.setToolTip('uV per count (tentative - confirm against an .mff export)')
        self.btn_conn = QtWidgets.QPushButton('Connect'); self.btn_conn.clicked.connect(self.toggle_connect)
        self.btn_rec = QtWidgets.QPushButton('● Record'); self.btn_rec.setEnabled(False)
        self.btn_rec.clicked.connect(self.toggle_record)
        self.live_w = [QtWidgets.QLabel('Host'), self.host, QtWidgets.QLabel('Port'), self.port,
                       self.send_cmd, QtWidgets.QLabel('cmd port'), self.cmd_port, self.cmd_text]
        self.rep_w = [QtWidgets.QLabel('File'), self.file, self.browse, QtWidgets.QLabel('Speed'), self.speed, self.loop]
        h.addWidget(self.mode)
        for w in self.live_w + self.rep_w + self.relay_w: h.addWidget(w)
        h.addStretch(); h.addWidget(QtWidgets.QLabel('µV/count')); h.addWidget(self.uv)
        h.addWidget(self.btn_conn); h.addWidget(self.btn_rec)
        self.mode.setCurrentIndex(2)   # Mac relay
        self.mode.currentIndexChanged.connect(self._mode_changed); self._mode_changed()
        v.addWidget(conn)

        self.tabs = QtWidgets.QTabWidget(); v.addWidget(self.tabs, 1)
        self.tabs.addTab(self._tab_signals(), 'Signals')
        self.tabs.addTab(self._tab_spectrum(), 'Spectrum')
        self.tabs.addTab(self._tab_quality(), 'Channel quality')
        self.tabs.addTab(self._tab_metrics(), 'Metrics && inferences')
        self.tabs.addTab(self._tab_aux(), 'Aux / monitor')
        self.tabs.addTab(self._tab_log(), 'Stream / events')
        self.sb = QtWidgets.QLabel(); self.statusBar().addPermanentWidget(self.sb, 1)

    def _tab_signals(self):
        w = QtWidgets.QWidget(); v = QtWidgets.QVBoxLayout(w); h = QtWidgets.QHBoxLayout()
        self.group = QtWidgets.QComboBox(); self.group.addItems(GROUPS)
        self.win = QtWidgets.QSpinBox(minimum=1, maximum=30, value=10, suffix=' s')
        self.scale = QtWidgets.QDoubleSpinBox(minimum=1, maximum=5000, value=50, suffix=' µV/ch')
        self.hp = QtWidgets.QComboBox(); self.hp.addItems(['HP off', 'HP 0.1 Hz', 'HP 0.5 Hz', 'HP 1 Hz']); self.hp.setCurrentIndex(3)
        self.notch = QtWidgets.QComboBox(); self.notch.addItems(['Notch off', 'Notch 50 Hz', 'Notch 60 Hz']); self.notch.setCurrentIndex(1)
        self.lp = QtWidgets.QComboBox(); self.lp.addItems(['LP off', 'LP 30 Hz', 'LP 40 Hz', 'LP 70 Hz']); self.lp.setCurrentIndex(2)
        self.car = QtWidgets.QCheckBox('Common avg ref')
        self.btn_pause = QtWidgets.QPushButton('Pause view'); self.btn_pause.setCheckable(True)
        self.btn_pause.toggled.connect(lambda s: setattr(self, 'paused', s))
        for lab, wd in [('Channels', self.group), ('Window', self.win), ('Spacing', self.scale)]:
            h.addWidget(QtWidgets.QLabel(lab)); h.addWidget(wd)
        for wd in (self.hp, self.notch, self.lp, self.car): h.addWidget(wd)
        h.addStretch(); h.addWidget(self.btn_pause); v.addLayout(h)
        for c in (self.hp, self.notch, self.lp): c.currentIndexChanged.connect(self._apply_filters)
        self.group.currentIndexChanged.connect(self._build_curves)
        self.p_sig = pg.PlotWidget(); self.p_sig.setMouseEnabled(x=False, y=True)
        self.p_sig.showGrid(x=True, y=False, alpha=0.3); self.p_sig.setLabel('bottom', 'time', 's')
        v.addWidget(self.p_sig, 1); self.curves = []; self._build_curves()
        return w

    def _build_curves(self):
        self.p_sig.clear(); self.curves = []
        self.sel = GROUPS[self.group.currentText()]
        for c in self.sel:
            it = self.p_sig.plot(pen=pg.mkPen('#222', width=1))
            it.setDownsampling(auto=True, method='peak'); it.setClipToView(True)
            self.curves.append(it)
        self._update_ticks()

    def _update_ticks(self):
        sp = self.scale.value(); step = max(1, len(self.sel) // 32)
        self.p_sig.getAxis('left').setTicks([[(-k * sp, CH[c]) for k, c in enumerate(self.sel) if k % step == 0], []])
        self.p_sig.setYRange(-(len(self.sel) - 0.5) * sp, 0.5 * sp, padding=0)

    def _tab_spectrum(self):
        w = QtWidgets.QWidget(); v = QtWidgets.QVBoxLayout(w); h = QtWidgets.QHBoxLayout()
        self.psd_ch = QtWidgets.QComboBox(); self.psd_ch.addItems(CH); self.psd_ch.setCurrentText('E75')
        self.psd_max = QtWidgets.QSpinBox(minimum=20, maximum=500, value=100, suffix=' Hz')
        h.addWidget(QtWidgets.QLabel('Highlight channel')); h.addWidget(self.psd_ch)
        h.addWidget(QtWidgets.QLabel('Max freq')); h.addWidget(self.psd_max); h.addStretch(); v.addLayout(h)
        self.p_psd = pg.PlotWidget(); self.p_psd.setLogMode(y=True); self.p_psd.addLegend()
        self.p_psd.setLabel('bottom', 'frequency', 'Hz'); self.p_psd.setLabel('left', 'power (µV²/Hz)')
        for (nm, lo, hi), col in zip(BANDS, ['#e3f2fd', '#e8f5e9', '#fff8e1', '#fce4ec', '#ede7f6']):
            r = pg.LinearRegionItem((lo, hi), movable=False, brush=pg.mkBrush(col)); r.setZValue(-10)
            self.p_psd.addItem(r)
            t = pg.TextItem(nm, color='#555', anchor=(0.5, 0)); t.setPos((lo + hi) / 2, 0); self.p_psd.addItem(t)
            r._label = t
        self.c_psd_all = self.p_psd.plot(pen=pg.mkPen('#9e9e9e', width=1), name='90th percentile of good channels')
        self.c_psd_raw = self.p_psd.plot(pen=pg.mkPen('#f4a6a6', width=1), name='median, before notch')
        self.c_psd_med = self.p_psd.plot(pen=pg.mkPen('#c62828', width=2), name='median of good channels (notched)')
        self.c_psd_ch = self.p_psd.plot(pen=pg.mkPen('#1565c0', width=2), name='highlighted channel')
        self.c_psd_post = self.p_psd.plot(pen=pg.mkPen('#2e7d32', width=2, style=QtCore.Qt.PenStyle.DashLine), name='posterior mean')
        v.addWidget(self.p_psd, 1); return w

    def _tab_quality(self):
        w = QtWidgets.QWidget(); v = QtWidgets.QVBoxLayout(w)
        self.q_label = QtWidgets.QLabel('—'); self.q_label.setWordWrap(True); v.addWidget(self.q_label)
        gl = pg.GraphicsLayoutWidget(); v.addWidget(gl, 1)
        self.q_plots = {}
        for row, (key, title) in enumerate([('rms', '1–40 Hz RMS (µV)'), ('line', 'Mains peak ratio, log10 (1 = 10×, 2 = 100×)'),
                                             ('dc', 'DC offset (mV)')]):
            p = gl.addPlot(row=row, col=0, title=title); p.showGrid(y=True, alpha=0.3)
            b = pg.BarGraphItem(x=np.arange(1, NCH + 1), height=np.zeros(NCH), width=0.8); p.addItem(b)
            if key == 'line': p.setLogMode(y=False)
            self.q_plots[key] = (p, b)
        self.q_plots['dc'][0].setLabel('bottom', 'channel E#')
        leg = QtWidgets.QLabel(' '.join(f'<span style="color:{c}">■ {k}</span>' for k, c in COLORS.items()) +
                               '  (ok · strong mains pickup · noisy &gt;4× median · flat)')
        v.addWidget(leg); return w

    def _tab_metrics(self):
        w = QtWidgets.QWidget(); g = QtWidgets.QGridLayout(w)
        self.cards = {}
        names = [('signal', 'Signal present?'), ('eyes', 'Eyes / relaxation (posterior alpha)'),
                 ('blinks', 'Blinks'), ('move', 'Movement / artifacts'), ('muscle', 'Muscle tension (EMG)'),
                 ('mains', 'Mains interference'), ('contact', 'Electrode contact'), ('stream', 'Stream health')]
        for i, (k, t) in enumerate(names):
            box, lab = card(t); self.cards[k] = lab; g.addWidget(box, i // 4, i % 4)
        self.p_band = pg.PlotWidget(title='Relative band power (global median vs posterior)')
        self.b_glob = pg.BarGraphItem(x=np.arange(5) - 0.2, height=np.zeros(5), width=0.38, brush='#1565c0')
        self.b_post = pg.BarGraphItem(x=np.arange(5) + 0.2, height=np.zeros(5), width=0.38, brush='#2e7d32')
        self.p_band.addItem(self.b_glob); self.p_band.addItem(self.b_post)
        self.p_band.getAxis('bottom').setTicks([[(i, b[0]) for i, b in enumerate(BANDS)]])
        self.p_band.setYRange(0, 1); g.addWidget(self.p_band, 2, 0, 1, 2)
        self.p_trend = pg.PlotWidget(title='Trends (last 10 min)'); self.p_trend.addLegend()
        self.p_trend.setLabel('bottom', 'time since connect', 's')
        self.c_tr_alpha = self.p_trend.plot(pen=pg.mkPen('#2e7d32', width=2), name='posterior alpha (rel)')
        self.c_tr_blink = self.p_trend.plot(pen=pg.mkPen('#6a1b9a', width=2), name='blinks/min ÷100')
        self.c_tr_rms = self.p_trend.plot(pen=pg.mkPen('#ef6c00', width=2), name='median RMS ÷100 µV')
        g.addWidget(self.p_trend, 2, 2, 1, 2)
        note = QtWidgets.QLabel('<i>Inferences are simple heuristics on the last 4 s of data, for orientation only '
                                '- not clinical interpretation. Regions use approximate HydroCel-128 positions.</i>')
        g.addWidget(note, 3, 0, 1, 4); g.setRowStretch(2, 1)
        return w

    def _tab_aux(self):
        gl = pg.GraphicsLayoutWidget(); self.aux_curves = []; first = None
        for r, s in enumerate(AUX_SLOTS):
            p = gl.addPlot(row=r, col=0); p.setLabel('left', f'slot {s}'); p.showGrid(x=True, alpha=0.3)
            if first: p.setXLink(first)
            first = first or p
            c = p.plot(pen=pg.mkPen('#1565c0')); c.setDownsampling(auto=True, method='peak'); c.setClipToView(True)
            self.aux_curves.append((p, c))
        return gl

    def _tab_log(self):
        w = QtWidgets.QWidget(); v = QtWidgets.QVBoxLayout(w)
        self.stream_info = QtWidgets.QLabel('—'); self.stream_info.setTextFormat(QtCore.Qt.TextFormat.RichText)
        v.addWidget(self.stream_info)
        self.log = QtWidgets.QListWidget(); v.addWidget(QtWidgets.QLabel('Events (status/DIN changes, gaps, connection):'))
        v.addWidget(self.log, 1); return w

    # ---------------- controls
    def _mode_changed(self):
        m = self.mode.currentIndex()
        for w in self.live_w: w.setVisible(m == 0)
        for w in self.rep_w: w.setVisible(m == 1)
        for w in self.relay_w: w.setVisible(m == 2)

    def _browse(self):
        p, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open capture', os.path.dirname(self.file.text()),
                                                     'Captures (*.pcap *.raw *.bin);;All (*)')
        if p: self.file.setText(p)

    def _apply_filters(self):
        hp = [None, 0.1, 0.5, 1.0][self.hp.currentIndex()]
        nt = [None, 50, 60][self.notch.currentIndex()]
        lp = [None, 30, 40, 70][self.lp.currentIndex()]
        self.fc.configure(hp, nt, lp)
        if self.raw.n:                                  # refilter history so the view stays continuous
            y = self.fc.process(self.raw.last(self.raw.n)); self.filt.clear(); self.filt.push(y)

    def log_event(self, txt):
        self.log.insertItem(0, f'{time.strftime("%H:%M:%S")}  {txt}')

    def toggle_connect(self):
        if self.acq:
            self.acq.stop_ev.set(); self.btn_conn.setEnabled(False); return
        cfg = dict(mode=['tcp', 'replay', 'relay'][self.mode.currentIndex()], host=self.host.text().strip(),
                   port=self.port.value(), send_cmd=self.send_cmd.isChecked(), cmd_port=self.cmd_port.value(),
                   cmd_text=self.cmd_text.text(), file=self.file.text(), speed=self.speed.value(),
                   loop=self.loop.isChecked(), relay_host=self.relay_host.text().strip(),
                   relay_port=self.relay_port.value())
        for r in (self.raw, self.filt, self.aux): r.clear()
        self.fc.zi = None; self.total = 0; self.last_counter = None; self.dropped = self.discont = 0
        self.repeats = 0; self.uniq = 0; self.rate_hist.clear(); self.repeat_noted = False
        self.blinks.clear(); self.metrics = None; self.last_status = None
        for d in (self.trend_t, self.trend_alpha, self.trend_blink, self.trend_rms): d.clear()
        self.counts_peak[:] = 0
        self.acq = Acquisition(cfg, self.q); self.acq.start()
        self.btn_conn.setText('Disconnect'); self.mode.setEnabled(False)

    def toggle_record(self):
        if not self.acq: return
        if self.rec_path:
            self.acq.stop_recording(); p = self.rec_path; self.rec_path = None
            self.btn_rec.setText('● Record'); self.log_event(f'Recording stopped: {p}')
            uv = self.uv.value()
            threading.Thread(target=self._convert_bg, args=(p, uv), daemon=True).start()
            return
        d = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'recordings'); os.makedirs(d, exist_ok=True)
        self.rec_path = os.path.join(d, time.strftime('egi_%Y%m%d_%H%M%S.raw'))
        json.dump(dict(source=self.acq.cfg, start=time.strftime('%Y-%m-%d %H:%M:%S'), fs=FS,
                       uv_per_count=self.uv.value(), format='raw EGI TCP stream bytes; decode with egi_live.py --convert'),
                  open(self.rec_path[:-4] + '.json', 'w'), indent=2)
        self.acq.start_recording(self.rec_path); self.rec_t0 = time.time()
        self.btn_rec.setText('■ Stop recording'); self.log_event(f'Recording to {self.rec_path}')

    def _proc_notch(self):
        """Notch used for processing/saving: UI choice, else detected mains (default 50 Hz)."""
        return [None, 50, 60][self.notch.currentIndex()] or (self.metrics['mains'] if self.metrics else 50)

    def _convert_bg(self, p, uv):
        try:
            out, n, drop = convert_raw_to_npz(p, uv, self._proc_notch())
            self.q.put(('status', f'Saved {out} ({n} samples, {drop} gaps, notch {self._proc_notch()} Hz)'))
        except Exception as ex:
            self.q.put(('status', f'Conversion failed: {ex}'))

    # ---------------- data path
    def _ingest(self, A):
        counter, status, eeg, aux = decode(A)
        # counter steps: 1 = next sample, 0 = repeated record (amp sends each sample N times at lower
        # sample rates, e.g. 4x at 250 Hz), >1 = samples missing, negative/huge = stream restarted
        steps = np.diff(np.r_[counter[0] - 1 if self.last_counter is None else self.last_counter, counter])
        self.repeats += int((steps == 0).sum()); self.uniq += int((steps != 0).sum())
        if self.repeats and not self.repeat_noted:
            self.log_event('Amp repeats records (same counter, identical data) - lower sample rate in Net Station; '
                           'time axis stays correct'); self.repeat_noted = True
        joining = (self.acq is not None and self.acq.cfg['mode'] == 'relay' and self.t_connect is not None
                   and time.time() - self.t_connect < 3)
        for i in np.where((steps != 0) & (steps != 1))[0][:20]:
            st = int(steps[i])
            if joining:                       # relay sends a bit of old backlog, then jumps to live data
                self.log_event(f'Joined live stream at counter {counter[i]} (skipped relay backlog)'); continue
            if 1 < st < 100000: self.dropped += st - 1; self.log_event(f'Gap: {st - 1} samples missing before counter {counter[i]}')
            else: self.discont += 1; self.log_event(f'Counter jump → {counter[i]} (stream restarted?)')
        self.last_counter = counter[-1]
        ch = np.where(status[1:] != status[:-1])[0]
        if self.last_status is None:
            self.log_event(f'First status word 0x{status[0]:08X}')
        elif status[0] != self.last_status:
            self.log_event(f'Status/DIN changed 0x{self.last_status:08X} → 0x{status[0]:08X} at counter {counter[0]}')
        for i in ch[:20]:
            self.log_event(f'Status/DIN changed 0x{status[i]:08X} → 0x{status[i + 1]:08X} at counter {counter[i + 1]}')
        self.last_status = status[-1]
        self.counts_peak = np.maximum(self.counts_peak, np.abs(eeg).max(0))
        x = eeg * self.uv.value()
        self.raw.push(x); self.filt.push(self.fc.process(x)); self.aux.push(aux)
        self.total += len(A)
        self.rate_hist.append((time.time(), self.total, self.uniq))

    def tick_fast(self):
        try:
            while True:
                kind, val = self.q.get_nowait()
                if kind == 'data': self._ingest(val)
                elif kind == 'connected':
                    self.t_connect = time.time(); self.btn_rec.setEnabled(True); self.log_event(f'Connected: {val}')
                    self.statusBar().showMessage(f'Connected: {val}', 5000)
                elif kind == 'status': self.log_event(val); self.statusBar().showMessage(val, 8000)
                elif kind == 'error':
                    self.log_event(f'ERROR {val}'); QtWidgets.QMessageBox.warning(self, 'Stream error', val)
                elif kind == 'stopped':
                    self.acq = None; self.btn_conn.setText('Connect'); self.btn_conn.setEnabled(True)
                    self.btn_rec.setEnabled(False); self.mode.setEnabled(True); self.log_event('Disconnected')
                    if self.rec_path: self.toggle_record_after_stop()
        except queue.Empty:
            pass
        if self.paused or not self.raw.n: self._update_statusbar(); return
        tab = self.tabs.currentIndex()
        n = min(self.win.value() * FS, self.filt.n)
        t_end = self.total / FS; x = (np.arange(self.total - n, self.total)) / FS
        if tab == 0:
            y = self.filt.last(n)[:, self.sel].astype(np.float32)
            if self.car.isChecked() and self.metrics is not None:
                good = self.metrics['good']
                y = y - self.filt.last(n)[:, good].mean(1, keepdims=True)
            y = y - np.median(y, 0)
            sp = self.scale.value()
            for k, cu in enumerate(self.curves):
                cu.setData(x, y[:, k] - k * sp)
            self.p_sig.setXRange(t_end - self.win.value(), t_end, padding=0)
        elif tab == 4:
            a = self.aux.last(n)
            for k, (p, cu) in enumerate(self.aux_curves): cu.setData(x, a[:, k])
            self.aux_curves[0][0].setXRange(t_end - self.win.value(), t_end, padding=0)
        self._update_statusbar()

    def toggle_record_after_stop(self):
        p = self.rec_path; self.rec_path = None; self.btn_rec.setText('● Record')
        threading.Thread(target=self._convert_bg, args=(p, self.uv.value()), daemon=True).start()

    def _rate(self, unique=False):
        if len(self.rate_hist) < 2: return 0.0
        a, b = self.rate_hist[0], self.rate_hist[-1]
        k = 2 if unique else 1
        return (b[k] - a[k]) / (b[0] - a[0]) if b[0] > a[0] else 0.0

    def _update_statusbar(self):
        if not self.acq and not self.raw.n: self.sb.setText('Not connected'); return
        s = (f"{'● LIVE' if self.acq else '○ stopped'}   {self._rate():7.1f} rec/s  "
             f"({self._rate(True):.0f} unique samples/s)   samples {self.total:,}   "
             f"counter {self.last_counter}   dropped {self.dropped}   resyncs {self.acq.framer.resyncs if self.acq else '-'}")
        ps = getattr(self.acq, 'pcap', None) if self.acq else None
        if ps: s += f"   relay holes {ps.gaps} ({ps.gap_bytes / 1e6:.1f} MB)"
        if self.rec_path and self.acq:
            s += f"   ⏺ REC {time.time() - self.rec_t0:5.0f}s  {self.acq.rec_bytes / 1e6:.1f} MB"
        self.sb.setText(s)

    # ---------------- metrics (1 Hz)
    def tick_slow(self):
        if self.raw.n < 2 * FS: return
        m = compute_metrics(self.raw.last(4 * FS), self.total, notch=self._proc_notch()); self.metrics = m
        for b in m['blink_abs']:
            if not self.blinks or b - self.blinks[-1] > 0.3 * FS: self.blinks.append(b)
        while self.blinks and self.blinks[0] < self.total - 60 * FS: self.blinks.popleft()
        span = min(60.0, self.total / FS); bpm = len(self.blinks) / span * 60 if span > 5 else float('nan')
        tnow = time.time() - (self.t_connect or time.time())
        self.trend_t.append(tnow); self.trend_alpha.append(m['alpha_post'])
        self.trend_blink.append(0 if np.isnan(bpm) else bpm / 100); self.trend_rms.append(m['med_rms'] / 100)
        # colour bad channels in the signal view
        for k, c in enumerate(self.sel):
            self.curves[k].setPen(pg.mkPen('#222' if m['state'][c] == 'ok' else COLORS[m['state'][c]], width=1))
        self._update_ticks()
        self._upd_spectrum(m); self._upd_quality(m); self._upd_metrics(m, bpm); self._upd_stream()

    def _upd_spectrum(self, m):
        f, P = m['f'], m['P']; sel = f <= self.psd_max.value(); f = f[sel]; P = P[sel] + 1e-12
        good = m['good']
        self.c_psd_raw.setData(f, np.median(m['P0'][sel][:, good], 1) + 1e-12)
        self.c_psd_med.setData(f, np.median(P[:, good], 1))
        self.c_psd_all.setData(f, np.percentile(P[:, good], 90, axis=1))
        self.c_psd_ch.setData(f, P[:, CH.index(self.psd_ch.currentText())])
        self.c_psd_post.setData(f, P[:, [c - 1 for c in POSTERIOR]].mean(1))
        ymin = np.log10(np.median(P[:, good], 1).min())
        for it in self.p_psd.items():
            if isinstance(it, pg.LinearRegionItem): it._label.setPos(it.getRegion()[0] / 2 + it.getRegion()[1] / 2, ymin)
        self.p_psd.setXRange(0, self.psd_max.value())

    def _upd_quality(self, m):
        br = [pg.mkBrush(COLORS[s]) for s in m['state']]
        self.q_plots['rms'][1].setOpts(height=m['rms'], brushes=br)
        self.q_plots['line'][1].setOpts(height=np.log10(np.maximum(np.maximum(m['line50'], m['line60']), 1)), brushes=br)
        self.q_plots['dc'][1].setOpts(height=m['dc'] / 1000, brushes=br)
        railed = [CH[i] for i in np.where(self.counts_peak >= 2 ** 31 - 512)[0]]
        lst = lambda s: ', '.join(CH[i] for i in np.where(m['state'] == s)[0]) or 'none'
        self.q_label.setText(f"<b>Median RMS</b> {m['med_rms']:.1f} µV &nbsp; <b>Flat:</b> {lst('flat')} &nbsp; "
                             f"<b>Noisy:</b> {lst('noisy')} &nbsp; <b>Strong mains:</b> {lst('line')} &nbsp; "
                             f"<b>Railed (ever):</b> {', '.join(railed) or 'none'}")

    def _upd_metrics(self, m, bpm):
        C = self.cards
        def tag(txt, col): return f'<span style="color:{col};font-weight:bold">{txt}</span>'
        ok_sig = 2 < m['med_rms'] < 100
        C['signal'].setText(f"{tag('EEG-like signal', COLORS['ok']) if ok_sig else tag('Unusual amplitude', COLORS['noisy'])}"
                            f"<br>median 1–40 Hz RMS {m['med_rms']:.1f} µV<br>dominant posterior band: "
                            f"<b>{max(m['rel_post'], key=m['rel_post'].get)}</b>")
        a = m['alpha_post']
        st = (tag('likely eyes closed / relaxed', COLORS['ok']) if a > 0.35 else
              tag('likely eyes open / alert', '#1565c0') if a < 0.2 else tag('mixed', '#555'))
        C['eyes'].setText(f'{st}<br>posterior alpha {a * 100:.0f}% of 1–45 Hz power<br>global alpha {m["alpha_glob"] * 100:.0f}%')
        C['blinks'].setText(f"<b>{'—' if np.isnan(bpm) else f'{bpm:.0f}'} / min</b> (last 60 s)<br>"
                            f"{len(self.blinks)} detected · VEOG = above-eye (E25,E8) − below-eye (E127,E126),"
                            f" bad channels excluded")
        mv = m['move_frac']
        C['move'].setText((tag('artifact now', COLORS['flat']) if mv > 0.2 else tag('quiet', COLORS['ok'])) +
                          f'<br>{mv * 100:.0f}% of good channels &gt;200 µV in last 1 s')
        gm = m['gamma_glob']
        C['muscle'].setText((tag('elevated', COLORS['noisy']) if gm > 0.15 else tag('normal', COLORS['ok'])) +
                            f'<br>30–45 Hz = {gm * 100:.0f}% of power')
        glob = m['mains_ratio']
        lvl = (tag('very high on all channels - check ground/reference', COLORS['flat']) if glob > 200 else
               tag('elevated', COLORS['noisy']) if glob > 30 else tag('normal', COLORS['ok']))
        C['mains'].setText(f"<b>{m['mains']} Hz</b> {lvl}<br>median peak ratio {glob:.0f}× (before notch)<br>"
                           f"{(m['state'] == 'line').sum()} channels far above the rest<br>"
                           f"processing notch: <b>{m['notch']} + {2 * m['notch']} Hz</b>")
        nbad = int((m['state'] != 'ok').sum())
        C['contact'].setText((tag(f'{NCH - nbad}/{NCH} good', COLORS['ok'] if nbad < 8 else COLORS['noisy'])) +
                             f"<br>{(m['state'] == 'noisy').sum()} noisy · {(m['state'] == 'flat').sum()} flat · "
                             f"{(m['state'] == 'line').sum()} mains")
        r = self._rate()
        exp = FS * (self.acq.cfg['speed'] if self.acq and self.acq.cfg['mode'] == 'replay' else 1)
        C['stream'].setText((tag('healthy', COLORS['ok']) if self.dropped == 0 and abs(r - exp) < 0.1 * exp else
                             tag('check', COLORS['noisy'])) +
                            f'<br>{r:.1f} Hz (expected {exp:.0f}) · dropped {self.dropped} · restarts {self.discont}')
        self.b_glob.setOpts(height=[m['rel_glob'][b[0]] for b in BANDS])
        self.b_post.setOpts(height=[m['rel_post'][b[0]] for b in BANDS])
        t = np.array(self.trend_t)
        self.c_tr_alpha.setData(t, np.array(self.trend_alpha))
        self.c_tr_blink.setData(t, np.array(self.trend_blink)); self.c_tr_rms.setData(t, np.array(self.trend_rms))

    def _upd_stream(self):
        a = self.acq
        self.stream_info.setText(
            f"<b>Samples</b> {self.total:,} ({self.total / FS:.1f} s) &nbsp; <b>Counter</b> {self.last_counter} &nbsp; "
            f"<b>Rate</b> {self._rate():.1f} Hz &nbsp; <b>Dropped</b> {self.dropped} &nbsp; <b>Restarts</b> {self.discont}"
            f" &nbsp; <b>Status word</b> 0x{(self.last_status or 0):08X} &nbsp; "
            f"<b>Bytes in</b> {(a.bytes_in / 1e6 if a else 0):.1f} MB &nbsp; <b>Resyncs</b> {a.framer.resyncs if a else '-'}")

    def closeEvent(self, e):
        if self.acq: self.acq.stop_ev.set(); self.acq.join(2)
        super().closeEvent(e)


# ----------------------------------------------------------------------------- entry points
def make_app():
    """QApplication with a fixed light theme (Windows dark mode would otherwise turn the plots black)."""
    app = QtWidgets.QApplication(sys.argv)
    try: app.styleHints().setColorScheme(QtCore.Qt.ColorScheme.Light)
    except AttributeError: pass
    app.setStyle('Fusion')
    pal = QtGui.QPalette()
    R = QtGui.QPalette.ColorRole
    for role, col in [(R.Window, '#f0f0f0'), (R.WindowText, '#000000'), (R.Base, '#ffffff'),
                      (R.AlternateBase, '#f5f5f5'), (R.Text, '#000000'), (R.Button, '#e8e8e8'),
                      (R.ButtonText, '#000000'), (R.ToolTipBase, '#ffffdc'), (R.ToolTipText, '#000000'),
                      (R.Highlight, '#1565c0'), (R.HighlightedText, '#ffffff'), (R.PlaceholderText, '#808080')]:
        pal.setColor(role, QtGui.QColor(col))
    app.setPalette(pal)
    pg.setConfigOptions(antialias=False, background='w', foreground='k')
    return app


def force_white_plots(win):
    for gv in win.findChildren(pg.GraphicsView):
        gv.setBackground('w')


def selftest(path, outdir, secs):
    os.makedirs(outdir, exist_ok=True)
    app = make_app(); w = Main(); force_white_plots(w); w.show()
    if path.startswith('tcp:'):              # tcp:HOST:PORT
        _, hst, prt = path.split(':'); w.mode.setCurrentIndex(0); w.host.setText(hst); w.port.setValue(int(prt))
    elif path.startswith('relay:'):          # relay:HOST:PORT
        _, hst, prt = path.split(':'); w.mode.setCurrentIndex(2); w.relay_host.setText(hst); w.relay_port.setValue(int(prt))
    else:
        w.mode.setCurrentIndex(1); w.file.setText(os.path.abspath(path)); w.speed.setValue(2.0)
    w.toggle_connect()
    shots = {}
    def snap(i):
        w.tabs.setCurrentIndex(i); app.processEvents(); w.tick_fast(); w.tick_slow()
        for _ in range(5): app.processEvents(); time.sleep(0.05)
        page = w.tabs.widget(i); page.resize(w.tabs.size()); page.show(); app.processEvents()
        page.grab().save(os.path.join(outdir, f'tab{i}.png')); shots[i] = 1
    for k in range(w.tabs.count()):
        QtCore.QTimer.singleShot(int(secs * 1000) + 600 * k, lambda k=k: snap(k))
    QtCore.QTimer.singleShot(int(secs * 1000) + 600 * w.tabs.count() + 300, app.quit)
    app.exec()
    print('samples', w.total, 'dropped', w.dropped, 'resyncs', w.acq.framer.resyncs if w.acq else '-',
          'rate', round(w._rate(), 1), 'shots', sorted(shots))
    print('event log:'); [print('  ', w.log.item(i).text()) for i in range(w.log.count() - 1, -1, -1)]
    if w.acq: w.acq.stop_ev.set()


if __name__ == '__main__':
    if len(sys.argv) >= 3 and sys.argv[1] == '--convert':
        for p in sys.argv[2:]: print(convert_raw_to_npz(p))
    elif len(sys.argv) >= 5 and sys.argv[1] == '--selftest':
        selftest(sys.argv[2], sys.argv[3], float(sys.argv[4]))
    else:
        app = make_app(); w = Main(); force_white_plots(w); w.show(); sys.exit(app.exec())
