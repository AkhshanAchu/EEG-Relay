# EGI NA400 data stream — packet structure

Amp: NA400, serial A16340627, firmware 2.0.17, 128 channels, packet format 2.
Decoded from `abba.pcap` (125.75 s, 125,750 samples, 0 dropped).

## Ports (amp 10.10.10.51)

| Port | Use |
|------|-----|
| 9877 | Commands (text, e.g. `(sendCommand cmd_GetAmpDetails 0 -1 -1)`) |
| 9878 | Notifications (text) |
| 9879 | EEG data (binary, amp → client) |

## Stream = blocks

```
offset  size  type        field
0       8     u64 BE      amp id (0)
8       8     u64 BE      payload length (multiple of 1264)
16      N     —           N/1264 records
```

## Record = 1 sample, 1264 bytes, 1000 records/s

At 250 Hz each sample is sent 4 times (identical record, same counter). Keep one record per counter value.

```
offset  size  type        field
0       4     u32 BE      status / digital inputs (0xFFFF1F00 = idle)
25      4     u32 LE      sample counter (+1 per sample)
33      8     u64 LE      timestamp-like field
42      4     bytes       sync marker 87 65 43 21
69      4     bytes       sync marker 87 65 43 21
80      512   128 × i32 LE  EEG E1..E128
592     512   128 × i32 LE  unused (0)
1104    160   40 × i32 LE   aux/monitor; slots 0–5, 7 active (24-bit << 8); slot 6 = 0x7FFFFF00
```

All other bytes are constant (0).

## Units

`µV = count × 0.00015522042` — tentative NA400 value, not sent in the stream. Confirm against an `.mff` export.

## Decode (Python)

```python
import numpy as np
A = records  # (n, 1264) uint8
counter = A[:, 25:29].copy().view('<u4').ravel()
status  = A[:, 0:4].copy().view('>u4').ravel()
eeg_uV  = A[:, 80:592].copy().view('<i4') * 0.00015522042   # (n, 128)
aux     = A[:, 1104:1136].copy().view('<i4')[:, [0,1,2,3,4,5,7]] >> 8
keep    = np.r_[True, np.diff(counter) != 0]   # drop repeated records
```
