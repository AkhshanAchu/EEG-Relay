# EEG-Relay

TO Get the live EEG stream from an EGI NA400 amp onto another machine while Net Station keeps running. The Mac copies the amp's packets and serves them on a port; the client reads and decodes them.

## Mac (Net Station side)

```
chmod +x amp_relay.sh
sudo PORT=9879 ./amp_relay.sh
```

Serves on port 9000. Set `AMP`, `LISTEN` or `IFACE` if yours differ. One reader at a time.

## Client

```python
from egi_relay import read_eeg, stream_eeg

data = read_eeg(seconds=10)
data['eeg_uV']   # (samples, 128) in µV
data['fs']       # sample rate

for chunk in stream_eeg(chunk_seconds=1):
    process(chunk['eeg_uV'])
```

