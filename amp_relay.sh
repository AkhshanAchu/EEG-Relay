#!/bin/bash
# Runs on the Mac ALONGSIDE Net Station. It does NOT connect to the amp: it sniffs a copy
# of the amp's packets with tcpdump and pipes that live capture, in pcap format, out over
# a TCP port with nc. Another machine connects and reads it back with tcpdump (amp_read.sh).
# Because it only listens to the wire, it can't disturb Net Station's acquisition.
#
# Usage (tap ONE data port you found in the capture summaries, e.g. 9879):
#     sudo PORT=9879 ./amp_relay.sh
# Tap every TCP port from the amp:
#     sudo ./amp_relay.sh
# Pick the re-serve port / amp IP / interface:
#     sudo AMP=10.10.10.51 PORT=9879 LISTEN=9000 IFACE=en0 ./amp_relay.sh
# Test offline by replaying a capture you already took (no amp needed, plays at real speed):
#     REPLAY=capture.pcap PORT=9879 ./amp_relay.sh
#
# Then on the other machine:   ./amp_read.sh <mac-ip> 9000
#
# Note: this serves ONE reader at a time (re-arms automatically when it disconnects).

AMP="${AMP:-10.10.10.51}"
PORT="${PORT:-}"            # single amp SOURCE port; empty = all TCP from the amp
LISTEN="${LISTEN:-9000}"
REPLAY="${REPLAY:-}"

# What to capture: everything FROM the amp, optionally one source port.
if [ -n "$PORT" ]; then
  FILTER="src host $AMP and tcp src port $PORT"
else
  FILTER="src host $AMP and tcp"
fi

# Where the pcap bytes come from.
if [ -n "$REPLAY" ]; then
  [ -f "$REPLAY" ] || { echo "No such file: $REPLAY"; exit 1; }
  echo "[relay] REPLAY mode: $REPLAY  filter: $FILTER"
  capture() { tcpdump -r "$REPLAY" -n -s 0 -U -w - "$FILTER" 2>/dev/null; }
else
  IFACE="${IFACE:-$(route -n get "$AMP" 2>/dev/null | awk '/interface:/{print $2}')}"
  [ -n "$IFACE" ] || { echo "[relay] can't find interface to $AMP — set IFACE=enX"; exit 1; }
  echo "[relay] interface: $IFACE   filter: $FILTER   serving on :$LISTEN"
  echo "[relay] (needs sudo for capture)"
  sudo -v || exit 1
  capture() { sudo tcpdump -i "$IFACE" -n -s 0 -U -w - "$FILTER" 2>/dev/null; }
fi

# Ctrl+C just sets a flag; the capture/nc children get the same SIGINT from the
# terminal and exit on their own, so we never signal our own process group.
STOP=0
trap 'STOP=1' INT TERM

# Serve loop: each reader that connects gets a fresh live capture from the moment it connects.
while [ "$STOP" -eq 0 ]; do
  echo "[relay] waiting for a reader to connect on :$LISTEN ..."
  capture | nc -l "$LISTEN"
  [ -n "$REPLAY" ] && { echo "[relay] replay finished."; break; }
  [ "$STOP" -eq 0 ] && { echo "[relay] reader disconnected; re-arming (Ctrl+C to quit)"; sleep 0.5; }
done
echo
echo "[relay] stopped."
