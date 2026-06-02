# LORAX — Lessons Learned
## Building a LoRa Credential Exfiltration Tool from Scratch

This document covers the journey from initial concept to working tool — every bug, dead end, and unexpected discovery encountered along the way. Written to support the security talk narrative.

---

## 1. The Starting Concept

The question was simple: **can you exfiltrate data off an air-gapped machine with no network, no Bluetooth, and no USB?**

LoRa (Long Range radio) and the Meshtastic mesh protocol seemed like a natural answer. Meshtastic is an open-source, off-grid mesh radio platform with off-the-shelf hardware available for under £30 a node. It's primarily used for hiking, emergency comms, and community networks — nobody is looking for credential exfiltration tools on it.

The attack concept:
- Victim machine runs the LORAX sender, connected to a small Meshtastic radio node
- A solar-powered relay node somewhere in range extends the reach
- Attacker machine has its own Meshtastic node, runs the receiver
- No internet. No Wi-Fi. No attribution trail beyond LoRa RF signals

---

## 2. Protocol Evolution: v1 → v2

### v1 — Text-based, naive

The first version used Meshtastic's text message channel. Data was:
- Gzip-compressed
- Base64-encoded (to fit in text messages)
- Chunked at 110 bytes per chunk
- Framed with a hand-rolled ASCII protocol: `EX|<tid>|<seq>|<total>|<data>`

This worked but was inefficient. Base64 inflates size by ~33%, and the ASCII framing added overhead on every single packet. The 110 byte limit was conservative.

### v2 — Binary frames over PRIVATE_APP

The upgrade moved to a binary framing protocol over Meshtastic's `PRIVATE_APP` portnum (256) — a portnum reserved for custom applications. Key improvements:

- Ditched base64: raw binary, 175 bytes usable payload per chunk (vs 110 in v1)
- Proper frame header: `[MAGIC "LX"][TYPE byte][3-char TID][body]`
- ACK/NACK/CHECKPOINT as dedicated frame types
- Auto-selects best compression algorithm (gzip, lzma, or none) per file
- MD5 verification before saving

**Lesson:** Using the right Meshtastic portnum matters. Text messages get processed by every client app and could trigger notifications on other nodes. `PRIVATE_APP` is invisible to normal users.

---

## 3. The PubSub Garbage Collection Bug

The meshtastic-python library uses [PyPubSub](https://pypubsub.readthedocs.io/) for packet callbacks. You subscribe a function to a topic and it fires whenever a matching packet arrives.

The bug was subtle. In the receiver:

```python
# BROKEN — closure has no other reference
pub.subscribe(make_receiver(iface, output_dir, auto_extract), "meshtastic.receive")
```

`make_receiver()` returns a closure. That closure is passed directly to `pub.subscribe`. **PyPubSub stores listeners with weak references.** With no other variable holding the closure, CPython's reference counting immediately garbage-collected it — the subscription vanished microseconds after it was registered.

The tool appeared to start correctly ("Receiver ready") but the callback was already dead. Packets arrived, nothing happened.

The fix was trivially simple:

```python
# FIXED — local variable keeps a strong reference for the life of the function
on_receive = make_receiver(iface, output_dir, auto_extract)
pub.subscribe(on_receive, "meshtastic.receive")
```

**Lesson:** Weak references in callback frameworks are a silent footgun. If a callback registers fine but never fires, check whether the callable is being kept alive. This class of bug produces no error and no warning — it just quietly doesn't work.

---

## 4. The Meshtastic 2.7.x Topic Change

After a meshtastic-python upgrade to 2.7.8, transfers silently stopped working. The library changed how it dispatches received packets. Older versions published everything to `"meshtastic.receive"`. Version 2.7.8 now publishes decoded packets to a portnum-specific subtopic: `"meshtastic.receive.data.PRIVATE_APP"`.

The key discovery: PyPubSub 4.x has a hierarchical topic model. Publishing to a **child** topic notifies **both** child and parent subscribers. Publishing to a **parent** topic only notifies parent subscribers — not children.

This meant:
- Subscribing to `"meshtastic.receive"` (parent): catches all packets regardless of portnum ✓
- Subscribing to `"meshtastic.receive.data.PRIVATE_APP"` (child): only catches decoded PRIVATE_APP; misses undecoded/encrypted packets ✗

The correct subscription is always the parent topic.

**Lesson:** When a library's pubsub dispatch changes, the direction of the hierarchy matters as much as the topic name itself. Test both directions before assuming parent-child delivery is symmetric.

---

## 5. The Asymmetric Radio Link

During early testing, transfers appeared to work in one direction only. The receiver (ThinkNode M1) successfully received all chunks and saved files correctly. But the sender (Heltec) never received ACKs back, and timed out after 90 seconds every time.

Initial suspects: wrong channel PSK, wrong portnum, Python callback issues.

Actual cause: **the radio link was asymmetric**. The Heltec's signal was strong enough to reach the ThinkNode M1 directly. The ThinkNode M1's signal was not reaching the Heltec (or the relay node that would forward it).

A `--mode sniff` on a third node confirmed that ThinkNode M1 transmissions were invisible on the mesh — it was receiving but not being heard.

The immediate fix was to change all receiver response frames (ACK, NACK, HAVE, PONG) from unicast (addressed to sender) to broadcast (`^all`). This slightly improves chances of delivery without requiring a known route back, at the cost of slightly more mesh traffic.

The deeper lesson: **on a unidirectional link, data exfil still works**. The attacker receives everything. The victim just doesn't know delivery was confirmed. For a stealthy implant, not sending ACKs is actually *better* — the attacker node never transmits anything, producing zero RF footprint from the attacker side.

**Lesson:** Asymmetric radio links are common in real deployments. Design protocols to degrade gracefully when the return path is unavailable. Fire-and-forget should be the default mode; ACK confirmation is an optional feature for controlled environments.

---

## 6. Diagnosing with Conn Mode

The asymmetric link problem was initially misdiagnosed multiple times because there was no easy way to test bidirectional comms. Adding a `--mode conn` diagnostic made the issue immediately obvious:

```
Sender side:  PING → !eea17dfc [yas]        ← sends ping, no reply visible
Receiver side: PING → !043aae20 [b90]        ← sends ping
               ✓ PONG from !043aae20 ✓ LINK UP  ← receiver gets pong back
```

One side shows `✓ LINK UP`, the other shows only outgoing pings with no responses. Broken direction identified instantly.

**Lesson:** Build diagnostic modes into tools from the start. A 30-line connectivity check saved hours of guessing during testing. For a talk demo, a clean `✓ LINK UP` / `✗ NO RESPONSE` output is also much more readable to an audience than packet hex dumps.

---

## 7. The rebroadcastMode Config Bug

After ruling out hardware TX faults (a plain text message from the ThinkNode M1 successfully arrived at the Heltec), the issue was narrowed to portnum filtering.

A Meshtastic text message uses portnum `1` (TEXT_MESSAGE_APP). It arrived fine. LORAX uses portnum `256` (PRIVATE_APP). It never arrived.

Root cause: the Heltec had `rebroadcastMode: CORE_PORTNUMS_ONLY` in its device config. This is documented as a *relay* setting — nodes only forward core portnum packets to other mesh nodes. What the documentation doesn't make clear is that in practice, **it also prevents PRIVATE_APP packets from being delivered to the connected Python client**. The firmware received the packet, decided it wasn't worth relaying, and never passed it up the stack.

The fix was a single command:

```bash
meshtastic --host 192.168.8.179 --set device.rebroadcast_mode ALL
meshtastic --host 192.168.8.179 --reboot
```

`conn` mode immediately showed `✓ LINK UP` on both sides after the reboot.

**Lesson:** Meshtastic configuration options interact in non-obvious ways. A relay/routing config (`rebroadcastMode`) accidentally acts as a receive filter for the application layer. When custom portnums behave differently from core portnums, check this setting first. It is the single most common misconfiguration that breaks LORAX-style tools.

---

## 8. What the Sniffer Sees (and Why It Matters)

With a third node running `--mode sniff` during a transfer, you can see exactly what an eavesdropper on the same Meshtastic channel would observe:

**Without encryption:**
```
LORAX  port=PRIVATE_APP  from=!043aae20  to=!eea17dfc  payload=30B  magic=b'LX\x01bsm'
LORAX  port=PRIVATE_APP  from=!043aae20  to=!eea17dfc  payload=183B magic=b'LX\x02bsm'
```

- Source and destination node IDs: visible
- Port 256 (PRIVATE_APP): visible and unusual — no legitimate Meshtastic app uses it
- Transfer timing and packet count: visible
- Filename in the T_START frame: **readable in plaintext** to anyone with the channel PSK

**With E2E encryption:**
```
LORAX  port=PRIVATE_APP  from=!043aae20  to=!eea17dfc  payload=93B  magic=b'LX\x01bsm'
LORAX  port=PRIVATE_APP  from=!043aae20  to=!eea17dfc  payload=199B magic=b'LX\x02bsm'
```

Structurally identical. Same node IDs, same portnum, same packet count. But the payload — including the filename — is now opaque ciphertext. Even a node with the channel PSK sees nothing useful.

**What encryption cannot hide:** that a LORAX transfer happened, between which two node IDs, at what time, and approximately how much data was sent. Traffic analysis is still possible. The only way to hide that is burner hardware with no prior mesh presence.

**Lesson:** Encryption protects content, not metadata. Node IDs are the most dangerous piece of information on the mesh — they're hardware-derived and can tie a transfer to a specific physical device. For a real engagement, use dedicated nodes that have never been registered or associated with any identity.

---

## 9. The MQTT Surprise

While reviewing the Meshtastic node config files, MQTT was found enabled on both the sender and receiver nodes, pointing at a **public** Meshtastic MQTT broker (`mqtt.meshtastic.liamcottle.net`). The primary channel on the Heltec had `uplink_enabled: true` and `downlink_enabled: true`.

This meant that every LORAX transfer — node IDs, timing, packet sizes — was being published to a public MQTT feed, visible to anyone subscribed to `msh/EU_868/#`. The channel PSK encrypts the payload before MQTT upload, so file content wasn't exposed, but operational metadata was.

Additionally, the ThinkNode M1 had `mqtt.proxyToClientEnabled: true`, which proxies MQTT traffic through the connected serial client. This can inject unexpected packets into the LORAX receive stream.

**Lesson:** Meshtastic is designed to be a community mesh network with optional internet bridging. By default, nodes may be connected to the public map and MQTT. Always check MQTT settings before deploying for any covert purpose. Disable it completely with `--set mqtt.enabled false` on every node in the chain.

---

## 10. End-to-End Encryption Design

The Meshtastic channel PSK is shared across all nodes on the channel. For the demo this makes a useful point: without E2E encryption, any node with the PSK can read the transferred credentials. With the default PSK (`AQ==`) — which ships on every out-of-box Meshtastic device — *everyone* can read it.

Adding E2E encryption required solving a key distribution problem without a key exchange server:

**Solution: ephemeral ECDH per transfer**

1. Receiver has a static X25519 key pair stored in `lorax.key` (generated on first run)
2. Receiver prints its public key at startup — operator copies it out-of-band
3. Sender generates a fresh ephemeral X25519 key pair per transfer
4. Sender includes the ephemeral public key in the T_START frame
5. Both sides compute `X25519(my_priv, their_pub)` → HKDF-SHA256 → 32-byte session key scoped to the TID
6. Filename and all chunk data encrypted with ChaCha20-Poly1305

Overhead: 60 bytes on START (one-time), 16 bytes per chunk (AEAD tag). Still comfortably within the 233-byte Meshtastic packet budget.

Forward secrecy: each transfer uses a fresh ephemeral key. Compromise of the receiver's long-term private key does not decrypt past captures, because the session keys were derived from ephemeral keys that no longer exist.

**Lesson:** Off-the-shelf Meshtastic encryption protects data from the general public but not from a targeted adversary with the channel PSK. Adding application-layer E2E takes ~100 lines of Python and changes the threat model completely. The `cryptography` library was already a transitive dependency via meshtastic, so no extra install was required.

---

## 11. Multi-Sender Concurrency

The original receiver used a single `on_receive` callback that maintained a global `transfers` dict keyed by TID. Each received packet updated the dict synchronously inside the meshtastic publishing thread.

The problem: file saving (decompress + write to disk) happened inline inside the callback. With a large file, this blocked the callback thread for several seconds, potentially causing packets from a concurrent sender to be missed.

The fix: each TID spawns a dedicated daemon thread with its own queue. The `on_receive` callback becomes a lightweight dispatcher — it parses the frame type and routes it to the correct thread's queue. Each thread handles chunk accumulation, checkpoint NACKs, END verification, file saving, and ACK sending for its own transfer independently.

```
on_receive()              transfer-abc thread      transfer-xyz thread
      │                         │                         │
      ├─ T_START (abc) ─────────►│                         │
      ├─ T_CHUNK (abc) ─────────►│                         │
      ├─ T_START (xyz) ──────────│─────────────────────────►│
      ├─ T_CHUNK (xyz) ──────────│─────────────────────────►│
      ├─ T_CHUNK (abc) ─────────►│                         │
      └─ T_END   (abc) ─────────►│                         │
                                 │── saves file             │
```

**Lesson:** Callback-based I/O frameworks like PyPubSub expect listeners to return quickly. Move any blocking work (disk I/O, decompression) off the callback thread immediately. Python's `queue.Queue` is the cleanest way to hand off work to a per-task thread without shared mutable state.

---

## Talk Demo Flow

1. **Setup** — show `--mode conn` on both sides: `✓ LINK UP` confirms bidirectional link
2. **Scan** — run `--mode scan` on the victim machine: show what LORAX would harvest
3. **Sniff** — start `--mode sniff` on the third "bystander" node
4. **Unencrypted transfer** — run harvest without `--pubkey`; show sniffer seeing filenames in plaintext
5. **Encrypted transfer** — run harvest with `--pubkey`; show sniffer seeing identical packet structure but opaque ciphertext
6. **Confirm delivery** — show receiver output: MD5 verified, saved, ACK sent
7. **Key points to land:**
   - No network required at any point
   - Solar relay extends range to hundreds of metres or more
   - Encryption hides content but not the fact of a transfer
   - A single misconfigured Meshtastic option (`rebroadcastMode`) can silently break the return path
   - The default Meshtastic PSK means all channel traffic is readable to anyone with a radio and stock firmware

---

## Summary of Key Technical Findings

| Finding | Impact | Fix |
|---|---|---|
| PyPubSub uses weak references | Callback silently disappears if not kept alive | Always assign callback to a named variable before subscribing |
| meshtastic 2.7.x changed pubsub topics | Subscription to wrong topic misses packets | Subscribe to parent topic `"meshtastic.receive"` — catches all portnum subtopics |
| `rebroadcastMode: CORE_PORTNUMS_ONLY` | Silently drops PRIVATE_APP from Python client | Set to `ALL` on any node that needs to receive LORAX traffic |
| Default Meshtastic PSK | All channel traffic readable by any default node | Use a custom channel with random PSK for any sensitive operation |
| MQTT uplink enabled by default | Transfer metadata published to public broker | Disable MQTT on all nodes (`--set mqtt.enabled false`) |
| LORAX filenames in plaintext (without E2E) | Eavesdroppers on same channel see exact filenames | Use `--pubkey` for E2E encryption on all real transfers |
| Asymmetric radio links are common | ACK never reaches sender; sender retransmits indefinitely | Fire-and-forget by default; treat ACK as optional confirmation |
| Node IDs are hardware-derived and permanent | Identifies device across all mesh traffic | Use dedicated burner hardware never previously registered |
