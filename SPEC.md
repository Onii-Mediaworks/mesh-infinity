# Mesh Infinity Technical Specification

**Specification version:** 1.2
**Date:** 2026-03-16
**Status:** Active

---

## Revision History

| Version | Date | Summary |
|---------|------|---------|
| 1.0 | 2026-03-09 | Initial specification. Covered identity model, cryptography, network map, transports (WireGuard/Tor/I2P/BLE/RF/clearnet), hop-by-hop routing, store-and-forward, 4-layer message encryption, key ratcheting, pairing and trust model, social profiles (`identity_is_public`, `address_is_associable`), Signal-parity messaging, file sharing, hosted services, VPN/exit nodes, notifications, platform architecture, FFI boundary, mesh address format, and Mesh DNS (Tailscale-style short-name approval). |
| 1.1 | 2026-03-10 | Security hardening pass. (1) Bootstrap node integrity: pinned Ed25519 pubkey required for all bootstrap entries. (2) Key compromise recovery: new §3.8 `KeyRotationAnnouncement` protocol. (3) Argon2id minimum parameters specified (m=64 MB, t=3, p=4); weaker backups rejected on import. (4) Sequence numbers explicitly u64; 32-bit overflow risk documented. (5) Map timestamp validation: entries >1 hour in the future rejected. (6) Sybil/storage-exhaustion defence: map capped at 100k entries, gossip rate-limited to 500 entries/peer/hour, deduplication set persisted to disk. (7) WoT key-change corroborators must be pre-existing trusted peers, not newly paired. (8) Nonce counter re-handshake threshold specified at 2^48. (9) Padding buckets (256 B–1 MB) and timing jitter ranges (0–250 ms by priority level) defined. (10) Endorsement revocation: `TrustRevocation` record with sequence numbers. (11) Capability flags table (§8.1): `can_be_exit_node`, `can_be_wrapper_node`, etc. — trust level alone no longer sufficient for privileged roles. (12) Exit node DNS: forwarding mandatory in Exit Node mode; exit node uses DoH upstream. (13) Platform keyfile storage: Android Keystore / iOS Keychain / DPAPI / Secret Service per platform. (14) BLE advertisements: rotating ephemeral token only; full identity fetched over encrypted GATT. (15) Tor circuit rotation: explicit 10-minute / 200-message schedule. (16) Store-and-forward TTL: sender-signed expiry enforced by recipient regardless of server behaviour. (17) §17.4 Mesh DNS: replaced BIP39 word-phrase model with Tailscale-style short-name advertisement and per-peer approval. |
| 1.2 | 2026-03-16 | **Signal crypto embedded in Step 2 of the 4-layer scheme.** The 4-layer routing envelope is preserved — it handles forwarding authenticity, sender privacy from relay nodes, and outer recipient encryption. The Step 2 static `channel_key` is replaced with a **Double Ratchet** session key, established via **X3DH** on first contact. This gives the existing scheme per-message forward secrecy and break-in recovery without changing the routing layer. §7.0 added: X3DH pre-key material and session initiation. §7.1 Step 2 updated to use the ratchet-derived `msg_key`. §7.4 ratcheting updated: timer-based rotation replaced with the Double Ratchet algorithm. Group encryption updated to Signal Sender Keys (replacing static group channel key). |

---

## 1. Overview

Mesh Infinity is a **private mesh wide-area network (PMWAN)** and communications platform. It is an alternative to the centralised internet — replacing centralised servers with a web-of-trust-based mesh network bootstrapped over friend nodes, using Tor and I2P as anonymous transports.

At its centre is a **Signal-replacement chat application**. Built out from that core are: social profiles, file sharing, hosted services, system-wide VPN routing, and exit nodes. Every feature available on the open internet must have a mesh equivalent.

The Rust backend is the trusted security boundary. The Flutter UI is a thin rendering layer that issues intent-based commands and renders backend state. Keys, cryptography, transport, and storage never leave Rust.

Unlike Tor, which routes through random relays selected by a directory authority, Mesh Infinity routes through a social graph. Nodes you trust become your routing infrastructure. Nodes your friends trust become reachable via them. The network topology emerges from human relationships rather than from a central coordinator.

Unlike I2P, which forms a standalone overlay, Mesh Infinity is transport-agnostic: it can route over Tor, I2P, WireGuard, Bluetooth, RF, or clearnet — and can mix transports simultaneously. The mesh is the routing and trust layer; the transport is pluggable beneath it.

Unlike Signal, which relies on centralised Signal servers for message delivery, key distribution, and group management, Mesh Infinity performs all of these functions in a distributed manner across the peer network.

A note on the trust model: **anonymization in Mesh Infinity is directed at adversaries, not at trusted contacts.** The goal of wrapper nodes, ephemeral addresses, and onion routing is to prevent surveillance by ISPs, state actors, or unknown nodes — not to hide your identity from people you trust. Within a trusted channel, messages are as transparent as a Signal conversation: the sender and recipient are known to each other, full metadata is visible to both parties, and the experience is designed to feel as natural as any modern chat app. Trusted peers are trusted. The complexity of the anonymization layer is invisible to users communicating with their friends. This is the foundation of the social model: without the ability to genuinely trust your contacts, the network has no value.

---

## 2. Design Principles

1. **Every known attack vector must have a mitigation.** If a design choice creates a deanonymization, correlation, or censorship risk, a countermeasure must exist — not necessarily mandatory, but available. No feature ships if its only known mitigation is "don't use it."

2. **If you can do it on the open internet, you must be able to do it on Mesh Infinity.** Chat, file sharing, web browsing, hosting services, VPN routing, social profiles — all must have a mesh equivalent. This is the feature completeness bar.

3. **Complexity belongs to the system, not the user.** The average user's mental model is: add friends, chat, it's secure. Advanced features exist and are accessible, but never required to achieve safety or functionality. Default settings must be safe defaults.

4. **No cloud dependencies for core function.** Google Play Services, Apple cloud, Microsoft cloud, and equivalent vendor-specific services are prohibited from the critical path. Cloud notifications are permitted only as a ping-only wake transport carrying zero message content (see §14).

5. **Trust is explicit and user-controlled.** No system makes automatic trust decisions on behalf of the user. Trust levels are set by the user; propagated trust is advisory and always overridable.

---

## 3. Identity and Cryptography

### 3.1 Identity Model

Each node has a **local identity** consisting of:

- An **Ed25519 keypair** — used for signing all authenticated communications
- An **X25519 static keypair** — used for Diffie-Hellman key agreement to derive shared secrets
- A **peer ID** — computed as `SHA-256("meshinfinity-peer-id-v1" || ed25519_public_key)`, producing a 32-byte stable identifier

The peer ID is the canonical identity reference used in routing tables, trust records, and the network map. It is derived from the Ed25519 public key but is distinct from any address — addresses are routing targets, the peer ID is the identity.

Nodes may hold multiple identities locally, but one is designated **primary**. The primary identity is used for all outbound signing and is the identity presented to the network.

On first launch, if no identity exists on disk, the onboarding flow runs before the node connects to the network. The node operates with an ephemeral in-memory identity until the user completes onboarding and the identity is persisted.

### 3.2 Key Derivation and Peer ID

Peer IDs use domain separation to prevent cross-protocol attacks:

```
peer_id = SHA-256("meshinfinity-peer-id-v1" || ed25519_public_key_bytes)
```

The domain separation string ensures that the same Ed25519 key used in a different protocol cannot produce the same peer ID.

Trusted-channel symmetric keys are derived from the X25519 DH exchange between two peers:

```
shared_secret = X25519(my_x25519_secret, their_x25519_public)
channel_key   = HKDF-SHA256(shared_secret, salt="meshinfinity-channel-v1", info=peer_id_a || peer_id_b)
```

where `peer_id_a` and `peer_id_b` are sorted lexicographically to produce the same key regardless of which side initiates.

### 3.3 Multiple Public Addresses and Keys

Every node has **at least one public address**, and deliberately maintains multiple. A node bound to a single stable public address is a deanonymization vector: an observer correlating traffic across transports can link all activity to one identity via that address.

Each public address corresponds to a distinct keypair. A node generates multiple Ed25519/X25519 keypair sets, each producing a distinct public address. Rotating or adding addresses does not require updating the trusted-channel addresses established with existing friends, because trusted channels use the DH-derived key, not the public address.

Address types and their propagation:

| Type | Derivation | Propagated In | Scope |
|------|-----------|---------------|-------|
| **Primary** | Deterministic from primary Ed25519 public key | Network map | Anyone |
| **Secondary** | Additional keypairs, same node | Network map | Anyone |
| **Trusted Channel** | X25519 DH between two specific peers | Direct trusted exchange only | That peer only |
| **Group Channel** | X25519 DH with group keypair | Group member exchange | Group members only |
| **Ephemeral** | Random per session | Never stored or propagated | Single session |

Public addresses and their corresponding public keys are broadcast in the network map. Any node can encrypt an initial message to a public address using the public key. Ephemeral addresses are generated for individual sessions and discarded; they prevent session correlation without requiring key material management.

### 3.4 Encryption Negotiations

Mesh Infinity does not assume software-only cryptography. On connection establishment, peers negotiate which cryptographic primitives to use based on hardware capabilities and mutual preference:

**Symmetric encryption:**
- `CHACHA20_POLY1305` — preferred for software-only environments; constant-time on all platforms without hardware support
- `AES_256_GCM` — preferred when AES hardware acceleration is available (ARM AES, Intel AES-NI); faster on supported hardware

**Key agreement:** X25519 (always; not negotiated)

**Signing:** Ed25519 (always; not negotiated)

**Hash:** SHA-256 (baseline), BLAKE3 (preferred where available — faster in software)

The negotiation handshake is itself signed by both parties' Ed25519 keys, preventing a downgrade-by-interception attack. If either party's preferred primitive set is not supported by the other, they fall back to the common intersection. If no intersection exists, the connection is rejected.

All connections default to ChaCha20-Poly1305 to ensure a safe baseline without hardware probing.

### 3.5 Zero-Knowledge Proofs and Deniability

Deniability is a core requirement. The system provides it at multiple layers:

#### Message-Level Deniability

Messages within trusted channels are authenticated using **HMAC-SHA256 with the shared channel key** (derived from X25519 DH, see §3.2), rather than Ed25519 signatures alone. Since both parties possess the shared channel key, neither party can prove to a third party who authored any specific message — both have the cryptographic capability to produce any MAC under that key.

Ed25519 signatures are still applied at the transport/routing layer for hop-by-hop forwarding authentication, but these outer signatures cover only the encrypted payload, not the plaintext content. A forwarding node cannot determine whether the signature on a packet it forwards represents the original author or a re-signed relay.

#### Group Membership Deniability — Ring Signatures

To prove membership in a trusted group without revealing *which* member you are, group operations use **ring signatures** (specifically, a Schnorr-based ring signature scheme):

- A ring signature proves that the signer holds *one of* the private keys in a set (the ring), without revealing which one
- Group membership proofs, group message authentication, and group admin actions use ring signatures over the group's member public key set
- An external observer can verify that *some* group member performed an action, but cannot determine which member
- The ring is the current group member set; as members join or leave, the ring is updated

#### Connection Deniability

Wrapper node routing (§4.3) combined with ephemeral source addresses prevents linking a specific connection event to a specific identity. No persistent logs are kept of which identities connected to which. Routing metadata (which hops were used) is not preserved beyond the active session.

#### Key Ownership Proofs — Sigma Protocols

During pairing, a **Σ-protocol (Sigma protocol)** is used to prove knowledge of the private key corresponding to a presented public key, without transmitting the private key or creating a replayable transcript:

1. **Commit:** The prover generates an ephemeral keypair `(r, R)` where `R = r·G`. They send `R` to the verifier.
2. **Challenge:** The verifier sends a random challenge `c`.
3. **Respond:** The prover sends `s = r + c·sk` where `sk` is the secret key.
4. **Verify:** The verifier checks `s·G == R + c·PK`.

The transcript `(R, c, s)` is non-replayable: `c` is chosen by the verifier in this session and cannot be forged. The interaction proves knowledge of `sk` without revealing it. The transcript does not constitute a proof to a third party because the verifier could have fabricated a consistent `(R, c, s)` tuple.

All pairing flows use this protocol as the authentication step.

### 3.6 Identity Persistence

Identity material is stored on disk encrypted with a random keyfile:

- `identity.key` — 32 bytes of random data, the encryption key
- `identity.dat` — 12-byte random nonce followed by ChaCha20-Poly1305 ciphertext of the JSON-serialised identity payload

**Platform-level keyfile protection:**

The `identity.key` file is the highest-value target for an attacker with filesystem access. Where the platform provides hardware-backed secure storage, the keyfile bytes are stored there instead of as a plain file:

| Platform | Keyfile storage |
|----------|----------------|
| Android | Android Keystore (hardware-backed if device supports StrongBox or TEE) |
| iOS | iOS Keychain with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` |
| macOS | macOS Keychain (may be software-backed on non-T2/Apple Silicon) |
| Linux | Secret Service API (if available: GNOME Keyring, KWallet); otherwise filesystem with `0600` permissions |
| Windows | DPAPI (Data Protection API) wrapping the keyfile bytes |

On platforms where no secure storage is available, the filesystem keyfile is used with the most restrictive permissions the OS allows. Full-disk encryption is strongly recommended in this case (documented in the setup guide).

The identity payload contains:
- Ed25519 secret key (32 bytes)
- X25519 static secret key (32 bytes)
- Display name (optional)
- Public profile fields
- Private profile fields

On startup, if both files exist, the identity is decrypted and loaded into memory. If either file is absent, the node treats itself as having no persistent identity and runs the onboarding flow.

### 3.7 Identity Backup and Restore

Identity backups preserve the **network map, public profile, and private profile**. Private keys are intentionally **not** backed up. This is a deliberate design decision: if a backup is compromised, the attacker gains the social graph and profile data but cannot impersonate the original identity or decrypt past messages encrypted to the original keys.

**What is backed up:**
- Network map snapshot: known peer IDs, their public addresses, their public keys
- Public profile: display name, bio, avatar hash, visibility settings
- Private profile: private display name, private bio, contact hints
- Trusted group membership records (group IDs, group public keys, member lists)

**What is NOT backed up:**
- Private signing keys
- Private DH keys
- Trusted-channel shared secrets
- Message history (handled separately, if at all)

**Restore process:**
1. User imports the backup file and provides the passphrase
2. The system decrypts the backup using ChaCha20-Poly1305 with Argon2id-derived key. Argon2id parameters must meet or exceed the minimum values: `m_cost = 65536` (64 MB), `t_cost = 3`, `p_cost = 4`. Backup files produced with weaker parameters are rejected on import with an explicit error. These defaults are reviewed against OWASP recommendations at each major version bump.
3. A fresh Ed25519 and X25519 keypair is generated
4. New public addresses are derived from the new keypair
5. The network map is restored, giving the node a starting list of known peers
6. Profile data is restored
7. The node connects to the network using the restored map as its bootstrap list
8. Existing trusted peers see a new peer ID at the restored public addresses. They must manually re-mark the restored identity as trusted — trust cannot be re-established automatically because the keypair changed.

### 3.8 Key Compromise Recovery

If a private key is believed compromised (device stolen, disk imaged by an adversary), the user must:

1. **Trigger the killswitch** (§3.9) on the compromised device if accessible, destroying the local key material.
2. **Generate a new identity** on a clean device (via the normal onboarding flow or backup restore).
3. **Announce the key rotation** to trusted peers: the user signs a `KeyRotationAnnouncement` using their *old* key (if still available) that binds the old peer ID to the new peer ID:

```
KeyRotationAnnouncement {
    old_peer_id:      [u8; 32],
    new_peer_id:      [u8; 32],
    new_ed25519_pub:  [u8; 32],
    new_x25519_pub:   [u8; 32],
    timestamp:        u64,
    reason:           String,        // "device_loss", "compromise", "migration"
    old_signature:    [u8; 64],      // Ed25519 signature by old key over all other fields
}
```

Trusted peers who receive and verify a `KeyRotationAnnouncement` signed by the old key may automatically accept the new key at the same trust level, skipping the WoT corroboration requirement of §4.6. The user is still notified and can review.

4. **If the old key is no longer available** (e.g., device is gone and no backup exists), key rotation cannot be cryptographically proven. In this case trusted peers must re-pair directly with the new identity. The old peer ID should be treated as permanently revoked by the user's contacts — a signed revocation can be issued by any peer at trust level ≥ `Trusted` and gossiped as a social signal.

**Important:** A `KeyRotationAnnouncement` from an *unrecognised* old key (i.e., an old key no peer has seen before) is not automatically trusted — this would allow an attacker to pre-generate a chain of key rotations. The announcement is only accepted if the old key matches the previously known key for that peer ID.

The backup file format is:
```
EncryptedBackup {
    version: u32,
    argon2id_salt: [u8; 32],
    argon2id_params: { m_cost, t_cost, p_cost },   // minimum: m_cost=65536 (64 MB), t_cost=3, p_cost=4
    nonce: [u8; 12],
    ciphertext: Vec<u8>,  // ChaCha20-Poly1305 of JSON BackupPayload
}
```

### 3.9 Killswitch / Emergency Data Destruction

The killswitch permanently destroys the local identity and renders all associated data unreadable:

1. `identity.key` is **overwritten with 32 bytes of fresh random data** — this makes the existing `identity.dat` ciphertext permanently unreadable even if an adversary has a copy of the ciphertext, because they cannot know the new key that was written over the original
2. `identity.key` is then deleted
3. `identity.dat` is deleted
4. The network map database is deleted
5. Profile data is deleted
6. Cached messages are deleted

Steps 1–2 are the security-critical steps. The overwrite is performed before deletion to ensure the original key material is irrecoverable even from undeleted disk sectors. After step 1, the ciphertext in `identity.dat` is cryptographically orphaned.

This is irreversible without a prior backup.

---

## 4. Network Model

### 4.1 Bootstrapping and Network Map Propagation

Mesh Infinity has no central directory server. Discovery is bootstrapped as follows:

1. On startup, attempt to connect to known **friend nodes** (peers in the local trust store at level `Trusted` or above) first.
2. If no friend nodes are immediately reachable, attempt connection to any previously known node in the network map.
3. On any new connection, perform a **map exchange**: each side serialises their known network map and sends it. The receiving side merges the incoming entries with their local map, preferring newer timestamps.
4. The merged map is then gossiped to other connected peers, who repeat the merge process. Changes propagate across the network in rounds of gossip until they reach all connected nodes.

There is no guarantee of delivery speed. The network is **eventually consistent**: a new node appearing in the map will be visible to all connected peers within some number of gossip rounds, proportional to the diameter of the connected graph.

The network map is a **public-only** structure. It contains:
- Peer IDs
- Public addresses and their corresponding public keys
- Last-seen timestamp (for staleness detection)
- Reachability hints: which transports this peer has been seen on
- Optional: public profile summary (display name, avatar hash) if the peer has `identity_is_public = true`
- Optional: public service advertisements

Trusted-channel addresses, private profile data, and group membership are **never included** in the network map.

### 4.2 Network Map Data Structure

Each entry in the network map:

```
NetworkMapEntry {
    peer_id: [u8; 32],
    public_keys: Vec<PublicKeyRecord>,
    last_seen: u64,             // Unix timestamp
    transport_hints: Vec<TransportHint>,
    public_profile: Option<PublicProfileSummary>,
    services: Vec<PublicServiceAdvertisement>,
}

PublicKeyRecord {
    ed25519_public: [u8; 32],
    x25519_public: [u8; 32],
    address: DeviceAddress,     // The public address this key corresponds to
}

TransportHint {
    transport: TransportType,
    endpoint: Option<String>,   // e.g. Tor hidden service address, clearnet IP
}
```

Map entries are versioned by `last_seen` timestamp. When merging two maps, the entry with the newer `last_seen` wins for each `peer_id`. Entries older than a configurable staleness threshold (default: 30 days) are pruned from the local map.

**Sybil and storage-exhaustion defense:**

- The local network map is capped at a configurable maximum entry count (default: **100,000 entries**). When the cap is reached, new entries from peers below trust level `Trusted` are accepted only by evicting the oldest `Untrusted` entry (LRU eviction within the `Untrusted` bucket). Entries from `Trusted` or higher peers are always accepted.
- Gossip from a single peer is rate-limited: a node will not accept more than **500 new peer ID entries per peer per hour**. Entries beyond that rate are dropped and the sending peer's gossip rate is logged.
- Per-gossip-round deduplication: a node that has already forwarded an announcement with a given `announcement_id` will not forward it again for **24 hours**, preventing amplification storms even if the node restarts (the deduplication set is persisted to disk across restarts to survive crashes).

### 4.3 Server-Mode Directory Nodes

Standard client nodes maintain a network map as a side effect of normal operation, but do not actively seek out updates. **Server-mode directory nodes** actively maintain map freshness:

- Periodically re-ping known peers to update their last-seen timestamps
- Accept map update requests from client nodes without requiring a full map exchange
- Cache and re-serve the full map to any connecting node
- Keep a longer staleness window (configurable; default 90 days vs clients' 30 days)
- May be configured as a **bootstrap node**: its address is hardcoded or user-configured as the first-connection target for new nodes

Directory nodes are not a privileged position in the network. They hold more current data but have no special routing or trust authority. Multiple directory nodes may exist; a client node can query any of them.

**Bootstrap node integrity:** A new node that connects to a bootstrap node with a poisoned map receives incorrect peer data before it has any trusted peers to cross-check against. To mitigate this:

- Hardcoded or user-configured bootstrap node addresses must include the expected **Ed25519 public key** (not just an address). The first connection verifies the WireGuard handshake against that pinned key; if they don't match, the connection is rejected and the user is warned.
- Bootstrap addresses are specified in the form `<transport_address>:<pubkey_hex>` so the public key is always bundled with the address. A bootstrap entry without a pinned key is accepted only interactively (the user sees the fingerprint and confirms before the map is merged).
- Once the first trusted peer is established via direct pairing, subsequent map updates are cross-checked against the trusted peer's map. Systematic divergence between the bootstrap node's map and the trusted-peer map triggers a warning.

### 4.4 Anonymization: Wrapper Nodes

Wrapper nodes are an **optional** privacy layer for situations where the public address correlation risk is unacceptable. A sender routes a message through one or more intermediate nodes before it reaches the destination, with each layer of the message encrypted for the next hop — an onion model, but routed through the web-of-trust graph.

**Key design detail:** Keys are shared with **both** the wrapper node and the target directly. Specifically:

- The message payload is encrypted for the target's public key in the innermost layer
- Each wrapper node receives a key that allows it to decrypt only the outer envelope, revealing the address of the next hop
- The target can decrypt the innermost layer using its own private key
- Removing a wrapper node from the network does not prevent the target from receiving messages — the target already has the key to the innermost layer, and can receive via an alternative path or directly

This differs from pure onion routing: in Tor, if a relay disappears, the circuit breaks. In Mesh Infinity wrapper routing, the key material is pre-shared, so the sender can attempt an alternative path to the target while the target can still decrypt any copy of the message that arrives.

**Wrapper node selection:** Wrappers are chosen from trusted peers, based on:
- Trust level (higher preferred)
- Connectivity (well-connected peers make better wrappers)
- Mutual agreement — a node can indicate willingness to act as a wrapper in its network map entry

Multiple layers can be stacked. The depth is configurable per-message or per-contact.

### 4.5 Map Update Authentication

All network map updates must be **signed by the key being updated**. A "fresher timestamp wins" model is not used alone — it is trivially exploitable: any node could broadcast a fake update with a future timestamp and overwrite legitimate entries.

Every `NetworkMapEntry` carries a `signature` field:

```
NetworkMapEntry {
    ...
    sequence:  u64,       // Monotonically increasing per peer_id; prevents replay. 64-bit minimum — 32-bit overflows are exploitable.
    signature: [u8; 64],  // Ed25519 signature over all other fields, by the entry's own key
}
```

Rules for accepting an update:
1. The signature must verify against the Ed25519 public key in the entry itself
2. The `sequence` number must be strictly greater than the locally stored sequence for that `peer_id`
3. The `last_seen` timestamp must not be more than **1 hour in the future** relative to the receiving node's local clock. Entries with future-dated timestamps beyond this window are rejected outright — without this check, an attacker can craft an entry with a timestamp 60 days in the future that survives all pruning passes and permanently displaces the legitimate entry.
4. If the entry's public key set **differs** from the locally stored one (a key change), the update is not automatically accepted — see §4.6

Revocations follow the same model: a `Revocation { address, sequence, signature }` is only accepted if signed by the key that owns the address being revoked, and the sequence is newer than any accepted entry for that peer.

### 4.6 Key Change Validation via Web of Trust

When a received map update changes the public key(s) for a known `peer_id`, this is a high-suspicion event. A sudden key change is the signature of either a legitimate device migration or an impersonation attack — the network cannot distinguish these automatically.

**Key change policy:**

1. **Flagged, not automatically accepted.** A key-change update is held in a quarantine state locally. The user is notified: *"[Peer name] appears to have changed their key. This may mean they have a new device, or it may indicate an attack."*

2. **WoT corroboration required.** The update is not promoted to accepted until a threshold of mutually trusted peers have also received and accepted the same key change for that peer ID. The threshold is configurable (default: 2 trusted peers). If 2 or more peers at trust level ≥ `Trusted` have accepted the new key, the update is promoted. **Corroborating peers must be independently established:** a peer cannot satisfy the threshold by corroborating their own key change (i.e., the peer whose key is changing cannot count as a corroborator), and both corroborators must have been trusted by the local node *before* the key-change event — not newly paired after it.

3. **Direct confirmation overrides.** If the local user directly pairs with the peer again (any pairing method — QR, code, proximity), this constitutes first-hand confirmation and immediately accepts the key change.

4. **Automatic rejection of rapid re-changes.** If a peer's key changes more than once within a short window (default: 24 hours), all further changes within that window are rejected outright and the user is alerted. Legitimate device migrations do not involve rapid key cycling.

5. **Stale key protection.** A previously accepted key is never overwritten by a key-change update that only has timestamp authority (i.e., a newer timestamp alone is not sufficient — it must also have WoT corroboration or direct confirmation).

This model follows "trust, but verify": the network accepts that key changes happen legitimately, but treats them with appropriate suspicion and requires social consensus before acting on them.

### 4.7 Map Conflict Resolution

For non-key-change updates (address additions, transport hint updates, profile updates) to an already-known key:

- The update with the higher `sequence` number wins
- If `sequence` numbers are equal but content differs, entries are merged: the union of transport hints and public keys is taken; the newer profile summary wins
- All accepted updates must pass signature verification (§4.5) before being applied or gossiped

---

## 5. Transport Layer

### 5.1 WireGuard — Primary Per-Hop Link Encryption

**WireGuard is the primary protocol for all active direct connections between mesh peers.** Every direct link in the mesh is a WireGuard tunnel. This is not a transport in the anonymization sense — it is the encrypted link layer that runs *beneath* anonymizing transports.

The WireGuard layer provides:
- **Peer authentication** — WireGuard handshake authenticates both sides using their public keys, which are the same public keys known from the network map. A connection that claims to be from peer X but does not hold X's private key will fail the handshake.
- **Forward secrecy** — WireGuard's handshake rotates ephemeral Diffie-Hellman keys. Compromise of the static keys does not expose past session content.
- **Efficient encrypted tunneling** — after the handshake, WireGuard provides a low-overhead encrypted UDP channel suitable for high-throughput data

The full stack for a message from A to B via Tor:

```
A: application message
   → 4-layer application crypto (§7)
   → WireGuard encrypt (A→B tunnel key)
   → Tor circuit to B's hidden service
B: Tor circuit
   → WireGuard decrypt
   → 4-layer application crypto decrypt
   → deliver to application
```

WireGuard is always present. The anonymizing transport (Tor, I2P) wraps the WireGuard tunnel. Direct transports (Bluetooth, clearnet) carry the WireGuard tunnel directly.

### 5.2 Tor

Tor is the **primary anonymizing transport**. Tor hidden services are used to expose mesh endpoints without revealing the host's IP address.

- Each node generates a Tor v3 onion address derived from its Ed25519 keypair (Tor v3 uses the same Ed25519 key format)
- This onion address is included in the node's network map `transport_hints` for peers who have Tor enabled
- Outbound connections to peers use the Tor SOCKS proxy (via the `arti` Rust client)
- Inbound connections are received on the node's hidden service

Tor circuit management:
- Separate Tor circuits are used per peer where possible, to prevent correlation of traffic across conversations
- Circuit isolation is implemented at the Tor stream level using separate SOCKS credentials per peer (Tor's stream isolation feature)
- **Circuit rotation:** circuits are rotated on a **10-minute** periodic schedule or after **200 messages** on a single circuit, whichever comes first. Circuits are also rotated immediately on a sustained latency spike (> 2× baseline for more than 30 seconds), which may indicate circuit-level surveillance or congestion. A new circuit is established before the old one is torn down to prevent a gap in connectivity.

When Tor is unavailable or the peer is not reachable via Tor, the system falls back to I2P, then clearnet (if enabled).

### 5.3 I2P

I2P is the **secondary anonymizing transport**, using garlic routing (bundled encrypted tunnels). I2P provides different anonymity properties from Tor — it is more resistant to some traffic analysis attacks and less resistant to others, making it a useful complement.

- Each node generates an I2P destination from its keypair
- I2P destinations are included in the network map `transport_hints`
- Outbound connections use I2P's SAM (Simple Anonymous Messaging) API
- Inbound connections arrive at the node's I2P destination

I2P is slower to establish than Tor (tunnel building takes longer) but may be more resilient in environments where Tor is actively blocked.

### 5.4 Clearnet

Clearnet is direct IP connectivity — TCP or UDP to a known IP address. It carries no transport-level anonymization, but like all transports, it carries WireGuard-encrypted traffic and application-layer encryption.

**Critical constraint: clearnet is used for single hops only.** It is never used end-to-end. The hop-by-hop routing model ensures this naturally: the destination address in any packet is always a mesh address, never an IP address. A clearnet hop connects two mesh nodes that happen to be adjacent in the routing path and both have clearnet enabled. The routing node forwarding the packet knows only the next mesh hop; it does not know whether that hop is the origin or destination of the original message.

**Clearnet public addresses:** A node with clearnet enabled gets its own distinct public address(es) for its clearnet-accessible endpoint(s). This address is separate from the node's Tor or I2P addresses. Because the clearnet address is just another mesh address from the routing layer's perspective, even a direct clearnet hop between two nodes that happen to be the origin and destination of a conversation does not expose that relationship — the routing tables operate on mesh addresses, and the clearnet IP is a transport detail below that layer.

- **Disabled by default.** Enabling is an explicit user opt-in, clearly labelled as reducing transport anonymization.
- When enabled, the node's clearnet endpoint (IP:port) and its associated mesh address are added to its network map entry's transport hints.
- Suitable for high-bandwidth local-network scenarios (home server, LAN file transfer, voice/video calls) where anonymization is secondary to performance.
- Priority in transport selection: lowest for security-sensitive connections; elevated for latency-sensitive or bandwidth-intensive connections (voice, video, large file transfers) when the user has opted in.

### 5.5 Bluetooth LE

Bluetooth Low Energy enables **offline local mesh formation** without any internet connection. This is critical for scenarios where all internet connectivity is blocked or unavailable.

- Nodes advertise their presence via BLE advertising packets. **BLE advertisements are unencrypted by protocol design** — any nearby BLE scanner can see them. To limit information leakage:
  - The advertisement payload contains only the **Mesh Service UUID** and a rotating **ephemeral token** (32 bits, rotated every 15 minutes). It does not contain the node's mesh address, peer ID, or display name.
  - The full peer identity (mesh address, Ed25519 public key) is fetched over a GATT connection *after* the remote device has indicated it is a Mesh Infinity node — this fetch is encrypted at the WireGuard layer.
  - The ephemeral token rotation prevents passive BLE scanners from tracking the device over time by its advertisement payload.
- Discovered nearby nodes are added as potential routing targets after the encrypted GATT identity exchange completes
- A custom GATT profile is used for data exchange:
  - **Mesh Service UUID**: a fixed UUID identifying the Mesh Infinity GATT service
  - **Packet Characteristic**: write-with-response, for sending mesh packets
  - **Notification Characteristic**: notify, for the remote node to push incoming packets
- BLE connections are short-range (~10m) and low-bandwidth; they are best suited for discovery and short messages
- WireGuard tunnels run over BLE connections for link encryption and peer authentication
- MTU negotiation is performed at connection time; large messages are fragmented

The BLE transport enables device-to-device meshing without any infrastructure, making it suitable for local groups, events, or disaster scenarios.

### 5.6 RF / Meshtastic

RF (radio frequency) transport via Meshtastic-compatible hardware provides **long-range, infrastructure-free** connectivity:

- Supported hardware: LoRa-based Meshtastic devices connected to the host device via USB or Bluetooth serial
- Range: typically 5–50km line-of-sight depending on hardware and terrain
- Bandwidth: very low (typically 250 bps–5 kbps); suitable for text messages and small packets only
- The Meshtastic serial protocol is used to send and receive mesh packets via the connected radio
- Mesh Infinity uses Meshtastic as a transport backend; it does not replicate Meshtastic's own routing — Mesh Infinity's routing layer runs on top
- This transport is critical for disaster scenarios, remote areas, and situations where all electronic infrastructure is unavailable

Due to the extreme bandwidth constraints of RF, large messages (media, files) cannot be sent over this transport. The system automatically selects transports based on message size and transport capabilities.

### 5.7 Transport Selection and Fallback

The TransportManager selects the best available transport per peer per message:

**Priority order (default, user-configurable):**
1. Direct WireGuard over BLE (if peer is in BLE range — lowest latency for local)
2. Tor (primary anonymizing transport)
3. I2P (secondary anonymizing transport)
4. WireGuard over clearnet (if enabled by user)
5. RF/Meshtastic (if connected radio hardware is present and peer is reachable)

Fallback is automatic and transparent to the user. If the highest-priority transport fails to connect within a timeout, the next transport is tried.

Per-peer transport preferences override the global order. A peer can specify in their network map which transports they prefer for inbound connections.

For **large payloads** (file transfers, voice/video streams), the system additionally considers:
- Available bandwidth (RF is excluded for payloads above a configurable size threshold)
- Connection latency (important for voice/video)
- Connection stability (BLE is not suitable for large sustained transfers)

### 5.8 Transport Health Monitoring

The TransportManager continuously monitors the health of active connections:

- **Keepalive probes** sent on idle connections at a configurable interval (default: 25s, matching WireGuard's persistent keepalive recommendation)
- **Latency measurement** via probe round-trip times; reported in reachability announcements
- **Bandwidth estimation** for large transfers; used for transport selection
- **Dead connection detection**: connections with no response within a timeout are marked dead and the peer is attempted via the next available transport
- Transport health metrics are exposed via the FFI for UI display

---

## 6. Routing

### 6.1 Hop-by-Hop Routing (Default)

Mesh Infinity uses **discovery-driven, hop-by-hop routing** by default. This model has strong privacy properties: no single node knows the full path a message takes.

Routing decisions at each node:
1. Check the local routing table for the destination address
2. If a direct connection to the destination exists, deliver directly
3. Otherwise, forward to the neighbour with the best `(hop_count, latency, trust_level)` score toward the destination
4. The next node repeats the process

```
Node A ──► Node B ──► Node C ──► Node D (destination)

At A: "my routing table says B has the lowest-cost path to D"
At B: "my routing table says C has the lowest-cost path to D"
At C: "my routing table says D is directly connected to me"
```

No node except A knows the full path A→B→C→D. B knows only that it received a packet from A destined for D and forwarded it to C. C knows only that it received from B and delivered to D.

### 6.2 Reachability Announcements

Nodes share routing information with their direct neighbours via **reachability announcements**:

```
ReachabilityAnnouncement {
    destination:      DeviceAddress,   // Who can be reached via this path
    hop_count:        u8,              // Number of hops (this node adds 1 before forwarding)
    latency_ms:       u32,             // Cumulative estimated latency
    path_trust:       TrustLevel,      // Minimum trust level along the path
    announcement_id:  [u8; 16],        // Random ID for deduplication
    timestamp:        u64,             // When this announcement was generated
    ttl:              u8,              // Max hops to propagate (decremented each hop)
}
```

Announcements are signed by the originating node and re-signed at each forwarding hop (outer signature only). Nodes that receive an announcement:
1. Check `announcement_id` for deduplication — if already seen, discard
2. Decrement `ttl` — if zero, discard
3. Add 1 to `hop_count` and update `latency_ms` based on observed link latency
4. Update the local routing table if this is a better path than the existing entry
5. Forward the announcement to direct neighbours

### 6.3 Trust-Weighted Path Selection

When multiple paths exist to a destination, paths are scored by:

```
score = (1.0 / hop_count) * trust_weight(path_trust) * (1.0 / latency_ms)

trust_weight(Untrusted)     = 0.1
trust_weight(Caution)       = 0.5
trust_weight(Trusted)       = 1.0
trust_weight(HighlyTrusted) = 1.5
```

A path with high trust and moderate latency is preferred over a lower-latency path through untrusted nodes. This prevents an adversary from inserting high-performance relay nodes to attract traffic.

### 6.4 Loop Prevention

Routing loops are prevented by:
- The `announcement_id` deduplication field — nodes never forward an announcement they have already forwarded
- The `ttl` field — announcements expire after a bounded number of hops (default max TTL: 16)
- The `hop_count` field — loops would cause `hop_count` to exceed the known diameter of the network, at which point announcements are discarded

### 6.5 Fast Routing Mode (Opt-in, Reduced Privacy)

An opt-in **fast routing mode** is available in settings for users who prioritise latency over anonymity:

- Nodes in fast mode share their full local routing table (not just reachability announcements)
- A Dijkstra's algorithm is run over the collected topology to compute optimal end-to-end paths
- The source node encodes the full path in the packet header
- Intermediate nodes follow the encoded path without making independent decisions

Privacy tradeoffs:
- The originating node must know the full network topology to compute paths
- Each intermediate node learns both the previous and next hop, making traffic analysis easier
- A network observer watching multiple nodes can reconstruct the full path

This mode is appropriate for high-throughput local mesh scenarios (LAN over Bluetooth, trusted home network over clearnet) where anonymization is not the concern. It is disabled by default and clearly labelled in the settings UI as a privacy-reducing option.

### 6.6 Store-and-Forward as Offline Fallback

When the destination is unreachable and a server-mode node in the routing path supports store-and-forward:

1. The message is forwarded to the server node as far as it can be delivered
2. The server node caches the message with the destination address. The message envelope includes a **signed expiry timestamp** set by the original sender: `expiry = send_time + ttl`, signed by the sender's Ed25519 key. The server node cannot extend this expiry without breaking the signature.
3. The server retries delivery periodically (configurable interval; default: every 5 minutes)
4. When the destination comes online and polls its known server nodes, the queued message is delivered. **Recipients reject messages whose signed expiry timestamp has passed** — even if the server delivers them late. This prevents a malicious server from replaying stored messages after their intended TTL.
5. Messages have a configurable sender-side TTL (default: 7 days). The signed expiry is authoritative; server-side TTL enforcement is a courtesy only.

The store-and-forward mechanism operates above the routing layer. The hop-by-hop router handles live delivery; store-and-forward is invoked only when live delivery fails and a capable server node is reachable.

---

## 7. Message Encryption Scheme

### 7.0 Inner Session Key Establishment — X3DH + Double Ratchet

The 4-layer scheme (§7.1) uses a per-peer **session key** for Step 2 (trusted-channel encryption). This session key is not static — it is established via **X3DH** on first contact and advanced with every message via the **Double Ratchet**. This gives the chat layer the same cryptographic properties as Signal: authenticated key agreement, per-message forward secrecy, and break-in recovery.

#### Pre-Key Material

Each node maintains and publishes in the network map:

```
PreKeyBundle {
    identity_key_pub:    [u8; 32],   // X25519 IK public (same as §3.1 X25519 static pub)
    signed_prekey_pub:   [u8; 32],   // X25519 SPK public (rotated every 7 days)
    signed_prekey_id:    u32,
    signed_prekey_sig:   [u8; 64],   // Ed25519 sig over signed_prekey_pub by IK's Ed25519 key
    one_time_prekey_pub: Option<[u8; 32]>,  // OPK (single-use; absent when pool is empty)
    one_time_prekey_id:  Option<u32>,
}
```

OPK pool: minimum threshold 10, refill target 50. SPK rotation: 7-day default.

#### X3DH Session Initiation (first message to a peer)

Alice fetches Bob's `PreKeyBundle`, verifies `signed_prekey_sig`, then:

```
EK_A = generate_x25519_keypair()          // ephemeral key, discarded after

DH1 = X25519(IK_A_secret,  SPK_B_pub)
DH2 = X25519(EK_A_secret,  IK_B_pub)
DH3 = X25519(EK_A_secret,  SPK_B_pub)
DH4 = X25519(EK_A_secret,  OPK_B_pub)    // omitted if no OPK

master_secret = HKDF-SHA256(
    salt = 0x00 * 32,
    ikm  = 0xFF * 32 || DH1 || DH2 || DH3 [|| DH4],
    info = "MeshInfinity_X3DH_v1",
    len  = 32
)
```

Alice then initialises the Double Ratchet as sender (`master_secret`, `SPK_B_pub` as initial ratchet pub). The first message includes an `X3dhInitHeader { ik_pub, eph_pub, opk_id }` so Bob can reproduce the same `master_secret` and initialise the ratchet as receiver.

#### Double Ratchet

After X3DH the session key advances with every message:

```
// KDF chain (symmetric ratchet — advances per message)
msg_key       = HMAC-SHA256(chain_key, 0x01)
new_chain_key = HMAC-SHA256(chain_key, 0x02)

// Root key ratchet (DH step — triggered by each new DH ratchet public key received)
(new_root_key, new_chain_key) = HKDF-SHA256(
    salt = root_key,
    ikm  = X25519(my_ratchet_secret, their_new_ratchet_pub),
    info = "MeshInfinity_DR_v1",
    len  = 64                         // first 32: new root; last 32: new chain key
)

// Message key expansion (key + nonce for AEAD)
keys       = HKDF-SHA256(salt=0*32, ikm=msg_key, info="MeshInfinity_MK_v1", len=76)
cipher_key = keys[0..32]
nonce      = keys[32..44]             // 12 bytes for ChaCha20-Poly1305
```

The `msg_key` derived here is what Step 2 below uses as `session_key`. Out-of-order delivery is handled by caching up to 1,000 skipped message keys indexed by `(ratchet_pub, msg_number)`.

#### Group Encryption — Sender Keys

Group chats use **Signal Sender Keys** rather than a static group channel key:

- Each member has a per-group **Sender Key**: `(chain_key: [u8; 32], iteration: u32, signing_key: Ed25519)`
- On joining, the new member's Sender Key is distributed to each existing member via individual X3DH-encrypted direct messages (the same X3DH path as §7.0 above)
- Group messages are encrypted with `msg_key` from a single KDF_CK step on the sender's chain — one encryption, decryptable by all members who hold the sender's current chain state
- Member departure triggers Sender Key rekeying: the admin distributes new Sender Keys to all remaining members; the departed member's key is discarded

---

### 7.1 Four-Layer Encryption

All messages use a **multi-layer signing and encryption scheme** that provides authenticity at every hop, privacy of sender identity from routing nodes, and trust-channel encryption for messages between trusted peers. The inner session key (Step 2) is derived from the Double Ratchet (§7.0), not a static key.

```
Input: plaintext message

Step 1 — Inner authentication:
  For trusted-channel messages:
    mac = HMAC-SHA256(ratchet_msg_key, plaintext)  ← deniable; both parties can produce
    authenticated = plaintext || mac
  For untrusted messages:
    sig = Ed25519_Sign(sender_privkey, plaintext)
    authenticated = plaintext || sig

Step 2 — Trust-channel encryption (trusted peers only):
  If mutual_trust:
    // session_key is the cipher_key derived from the Double Ratchet msg_key (§7.0)
    // nonce is the 12-byte nonce derived from the same msg_key expansion
    trust_encrypted = ChaCha20Poly1305_Encrypt(session_key, nonce, authenticated)
    payload = dr_header || trust_encrypted   // dr_header carries ratchet_pub, prev_n, msg_n
  Else:
    payload = authenticated

Step 3 — Outer signing (forwarding authenticity):
  outer_sig = Ed25519_Sign(sender_privkey, payload)
  double_signed = payload || outer_sig

Step 4 — Recipient encryption:
  ephemeral_keypair = generate_x25519_keypair()
  shared = X25519(ephemeral_secret, recipient_x25519_public)
  message_key = HKDF-SHA256(shared, salt=ephemeral_public, info="meshinfinity-message-v1")
  nonce = random_12_bytes()
  final = ephemeral_public || nonce || ChaCha20Poly1305_Encrypt(message_key, nonce, double_signed)
```

### 7.2 Security Properties

| Property | Mechanism |
|----------|-----------|
| Sender authenticity (to recipient) | Inner HMAC with ratchet key (Step 1) — deniable; both parties can produce |
| Authenticated key agreement | X3DH (§7.0): both IK keys contribute; SPK signature verified before first message |
| Per-message forward secrecy | Double Ratchet KDF chain: each message advances the chain; old keys deleted |
| Break-in recovery | DH ratchet step on every inbound ratchet key; future messages use fresh DH material |
| Trust channel privacy | Step 2 Double Ratchet encryption hides content from relay nodes |
| Forwarding authenticity | Outer Ed25519 signature (Step 3) — relay nodes verify before forwarding |
| Sender privacy from routing nodes | Step 4 encryption: relay nodes see only the encrypted blob and outer sig |
| Recipient privacy | Only the holder of `recipient_x25519_secret` can decrypt Step 4 |
| Out-of-order delivery | Skipped message key cache, bounded at 1,000 entries per peer |

### 7.3 Session Keys for Ongoing Connections

For ongoing connections (file transfers, voice/video streams), establishing the full 4-layer scheme per packet would be prohibitively expensive. The 4-step scheme is used for the **session handshake**, which derives a session key:

```
handshake_message = encrypt_4layer(session_proposal { ephemeral_session_key_public })
send(handshake_message)
receive(handshake_response)

session_key = HKDF-SHA256(
    X25519(my_ephemeral_secret, their_ephemeral_public),
    salt = handshake_nonce,
    info = "meshinfinity-session-v1"
)
```

Subsequent data in the session uses:
```
ChaCha20Poly1305_Encrypt(session_key, counter_nonce, data)
```

where `counter_nonce` is a monotonically incrementing u64 (12 bytes, big-endian) to prevent nonce reuse. Rekeying occurs at counter 2^48 or 1 hour, whichever comes first, by repeating the handshake via the Double Ratchet channel.

### 7.4 Key Ratcheting

The Double Ratchet (§7.0) is the ratcheting mechanism for chat messages. It advances automatically with every message — no timer, no message-count threshold. Properties:

- **Per-message forward secrecy**: every message uses a unique `msg_key` derived by advancing the KDF chain; the chain key from step N cannot recover step N−1
- **Break-in recovery**: the DH ratchet step, triggered on each inbound ratchet key change, mixes fresh Diffie-Hellman output into the root key; an adversary who captured a chain key cannot predict future chain keys after the next DH step
- **No re-handshake required**: the ratchet is self-healing; a missed DH ratchet step is caught up automatically on the next received message carrying a new ratchet public key

For streaming sessions (§7.3), rekeying is counter- and time-bounded as specified above.

### 7.5 Reconnect and Sync

When a peer reconnects after being offline:

1. A re-handshake is performed to establish a fresh session key
2. The reconnecting peer sends a **sync request** with the timestamp of its last received message
3. The remote peer (or a store-and-forward server holding messages for it) sends any messages with timestamps after the sync point
4. Message ordering within a conversation is by timestamp; ties are broken by message ID (random 128-bit value assigned at send time)

---

## 8. Peer Pairing and Trust

### 8.1 Trust Levels

| Level | Value | Meaning |
|-------|-------|---------|
| `Untrusted` | 0 | Unknown node. Routed through for mesh connectivity but no privileged access. |
| `Caution` | 1 | Known but not personally verified. Can send messages; no trusted-channel address shared. |
| `Trusted` | 2 | Verified friend. Trusted-channel address and private profile shared. Full messaging features. |
| `HighlyTrusted` | 3 | Close contact. Maximum feature access; can act as wrapper node, exit node, or admin of shared groups. |

**Capability flags (per peer, independent of trust level):**

Certain privileged roles require an explicit capability grant in addition to a minimum trust level. A peer at `HighlyTrusted` does not automatically receive these capabilities — the user must grant them individually:

| Capability | Minimum trust level required | What it enables |
|-----------|------------------------------|-----------------|
| `can_be_wrapper_node` | `Trusted` | Allow this peer to be selected as a wrapper/relay for your outbound traffic |
| `can_be_exit_node` | `HighlyTrusted` | Allow this peer to route your internet traffic (exit node) |
| `can_be_store_forward` | `Trusted` | Allow this peer to cache your offline messages |
| `can_endorse_peers` | `Trusted` | Accept WoT endorsements from this peer |

The capability flags are stored locally and are never gossiped. Granting a capability to a peer does not broadcast anything to the network. Default: all capabilities `false`; the user opts in per-peer.

### 8.2 Pairing Methods

All pairing methods achieve the same result: mutual exchange of public keys, peer IDs, and an initial trust assignment, authenticated by a Σ-protocol proof. They differ in the out-of-band channel used to convey the initial key material.

#### QR Code

Suitable for in-person pairing. One peer displays a QR code; the other scans it.

QR payload (JSON, then Base58-encoded):
```json
{
  "v": 1,
  "peer_id": "<hex>",
  "ed25519_public": "<hex>",
  "x25519_public": "<hex>",
  "pairing_token": "<random_32_bytes_hex>",
  "display_name": "<optional>",
  "transport_hints": [...]
}
```

The `pairing_token` is a one-time random nonce that expires after 5 minutes or first use. After scanning, both sides perform a Σ-protocol handshake over any available transport to confirm mutual key possession and establish the trust relationship.

#### Pairing Code

A short alphanumeric code (default: 8 characters, Base32) derived from the public key and a random nonce. Suitable for verbal exchange or display in a UI.

The code encodes enough data to look up the peer in the network map and initiate a Σ-protocol handshake. The code expires after 10 minutes or first use.

#### Link Share

A deep-link URL of the form:
```
meshinfinity://pair?v=1&peer_id=<hex>&ed25519=<hex>&x25519=<hex>&token=<hex>&name=<optional>
```

The link can be shared via SMS, email, any messaging app, or pasted into the app. The same Σ-protocol handshake follows.

#### Key Export / Import

The full public key material exported as a text block (PEM-like format). Suitable for manual exchange between technically proficient users or for scripted deployment.

#### Proximity (Bluetooth)

When a user activates **pairing mode**, the device broadcasts a BLE advertisement including:
- Service UUID: Mesh Infinity pairing service UUID
- Pairing data: peer ID, Ed25519 public key, X25519 public key, pairing token (all truncated to fit the 31-byte advertisement payload; full data fetched via GATT on connection)

Other devices in range with Mesh Infinity running and pairing mode active see the advertisement, display the peer's name, and prompt the user to confirm. Confirmation triggers the Σ-protocol handshake over the BLE connection.

### 8.3 Pairing Flow (Common Steps)

Regardless of the method used to exchange initial key material:

1. **Key exchange complete**: both sides have each other's Ed25519 and X25519 public keys
2. **Σ-protocol handshake**: both sides prove knowledge of their respective private keys
3. **Mutual trust assignment**: the initiating user assigns a trust level; the receiving user is notified and assigns their own trust level independently
4. **Trusted-channel key derivation**: if both sides have assigned trust ≥ `Trusted`, the X25519 DH exchange is performed to derive the trusted-channel key
5. **Profile exchange**: if trust ≥ `Trusted`, private profiles are exchanged over the trusted channel
6. **Network map entry**: the new peer is added to the local network map with their public addresses

### 8.4 Web of Trust and Trust Propagation

Beyond direct pairing, trust can propagate through the web of trust:

- A peer at level ≥ `Trusted` can **endorse** an unknown peer by signing a `TrustEndorsement` record and broadcasting it to their trusted contacts
- Receiving nodes may treat endorsed peers as `Caution` level (not automatically `Trusted`) pending their own verification
- Trust propagation depth is user-configurable (default: 1 hop — friends of friends are `Caution`; strangers are `Untrusted`)
- Propagated trust never automatically rises above `Caution` without direct user action
- Trust endorsements are themselves signed and carry the endorser's peer ID, allowing recipients to weight them by how much they trust the endorser

Trust propagation is strictly opt-in. Users can disable it entirely, or set it to not propagate at all, if they want a purely direct-pairing trust model.

**Endorsement revocation:** A peer can revoke a previously issued endorsement by broadcasting a signed `TrustRevocation { endorsed_peer_id, endorser_peer_id, timestamp, signature }`. Receiving peers remove the endorsement from their local WoT graph and recompute the endorsed peer's derived trust level. If the revocation drops the endorsed peer below `Caution`, they are immediately downgraded. Revocations are gossiped with the same rules as endorsements — they carry a `sequence` number (incremented from the same endorsement counter) so a revocation cannot be replayed against a later, fresher endorsement.

### 8.5 Trust Revocation

A user can revoke trust in a peer at any time:

- Setting trust to `Untrusted` immediately removes the trusted-channel address, revokes private profile access, and stops routing through that peer
- A **revocation notice** (signed, timestamped) can be broadcast to trusted contacts to inform them of the revocation
- Revoked peers cannot be automatically re-trusted via trust propagation from other peers; re-trusting requires explicit direct action

### 8.6 Trusted Groups

Trusted groups are named collections of peers that share a group identity and communication channel.

**Group structure:**
- A group has a **group keypair** (Ed25519 + X25519) generated by the creator
- The group public key is shared with all members
- The group private key is held by **admin members** only
- A **group channel key** is derived from the group keypair and is used to encrypt group messages (so all members can decrypt but non-members cannot)

**Membership management:**
- The group creator is the initial admin
- Admins can add members (by sharing the group public key and channel key over a trusted channel), remove members, and promote other members to admin
- When a member is removed, the group channel key is rotated. The admin generates a new group keypair, derives a new channel key, and distributes it to remaining members. Removed members cannot decrypt messages after the rotation.
- Member lists are shared only among members; non-members cannot enumerate the group

**Group message delivery:**
- Messages addressed to the group are encrypted with the group channel key
- Each message is then individually wrapped (Step 4 of §7.1) for each group member's X25519 public key
- This means each member receives a copy wrapped specifically for them, rather than a single ciphertext that all members decrypt — this prevents a compromised member from trivially sharing a single decryption key that unlocks all messages

**Group features:**
- Group name, description, and avatar
- Group-scoped file sharing and hosted service access
- Admin controls: rename, set avatar, pin messages, remove members
- Group invites are sent via direct trusted-channel messages with a signed group credential

---

## 9. Social Profile

Each node has a **two-layer profile** separating information for the general public from information for trusted peers.

### 9.1 Public Profile

The public profile is visible to **all nodes** in the network, including nodes the user has never interacted with. It is propagated in the network map alongside the public address. Populating the public profile is entirely opt-in; all fields are optional.

**Public profile fields:**
- `identity_is_public` (bool) — controls whether this node **has a public profile at all**. Default: `false`. When `false`, the node has no public profile — no display name, bio, or avatar is propagated in the network map. The node still has public addresses and can be contacted by anyone who obtains an address, but nothing links that address to a human identity. When `true`, the public profile fields below are populated and gossiped.
- `public_display_name` (optional string) — a display name visible to anyone with `identity_is_public = true`. May differ from the private display name shown to trusted peers.
- `public_bio` (optional string) — a short public description.
- `avatar_hash` (optional bytes) — SHA-256 hash of a publicly available avatar image. Fetched separately from the hosting node as a service (§12) or content-addressed file.
- `public_services` (list) — public service advertisements the user wants discoverable (see §12.4).

**Address associability — `address_is_associable` per address:**

Each public address carries an independent `address_is_associable` flag (default: `true` for addresses linked to a public profile; `false` for all others).

- `address_is_associable = true` — this address is linked to the node's identity and public profile in the network map. Anyone who looks up the address can find the associated profile (if `identity_is_public` is also `true`).
- `address_is_associable = false` — this address exists in the network map for routing purposes only. No profile information is attached to it. It can be used for hosting services or receiving connections without revealing that it belongs to the same node as any other address.

This allows a node to have, for example, one address tied to its social identity (associable, used for chat) and one or more addresses exclusively for service hosting that cannot be linked back to the user by any observer of the network map. Because each address is backed by an independent keypair (§3.3), there is no cryptographic linkage between associable and non-associable addresses.

**Public profile propagation:**
- Nodes with `identity_is_public = true` have their public profile included in network map entries and gossiped to the whole network
- Nodes with `identity_is_public = false` have no public profile in the map; their addresses appear without profile data
- Addresses with `address_is_associable = false` appear in the map with no profile reference, even if the node has `identity_is_public = true`

### 9.2 Private Profile

The private profile is visible only to peers at trust level `Trusted` or above. It is exchanged over the trusted channel after pairing is complete.

**Private profile fields:**
- `private_display_name` (optional string) — the preferred name for trusted peers to use. This is the name that appears in the chat UI for trusted contacts.
- `private_bio` (optional string) — a fuller, personal description shared only with trusted peers.
- `contact_hints` (optional list) — additional ways to reach this node (other mesh addresses, Tor addresses, etc.) that the user does not want in the public map.
- `avatar_override_hash` (optional bytes) — a different avatar shown only to trusted peers.

**Private profile storage:**
- Private profile data is stored locally, encrypted at rest alongside the identity material
- It is transmitted only to peers who have been explicitly trusted
- Private profile updates are pushed to trusted peers over the trusted channel when the user saves changes

### 9.3 Profile Synchronisation

When a user updates their profile:

1. Public profile changes are gossiped to the network map via connected peers (the updated `NetworkMapEntry` is broadcast)
2. Private profile changes are pushed directly to each trusted peer over their respective trusted channels
3. Peers store a local cache of the last-received profile for each contact, used for display

Because trusted-channel addresses are bilateral and not in the public map, private profile updates can only be delivered when the relevant trusted peer is online. If they are offline, the update is queued and delivered on their next connection.

---

## 10. Messaging (Signal Parity)

The chat application is the primary user interface. Signal feature parity is the baseline requirement; the mesh model extends beyond it where the underlying infrastructure allows.

### 10.1 Direct Messaging

1:1 messaging between any two peers:

- Messages are addressed to the peer's **trusted-channel address** if a trust relationship exists (ensuring only the intended recipient can read them, and that the routing is via the private address not the public one)
- For initial contact with an unknown peer (e.g., someone found via public profile search), messages are addressed to their **public address**
- Message delivery confirmation: the recipient sends a delivery receipt (a small signed acknowledgement) on reception
- Offline delivery: if the recipient is unreachable, the message is passed to store-and-forward server nodes (§6.6)

### 10.2 Group Messaging

Group chats using trusted groups (§8.6):

- Messages are encrypted to the group channel key and individually wrapped per member
- Group admin controls: add/remove members, rename, set avatar, pin messages
- Group invites are delivered as direct messages to the invited peer
- Delivery receipts are per-member; the sender sees delivered/read status per group member (opt-out available)

### 10.3 Message Format

Every message, whether direct or group, carries:

```
Message {
    id:            [u8; 16],         // Random message ID (for deduplication, threading)
    conversation_id: [u8; 16],       // Room/conversation this belongs to
    sender_peer_id: [u8; 32],        // Sender's peer ID
    timestamp:     u64,              // Unix ms timestamp (sender's clock)
    content_type:  ContentType,      // Text, Image, Video, Audio, File, Reaction, Receipt, ...
    payload:       Vec<u8>,          // Content-type-specific payload
    reply_to:      Option<[u8; 16]>, // Message ID being replied to (for threads)
    expires_at:    Option<u64>,      // Unix ms timestamp for disappearing messages
}
```

### 10.4 Message Features

**Reactions:** Any peer in a conversation can react to any message with an emoji. Reactions are stored as a list of `(emoji, sender_peer_id)` pairs on the message. Reactions are propagated to all conversation participants.

**Read receipts:** The recipient sends a `MessageReceipt { message_id, status: Delivered | Read, timestamp }` back to the sender. Read receipts are visible per-participant in group chats. Users can disable sending read receipts globally or per-conversation.

**Typing indicators:** A `TypingIndicator { conversation_id, typing: bool }` is sent when the user starts or stops typing. Indicators expire automatically after 10 seconds without a refresh. Users can disable typing indicators.

**Disappearing messages:** Messages with `expires_at` set are deleted from both the sender's and recipient's local storage after the expiry time. Expiry is enforced locally by each client; there is no server-enforced deletion. Default expiry options: 1 hour, 24 hours, 7 days, 30 days, or off. Disappearing messages can be configured per-conversation.

**Message editing:** Edits are delivered as a new message with `content_type: Edit` referencing the original `message_id`. Edit history is retained locally. The latest edit is displayed by default; users can view edit history.

**Message deletion:**
- *Delete for me*: removes the message from local storage only
- *Delete for everyone*: the sender broadcasts a signed `Deletion { message_id }` to all participants, who remove the message from local storage. Participants who are offline when the deletion is sent receive it on next sync.

**Reply threads:** Messages with `reply_to` set are displayed as inline replies, quoting the referenced message's preview. Thread depth is unlimited.

**Pinned messages:** Any admin (in groups) or participant (in DMs, by mutual agreement) can pin a message. Pinned messages are listed in a conversation-level index separate from the message stream.

**Message forwarding:** Any message can be forwarded to another conversation. Forwarded messages carry an attribution field indicating the original sender (their display name, not peer ID) unless the forwarder clears it.

**Search:** Full-text search across all local message history. Search is performed locally on the device; no search query leaves the device. The search index is encrypted at rest alongside the message database.

### 10.5 Media and File Sharing

**Images and video:** Sent as message attachments. The media is encrypted with the session key, chunked, and transferred over the best available transport. A thumbnail or preview is generated locally before sending and included in the message payload for immediate display.

**Audio:** Voice messages (short recordings) and audio files are sent as attachments. Playback is inline in the chat UI.

**Arbitrary files:** Any file can be sent as a message attachment. Files above a configurable size threshold (default: 50 MB for in-message transfer) are automatically promoted to a **file transfer session** (see §11).

**Media compression:** The sender can choose whether to send media at original quality or compressed. Original quality is the default for files; compressed is the default for images shared in chat.

### 10.6 Voice and Video Calls

End-to-end encrypted voice and video calls:

- **Call signalling** is performed over the existing mesh messaging channel — a `CallSignal` message type is used for offer/answer/ice-candidate/hangup
- **Media streams** are transported over a dedicated WireGuard session established for the call, direct between the two peers where possible
- **Codec negotiation** is part of the call signalling: Opus for audio, VP8/VP9/AV1 for video
- **Group calls** are supported for trusted groups; each participant establishes individual WireGuard sessions to every other participant (mesh calls, no central media server)
- **Fallback to audio-only** when bandwidth or CPU is insufficient; the UI notifies the user
- **Call encryption** uses the same session key derivation as file transfer sessions, separate from the messaging session key

### 10.7 Presence and Status

- **Online/Away/Do Not Disturb/Offline** status is propagated to trusted peers over trusted channels
- **Custom status text** is included alongside the status enum
- **Last-seen timestamp** is shared with trusted peers, opt-out per-contact or globally
- Presence updates are pushed; no polling. When the user goes offline, a final `Offline` presence update is sent before disconnect.
- Presence information is never included in the public network map — it is only shared with trusted peers

---

## 11. File Sharing

### 11.1 Direct File Transfer

Peer-to-peer file transfers:

1. **Initiation:** The sender creates a `FileTransferOffer { file_id, name, size, sha256_hash, mime_type }` and sends it as a message
2. **Acceptance:** The recipient replies with `FileTransferAccept { file_id }`, which triggers session key negotiation
3. **Transfer:** The file is split into chunks (default: 64 KB). Each chunk is encrypted with the session key, tagged with its chunk index, and sent. Chunks may be sent out of order.
4. **Completion:** On receipt of all chunks, the recipient verifies the SHA-256 hash of the reassembled file. On success, a `FileTransferComplete` message is sent.
5. **Resumption:** If the transfer is interrupted, the recipient sends a `FileTransferResume { file_id, received_chunks: bitfield }` on reconnect. The sender retransmits only the missing chunks.

### 11.2 Public File Hosting

Files can be hosted publicly as a service (§12), making them accessible to any node that can reach the host:

- A publicly hosted file is served via the mesh HTTP layer (§12.2) at `public_address:port/path`
- The file is advertised in the host's public service list with its SHA-256 hash, size, MIME type, and optional description
- Clients fetch hosted files via the same session-encrypted channel used for all mesh connections
- Content addressing: files can optionally be addressed by their hash (`sha256:<hash>`) in addition to their host address, enabling content-addressed distribution

### 11.3 Private File Sharing

Files shared only with trusted contacts:

- Shared via the direct file transfer protocol (§11.1) to specific peers or groups
- Groups can have a **shared file repository**: a collection of files accessible to group members, hosted by one or more group members

---

## 12. Hosted Services

Any TCP or UDP service can be hosted over Mesh Infinity and made accessible to other nodes. This is the mechanism by which Mesh Infinity provides an alternative to web hosting, API services, SSH access, and any other internet service.

### 12.1 Service Addressing

Services are addressed by a **32-bit port number** combined with a node address:

```
service_address = device_address:port
```

- **Public services**: `public_address:port` — the `public_address` is in the network map; any node can look up the address and connect to the port
- **Private services**: `trusted_channel_address:port` — the `trusted_channel_address` is known only to the specific peer or group members who share it; only they can address the service
- **Group services**: `group_channel_address:port` — accessible to all members of the trusted group

The port namespace is 32-bit (0–4294967295), significantly larger than the internet's 16-bit port space. The lower 16 bits (0–65535) are reserved for well-known protocol mappings that mirror the internet port conventions. The upper 16 bits are free for application use.

### 12.2 Mesh HTTP Layer

The most common hosted service type is HTTP. The mesh HTTP layer provides a transparent proxy between standard HTTP clients and mesh-hosted services:

**Serving:**
- The host runs a standard HTTP server (nginx, a Rust HTTP server, a Python app — anything)
- Mesh Infinity's service proxy listens on the assigned mesh port and forwards inbound connections to the local HTTP server's port
- The service is exposed to the mesh as a normal service endpoint

**Accessing from a browser:**
- The mesh HTTP proxy runs a local HTTP proxy on the user's device (default: `127.0.0.1:7890`)
- Browsers and HTTP clients configured to use this proxy send requests to mesh service addresses
- The proxy resolves the service address via the mesh, establishes a WireGuard-encrypted session, and proxies the HTTP traffic
- HTTPS is handled end-to-end: the session encryption (WireGuard + application layer) replaces TLS; from the browser's perspective, it is connecting to a local proxy

**Domain names for services:**
- Mesh services can be assigned human-readable names via a distributed name system
- Trusted peers can assign local aliases to services (pet names)
- A future DNS-compatible mesh resolver (`.mesh` TLD or similar) is a planned extension

### 12.3 TCP and UDP Tunneling

For non-HTTP services (SSH, custom protocols, databases, game servers, etc.):

- Mesh Infinity acts as a transparent TCP/UDP tunnel between the client and the service
- The client opens a local port (e.g., `127.0.0.1:22222`); all traffic to that port is tunnelled over the mesh session to the target service address
- This is analogous to `ssh -L` port forwarding, but over the mesh
- The tunnel is established by a Mesh Infinity `connect` command specifying the target service address and the local port to bind

### 12.4 Service Registration and Discovery

**Registering a service:**
1. The service owner defines the service in local configuration: name, description, local port to proxy, mesh port to expose, access policy (public/private/group), minimum trust level
2. The service is registered in the local service database
3. For public services: the service record is added to the node's network map entry and gossiped to the network
4. For private services: the service is advertised directly to specific peers or groups over their trusted channels

**Service record:**
```
ServiceRecord {
    service_id:       [u8; 16],      // Random service identifier
    name:             String,
    description:      Option<String>,
    address:          DeviceAddress,  // The mesh address (public or trusted-channel)
    port:             u32,
    protocol:         ServiceProtocol, // HTTP, TCP, UDP, Custom
    access_policy:    AccessPolicy,
    min_trust_level:  TrustLevel,
    allowed_peers:    Option<Vec<[u8; 32]>>, // Specific peer IDs if restricted
}

AccessPolicy {
    Public,          // Anyone who can route to the address
    TrustedOnly,     // Trust >= Trusted
    GroupOnly(group_id), // Members of a specific group
    PeerList,        // Only peers in allowed_peers
}
```

**Discovering services:**
- Public services appear in the network map and are searchable by name, description, or host peer ID
- Private services are discovered via direct peer or group channel messages
- A local service directory aggregates all known services (public + private) for UI display

### 12.5 Access Control Enforcement

Access control is enforced at the connection layer:

1. When a client connects to a service address, the WireGuard handshake identifies the client by their peer ID
2. The service host's proxy checks the client's peer ID against the service's `access_policy` and `min_trust_level`
3. Connections from peers not meeting the policy are rejected before any application data is exchanged
4. Admins can further restrict access at the application level (HTTP authentication, etc.) as an additional layer

### 12.6 Service Health and Availability

- Service hosts publish a **last-alive timestamp** alongside their service records, updated periodically
- Clients cache service records and fall back to alternative hosts for redundant services
- A service can be **mirrored**: multiple nodes host the same service and advertise the same service ID; clients pick the best-connected host
- The service proxy monitors the local backend (e.g., the local HTTP server) and marks the service unavailable if the backend is down

### 12.7 Public vs Private Sharing Summary

The public/private distinction permeates all shareable resources:

| Resource | Public Variant | Private Variant |
|----------|---------------|-----------------|
| Address | Public address (in network map) | Trusted-channel address (bilateral) |
| Profile | Public profile (in network map) | Private profile (trusted peers only) |
| Service | Public-address service (any node) | Trusted-address service (specific peers/groups) |
| File | Hosted on public address | Direct file transfer or group file repo |
| Group | Public group (anyone can find, access-controlled) | Private group (members know only) |

In all cases, the **content** is end-to-end encrypted regardless of whether the access point is public or private. Public means "the address is known and anyone can attempt to connect" — but actual content access is still governed by the session encryption and any application-level access policy.

---

## 13. VPN and Exit Nodes

### 13.1 Overview

Mesh Infinity provides system-wide VPN functionality that gives users control over how all device traffic is routed. This is the PMWAN aspect of the system: not just a messaging app, but a replacement for the network layer itself.

### 13.2 Virtual Network Interface

Platform-specific virtual interface implementations:

- **Android**: VPN Service API (no root required). The app establishes a VPN interface that captures all device traffic.
- **iOS / macOS**: Network Extension framework (NEPacketTunnelProvider). Same capability as Android via the platform's official VPN API.
- **Linux**: TUN/TAP virtual interface. Requires either root or `CAP_NET_ADMIN` capability.
- **Windows**: WinTun virtual adapter (same driver used by WireGuard for Windows). No driver signing issues; WinTun is a well-established, signed driver.

The virtual interface intercepts outbound packets and routes them according to the current routing mode.

### 13.3 Traffic Routing Modes

| Mode | Behaviour |
|------|-----------|
| **Off** | No VPN active; Mesh Infinity runs as a messaging/service app only |
| **Mesh Only** | Only traffic destined for mesh addresses (`meshinfinity://` URLs, mesh service addresses) is routed through the mesh. All other traffic goes directly to the internet. |
| **Exit Node** | All internet traffic is forwarded through a selected trusted peer (the exit node), which forwards it to the internet on the user's behalf. The user's internet-facing IP becomes the exit node's IP. |
| **Policy-Based** | User-defined routing rules determine which traffic goes where. Some traffic to the mesh, some to an exit node, some direct. |

### 13.4 Exit Nodes

An **exit node** is a trusted peer that has opted in to serving as an internet gateway for other mesh nodes.

**Exit node operation:**
- The exit node enables IP forwarding on its host system and configures NAT/masquerade for outbound traffic
- When a client designates a peer as its exit node, it establishes a WireGuard tunnel to that peer and sends all internet-bound traffic through it
- The exit node's WireGuard interface routes the traffic out to the internet
- Return traffic follows the reverse path

**Exit node selection:**
- Exit nodes advertise their availability to trusted peers over the trusted channel (not in the public network map)
- Available exit nodes are listed in the client's exit node settings panel
- Selection criteria exposed to the user: approximate geographic location (if the exit node has disclosed it), measured latency, self-reported capacity/load
- Trust requirement: exit node must be at trust level `HighlyTrusted` **and** must have the `can_be_exit_node` capability explicitly granted by the local user (§8.1). These are two separate gates — meeting the trust level alone is not sufficient.

**Exit node privacy:**
- The exit node sees the destination IP addresses of the client's internet traffic but does not see the client's mesh identity (the WireGuard tunnel provides peer authentication, but the exit node need not be told the client's display name or peer ID)
- Wrapper node routing can be used to further hide the client's mesh identity from the exit node
- The exit node's ISP sees traffic from the exit node's IP, not the client's IP — this is the privacy benefit
- The client should trust exit nodes accordingly: they are a privileged position

**Kill switch:**
- If the exit node connection drops while the VPN is in Exit Node mode, traffic is halted by default (strict kill switch) until the connection is re-established or the user explicitly switches modes
- Users can configure the kill switch to permissive mode: on exit node disconnect, traffic falls back to direct internet rather than halting
- The kill switch state is displayed prominently in the UI

### 13.5 Split Tunneling and Policy-Based Routing

In policy-based mode, users define routing rules:

- Route by **destination IP range or domain**: e.g., all traffic to `10.0.0.0/8` through the mesh; all other traffic direct
- Route by **application** (Android/iOS): specific apps are routed through the mesh or exit node while others go direct
- Route by **service**: traffic to known mesh service addresses automatically routes through the mesh regardless of mode
- Multiple exit nodes: different traffic categories can be routed through different exit nodes (e.g., work traffic through exit A, streaming through exit B)

DNS routing:
- DNS queries for `.mesh` domains (or equivalent) are resolved locally via the mesh service directory
- When Exit Node mode is active, **all** DNS queries for internet domains are forwarded through the exit node by default (not optional) to prevent DNS leaks. The exit node uses DNS-over-HTTPS (DoH) for its upstream resolution — the exit node's ISP therefore sees HTTPS traffic to a DoH provider, not plaintext DNS queries. The DoH provider used by the exit node is configurable; default: the exit node operator's own DoH resolver or a well-known privacy-respecting provider.
- Users who do not want the exit node to see their DNS queries can configure the client to use a local DoH resolver tunnel that resolves queries before they reach the exit node — but this risks DNS/traffic destination correlation at the exit node level.
- A mesh-internal DNS resolver handles service address to peer ID resolution

### 13.6 Tailscale Feature Parity

Exit nodes and split tunneling are designed to achieve parity with Tailscale's feature set:

- **Subnet routing**: a mesh node can advertise a local subnet (e.g., `192.168.1.0/24`) to other mesh peers, making local network devices accessible from anywhere over the mesh
- **MagicDNS equivalent**: mesh service names are resolvable without manually entering service addresses
- **Access control lists**: per-peer and per-group traffic policies
- **Network topology view**: the UI shows connected peers, their reachability, and current routing paths

---

## 14. Notifications

### 14.1 Mesh-Native Notifications (Primary)

All security-sensitive notifications are delivered over the mesh itself:

- New direct messages, group messages, calls, group invites, pairing requests, file transfer offers
- Delivered over the same encrypted trusted-channel connection as the triggering event
- No third party involved; end-to-end encrypted; no metadata leaks to notification providers

For offline delivery, mesh-native notifications queue alongside messages in the store-and-forward system. When the user comes online, queued messages and their associated notifications are delivered together.

**Notification priority levels:**
- `Urgent`: calls, pairing requests (immediate delivery; will wake the app from background)
- `High`: direct messages from trusted peers
- `Normal`: group messages, file transfer offers
- `Low`: presence updates, network map updates, background sync

### 14.2 Cloud Notifications (Ping-Only, Optional)

Cloud push notifications (APNs on iOS, FCM on Android, or a self-hosted UnifiedPush server) may be used as a **wake-up mechanism only**:

- The cloud notification payload contains **zero message content** — only a wake signal and a priority level
- On receipt of a cloud ping, the client connects to the mesh and retrieves actual content via the encrypted mesh channel
- The cloud notification provider learns only: "this device should wake up" — nothing about who sent what to whom

**Self-hosted options:**
- [ntfy.sh](https://ntfy.sh) (self-hostable) or any UnifiedPush-compatible server
- The user enters their self-hosted push server URL in settings
- Using a self-hosted server eliminates dependence on Google/Apple notification infrastructure entirely

**Fallback:**
- Cloud notifications are opt-in. Without them, the app uses background polling (periodic wake-up to check for queued messages on known server nodes). This consumes slightly more battery but requires no cloud dependency.
- On platforms where background execution is less restricted (Linux, Windows, Android without aggressive battery management), polling is the default and cloud notifications are not needed.

---

## 15. Security

### 15.1 Memory Safety

- Sensitive data (private keys, session keys, plaintext message content, shared secrets) is held in Rust-managed memory with explicit zeroing on `Drop`
- `mlock` / `VirtualLock` is used to prevent sensitive pages from being swapped to disk
- Sensitive buffers use a `SecureBytes` wrapper type that zeroes on drop and does not implement `Clone` or `Debug` to prevent accidental copies or logging
- The Flutter UI layer receives only display-safe, redacted data: peer IDs are shown as display names or truncated public key fingerprints; no raw key material crosses the FFI boundary

### 15.2 Cryptographic Practices

- All symmetric encryption uses AEAD ciphers (ChaCha20-Poly1305 or AES-256-GCM, negotiated per connection — see §3.4)
- All key derivation uses HKDF-SHA256 with domain-separated labels; the same base secret with different labels produces independent keys
- Nonces are randomly generated per message (ChaCha20-Poly1305: 12 bytes); nonce reuse would be catastrophic and is prevented by never reusing a nonce across messages
- For session keys using counter-nonces (§7.3), the counter is monotonically increasing. A re-handshake is **mandatory** when the counter reaches **2^48** (281 trillion messages) — far below the 2^96 theoretical overflow, providing a safety margin of 2^48 before any nonce reuse risk. In practice, key ratcheting (§7.4) rotates the session key every 100 messages (default), so the counter resets far more frequently and the 2^48 hard limit is a backstop only
- Key ratcheting (§7.4) ensures that compromise of a current session key does not expose past messages
- Deniable authentication (§3.5) is used for trusted-channel message MACs

### 15.3 Network Security

- WireGuard handshake authentication on every direct peer connection prevents impersonation
- Transport-layer encryption (WireGuard) is present even when tunnelled over Tor or I2P — defence in depth
- Rate limiting: inbound connection attempts and message processing are rate-limited per peer ID to mitigate flood attacks
- Connection validation: peer IDs are verified against the network map on every handshake; connections from unknown peer IDs are treated as `Untrusted`
- No persistent logs of connection events, message routing decisions, or peer activity

### 15.4 Privacy

- No analytics, telemetry, crash reporting, or usage metrics of any kind
- **Traffic pattern obfuscation — padding:** Message payloads are padded to the nearest fixed-size bucket before encryption. Buckets (bytes): **256, 512, 1024, 4096, 16384, 65536, 262144, 1048576** (1 MB). Payloads larger than 1 MB are split into 1 MB chunks each padded independently. The AEAD ciphertext therefore reveals only the bucket tier, not the exact message size.
- **Traffic pattern obfuscation — timing jitter:** For messages at priority `Normal` or `Low` (§14.1), outbound transmission is delayed by a uniformly random value in the range **[0, 250 ms]**. For `High` priority, jitter is **[0, 50 ms]**. For `Urgent` (calls, pairing), jitter is zero. Jitter is applied independently per message; correlating two jittered transmissions requires observing the same message at multiple hops simultaneously.
- Metadata minimisation: routing headers carry only what is necessary; sender identity is not included in forwarded packets
- Plausible deniability at message level (HMAC), group membership level (ring signatures), and connection level (wrapper nodes, ephemeral addresses)
- Emergency data destruction via killswitch (§3.8) with cryptographic overwrite of key material

---

## 16. Performance

### 16.1 Network

- Active WireGuard tunnels to frequently contacted peers are kept alive and pooled
- Message batching: multiple small messages to the same peer may be batched into a single WireGuard packet when not latency-sensitive
- MTU discovery per transport: BLE and RF transports have much smaller MTUs than TCP; the transport layer negotiates and fragments accordingly
- QoS prioritisation: voice/video packets are marked urgent and processed ahead of file transfer and background sync traffic
- Bandwidth estimation: the transport layer maintains per-peer bandwidth estimates used for transport selection and codec negotiation for voice/video

### 16.2 Memory and CPU

- Async/await throughout the Rust backend via Tokio; no blocking the event loop on I/O
- Work-stealing thread pools for CPU-bound cryptographic operations (encryption, signing, ratchet computation)
- SIMD acceleration: ChaCha20 and BLAKE3 have SIMD-optimised paths detected at runtime; AES-GCM uses hardware AES instructions where available
- Lazy initialisation of transport backends: Tor client, I2P router, Bluetooth stack are initialised only when first needed
- Memory pools for frequently allocated fixed-size structures (WireGuard packets, message headers) to reduce allocator pressure

### 16.3 Flutter UI Performance

- All backend calls are asynchronous via the FFI event model; the UI never blocks on Rust operations
- Widget lifecycle is managed explicitly: `TextEditingController`, `ScrollController`, `StreamSubscription`, and similar objects are disposed in `State.dispose()` to prevent leaks
- Image and media caches are explicitly bounded (configurable; default 200 MB for images, 500 MB for video thumbnails) with LRU eviction
- Message lists use lazy-loading with virtualized rendering (`ListView.builder`); only visible messages are rendered
- Large media is loaded lazily and cached to disk; thumbnails are generated at display size and cached separately from originals
- Dart's garbage collector is invoked explicitly after large operations (e.g., decrypting a large file) via `dart:developer`'s `NativeRuntime` hooks to avoid GC pauses during active UI interaction

---

## 17. Platform and Backend Architecture

### 17.1 Rust Backend Module Structure

Single Rust crate (`mesh-infinity`), compiled as `cdylib` / `staticlib` / `rlib` depending on platform:

```
src/
  lib.rs           — top-level re-exports; module declarations
  runtime.rs       — RuntimeConfig: node mode, UI-enabled flag, startup parameters

backend/
  lib.rs           — public API surface re-exported from submodules
  service/
    mod.rs         — MeshInfinityService: top-level service orchestrator
    types.rs       — service-facing data types (Message, PeerSummary, Settings, ...)
    chat.rs        — messaging: send/receive, rooms, sync
    files.rs       — file transfer: initiation, chunking, progress, resume
    settings.rs    — settings read/write
    peers.rs       — peer management, trust operations
    trust.rs       — trust level management, WoT propagation
    hosted.rs      — hosted service proxy management
  auth/
    identity.rs    — Identity struct, IdentityManager: generate, load, sign, verify
    persistence.rs — IdentityStore: keyfile encryption, save, load, destroy
    wot.rs         — WebOfTrust: trust graph, endorsements, propagation
  crypto/
    backup.rs      — BackupManager: EncryptedBackup creation and restore
    session.rs     — session key derivation, ratchet
    signing.rs     — message signing and verification helpers
    zkp.rs         — Sigma protocol, ring signature primitives
  transport/
    mod.rs         — TransportManager: selection, health, pooling
    wireguard.rs   — WireGuard peer management
    tor.rs         — Tor/arti client integration
    i2p.rs         — I2P/SAM client
    bluetooth.rs   — BLE GATT service
    rf.rs          — Meshtastic serial integration
    clearnet.rs    — Direct TCP/UDP
  discovery/
    map.rs         — NetworkMap: storage, merge, gossip
    announce.rs    — ReachabilityAnnouncement: generation, forwarding
    bootstrap.rs   — startup bootstrap logic
  mesh/
    router.rs      — hop-by-hop routing table, next-hop selection
    fast_router.rs — Dijkstra fast-routing mode
    store_forward.rs — store-and-forward queue (server mode)
  ffi/
    lib.rs         — all #[no_mangle] pub extern "C" functions
    context.rs     — MeshContext: heap-allocated state held across FFI calls
    events.rs      — async event push to Flutter
    error.rs       — error code mapping

platforms/
  android/         — Gradle project, VPN Service, JNI bridge
  apple/           — Xcode project (Runner: macOS, RunnerIOS: iOS), Network Extension
  linux/           — CMake + GTK runner
  windows/         — CMake runner + WinTun, NSIS installer

frontend/          — Flutter UI project (pubspec.yaml, lib/, assets/)
assets/            — shared assets: logo.png, icons
```

### 17.2 Runtime Modes

The application is always built as a single binary bundle. The mode is determined at startup:

| Startup Condition | Default Mode |
|------------------|--------------|
| UI enabled | `Client` |
| UI enabled + dual-mode configured | `Dual` |
| UI disabled (headless/server) | `Server` |

Modes:
- **Client**: full UI, messaging, VPN. Does not relay for the network by default. Connects to server nodes for store-and-forward.
- **Dual**: full UI plus active mesh routing; relays messages for other peers. Contributes to the mesh as both a user node and a routing node.
- **Server**: no UI; runs as a mesh infrastructure node. Can be configured with any combination of: directory caching, store-and-forward, offline inbox, exit node, hosted services, wrapper node.

Mode can be toggled at runtime via `mi_set_node_mode`. Switching from Client to Server mode requires UI confirmation and disables the UI session.

### 17.3 FFI Boundary

The FFI layer exposes a C ABI consumed by Flutter via `dart:ffi`. Core design rules:

- Rust is the source of truth for all state
- Flutter is treated as untrusted: it issues intent-based commands and receives display-safe data
- No key material, plaintext message content, or internal cryptographic state crosses the FFI boundary
- All pointer parameters crossing the boundary are validated before use; null pointers and out-of-range lengths are rejected
- FFI functions return integer status codes; `mi_get_last_error(ctx)` retrieves the error string for the last failure
- All strings crossing the boundary are null-terminated UTF-8; lengths are validated

**FFI function categories:**

Lifecycle:
```
mesh_init(config_path: *const c_char) -> *mut MeshContext
mesh_destroy(ctx: *mut MeshContext)
mi_set_node_mode(ctx: *mut MeshContext, mode: u8) -> i32
mi_get_last_error(ctx: *mut MeshContext) -> *const c_char
```

Identity:
```
mi_has_identity(ctx: *mut MeshContext) -> i32
mi_create_identity(ctx: *mut MeshContext, name: *const c_char) -> i32
mi_import_identity(ctx: *mut MeshContext, backup_json: *const c_char, passphrase: *const c_char) -> i32
mi_set_public_profile(ctx: *mut MeshContext, profile_json: *const c_char) -> i32
mi_set_private_profile(ctx: *mut MeshContext, profile_json: *const c_char) -> i32
mi_reset_identity(ctx: *mut MeshContext) -> i32
mi_get_identity_summary(ctx: *mut MeshContext) -> *const c_char  // JSON
```

Peers and Trust:
```
mi_get_peer_list(ctx: *mut MeshContext) -> *const c_char  // JSON array
mi_set_trust_level(ctx: *mut MeshContext, peer_id: *const c_char, level: i32) -> i32
mi_get_pairing_code(ctx: *mut MeshContext) -> *const c_char
mi_accept_pairing(ctx: *mut MeshContext, pairing_data_json: *const c_char) -> i32
mi_get_network_stats(ctx: *mut MeshContext) -> *const c_char  // JSON
```

Messaging:
```
mi_get_room_list(ctx: *mut MeshContext) -> *const c_char  // JSON array
mi_get_messages(ctx: *mut MeshContext, room_id: *const c_char, before_ts: u64, limit: u32) -> *const c_char
mi_send_message(ctx: *mut MeshContext, room_id: *const c_char, text: *const c_char) -> i32
mi_create_room(ctx: *mut MeshContext, peer_id: *const c_char) -> *const c_char  // room_id
mi_send_reaction(ctx: *mut MeshContext, room_id: *const c_char, message_id: *const c_char, emoji: *const c_char) -> i32
mi_delete_message(ctx: *mut MeshContext, room_id: *const c_char, message_id: *const c_char, for_everyone: i32) -> i32
```

File Transfers:
```
mi_file_transfer_start(ctx: *mut MeshContext, peer_id: *const c_char, file_path: *const c_char) -> *const c_char
mi_file_transfer_cancel(ctx: *mut MeshContext, transfer_id: *const c_char) -> i32
mi_file_transfer_status(ctx: *mut MeshContext, transfer_id: *const c_char) -> *const c_char  // JSON
```

Settings and Transport:
```
mi_get_settings(ctx: *mut MeshContext) -> *const c_char  // JSON
mi_set_settings(ctx: *mut MeshContext, settings_json: *const c_char) -> i32
mi_toggle_transport(ctx: *mut MeshContext, transport: *const c_char, enabled: i32) -> i32
```

VPN:
```
mi_set_vpn_mode(ctx: *mut MeshContext, mode: u8) -> i32
mi_set_exit_node(ctx: *mut MeshContext, peer_id: *const c_char) -> i32
mi_get_vpn_status(ctx: *mut MeshContext) -> *const c_char  // JSON
```

Hosted Services:
```
mi_get_service_list(ctx: *mut MeshContext) -> *const c_char  // JSON array
mi_configure_service(ctx: *mut MeshContext, service_json: *const c_char) -> i32
mi_enable_service(ctx: *mut MeshContext, service_id: *const c_char, enabled: i32) -> i32
```

Events (async push to Flutter):
```
mi_set_event_callback(ctx: *mut MeshContext,
    callback: extern fn(event_type: u32, payload: *const c_char, user_data: *mut c_void),
    user_data: *mut c_void)
```

### 17.4 Mesh Address Format

Mesh addresses are **256-bit** (8 groups of 8 hexadecimal characters, colon-separated):

```
a1b2c3d4:e5f6a7b8:12345678:90abcdef:01234567:89abcdef:fedcba98:76543210
└──────────── device address (160 bits / 20 bytes) ──────────┘└── conversation ID (96 bits / 12 bytes) ───┘
```

- **Device address (160 bits)**: first 5 groups; identifies a specific node endpoint (one of the node's addresses)
- **Conversation ID (96 bits)**: last 3 groups; identifies a specific conversation or session on that endpoint
- A service address appends a 32-bit port: `device_address:port32`

Conversations are uniquely identified by `(source_address, destination_address, conversation_id)`. Multiple concurrent conversations between the same pair of nodes use different conversation IDs and are independently encrypted.

**Human-readable resolution (Mesh DNS):**

Raw hex addresses are used internally and are not intended for human memorisation. A short-name resolution layer maps human-friendly identifiers to raw addresses, operating on an opt-in approval model inspired by Tailscale's subnet route and exit node advertisement system:

- **Short-name advertisement**: A node may advertise a desired short name for one of its addresses (e.g. `alice` or `alice-laptop`). This advertisement is signed with the address keypair and gossiped to the node's trusted peers alongside the address entry.
- **Peer approval**: Receiving peers see the short-name request and individually choose to approve or deny it — no name is accepted automatically. The approval decision is stored locally and is never gossiped; each peer maintains their own name resolution table.
- **Approved names are local**: Once a peer approves a short name, it is added to that peer's local Mesh DNS table and resolves to the corresponding hex address. Approved names are never re-gossiped as canonical — they are local bindings only.
- **Conflict handling**: If two peers advertise the same short name, each receiving node resolves the conflict locally (first-approved wins, or user is prompted). There is no global name registry or first-come-first-served reservation.
- **Local pet names**: Any peer may also assign a private local alias to any address; these are never advertised or gossiped, and take precedence over approved short names in the local resolver.
- **Revocation**: An address owner may revoke a previously advertised short name by gossiping a signed revocation; peers that had approved it remove it from their local table.
- **Mesh DNS table**: The resolver checks, in order: (1) local pet names, (2) approved short names, (3) raw hex address. If a short name is unresolved or denied, the full hex address must be used.

### 17.5 Mesh URL Scheme

Mesh Infinity uses a two-stage URL scheme:

```
meshinfinity://<protocol>//<address>[:<port>][/path][?query]
```

The `<protocol>` segment identifies what kind of resource is being addressed:

| Protocol segment | Meaning | Example |
|-----------------|---------|---------|
| `chat` | Open a direct message conversation | `meshinfinity://chat//a1b2c3d4:...` |
| `group` | Open or join a group | `meshinfinity://group//a1b2c3d4:...:port` |
| `http` | Mesh-hosted HTTP service | `meshinfinity://http//a1b2c3d4:...:8080/index.html` |
| `https` | Mesh-hosted HTTPS (TLS from service) | `meshinfinity://https//a1b2c3d4:...:8443/` |
| `file` | Content-addressed file | `meshinfinity://file//sha256:<hash>` |
| `pair` | Pairing invitation | `meshinfinity://pair//a1b2c3d4:...?token=<hex>&name=<optional>` |
| `service` | Generic TCP/UDP service | `meshinfinity://service//a1b2c3d4:...:port` |

The double-slash after the protocol segment mirrors the `://` convention and makes the address visually distinct from the protocol. The `<address>` is either a raw hex mesh address or a resolved short name / local pet name (see §17.4 Mesh DNS).

URLs with the `pair` protocol are the standard format for all pairing link-share invitations (§8.2). URLs with `http` or `https` are what users share when pointing someone to a mesh-hosted website. The scheme is registered as a deep-link handler on all platforms so that tapping a `meshinfinity://` link opens the app and navigates to the appropriate resource.

### 17.6 Flutter UI Layer

- Flutter is the canonical UI across all platforms; Android is the primary target, iOS and desktop are secondary
- Slint and SwiftUI are deprecated; any remaining references are archival only
- Architecture: MVVM with `ChangeNotifier` and `Provider` for reactive state propagation
- All backend calls are async; the UI registers an FFI event callback and processes backend events on the main isolate
- No analytics, no third-party SDKs, no cloud service dependencies in the UI layer
- The UI layer's responsibility is rendering state and issuing intent commands — never performing business logic, cryptography, or network operations
