# Mesh Infinity Technical Specification

**Specification version:** 1.5
**Status:** Active

---

## Revision History

| Version | Date | Summary |
|---------|------|---------|
| 1.0 | 2026-03-09 | Initial specification. Covered identity model, cryptography, network map, transports (WireGuard/Tor/I2P/BLE/RF/clearnet), hop-by-hop routing, store-and-forward, 4-layer message encryption, key ratcheting, pairing and trust model, social profiles (`identity_is_public`, `address_is_associable`), Signal-parity messaging, file sharing, hosted services, VPN/exit nodes, notifications, platform architecture, FFI boundary, mesh address format, and Mesh DNS (Tailscale-style short-name approval). |
| 1.1 | 2026-03-10 | Security hardening pass. (1) Bootstrap node integrity: pinned Ed25519 pubkey required for all bootstrap entries. (2) Key compromise recovery: new §3.8 `KeyRotationAnnouncement` protocol. (3) Argon2id minimum parameters specified (m=64 MB, t=3, p=4); weaker backups rejected on import. (4) Sequence numbers explicitly u64; 32-bit overflow risk documented. (5) Map timestamp validation: entries >1 hour in the future rejected. (6) Sybil/storage-exhaustion defence: map capped at 100k entries, gossip rate-limited to 500 entries/peer/hour, deduplication set persisted to disk. (7) WoT key-change corroborators must be pre-existing trusted peers, not newly paired. (8) Nonce counter re-handshake threshold specified at 2^48. (9) Padding buckets (256 B–1 MB) and timing jitter ranges (0–250 ms by priority level) defined. (10) Endorsement revocation: `TrustRevocation` record with sequence numbers. (11) Capability flags table (§8.1): `can_be_exit_node`, `can_be_wrapper_node`, etc. — trust level alone no longer sufficient for privileged roles. (12) Exit node DNS: forwarding mandatory in Exit Node mode; exit node uses DoH upstream. (13) Platform keyfile storage: Android Keystore / iOS Keychain / DPAPI / Secret Service per platform. (14) BLE advertisements: rotating ephemeral token only; full identity fetched over encrypted GATT. (15) Tor circuit rotation: explicit 10-minute / 200-message schedule. (16) Store-and-forward TTL: sender-signed expiry enforced by recipient regardless of server behaviour. (17) §17.4 Mesh DNS: replaced BIP39 word-phrase model with Tailscale-style short-name advertisement and per-peer approval. |
| 1.2 | 2026-03-16 | **Signal crypto embedded in Step 2 of the 4-layer scheme.** The 4-layer routing envelope is preserved — it handles forwarding authenticity, sender privacy from relay nodes, and outer recipient encryption. The Step 2 static `channel_key` is replaced with a **Double Ratchet** session key, established via **X3DH** on first contact. This gives the existing scheme per-message forward secrecy and break-in recovery without changing the routing layer. §7.0 added: X3DH pre-key material and session initiation. §7.1 Step 2 updated to use the ratchet-derived `msg_key`. §7.4 ratcheting updated: timer-based rotation replaced with the Double Ratchet algorithm. Group encryption updated to Signal Sender Keys (replacing static group channel key). |
| 1.3 | 2026-03-17 | **Security baseline principle and LoSec transport mode.** §2 renumbered; new §2.1 establishes the maximally-hostile-observer baseline as the primary design principle. New §6.7 defines LoSec mode: a WireGuard-only (no onion layers), 0–2 hop transport for high-bandwidth connections (voice/video/arbitrary streams/services). Three-gate consent model: host-side `ServiceLoSecConfig` toggles (`allow_losec`, `allow_direct`) must be explicitly enabled, initiator must explicitly request, and remote peer must explicitly accept (default policy: deny). Direct mode (0-hop) requires WoT depth-1 peer and noisy connection graph; full-screen terror warning required. Relay nodes automatically participate subject to per-node bandwidth budget and metered-connection check. `ServiceRecord` extended with `losec_config: ServiceLoSecConfig`. §10.6 updated with LoSec call negotiation via `CallSignal.losec_requested`. |
| 1.4 | 2026-03-23 | **Storage, persistence, and implementation decisions.** (1) §17.7 added: Encrypted Vault Storage — all persistent data stored as XChaCha20-Poly1305-encrypted blobs using HKDF-SHA256-derived per-collection keys from the identity master key. Deliberate design: no SQLite, no portable format, no queryable structure on disk. Format: `[24-byte nonce][AEAD ciphertext of JSON-serialized data]`. Collections: rooms, messages, peers, network_map, signal_sessions, settings, trust_endorsements, prekeys, file_transfers. Atomic writes via tmp+rename. (2) §17.1 updated: `backend/storage/` module added to module structure — `blob_store.rs` (BlobStore<T>, CollectionStore<K,V>). (3) Build system: revision tags now use `git rev-list --count HEAD` (deterministic, same locally and in CI) instead of GitHub Actions `run_number`. `make push` creates and pushes revision tags to origin so Gitea mirror preserves them on GitHub. |
| 1.5 | 2026-03-24 | **Threat model review and architectural redesign.** Comprehensive integration of 61 GAPs from the threat model review. Key changes: (1) 8-level trust redesign replacing 4-level model with distinct untrusted/trusted tiers and single-endorser requirement. (2) Trust state machine: Self-Disavowed, Friend-Disavowed, and Compromised states with formal transition rules. (3) Transport redesign: Bluetooth steganographic advertisements, RF as plugin category, WiFi Direct as dedicated transport, NFC as pairing transport, transport selection as constraint solver. (4) Routing redesign: persistent outer tunnels with nested WireGuard inner tunnels, two-plane public/private routing model, Mesh NAT, self-ratcheted map entries, position-hiding privacy property, 8-level trust weights. (5) Profile hierarchy: global public, global private, per-context, per-group, and anonymous profiles with trust portability rules. (6) Integrated social channels restructure (§10). (7) Application plugin system with three-tier model. (8) Unified discovery system with mechanism taxonomy, autodiscovery pipeline, and hostile environment defaults. (9) Operational security section additions: PIN system with emergency erase, TPM prohibition, cloud backup prohibition, preauth key model replacing Signal OPK system. (10) Known limitations section documenting honestly unsolved problems. |

---

## 1. Overview

Mesh Infinity is a **private mesh wide-area network (PMWAN)** and communications platform. It is an alternative to the centralised internet — replacing centralised servers with a web-of-trust-based mesh network bootstrapped over friend nodes, using Tor and I2P as anonymous transports.

At its centre is a **Signal-replacement chat application**. Built out from that core are: social profiles, file sharing, hosted services, system-wide VPN routing, and exit nodes. Every feature available on the open internet must have a mesh equivalent.

The Rust backend is the trusted security boundary. The Flutter UI is a thin rendering layer that issues intent-based commands and renders backend state. Keys, cryptography, transport, and storage never leave Rust.

Unlike Tor, which routes through random relays selected by a directory authority, Mesh Infinity routes through a social graph. Nodes you trust become your routing infrastructure. Nodes your friends trust become reachable via them. The network topology emerges from human relationships rather than from a central coordinator.

Unlike I2P, which forms a standalone overlay, Mesh Infinity is transport-agnostic: it can route over Tor, I2P, WireGuard, Bluetooth, RF, or clearnet — and can mix transports simultaneously. The mesh is the routing and trust layer; the transport is pluggable beneath it.

Unlike Signal, which relies on centralised Signal servers for message delivery, key distribution, and group management, Mesh Infinity performs all of these functions in a distributed manner across the peer network.

A note on the trust model: **anonymization in Mesh Infinity is directed at adversaries, not at trusted contacts.** The goal of wrapper nodes, ephemeral addresses, and onion routing is to prevent surveillance by ISPs, state actors, or unknown nodes — not to hide your identity from people you trust. Within a trusted channel, messages are as transparent as a Signal conversation: the sender and recipient are known to each other, full metadata is visible to both parties, and the experience is designed to feel as natural as any modern chat app. Trusted peers are trusted. The complexity of the anonymization layer is invisible to users communicating with their friends. This is the foundation of the social model: without the ability to genuinely trust your contacts, the network has no value.

**Intended use:** This application is not intended to enable immoral activities regardless of their legality. The threat model assumes environments where institutions meant to protect people have become the threat — state security services in authoritarian regimes, persecution of journalists, activists, dissidents, and minorities, domestic situations where "arrested" means "taken by a hostile actor with state power who intends harm." ICE operations in the current US political environment are a concrete domestic example. This distinction must be explicit so that implementers reason correctly about edge cases: every design decision must serve people who need protection, not people who need concealment for predatory purposes.

---

## 2. Design Principles

### 2.0 Threat Model Baseline

The following assumptions underpin every design decision in this specification:

- Everyone who is not an explicitly trusted friend is a potential adversary.
- A device belonging to a friend can only be trusted with *that friend's* data and capabilities — not with the full trust surface of the network.
- Anyone who has not been granted access is assumed to be actively trying to kill the user.
- The system is designed for situations where rule of law has broken down.
- The weakest link is always the human — no code survives a $5 hammer.
- Physical seizure by a sophisticated adversary (device imaging in a Faraday cage) is an accepted risk that cannot be fully mitigated. This is documented honestly so users are never misled about what protection they have.

These are not hypothetical edge cases. They are the primary design context. Features that work "well enough in practice" under a benign threat model but fail under these assumptions are rejected. The maximally hostile observer is the default; reduced-security modes are explicit, informed opt-ins layered on top of the safe baseline.

### 2.1 Principles

1. **Assume a maximally hostile observer.** Every design decision must be evaluated against the threat model: all activity is surveilled, all metadata is retained, all exposures carry the highest possible consequence. "Probably fine in practice" is not acceptable reasoning. The question to ask when designing any feature is: *if every byte of metadata this produces were handed to the most hostile imaginable authority, what would they learn, and who would be harmed?* Default settings must reflect this worst case. Reduced-security modes exist only as explicit, informed opt-ins layered on top of a safe baseline — never the other way around.

2. **Every known attack vector must have a mitigation.** If a design choice creates a deanonymization, correlation, or censorship risk, a countermeasure must exist — not necessarily mandatory, but available. No feature ships if its only known mitigation is "don't use it."

3. **If you can do it on the open internet, you must be able to do it on Mesh Infinity.** Chat, file sharing, web browsing, hosting services, VPN routing, social profiles — all must have a mesh equivalent. This is the feature completeness bar.

4. **Complexity belongs to the system, not the user.** The average user's mental model is: add friends, chat, it's secure. Advanced features exist and are accessible, but never required to achieve safety or functionality. Default settings must be safe defaults.

5. **No cloud dependencies for core function.** Google Play Services, Apple cloud, Microsoft cloud, and equivalent vendor-specific services are prohibited from the critical path. Cloud notifications are permitted only as a ping-only wake transport carrying zero message content (see §14).

6. **Trust is explicit and user-controlled.** No system makes automatic trust decisions on behalf of the user. Trust levels are set by the user; propagated trust is advisory and always overridable.

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

The derived `channel_key` is used as the **WireGuard Pre-Shared Key (PSK)** when establishing connections with peers at trust level >= `Trusted` (Level 5+). Connections to lower-trust peers use WireGuard without a PSK. Both sides independently derive the same `channel_key` from their shared X25519 DH exchange; no open key exchange is needed. An adversary who holds only a peer's public key cannot complete the trusted WireGuard handshake because they do not possess the PSK.

When a peer is promoted to Trusted (Level 5+), the `channel_key` is derived and stored, then set as the WireGuard PSK for that peer's connections. When trust is revoked (dropped below Level 5), the PSK is removed and the `channel_key` is discarded.

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

**Software floor guarantee:** ChaCha20-Poly1305 + X25519 + Ed25519 + SHA-256 are the guaranteed software floor — fully implemented in software on all supported platforms. Hardware acceleration is an optimization, never a requirement. If no cryptographic implementation is available, the connection is rejected. There is no fallback to plaintext under any circumstances.

**DOS via capability advertisement:** Nodes must advertise only primitives they can execute at hardware-accelerated performance. A node without AES hardware acceleration must not advertise AES-256-GCM. Advertising beyond hardware capability exposes the node to denial-of-service via forced expensive software execution.

The negotiation handshake is itself signed by both parties' Ed25519 keys, preventing a downgrade-by-interception attack. If either party's preferred primitive set is not supported by the other, they fall back to the common intersection. If no intersection exists, the connection is rejected.

All connections default to ChaCha20-Poly1305 to ensure a safe baseline without hardware probing.

### 3.5 Zero-Knowledge Proofs and Deniability

Deniability is a core requirement. The system provides it at multiple layers:

#### Message-Level Deniability

Messages within trusted channels are authenticated using **HMAC-SHA256 with the ratchet-derived `msg_key`** (produced by the Double Ratchet as described in §7.0), rather than Ed25519 signatures alone. Since the `msg_key` is derived from shared ratchet state that both parties possess, neither party can prove to a third party who authored any specific message — both have the cryptographic capability to produce any MAC under that key.

The static `channel_key` derived in §3.2 is no longer used for message authentication (it serves as the WireGuard PSK, see §3.2 and §5.1). Message-level deniability is provided entirely by the Double Ratchet `msg_key`.

Ed25519 signatures are still applied at the transport/routing layer for hop-by-hop forwarding authentication, but these outer signatures cover only the encrypted payload, not the plaintext content. A forwarding node cannot determine whether the signature on a packet it forwards represents the original author or a re-signed relay.

#### Group Membership Deniability — Ring Signatures

To prove membership in a trusted group without revealing *which* member you are, group operations use **ring signatures** (specifically, a Schnorr-based ring signature scheme):

- A ring signature proves that the signer holds *one of* the private keys in a set (the ring), without revealing which one
- Group membership proofs, group message authentication, and group admin actions use ring signatures over the group's member public key set
- An external observer can verify that *some* group member performed an action, but cannot determine which member
- The ring is the current group member set; as members join or leave, the ring is updated

**Superset ring model (for ring signature continuity during member removal):**
- **First removal**: content encrypted for the reduced ring (excluding the removed member); the outer envelope still uses the full superset ring. External observers see no change; the removed member cannot read content.
- **Second removal before rekeying completes**: immediate forced rekeying. No third ring — the computational and storage cost in large groups (200-300 nodes) is prohibitive.

#### Connection Deniability

Wrapper node routing (§4.4) combined with ephemeral source addresses prevents linking a specific connection event to a specific identity. No persistent logs are kept of which identities connected to which. Routing metadata (which hops were used) is not preserved beyond the active session.

#### Key Ownership Proofs — Sigma Protocols

During pairing, a **Sigma-protocol (Sigma protocol)** is used to prove knowledge of the private key corresponding to a presented public key, without transmitting the private key or creating a replayable transcript:

1. **Commit:** The prover generates an ephemeral keypair `(r, R)` where `R = r*G`. They send `R` to the verifier.
2. **Challenge:** The verifier sends a random challenge `c`.
3. **Respond:** The prover sends `s = r + c*sk` where `sk` is the secret key.
4. **Verify:** The verifier checks `s*G == R + c*PK`.

The transcript `(R, c, s)` is non-replayable: `c` is chosen by the verifier in this session and cannot be forged. The interaction proves knowledge of `sk` without revealing it. The transcript does not constitute a proof to a third party because the verifier could have fabricated a consistent `(R, c, s)` tuple.

All pairing flows use this protocol as the authentication step.

### 3.6 Identity Persistence

Identity material is stored on disk encrypted with a random keyfile:

- `identity.key` — 32 bytes of random data, the encryption key
- `identity.dat` — 12-byte random nonce followed by ChaCha20-Poly1305 ciphertext of the JSON-serialised identity payload

**Private key serialization safety:** The `identity.dat` plaintext buffer must never contain private keys in a JSON-serializable form that could leak through normal serialization paths. Private key fields (`ed25519_secret`, `x25519_secret`) are excluded from JSON serialization (via `#[serde(skip)]` or equivalent). The plaintext buffer is constructed as:

```
[json_len (4 bytes LE)] [json_bytes] [ed25519_secret (32 bytes)] [x25519_secret (32 bytes)]
```

The entire buffer is wrapped in a `SecureBytes`/zeroize wrapper. On load, the decrypted buffer is split — JSON slice deserialized, key bytes extracted directly — and the buffer is zeroed before drop. The `zeroize` crate is used throughout to ensure private key material does not persist in process memory after use.

**Platform-level keyfile protection:**

The `identity.key` file is the highest-value target for an attacker with filesystem access. Where the platform provides hardware-backed secure storage, the keyfile bytes are stored there instead of as a plain file:

| Platform | Keyfile storage |
|----------|----------------|
| Android | Android Keystore (hardware-backed if device supports StrongBox or TEE) |
| iOS | iOS Keychain with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` |
| macOS | macOS Keychain (may be software-backed on non-T2/Apple Silicon) |
| Linux (desktop) | Secret Service API (if available: GNOME Keyring, KWallet); otherwise filesystem with `0600` permissions |
| Linux (headless) | **1. PKCS#11 hardware token** (YubiKey, Nitrokey, etc.) — genuinely user-controlled external hardware; **2. Secret Service API** — if daemon is running; **3. Plain `0600` file** — fallback only, must never be silent, warning shown on every startup until a hardware token or Secret Service is configured |
| Windows | DPAPI (Data Protection API) wrapping the keyfile bytes |

**TPM explicitly prohibited.** Intel fTPM runs inside Intel Management Engine (ME) — a known attack surface controlled by Intel, not the user. TPM-FAIL (CVE-2019-11090) demonstrated timing side-channel extraction of ECDSA keys from Intel fTPM in 4-20 minutes with local access. CIA differential power analysis attacks on TPM are confirmed (Snowden revelations). UEFI firmware has authority over TPM PCR values. Microsoft controls TPM 2.0 reference implementation signing keys. TPM must never be referenced as a security mechanism in this codebase. PKCS#11 hardware tokens (YubiKey, Nitrokey, etc.) are the correct alternative — genuinely user-controlled external hardware with no vendor backdoor surface.

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

**Cloud backup explicitly prohibited.** Backups must not be stored on public cloud services. State actors can subpoena cloud providers for encrypted files without the user's knowledge. Recommended storage: local physical media only. The app must not offer cloud backup destinations.

**Backup scope is reconnection only — not history.** The backup is explicitly scoped to network re-entry. It does not contain message history, Sender Key state, or any decryptable past content. Message history recovery after restore is handled by peer-to-peer sync, not by the backup file.

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
- Sender Key state
- Double Ratchet session state

**Restore process:**
1. User imports the backup file and provides the passphrase
2. The system decrypts the backup using ChaCha20-Poly1305 with Argon2id-derived key. Argon2id parameters must meet or exceed the minimum values: `m_cost = 65536` (64 MB), `t_cost = 3`, `p_cost = 4`. Backup files produced with weaker parameters are rejected on import with an explicit error. These defaults are reviewed against OWASP recommendations at each major version bump.
3. A fresh Ed25519 and X25519 keypair is generated
4. New public addresses are derived from the new keypair
5. The network map is restored, giving the node a starting list of known peers
6. Profile data is restored
7. The node connects to the network using the restored map as its bootstrap list
8. Existing trusted peers see a new peer ID at the restored public addresses. They must manually re-mark the restored identity as trusted — trust cannot be re-established automatically because the keypair changed.

**History sync after restore requires explicit peer consent.** After restore, a node's identity has changed (new keypairs). Message history sync is a separate, explicit action — never automatic on reconnect. A peer sharing history with a restored identity must be clearly informed: *"You are about to share message history with [name]'s restored identity. Their device keys have changed. Only do this if you are certain this is genuinely [name] on a new device."*

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
    is_emergency:     bool,        // false = planned (migration, upgrade, deliberate rotation)
                                   // true  = emergency (any unplanned situation)
    old_signature:    [u8; 64],    // Ed25519 signature by old key over all other fields
}
```

The `reason: String` field from earlier versions is replaced with `is_emergency: bool`. The previous `reason` field (accepting values like `"device_loss"`, `"compromise"`, `"migration"`) leaked operational intelligence — broadcasting `"compromise"` announces to the entire network that an attack was detected and when. The boolean field preserves the only distinction that matters to peers: was this planned or unplanned?

Trusted peers who receive and verify a `KeyRotationAnnouncement` signed by the old key may automatically accept the new key at the same trust level, skipping the WoT corroboration requirement of §4.6. The user is still notified and can review.

4. **If the old key is no longer available** (e.g., device is gone and no backup exists), key rotation cannot be cryptographically proven. In this case trusted peers must re-pair directly with the new identity. The old peer ID is handled by the Disavowed/Compromised state machine (§8.x) — peers who have ground-truth knowledge of the compromise use the Friend-Disavowed mechanism rather than issuing ad-hoc revocations.

**Important:** A `KeyRotationAnnouncement` from an *unrecognised* old key (i.e., an old key no peer has seen before) is not automatically trusted — this would allow an attacker to pre-generate a chain of key rotations. The announcement is only accepted if the old key matches the previously known key for that peer ID.

### 3.9 Killswitch / Emergency Data Destruction

The killswitch permanently destroys the local identity and renders all associated data unreadable.

**Activation methods:**

1. **Emergency Erase menu** — Settings > Security > Emergency Erase. Requires confirmation.
2. **Configured gesture** — Optional. User-configurable. Disabled by default.
3. **Emergency Erase PIN (Duress PIN)** — A separate PIN, stored encrypted in the keystore. Entering it on the unlock screen looks identical to normal unlock — same UI, same one-second pause. The one-second pause is present on ALL unlock attempts to normalize timing.

**Critical requirement:** The killswitch must be activatable WITHOUT entering the normal PIN first.

**Emergency Erase PIN — Genuine Identity Rotation:**
1. Emergency PIN entered on unlock screen
2. One-second pause (identical to normal unlock — indistinguishable)
3. Foreground: new identity loads, app appears normal per post-wipe configuration
4. Background: old identity wiped, Self-Disavowed broadcast attempted, new identity initialized
5. The Emergency Erase PIN becomes the legitimate unlock PIN for the new identity

**Post-Wipe Identity Configuration:** Configured entirely in advance, stored encrypted. User-selectable presets: Empty (blank slate), Light use (minimal plausible activity), Full decoy (populated with plausible decoy data). No prompts occur during the emergency flow — all decisions are made in advance.

**Destruction sequence:**
1. `identity.key` is **overwritten with 32 bytes of fresh random data** — this makes the existing `identity.dat` ciphertext permanently unreadable even if an adversary has a copy of the ciphertext, because they cannot know the new key that was written over the original
2. `identity.key` is then deleted
3. `identity.dat` is deleted
4. The network map database is deleted
5. Profile data is deleted
6. Cached messages are deleted

Steps 1–2 are the security-critical steps. The overwrite is performed before deletion to ensure the original key material is irrecoverable even from undeleted disk sectors. After step 1, the ciphertext in `identity.dat` is cryptographically orphaned.

This is irreversible without a prior backup.

**Remote Killswitch:**

```
RemoteKillswitchRequest {
    target_peer_id:  [u8; 32],
    requester_id:    [u8; 32],
    timestamp:       u64,
    signature:       [u8; 64],   // signed by requester's InnerCircle key
}
```

Requires InnerCircle (Level 8) trust level. First delivery triggers the killswitch. Known limitation: a sophisticated adversary using a Faraday cage prevents delivery of the remote killswitch signal.

**Interaction with Disavowed/Compromised State Machine (§8.x):**
- Local killswitch activation broadcasts Self-Disavowed before destruction
- Remote killswitch activation counts as a Self-Disavowed trigger
- Post-wipe new identity starts fresh — it is not Self-Disavowed

### 3.10 App PIN (Optional)

An optional app-level PIN provides a second encryption layer protecting the identity material from an adversary who has access to the device but not the user's knowledge.

**Architecture:**
- PIN wraps `identity.key` with a second encryption layer
- `pin.dat` stores: Argon2id params + salt + encrypted `identity.key`
- Without PIN entry: app can connect to mesh, receive encrypted packets, display non-sensitive UI — but cannot decrypt messages, sign as this identity, or access private profile data
- With PIN entry: Argon2id derives key from PIN, decrypts `identity.key`, full identity loads

**Attempt counter:**
- Stored in platform keystore — same hardware-backed store as key material
- Counter persists across app restarts — killing and restarting the app does not reset it
- Tampering with or deleting the counter file when PIN is enabled triggers immediate Self-Disavowed broadcast followed by identity wipe

**Backoff curve (not user-configurable — security property):**
```
Attempts 1-5:   No delay
Attempt 6:      30 seconds
Attempt 7:      2 minutes
Attempt 8:      10 minutes
Attempt 9:      1 hour
Attempt 10:     24 hours
Attempt 11+:    72 hours per attempt
```

At 72 hours/attempt: 4-digit PIN exhaustion takes approximately 80 years. 6-digit PIN exhaustion takes approximately 8,000 years.

**Wipe threshold:** User-configurable number of failed attempts before emergency wipe. On threshold: Self-Disavowed is broadcast FIRST (requires signing key in memory), THEN identity wipes.

**Default:** PIN disabled. Located in Settings > Security.

**PIN input must bypass Flutter entirely.** The PIN is security-critical input that must never pass through the Flutter rendering layer:
- iOS: native Swift `UITextField` with `isSecureTextEntry`, result passed directly to Rust via FFI
- Android: native Kotlin `EditText` with `inputType="textPassword"`, result passed directly to Rust via FFI
- Linux: native credential prompt or direct terminal input if headless
- Windows: native credential UI
- Flutter signals "authentication required" — the native platform layer handles input — Rust receives PIN bytes directly

**Timing normalization:** Normal PIN, emergency PIN, and incorrect PIN all take exactly the same wall-clock time to respond. Argon2id derivation runs for every attempt regardless of outcome. Observable behavior must be identical for all PIN types. Emergency wipe and identity rotation happen after the UI has already transitioned — from outside, the result looks like a normal successful unlock.

**Process monitoring mitigation:** PIN value must never appear in process memory in a form readable by an external process. PIN bytes are zeroed immediately after Argon2id derivation.

**Biometric prohibition:** Biometric authentication is explicitly prohibited for any security-critical unlock path. In most jurisdictions law enforcement can legally compel biometric authentication. Biometrics bypass the emergency PIN concept entirely — there is no biometric equivalent of "enter the duress PIN."

---

## 4. Network Model

### 4.1 Bootstrapping and Network Map Propagation

Mesh Infinity has no central directory server. Discovery is bootstrapped as follows:

1. On startup, attempt to connect to known **friend nodes** (peers in the local trust store at level `Trusted` (Level 5) or above) first.
2. If no friend nodes are immediately reachable, attempt connection to any previously known node in the network map.
3. On any new connection, perform a **map exchange**: each side serialises their known network map and sends it. The receiving side merges the incoming entries with their local map, preferring newer timestamps.
4. The merged map is then gossiped to other connected peers, who repeat the merge process. Changes propagate across the network in rounds of gossip until they reach all connected nodes.

There is no guarantee of delivery speed. The network is **eventually consistent**: a new node appearing in the map will be visible to all connected peers within some number of gossip rounds, proportional to the diameter of the connected graph.

**Bootstrap redundancy:** New nodes connect to multiple bootstrap sources simultaneously. There are no "official" bootstrap nodes — anyone can bootstrap anyone. Map cross-validation uses majority view to resolve disputed entries.

**Map trust typing by source:**

| Source | Initial trust | Routing use |
|--------|--------------|-------------|
| Direct pairing | Full — cross-reference anchor | Immediate |
| BLE/local transfer | Elevated — physical proximity signal | After WireGuard handshake |
| Clearnet protocol | Unverified | Read-only until pairing |
| Imported file | Unverified | Read-only until pairing |
| Bootstrap node (pinned key) | Partially verified | Read-only until pairing |

**Critical rule:** An unverified map is read-only until at least one direct pairing provides a cross-reference anchor.

**Map size-scaled validation threshold:**
```
Map entries < 100:     1 source sufficient
Map entries 100-1000:  2 independent sources required
Map entries 1000+:     3 independent sources required, majority agreement on disputed entries
```

**Explicit clearnet map sharing protocol:** Nodes can optionally expose a map-sharing HTTP endpoint on a non-associable address.

**BLE map sharing:** BLE-sourced maps receive "elevated" trust typing.

**Group-as-LAN (Private Network Namespaces):** A trusted group can optionally enable "network sharing" to become a private mesh namespace. This requires:
- `network_sharing_enabled: bool` flag on group configuration
- `proximity_share_enabled: bool` flag on group configuration
- Subnet route advertisement scoped to group membership
- Group-scoped map entries with explicit no-gossip flag
- Group-scoped name resolver

**Proximity-share extension:** A LAN group with `proximity_share_enabled = true` distributes Bluetooth token chains to group members through the trusted group channel, enabling stealthy Bluetooth rendezvous. This supports PTT over BLE within the group.

The network map is a **public-only** structure. It contains:
- Peer IDs
- Public addresses and their corresponding public keys
- Last-seen timestamp (for staleness detection)
- Reachability hints: which transports this peer has been seen on
- Optional: public profile summary (display name, avatar hash) if the peer has `identity_is_public = true`
- Optional: public service advertisements

Trusted-channel addresses, private profile data, and group membership are **never included** in the network map.

**Bootstrap node integrity:** A new node that connects to a bootstrap node with a poisoned map receives incorrect peer data before it has any trusted peers to cross-check against. To mitigate this:

- Hardcoded or user-configured bootstrap node addresses must include the expected **Ed25519 public key** (not just an address). The first connection verifies the WireGuard handshake against that pinned key; if they don't match, the connection is rejected and the user is warned.
- Bootstrap addresses are specified in the form `<transport_address>:<pubkey_hex>` so the public key is always bundled with the address. A bootstrap entry without a pinned key is accepted only interactively (the user sees the fingerprint and confirms before the map is merged).
- Once the first trusted peer is established via direct pairing, subsequent map updates are cross-checked against the trusted peer's map. Systematic divergence between the bootstrap node's map and the trusted-peer map triggers a warning.

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

**Gossip validation — entire NetworkMapEntry surface:**

Every unvalidated gossiped field is a potential injection vector. Any `NetworkMapEntry` with a field that fails validation is rejected entirely and not gossiped. Never sanitize-and-forward.

Per-field validation requirements:
```
public_display_name:    max 64 bytes, UTF-8 only, no control characters
public_bio:             max 256 bytes, UTF-8 only, no control characters
service.name:           max 64 bytes, UTF-8 only, no control characters
service.description:    max 256 bytes, UTF-8 only, no control characters
avatar_hash:            exactly 32 bytes, rejected if any other length
transport_hints:        max 8 per entry
public_keys:            max 16 per entry
services:               max 32 per entry

endpoint validation per transport type:
  Tor:      must match /^[a-z2-7]{56}\.onion(:\d{1,5})?$/ exactly
  Clearnet: must be valid RFC-compliant IP:port or hostname:port
  I2P:      must match I2P destination format
  BLE:      must match expected BLE address format
  RF:       must match Meshtastic node address format
```

All validation is performed in Rust before the FFI boundary. Flutter receives only pre-validated, display-safe data.

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

**Directory node map history retention:**

Directory nodes maintain a history of map snapshots for forensic analysis and recovery:

```
Retention schedule (flattened snapshots):
  Every hour    -> last 24 hours     (24 snapshots)
  Every day     -> last 7 days       (7 snapshots)
  Every week    -> last 4 weeks      (4 snapshots)
  Every month   -> last 12 months    (12 snapshots)
  Every year    -> last 5 years      (5 snapshots)
  Total:        52 snapshots maximum
```

Snapshot format:
```rust
MapSnapshot {
    version:      u32,
    timestamp:    u64,
    entry_count:  u32,
    compression:  CompressionType,  // None | Zstd (preferred) | LZ4 (fallback)
    data:         Vec<u8>,
}
```

Storage recommendation:
```
Minimum = avg_entry_size * max_entries * compression_ratio (~0.3) * 52 * 2 (headroom)
Example at defaults: 750B * 100K * 0.3 * 52 * 2 ~ 2.4 GB minimum
```

### 4.4 Anonymization: Wrapper Nodes

Wrapper nodes are an **optional** privacy layer for situations where the public address correlation risk is unacceptable. A sender routes a message through one or more intermediate nodes before it reaches the destination, with each layer of the message encrypted for the next hop — an onion model, but routed through the web-of-trust graph.

**Wrapper nodes are recipient-configured.** The *recipient* sets up wrapper nodes, establishes the onion structure, and holds the innermost key. The *recipient* advertises a wrapper-node-protected address through private/trusted channels. The *sender* encrypts to that address — they do not know or choose the wrapper topology. From the sender's perspective, a wrapper-protected address is indistinguishable from a direct address.

**Wrapper nodes are routing constructs, not encryption layers.** The four-layer message encryption scheme (§7) is unchanged and operates inside the wrapper envelope(s). Wrapper node envelopes are part of the routing layer. Wrapper nodes can be stacked arbitrarily — enumerating them as "layers" would make the spec infinitely expandable.

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

**Self-ratcheted map entries:** Each node maintains a cryptographic ratchet for its own map entry:

```rust
SelfMapEntry {
    peer_id:     [u8; 32],
    content:     MapEntryContent,
    prev_hash:   [u8; 32],           // SHA-256 of previous self-signed entry
    timestamp:   u64,
    signature:   [u8; 64],           // Ed25519 sign over all above fields
}
```

Properties of the self-ratchet model:
- **Counter loss impossible** — the ratchet is hash-chained, not counter-based
- **Replay attacks impossible** — each entry references its predecessor; replaying an old entry creates a detectable fork
- **Forks detectable** — two entries with the same `prev_hash` but different content prove the signing key is compromised or duplicated
- **Recovery after database loss** — a single network query retrieves the latest ratcheted entry

Every `NetworkMapEntry` additionally carries sequence and signature fields for backwards compatibility and additional validation:

```
NetworkMapEntry {
    ...
    sequence:  u64,       // Monotonically increasing per peer_id; prevents replay. 64-bit minimum -- 32-bit overflows are exploitable.
    signature: [u8; 64],  // Ed25519 signature over all other fields, by the entry's own key
}
```

Rules for accepting an update:
1. The signature must verify against the Ed25519 public key in the entry itself
2. The `sequence` number must be strictly greater than the locally stored sequence for that `peer_id`
3. The `last_seen` timestamp must not be more than **1 hour in the future** relative to the receiving node's local clock. Entries with future-dated timestamps beyond this window are rejected outright — without this check, an attacker can craft an entry with a timestamp 60 days in the future that survives all pruning passes and permanently displaces the legitimate entry.
4. If the entry's public key set **differs** from the locally stored one (a key change), the update is not automatically accepted — see §4.6
5. The `prev_hash` must match the SHA-256 of the locally stored previous entry for that `peer_id` (if one exists). A mismatch indicates a fork.

Revocations follow the same model: a `Revocation { address, sequence, signature }` is only accepted if signed by the key that owns the address being revoked, and the sequence is newer than any accepted entry for that peer.

### 4.6 Key Change Validation via Web of Trust

When a received map update changes the public key(s) for a known `peer_id`, this is a high-suspicion event. A sudden key change is the signature of either a legitimate device migration or an impersonation attack — the network cannot distinguish these automatically.

**Key change policy:**

1. **Flagged, not automatically accepted.** A key-change update is held in a quarantine state locally. The user is notified: *"[Peer name] appears to have changed their key. This may mean they have a new device, or it may indicate an attack."*

2. **WoT corroboration required.** The update is not promoted to accepted until a threshold of mutually trusted peers have also received and accepted the same key change for that peer ID. The threshold is configurable (default: 2 trusted peers). If 2 or more peers at trust level >= `Trusted` (Level 5+) have accepted the new key, the update is promoted. **Corroborating peers must be independently established:** a peer cannot satisfy the threshold by corroborating their own key change (i.e., the peer whose key is changing cannot count as a corroborator), and both corroborators must have been trusted by the local node *before* the key-change event — not newly paired after it.

3. **Direct confirmation overrides.** If the local user directly pairs with the peer again (any pairing method — QR, code, proximity), this constitutes first-hand confirmation and immediately accepts the key change.

4. **Two-channel verification protocol.** For trusted peers with an established verification passphrase (see below), a cryptographic two-channel verification can confirm the key change without requiring WoT corroboration or direct re-pairing.

**Two-channel key change verification:**

**Setup (at original pairing time):** Both parties establish a **verification passphrase** — short, memorable, case-insensitive. The app prompts for it, tests it immediately, and discards it permanently. The passphrase is never stored anywhere in the app — it exists only in human memory.

**During key change verification:**
```
code = HMAC-SHA256(
    key  = verification_passphrase,   // from memory only
    msg  = new_public_key_bytes
)[0..3]                               // 3 bytes -> 6 alphanumeric characters
```

**Channel A (in-band, can be monitored):** New public key transmitted in full.

**Channel B (out-of-band, low bandwidth, trusted):** Just the 6-character code — spoken aloud, written on paper, tapped in Morse, etc.

Neither channel alone is sufficient. An adversary needs both the key AND the code AND to break HMAC-SHA256 with an unknown key.

**In-band approval path (when out-of-band is impossible):**
- 72-hour mandatory waiting period — cannot be shortened
- Explicit risk acknowledgment required
- PIN re-authentication required
- No notification to requester during waiting period
- Permanently marked as in-band in the approval record

**Approval artifact:**
```rust
KeyChangeApproval {
    old_peer_id:             [u8; 32],
    new_peer_id:             [u8; 32],
    approver_peer_id:        [u8; 32],
    verification_method:     VerificationMethod,  // OutOfBand | InBand
    timestamp:               u64,
    signature:               [u8; 64],
}
```

**Forgotten passphrase:** In-band approval with maximum friction is the only recovery path. No cryptographic recovery exists. The pairing flow must make this consequence explicit.

5. **Automatic rejection of rapid re-changes.** If a peer's key changes more than once within a short window (default: 24 hours), all further changes within that window are rejected outright and the user is alerted. Legitimate device migrations do not involve rapid key cycling.

6. **Stale key protection.** A previously accepted key is never overwritten by a key-change update that only has timestamp authority (i.e., a newer timestamp alone is not sufficient — it must also have WoT corroboration or direct confirmation).

This model follows "trust, but verify": the network accepts that key changes happen legitimately, but treats them with appropriate suspicion and requires social consensus before acting on them.

### 4.7 Map Conflict Resolution

For non-key-change updates (address additions, transport hint updates, profile updates) to an already-known key:

- The update with the higher `sequence` number wins
- If `sequence` numbers are equal but content differs, entries are merged: the union of transport hints and public keys is taken; the newer profile summary wins
- All accepted updates must pass signature verification (§4.5) before being applied or gossiped

### 4.8 Unified Discovery System

Discovery is a coherent system spanning multiple mechanisms with different threat profiles. No single discovery mechanism is universally correct. Users get honest threat profiles for each mechanism, not just "secure" vs "insecure." Hostile-environment defaults never auto-activate deanonymizing mechanisms without explicit user awareness. Discovery mechanisms compose — multiple mechanisms can run simultaneously. Path building is separate from discovery — finding a peer and routing to them are distinct problems.

#### Discovery Mechanism Taxonomy

**Protocol-based (automatic, no prior coordination):**

| Mechanism | Scope | Threat profile | Valid contexts |
|-----------|-------|---------------|----------------|
| mDNS / DNS-SD | LAN broadcast | Broadcasts existence to entire local network. Any device on the LAN sees you. | Trusted home network, friendly office, controlled LAN |
| UPnP SSDP | LAN broadcast | Similar to mDNS. Gateway-level exposure. | Same as mDNS |
| DHT | Mesh-wide | Structured lookup. Querying DHT reveals interest in a peer ID to DHT neighbors. | Public mesh participation where presence is already known |

**Rendezvous-based (shared known coordination point):**

| Mechanism | Scope | Threat profile | Valid contexts |
|-----------|-------|---------------|----------------|
| Bootstrap / directory nodes | Mesh-wide | Bootstrap node learns you connected and when. Choice of bootstrap node is a trust decision. | Any context — bootstrap node is explicitly chosen |
| Tor .onion rendezvous | Global | Both parties connect to shared hidden service. Tor provides anonymization of connection origin. | High-surveillance environments |
| I2P rendezvous | Global | Similar to Tor. Best-effort per §5.3 maturity caveat. | High-surveillance environments |
| Public key as address | Global / trusted channel | If you know someone's preauth key, you can derive their address. Key distribution is out-of-band. | Trusted channel introduction |

**Proximity-based (requires physical proximity or handshake):**

| Mechanism | Scope | Threat profile | Valid contexts |
|-----------|-------|---------------|----------------|
| Bluetooth steganographic tokens (§5.5) | ~10m | Token visible to BLE scanners. Steganography prevents identification without mesh context. Liveness signal. | In-person, moderate surveillance |
| WiFi Direct (§5.7) | ~200m | Connection attempt visible on WiFi band. No network identity broadcast. | In-person, moderate surveillance |
| NFC | ~5cm | Proximity requirement IS the security. Physical touch required. Observable as NFC event but not content. | High-trust in-person, maximum security |
| QR / pairing codes (§8.2) | Visual range | Visual interception possible. See §8.2 for full threat profile. | In-person per context recommendations |

**Clearnet-based:**

| Mechanism | Scope | Threat profile | Valid contexts |
|-----------|-------|---------------|----------------|
| Direct IP | Global | Fully deanonymizing. Your IP is visible. Connection existence visible to network. | Trusted networks, non-hostile environments |
| DNS lookup | Global | DNS query reveals interest in address to DNS resolver. DNSSEC/DoH mitigates partially. | Non-hostile environments with trusted resolver |
| UDP hole punching | Global | STUN server learns both parties' IPs. Coordination server is a trust decision. | When Tor/I2P unavailable, non-hostile environments |

#### Hostile Environment Defaults

In `ThreatContext::Critical`:
- mDNS/SSDP: **disabled entirely** — never auto-activates
- DHT: **disabled** — querying reveals interest
- Direct IP: **disabled** — fully deanonymizing
- DNS lookup: **disabled** — resolver observability
- UDP hole punching: **disabled** — STUN server observability
- Only available: Tor rendezvous, I2P rendezvous, Bluetooth steganographic tokens, QR / pairing codes (in-person), pre-shared bootstrap nodes (explicitly configured)

In `ThreatContext::Elevated`:
- mDNS/SSDP: **user-configurable**, disabled by default, warning if enabled
- DHT: **user-configurable**, limited query rate
- Direct IP: **disabled**
- Tor/I2P/Bluetooth/Bootstrap: **available**

In `ThreatContext::Normal`:
- All mechanisms **available**, defaults reflect operational context
- mDNS: enabled by default on LAN interfaces, disabled on untrusted interfaces
- Clearnet mechanisms: enabled with ambient notification

#### Autodiscovery Pipeline

When a node needs to find a peer or service, the autodiscovery pipeline runs:

```
1. Local routing table check
   -> already know a path? use it

2. Network map lookup
   -> peer ID in map? use known transport hints

3. Proximity mechanisms (if peer may be nearby)
   -> Bluetooth token scan
   -> WiFi Direct probe
   -> NFC (if initiated by user)

4. Trusted peer query
   -> "Does anyone know how to reach peer X?"
   -> Query flows through trusted channels only

5. Directory node query
   -> Fresh reachability data from directory nodes
   -> Scoped to appropriate directory nodes per context

6. Bootstrap fallback (cold start / unknown peer)
   -> Query configured bootstrap nodes
   -> Bootstrap node provides map entries to search

7. Rendezvous mechanisms (for high-security contexts)
   -> Tor rendezvous
   -> I2P rendezvous

8. Failure
   -> SolverFailure with queue_eligible flag (§5.8)
   -> Store-and-forward if available
```

Pipeline stages are skipped based on ThreatContext — Critical skips stages 1-2 for untrusted paths, stage 3 (mDNS), stage 5 (directory nodes over clearnet), stage 6 (clearnet bootstrap).

#### Path Building

Discovery finds a peer. Path building determines how to route to them. These are distinct problems.

**Public routing plane path:**
- Use network map reachability announcements
- Gradient descent toward destination (§6)
- Persistent outer tunnel infrastructure handles actual transport

**Private routing plane path:**
- Dynamic — no pre-built paths
- Trusted peer queries find the transition point from public to private plane (§6.4)
- Path emerges from real-time trusted peer routing knowledge

**Path building constraints from ThreatContext:**
- Critical: minimum hop count enforced, no direct paths, only anonymizing transports
- Elevated: prefer anonymizing transports, accept latency penalty
- Normal: optimize for performance within security policy

Path building is continuous: the transport solver (§5.8) continuously re-evaluates paths. Discovery feeds fresh reachability data into the solver. A better path becoming available triggers seamless migration.

---

## 5. Transport Layer

### 5.1 WireGuard — Primary Per-Hop Link Encryption

**WireGuard is the primary protocol for all active direct connections between mesh peers.** Every direct link in the mesh is a WireGuard tunnel. This is not a transport in the anonymization sense — it is the encrypted link layer that runs *beneath* anonymizing transports.

The WireGuard layer provides:
- **Peer authentication** — WireGuard handshake authenticates both sides using their public keys, which are the same public keys known from the network map. A connection that claims to be from peer X but does not hold X's private key will fail the handshake.
- **Forward secrecy** — WireGuard's handshake rotates ephemeral Diffie-Hellman keys. Compromise of the static keys does not expose past session content.
- **Efficient encrypted tunneling** — after the handshake, WireGuard provides a low-overhead encrypted UDP channel suitable for high-throughput data
- **Pre-Shared Key for trusted peers** — connections to peers at trust level >= `Trusted` (Level 5+) use the `channel_key` derived in §3.2 as a WireGuard PSK, providing an additional layer of authentication that prevents an adversary with only the public key from completing the trusted handshake

The full stack for a message from A to B via Tor:

```
A: application message
   -> 4-layer application crypto (§7)
   -> WireGuard encrypt (A->B tunnel key [+ PSK if trusted])
   -> Tor circuit to B's hidden service
B: Tor circuit
   -> WireGuard decrypt
   -> 4-layer application crypto decrypt
   -> deliver to application
```

WireGuard is always present. The anonymizing transport (Tor, I2P) wraps the WireGuard tunnel. Direct transports (Bluetooth, clearnet) carry the WireGuard tunnel directly.

**WireGuard as stable session layer:** The architectural relationship is:
```
Application session
    +-- WireGuard tunnel (stable, persistent)
            +-- Transport (swappable, negotiated)
```

All connections are migratable by default. Migration: establish new transport while old is still active, then cut over.

### 5.2 Tor

Tor is the **primary anonymizing transport**. Tor hidden services are used to expose mesh endpoints without revealing the host's IP address.

**Independent Tor keypair architecture:** The Tor keypair is an independent sibling of the mesh identity keypair, with no derivation relationship between them:

```
address_keypair       -- mesh identity (WireGuard auth, signing, peer ID)
address_tor_keypair   -- Tor root (independent sibling, never used directly)
```

The Tor root keypair is never directly exposed — it derives service-specific Tor keypairs only:

```
service_tor_key = HKDF-SHA256(
    ikm  = address_tor_secret,
    info = "meshinfinity-tor-service-v1" || service_id || rotation_counter,
    salt = address_tor_public
)
```

Multiple services under the same mesh address have completely independent onion addresses. Compromise properties: compromising a service Tor key leaves the root and sibling services unaffected. Compromising the mesh keypair leaves the Tor keypair unaffected. There is no path from any Tor key to the mesh peer ID.

- Each service-specific Tor key generates a Tor v3 onion address
- Onion addresses are included in the node's network map `transport_hints` for peers who have Tor enabled
- Outbound connections to peers use the Tor SOCKS proxy (via the `arti` Rust client)
- Inbound connections are received on the node's hidden service(s)

Tor circuit management:
- Separate Tor circuits are used per peer where possible, to prevent correlation of traffic across conversations
- Circuit isolation is implemented at the Tor stream level using separate SOCKS credentials per peer (Tor's stream isolation feature)
- **Circuit rotation:** circuits are rotated on a **10-minute** periodic schedule or after **200 messages** on a single circuit, whichever comes first. Circuits are also rotated immediately on a sustained latency spike (> 2x baseline for more than 30 seconds), which may indicate circuit-level surveillance or congestion. A new circuit is established before the old one is torn down to prevent a gap in connectivity.

When Tor is unavailable or the peer is not reachable via Tor, the system falls back to I2P, then clearnet (if enabled).

### 5.3 I2P

I2P is the **secondary anonymizing transport**, using garlic routing (bundled encrypted tunnels). I2P provides different anonymity properties from Tor — it is more resistant to some traffic analysis attacks and less resistant to others, making it a useful complement.

**Independent I2P keypair architecture:** Same design as Tor (§5.2):
```
address_i2p_keypair -- I2P root (independent sibling, never used directly)
```

Service-specific I2P keys are derived identically to Tor service keys, with a distinct domain separation string (`"meshinfinity-i2p-service-v1"`).

- Each node generates I2P destinations from its I2P keypair hierarchy
- I2P destinations are included in the network map `transport_hints`
- Outbound connections use I2P's SAM (Simple Anonymous Messaging) API
- Inbound connections arrive at the node's I2P destination

I2P is slower to establish than Tor (tunnel building takes longer) but may be more resilient in environments where Tor is actively blocked.

**Emissary maturity caveat:** As of early 2026, emissary (the Rust I2P client) is explicitly early-stage. SSU2 (primary I2P transport) is described by the developer as "very experimental, only tested locally." I2P support is best-effort until emissary reaches production stability. No external binary fallback is acceptable (impossible on iOS, restricted on Android, supply chain risk everywhere).

### 5.4 Clearnet

Clearnet is direct IP connectivity — TCP or UDP to a known IP address. It carries no transport-level anonymization, but like all transports, it carries WireGuard-encrypted traffic and application-layer encryption.

**Clearnet is a first-class transport** with clearly documented threat properties. In many real-world deployments, clearnet will be the primary transport. The previous characterization of clearnet as "disabled by default" is replaced with a nuanced per-connection policy model.

**"Single hop only" clarified:** This is a routing policy, not a transport restriction. The routing layer must never construct a path where a clearnet segment directly connects origin to destination without intermediate hops.

**Per-connection clearnet policy:** User-configurable:
- Minimum intermediate hop count (default: 1)
- Notification preference for clearnet segment use
- Trust-level defaults for clearnet routing eligibility

**Clearnet public addresses:** A node with clearnet enabled gets its own distinct public address(es) for its clearnet-accessible endpoint(s). This address is separate from the node's Tor or I2P addresses. Because the clearnet address is just another mesh address from the routing layer's perspective, even a direct clearnet hop between two nodes that happen to be the origin and destination of a conversation does not expose that relationship — the routing tables operate on mesh addresses, and the clearnet IP is a transport detail below that layer.

- When enabled, the node's clearnet endpoint (IP:port) and its associated mesh address are added to its network map entry's transport hints.
- Suitable for high-bandwidth local-network scenarios (home server, LAN file transfer, voice/video calls) where anonymization is secondary to performance.
- Priority in transport selection: lowest for security-sensitive connections; elevated for latency-sensitive or bandwidth-intensive connections (voice, video, large file transfers) when the user has opted in.

**Transport Diversity Obligation:** Mesh Infinity nodes maintain transport diversity as a network obligation, independent of per-connection user policy:
1. **Multi-transport maintenance:** nodes maintain active connections over multiple available transports simultaneously
2. **Cover traffic contribution:** some traffic is routed over anonymizing transports even when clearnet would suffice
3. **Relay participation:** nodes relay other nodes' traffic to contribute to the network anonymity set
4. **Pattern avoidance:** transport usage must not correlate with communication events

### 5.5 Bluetooth

Bluetooth enables **offline local mesh formation** without any internet connection. This is critical for scenarios where all internet connectivity is blocked or unavailable.

**Three distinct Bluetooth modes:**
1. **Passive traffic (BLE)** — always available: discovery, presence, key exchange
2. **Key exchanges (BLE)** — always available: pairing flow, key material exchange
3. **Node traffic (Classic BT / BT5)** — explicitly opt-in: mesh routing, file transfer, PTT

#### Advertisement Model — Steganographic, Non-Identifying

No Mesh Service UUID in advertisements — a fixed service UUID is a deanonymization vector. Instead, a 64-bit rotating token is encoded steganographically within a plausible standard advertisement format.

Token chain:
```
token_n+1 = HMAC-SHA256(token_secret, token_n || timestamp_bucket)[0..8]
```

Token rotation period: several hours. Proximity map entries valid for 30 days.

**Likelihood calculation before connection attempts:** Before attempting a connection to an observed BLE device, the node evaluates: token mathematical properties, advertisement timing, network map cross-reference, and behavior patterns. Only high-confidence matches result in connection attempts.

**Untrusted relay model:** Bluetooth connections in the wild are untrusted relay connections, analogous to Tor relay participation. No identity exchange, no peer ID disclosure.

**Bluetooth proximity map:** Separate from the trusted network map. Contains: token patterns, observed capabilities, approximate last-seen timing. No identity information. Shareable with any Mesh Infinity node. Entries expire after 30 days.

#### Capability Profile

```
BLE: push_to_talk=true, full_duplex_call=false, file_transfer=true, video=false
BT5 high throughput (opt-in): push_to_talk=true, full_duplex_call=true, file_transfer=true, video=maybe
```

#### Data Exchange

- A custom GATT profile is used for data exchange once a connection is established
- BLE connections are short-range (~10m) and low-bandwidth; they are best suited for discovery and short messages
- WireGuard tunnels run over BLE connections for link encryption and peer authentication
- MTU negotiation is performed at connection time; large messages are fragmented

**Honest tracking risk:** Obfuscation reduces casual surveillance risk but does not eliminate targeted tracking. Users in high-surveillance environments should disable Bluetooth entirely.

The BLE transport enables device-to-device meshing without any infrastructure, making it suitable for local groups, events, or disaster scenarios.

### 5.6 RF Transport (Plugin Category)

RF (radio frequency) transport is a **plugin category**, not a single transport. The software makes no attempt to enforce radio regulations — legal compliance is the user's responsibility. In environments where rule of law has broken down, regulatory compliance is not a meaningful constraint.

**Two-tier RF model:**

**Tier 1 — Device-native (no additional hardware):**
- WiFi Direct — built-in, ~250 Mbps, ~200m range, peer-to-peer, no infrastructure (see §5.7)

**Tier 2 — Infrastructure-extended (dedicated hardware required):**
- LoRa (Meshtastic-compatible hardware as default)
- Zigbee (USB coordinator dongle)
- APRS/AX.25 (radio + TNC or SDR) — community plugin (license required)
- GMRS/FRS digital modes (radio hardware)
- Generic serial RF interface

Tier 2 transports are for infrastructure nodes — server-mode nodes with attached radio hardware. They bridge between IP mesh and RF mesh segments.

**RF transport plugin interface:**
```rust
RFTransportCapabilities {
    transport_id:        String,
    bandwidth_bps_min:   u32,
    bandwidth_bps_max:   u32,
    range_m_typical:     u32,
    topology:            RFTopology,  // PointToPoint | Broadcast | Mesh
    hardware_required:   HardwareRequirement,
    license_note:        Option<String>,  // informational only, never enforced
    infrastructure_only: bool,
}
```

Due to the extreme bandwidth constraints of most RF transports, large messages (media, files) cannot be sent over these transports. The system automatically selects transports based on message size and transport capabilities.

Mesh Infinity uses RF hardware as a transport backend; it does not replicate the routing of RF-native protocols (e.g., Meshtastic's own routing) — Mesh Infinity's routing layer runs on top.

Future work: point-to-point RF (directional antennas), one-way RF dead drop.

### 5.7 WiFi Direct

WiFi Direct is peer-to-peer WiFi without infrastructure — closer to clearnet than RF in protocol model.

**Capability profile:** BandwidthClass::High (~250 Mbps), ~200m range, no infrastructure, no license, AnonymizationLevel::None.

**Security model:** WireGuard handles authentication. WiFi Direct is a dumb byte pipe — WPS-style pairing is bypassed entirely.

**Platform implementation:**
- Android: full WiFi Direct API available, group owner role = higher peer ID
- iOS: MultipeerConnectivity only (best-effort, may fall back to BLE) — documented as platform limitation
- Linux: wpa_supplicant P2P mode
- Windows: WiFi Direct API (less mature than Android)

**Routing:** Single-hop constraint applies (same as clearnet). LoSec direct mode rules apply if attempting direct connection.

**BLE + WiFi Direct complementary pattern:** BLE for discovery and key exchange, WiFi Direct for high-bandwidth data transfer.

### 5.8 NFC

NFC is the highest-security local discovery and pairing mechanism — physical touch required.

Properties:
- ~5cm range — the proximity requirement IS the security model
- Observable as an NFC event but not the content
- Usable for: pairing initiation, key exchange, one-time tokens
- Platform support: Android (full), iOS (limited, NFC reader available since iPhone 7), Linux (libnfc)

NFC is primarily a pairing transport (see §8.2) and is the highest-security in-person pairing option — harder to observe than QR, shorter range than Bluetooth.

### 5.9 Transport Selection — Constraint Solver

Transport selection is a constraint-solving problem, not a priority list.

**Solver architecture — four layers:**
1. **Hard constraint elimination** — bandwidth, latency, anonymization floor, clearnet policy, hardware availability
2. **Soft scoring** — TransportScore: anonymization, reliability, latency, bandwidth, battery_cost, diversity_contribution
3. **Multi-transport composition** — Single | Parallel redundant | Split payload M-of-N
4. **Network diversity enforcement**

**Application layer hint interface:**
```rust
TransportHint {
    min_bandwidth_bps:       Option<u32>,
    max_latency_ms:          Option<u32>,
    min_anonymization:       Option<AnonymizationLevel>,
    redundancy_preference:   Option<RedundancyPolicy>,
    priority:                Priority,
    stream:                  bool,
}
```

**User threat context (global, not per-connection):**
```rust
ThreatContext { level: ThreatLevel }  // Normal | Elevated | Critical
```

**Failure handling:**
```rust
SolverFailure {
    reason:                  FailureReason,
    relaxable_constraints:   Vec<Constraint>,
    queue_eligible:          bool,
    estimated_retry_ms:      Option<u32>,
}
```

Store-and-forward is a solver failure handling path, not a separate system.

Per-peer transport preferences override global scoring. A peer can specify in their network map which transports they prefer for inbound connections.

For **large payloads** (file transfers, voice/video streams), the system additionally considers:
- Available bandwidth (RF is excluded for payloads above a configurable size threshold)
- Connection latency (important for voice/video)
- Connection stability (BLE is not suitable for large sustained transfers)

### 5.10 Transport Health Monitoring

The TransportManager continuously monitors the health of active connections via an internal event interface:

```rust
TransportHealthEvent {
    transport_id:           TransportId,
    peer_id:                [u8; 32],
    event:                  HealthEvent,
    measured_latency_ms:    Option<u32>,
    measured_bandwidth:     Option<BandwidthClass>,
    timestamp:              u64,
}
```

The transport solver subscribes to these events; they are not directly exposed to the UI.

**Latency baseline model:** Global per-node exponential moving average (alpha ~ 0.05). Baseline update is suspended during a detected latency spike — the spike triggers rotation, baseline resumes on the new circuit.

**Bandwidth estimation:** Precise measurement is replaced with a three-class passive system:
```rust
BandwidthClass { Low, Medium, High }
// Default by transport: RF=Low, BLE=Medium, clearnet/WiFi Direct=High
// Refined by passive observation of actual transfers
// No active probing -- eliminates regular-interval fingerprint
```

- **Keepalive probes** sent on idle connections at a configurable interval (default: 25s, matching WireGuard's persistent keepalive recommendation)
- **Dead connection detection**: connections with no response within a timeout are marked dead and the peer is attempted via the next available transport
- Transport health metrics are exposed via the FFI for UI display

---

## 6. Routing

### 6.1 Hop-by-Hop Routing (Default)

Mesh Infinity uses **discovery-driven, hop-by-hop routing** by default. This model has strong privacy properties: no single node knows the full path a message takes.

**Position-hiding privacy property:** In hop-by-hop routing, no intermediate node knows its position in the routing path. A node that receives from peer A and forwards to peer B knows only those two facts. An adversary who compromises any single intermediate node learns only: "A and B were adjacent in a routing path at this time." This is fundamentally stronger than circuit routing, where intermediate nodes know their position from the encoded path header.

Routing decisions at each node:
1. Check the local routing table for the destination address
2. If a direct connection to the destination exists, deliver directly
3. Otherwise, forward to the neighbour with the best `(hop_count, latency, next_hop_trust)` score toward the destination
4. The next node repeats the process

```
Node A --> Node B --> Node C --> Node D (destination)

At A: "my routing table says B has the lowest-cost path to D"
At B: "my routing table says C has the lowest-cost path to D"
At C: "my routing table says D is directly connected to me"
```

No node except A knows the full path A->B->C->D. B knows only that it received a packet from A destined for D and forwarded it to C. C knows only that it received from B and delivered to D.

**Routing layer vs transport solver separation:** The routing layer selects which mesh nodes are on the path. The transport solver (§5.9) selects how each hop is carried. These are entirely separate decisions.

### 6.2 Reachability Announcements

Nodes share routing information with their direct neighbours via **reachability announcements**:

```
ReachabilityAnnouncement {
    destination:      DeviceAddress,   // Who can be reached via this path
    hop_count:        u8,              // Number of hops (this node adds 1 before forwarding)
    latency_ms:       u32,             // Cumulative estimated latency
    next_hop_trust:   TrustLevel,      // Local node's trust in its immediate next hop (hop-by-hop only)
    announcement_id:  [u8; 16],        // Random ID for deduplication
    timestamp:        u64,             // When this announcement was generated
    scope:            AnnouncementScope,  // Public | Group(group_id) | Private
}
```

**Address scope field on announcements:**
```rust
AnnouncementScope {
    Public,                    // gossip freely to all nodes
    Group(group_id: [u8; 16]), // gossip only within this group's trusted channel
    Private,                   // never gossip -- local routing table only
}
```

**Owner-only origination rule:** Only the address owner may originate a `ReachabilityAnnouncement`. Intermediate nodes forward and re-sign but never originate.

Announcements are signed by the originating node and re-signed at each forwarding hop (outer signature only). Nodes that receive an announcement:
1. Check `announcement_id` for deduplication — if already seen, discard
2. Add 1 to `hop_count` and update `latency_ms` based on observed link latency
3. Update the local routing table if this is a better path than the existing entry
4. Forward the announcement to direct neighbours (respecting scope — Group-scoped announcements are forwarded only within the group's trusted channel; Private announcements are never forwarded)

**Group-scoped routing table:**
```rust
RoutingTable {
    public:        HashMap<DeviceAddress, RoutingEntry>,
    groups:        HashMap<GroupId, HashMap<DeviceAddress, RoutingEntry>>,
    local:         HashMap<DeviceAddress, RoutingEntry>,
    ble_ephemeral: HashMap<BleToken, EphemeralRoutingEntry>,
}
```

**Bluetooth proximity map** operates separately from reachability announcements. Untrusted BLE relay nodes get ephemeral routing entries, not reachability announcements.

### 6.3 Trust-Weighted Path Selection

When multiple paths exist to a destination, paths are scored by:

```
let effective_hop_count = hop_count.max(1);
let effective_latency_ms = latency_ms.max(1);
let score = (1.0 / effective_hop_count as f32)
    * trust_weight(next_hop_trust)   // ONLY local node's trust in its next hop
    * (1.0 / effective_latency_ms as f32);
```

The `.max(1)` guards prevent division-by-zero when `hop_count` or `latency_ms` is zero.

**Trust weights — exponential defaults, 8 levels, user-configurable:**
```
Level 0 (Unknown):       0.05
Level 1 (Public):        0.10
Level 2 (Vouched):       0.20
Level 3 (Referenced):    0.35
Level 4 (Ally):          0.55
Level 5 (Trusted):       0.75
Level 6 (CloseTrusted):  1.00
Level 7 (HighlyTrusted): 1.30
Level 8 (InnerCircle):   1.60
```

The ceiling is intentionally modest — trust is a tiebreaker, not a dominant factor. A path with high trust and moderate latency is preferred over a lower-latency path through untrusted nodes. This prevents an adversary from inserting high-performance relay nodes to attract traffic.

**`next_hop_trust` replaces `path_trust`:** In hop-by-hop routing, a node knows only itself and the next hop. The concept of `path_trust` as a path-wide minimum does not exist in this context. The scoring function uses `next_hop_trust` — the local node's trust in its immediate next hop. The `path_trust` concept is reserved for circuit-routing modes (§6.6) where the full path is known.

### 6.4 Two-Plane Routing Model

Routing operates on two distinct planes:

**Public routing plane:** Uses network map reachability announcements. Address-based, no ownership revealed. Anyone can route here. Handles delivery until the packet reaches a node with private routing knowledge.

**Private routing plane:** Uses trusted-channel routing information only. Completely invisible to the public routing plane. Handles final delivery.

**Critical principle — no over-advertisement:** The sender knows only the destination address. No static mapping of private addresses to public gateways is ever advertised. The handoff point is determined dynamically.

**Dynamic private routing discovery:** When a packet reaches a node that does not know the destination, that node queries its trusted peers in real time. The query is contained, ephemeral, and recursive.

**Mesh Infinity NAT types:**
- **Wrapper nodes** — node sits in front of another node; inner node is unreachable from public plane
- **Port forwarders** — receive on address:X, forward to internal address:Y
- **Address translation** — receive traffic for address X, deliver to address Y internally

**Security property:** An adversary monitoring the public plane cannot determine whether an endpoint is the final destination or a gateway, what private routing happens after handoff, or any relationship between public and private addresses.

### 6.5 Persistent Tunnels and Cover Traffic

**Persistent tunnel model:** Every directly connected peer maintains 1-3 open WireGuard tunnels at all times. These carry real traffic, cover traffic, and topology gossip — indistinguishably mixed.

**Nested WireGuard architecture:**
```
Outer tunnel: WireGuard between directly connected peers
    -- always present, always carrying traffic
    -- carries real traffic, cover traffic, gossip -- indistinguishable

Inner tunnel: WireGuard end-to-end to destination
    -- established when needed
    -- travels through outer tunnels hop-by-hop
    -- nobody except endpoints knows it exists
    -- not a declared circuit -- no fixed path
```

The goal is data poisoning, not invisibility. Make observable traffic always present, indistinguishable, and overwhelming in volume.

**Routing poisoning mitigation:** A malicious node that blackholes inner tunnel traffic must also disrupt its outer tunnel — affecting ALL traffic, making selective blackholing detectable.

**Every node as directory:** Nodes differ in degree of participation, not kind. Routing claims are weighted by trust level combined with routing track record.

**Packet deduplication (replaces TTL):** 256-bit packet IDs:
- Routing deduplication: 1-hour window per node, bounded LRU cache
- Message deduplication: permanent per conversation

Delivery confirmation: signed `DeliveryReceipt { packet_id, recipient, timestamp, signature }`.

### 6.6 Loop Prevention

Routing loops are prevented by:
- Packet ID deduplication — nodes never forward a packet they have already forwarded (1-hour deduplication window, bounded LRU cache)
- The `hop_count` field in reachability announcements — loops would cause `hop_count` to exceed the known diameter of the network, at which point announcements are discarded
- The `announcement_id` deduplication field — nodes never forward an announcement they have already forwarded

### 6.7 Fast Routing Mode (Opt-in, Reduced Privacy)

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

**Ambient traffic threshold requirement:** Fast routing and LoSec (§6.9) rely on ambient mesh traffic for cover. They are only available when ambient traffic is sufficient to make a shorter path statistically indistinguishable. The transport solver continuously monitors active outer tunnel count, traffic volume, and traffic variance. Below threshold, fast routing and LoSec are absent from the UI — not disabled, absent. The threshold is an implementation constant not reducible by the user.

### 6.8 Store-and-Forward

When the destination is unreachable, store-and-forward provides a general protocol for deferred delivery:

**Server mode clarification:** Server mode is a declaration of availability and functionality, not a security mechanism.

```rust
StoreAndForwardRequest {
    destination:       DeviceAddress,
    payload:           Vec<u8>,
    expiry:            u64,
    expiry_sig:        [u8; 64],
    priority:          Priority,
    release_condition: ReleaseCondition,
    application_id:    Option<[u8; 16]>,
}

ReleaseCondition {
    Immediate,
    NotBefore(timestamp: u64),
    CancellationBased {
        cancellation_window_secs: u32,
        last_cancellation: u64,
    },
}
```

The message envelope includes a **signed expiry timestamp** set by the original sender: `expiry = send_time + ttl`, signed by the sender's Ed25519 key. The server node cannot extend this expiry without breaking the signature. Recipients reject messages whose signed expiry timestamp has passed — even if the server delivers them late.

Messages have a configurable sender-side TTL (default: 7 days). The signed expiry is authoritative; server-side TTL enforcement is a courtesy only.

**Metadata honestly documented:** A store-and-forward node knows: destination address, payload size, send time, expiry time, priority, application ID. This cannot be eliminated. Mitigation: use only trusted nodes. This is a social trust guarantee, not a protocol-level privacy guarantee.

**CancellationBased release condition:** Enables dead man's switch functionality. A sender pre-signs a message, distributes it to store-and-forward nodes, and periodically sends signed cancellation signals. If the cancellation stops arriving within the `cancellation_window_secs`, the message is released. Full cancellation protocol design is deferred (see Deferred Questions).

The store-and-forward mechanism operates above the routing layer. The hop-by-hop router handles live delivery; store-and-forward is invoked only when live delivery fails and a capable server node is reachable.

### 6.9 LoSec Mode (Low-Security, High-Bandwidth Transport)

**Three distinct connection modes:**

**Mode 1 — Standard mesh (default):** Full inner tunnel, multi-hop, maximum anonymity, outer cover traffic always present.

**Mode 2 — LoSec (Low-Security mesh):** Still uses mesh routing layer. Still 1-2 relay nodes. Shorter path = lower latency, higher bandwidth. Relies on ambient mesh traffic for cover. Amber indicator: *"LoSec mode active -- fine for everyday use, not recommended for sensitive communications."*

**Mode 3 — Direct (peer-to-peer, no mesh layer):** Bypasses mesh routing entirely. Your network location is directly visible. Full-screen terror warning. Persistent red banner.

#### Security properties

| Property | Standard mesh path | LoSec (1-2 hops) | LoSec (direct) |
|---|---|---|---|
| Confidentiality | 4-layer onion | WireGuard | WireGuard |
| Authentication | Yes | Yes | Yes |
| Forward secrecy | Yes | Yes | Yes |
| Sender anonymity | Strong | Weak | None |
| Traffic analysis resistance | Strong | Weak | None |
| Relationship hiding | Strong | Weak | None |
| Bandwidth | Low | High | Maximum |
| Latency | High | Low | Minimum |

LoSec connections are protected by WireGuard only: authenticated encryption, forward secrecy, and replay protection. The onion layers of §7.1 are not applied. Intermediate relay nodes cannot read content, but can observe that two identities are communicating and approximately how much data is exchanged.

**Users must be informed of this tradeoff before and during any LoSec connection.** See UI requirements below.

#### LoSec hardening measures (all five, no trust level restriction)

1. Relay node rotation per session or on configurable timer
2. Traffic shaping to fixed bandwidth tiers (aligned with §15.4 padding buckets)
3. Mandatory cover traffic injection while LoSec session is active
4. Time-bounded sessions with automatic re-establishment
5. Ambient threshold enforcement (§6.7)

**Service normalization principle:** Normal services (gaming, streaming, file sharing) should default to LoSec. Every normal LoSec session is cover for sensitive LoSec sessions. "Use LoSec for everything non-sensitive" is the mesh equivalent of "use Tor for everything."

#### Direct mode — TLS bridge node extension

```
WireGuard tunnel -> TLS wrapper -> TCP (looks like HTTPS to observer)
```

A bridge node accepts TLS-wrapped direct connections. This makes mesh connections look like ordinary HTTPS traffic. Useful for censorship circumvention. Advertised through trusted channels only.

#### Hop counts

- **1-2 hop mode** (standard LoSec): traffic passes through one or two relay nodes selected from the local peer graph. This is the default LoSec path. Hops are selected from trusted peers where available; the hop count is fixed (not "up to N") so latency is predictable.
- **Direct mode** (0 hops): traffic goes peer-to-peer with no relay. This is the most privacy-compromising option and is subject to strict availability requirements (see below).

#### Direct mode availability requirements

Direct mode is only offered when **both** of the following conditions are met:

1. **The remote peer is directly trusted** (WoT depth 1 — a peer the local user has explicitly paired with). Optionally, the user may enable "trust friends-of-friends" in settings (WoT depth 2), which extends direct mode eligibility to peers trusted by directly trusted peers. No further extension is permitted; beyond depth 2, the standard LoSec relay path is used.
2. **The local connection graph is sufficiently noisy** — a configurable threshold of active mesh peers and concurrent traffic flows must be exceeded so that a direct link does not stand out as an anomaly. The exact threshold is an implementation constant subject to tuning; it must not be user-reducible below the compiled default.

When direct mode would be used but condition 2 is not met, the UI does not offer the option at all. It is not shown as disabled — it is simply absent.

When direct mode is available and the user selects it, a **full-screen modal** is displayed before the connection is established:

> **WARNING: DIRECT CONNECTION -- SEVERE PRIVACY RISK**
>
> A direct connection exposes your network location to the remote peer and to any observer on your network path. There is no relay, no anonymization, and no protection against traffic analysis. Your IP address will be visible to the other party.
>
> This mode should only be used when both parties are fully trusted and network privacy is not a concern (e.g., a local home network with no threat model).
>
> **[I understand the risks -- connect directly]**   **[Cancel]**

The checkbox must be actively clicked; the confirm button is disabled until it is. During the connection, a **persistent red banner** is displayed: "Direct connection -- no anonymization."

For 1-2 hop LoSec (not direct), a **persistent amber indicator** is displayed during the connection: "Low-security mode active -- your network location may be visible to relay nodes."

#### Negotiation for peer-to-peer connections

For any connection involving two peers (calls, tunnels, transfers), LoSec requires **three conditions** to all be true before it activates:

1. **The service or context has the relevant host-side toggle enabled** (`allow_losec` or `allow_direct` in `ServiceLoSecConfig`, §12.4). For the built-in chat application, the local node acts as its own service host; users control this toggle in settings. If the host-side toggle is off, the mode is unavailable regardless of what the other party wants — the UI does not offer it.

2. **The initiator explicitly requests it.** The initiator sends `LoSecRequest { session_id, mode: LoSecOrDirect, hop_count, reason }` to the remote peer over the standard full-security mesh channel. The initiator must have affirmatively chosen the mode; it is never selected automatically.

3. **The remote peer explicitly accepts it.** The remote peer's node checks its local policy:
   - **Deny** (default): the request is silently auto-declined — `LoSecResponse { accepted: false }`. No UI prompt is shown to the remote user.
   - **Prompt**: the remote user is shown a notification explaining the request, with Accept / Deny options.
   - **Allow**: the request is auto-accepted.

Only when all three conditions are satisfied does the LoSec path activate. If the request is declined at any stage, the connection proceeds over the standard mesh path (or fails if the initiator explicitly requires LoSec and the caller chooses not to fall back).

The default peer policy is **deny** for both LoSec and direct. Users enable prompting or auto-allow in settings under "Allow incoming LoSec / Direct connection requests." These are two separate toggles. The chat application's toggles are independent of hosted service toggles.

`LoSecRequest` messages are always delivered over the full-security mesh channel — the negotiation itself produces no observable metadata outside the existing trusted session.

#### Service host permissions

Services registered in §12.4 include two independent host-side toggles that must each be **explicitly enabled** by the service operator before clients may use the corresponding mode:

```
ServiceLoSecConfig {
    allow_losec:   bool,   // Permit clients to request 1-2 hop LoSec routing (default: false)
    allow_direct:  bool,   // Permit clients to request 0-hop direct routing (default: false)
}
```

Both default to `false`. A service operator must consciously set `allow_losec = true` before any client can negotiate LoSec for that service, and separately set `allow_direct = true` before any client can negotiate a direct connection. `allow_direct = true` without `allow_losec = true` is valid (direct only, no relay-reduced path).

Even with host-side toggles enabled, the connection is not established in LoSec or direct mode unless the **client also explicitly requests it** and the **remote peer's policy accepts it**. The host enabling the mode is a necessary but not sufficient condition — mutual consent is always required.

#### Relay node behaviour

Nodes acting as LoSec relay hops do **not** need to explicitly opt in. Relaying is a standard part of mesh participation. However, the following protections apply by default:

- **Relay bandwidth budget**: each node enforces a configurable cap on total bandwidth consumed by forwarding LoSec streams (default: 2 Mbps aggregate). When the budget is exhausted, new LoSec relay requests are declined; in-progress relays are not interrupted.
- **Metered connection detection**: before accepting a LoSec relay request, the node queries the OS network API to determine if the active connection is metered (mobile data, capped ISP plan, etc.). On a metered connection, relay requests are declined by default. Users may override this in settings ("Allow LoSec relaying on metered connections").
- **No content visibility**: relay nodes forward encrypted WireGuard packets and have no access to stream content. They observe only: source peer ID, destination peer ID, approximate throughput, and session duration.

---

## 7. Message Encryption Scheme

### 7.0 Inner Session Key Establishment — X3DH + Double Ratchet

The 4-layer scheme (§7.1) uses a per-peer **session key** for Step 2 (trusted-channel encryption). This session key is not static — it is established via **X3DH** on first contact and advanced with every message via the **Double Ratchet**. This gives the chat layer the same cryptographic properties as Signal: authenticated key agreement, per-message forward secrecy, and break-in recovery.

#### Pre-Key Material — Preauth Key Model

Each node maintains and publishes a **preauth key** — a single X25519 keypair per identity/address used purely for encryption/key agreement:

- **Cannot be used for signing** — no signing capability, like a TLS public key
- **No identity attached** — just an encryption endpoint
- **Single key, not a pool** — no consumption metadata to leak (unlike the Signal OPK model where pool depletion is itself a signal)

**Multiple acquisition paths with different trust weights:**

| Path | Trust signal |
|------|--------------|
| From network map | Minimum — stranger contact |
| From trusted mutual friend | Higher — WoT-mediated introduction |
| Exchanged during in-person pairing | Maximum — direct verification |

**Rotation model — arbitrary and aperiodic:**
- No schedule, no timer, no predictable trigger
- **Manual rotation is a first-class, low-friction UI action** — accessible from the profile screen, no warning or confirmation dialog
- "I'm bored, rotating my key for funsies" is valid and encouraged — arbitrary rotation events carry zero information

For X3DH session initiation, the preauth key serves the role of the signed prekey (SPK). The traditional Signal OPK (one-time prekey) pool is not used — the single preauth key model avoids the metadata leakage inherent in pool depletion tracking.

#### X3DH Session Initiation (first message to a peer)

Alice fetches Bob's preauth key (and verifies it if available via a trusted path), then:

```
EK_A = generate_x25519_keypair()          // ephemeral key, discarded after

DH1 = X25519(IK_A_secret,  preauth_B_pub)
DH2 = X25519(EK_A_secret,  IK_B_pub)
DH3 = X25519(EK_A_secret,  preauth_B_pub)

master_secret = HKDF-SHA256(
    salt = 0x00 * 32,
    ikm  = 0xFF * 32 || DH1 || DH2 || DH3,
    info = "MeshInfinity_X3DH_v1",
    len  = 32
)
```

Alice then initialises the Double Ratchet as sender (`master_secret`, `preauth_B_pub` as initial ratchet pub). The first message includes an `X3dhInitHeader { ik_pub, eph_pub }` so Bob can reproduce the same `master_secret` and initialise the ratchet as receiver.

#### Double Ratchet

After X3DH the session key advances with every message:

```
// KDF chain (symmetric ratchet -- advances per message)
msg_key       = HMAC-SHA256(chain_key, 0x01)
new_chain_key = HMAC-SHA256(chain_key, 0x02)

// Root key ratchet (DH step -- triggered by each new DH ratchet public key received)
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

**Scope clarification:** The four-layer scheme is for discrete blob payloads. Stream encryption is handled by the WireGuard inner tunnel (§6.5) with counter nonces. These are entirely separate concerns.

**Wrapper node relationship:** The four-layer scheme operates inside any wrapper node envelope(s) (§4.4). Wrapper node routing is part of the routing layer; the four-layer scheme is between sender and recipient only.

```
Input: plaintext message

Step 1 -- Inner authentication:
  For trusted-channel messages:
    mac = HMAC-SHA256(ratchet_msg_key, plaintext)  <-- deniable; both parties can produce
    authenticated = plaintext || mac
  For untrusted messages:
    sig = Ed25519_Sign(sender_privkey, plaintext)
    authenticated = plaintext || sig

Step 2 -- Trust-channel encryption (trusted peers only):
  If mutual_trust:
    // session_key is the cipher_key derived from the Double Ratchet msg_key (§7.0)
    // nonce is the 12-byte nonce derived from the same msg_key expansion
    trust_encrypted = ChaCha20Poly1305_Encrypt(session_key, nonce, authenticated)
    payload = dr_header || trust_encrypted   // dr_header carries ratchet_pub, prev_n, msg_n
  Else:
    payload = authenticated

Step 3 -- Outer signing (sender identity verification):
  outer_sig = Ed25519_Sign(sender_privkey, payload)
  double_signed = payload || outer_sig

Step 4 -- Recipient encryption:
  ephemeral_keypair = generate_x25519_keypair()
  shared = X25519(ephemeral_secret, recipient_x25519_public)
  message_key = HKDF-SHA256(shared, salt=ephemeral_public, info="meshinfinity-message-v1")
  nonce = random_12_bytes()
  final = ephemeral_public || nonce || ChaCha20Poly1305_Encrypt(message_key, nonce, double_signed)
```

**Correct decryption flow (outside-in):**

**Step 4 -- Recipient decryption:** Only the recipient can decrypt. Relay nodes see an opaque blob. This is the fundamental privacy guarantee.

**Step 3 -- Sender identity verification (RECIPIENT-SIDE trust check):** After Step 4 unwrapping, the recipient verifies the Ed25519 signature against their trust list. This is NOT for relay node authentication — it is a recipient-side trust check. A mismatched key signals tampering.

**Step 2 -- Trust-channel decryption:** Double Ratchet decryption. Only succeeds if both parties have correct ratchet state.

**Step 1 -- Content integrity verification:** HMAC verification. A mismatch here means the plaintext was tampered with after outer layers were intact. This is a critical security event — notify the trusted peer immediately.

**Relay node authentication:** Entirely at the WireGuard tunnel layer. The four-layer scheme is purely between sender and recipient. Relay nodes are not participants in the four-layer scheme.

### 7.2 Security Properties

| Property | Mechanism |
|----------|-----------|
| Sender authenticity (to recipient) | Inner HMAC with ratchet key (Step 1) — deniable; both parties can produce |
| Authenticated key agreement | X3DH (§7.0): both IK keys contribute; preauth key verified before first message |
| Per-message forward secrecy | Double Ratchet KDF chain: each message advances the chain; old keys deleted |
| Break-in recovery | DH ratchet step on every inbound ratchet key; future messages use fresh DH material |
| Trust channel privacy | Step 2 Double Ratchet encryption hides content from relay nodes |
| Sender identity verification | Outer Ed25519 signature (Step 3) — recipient verifies sender identity post-decryption |
| Sender privacy from routing nodes | Step 4 encryption: relay nodes see only the encrypted blob and outer sig |
| Recipient privacy | Only the holder of `recipient_x25519_secret` can decrypt Step 4 |
| Out-of-order delivery | Skipped message key cache, bounded at 1,000 entries per peer |

### 7.3 Session Keys for Ongoing Connections

For ongoing connections (file transfers, voice/video streams), establishing the full 4-layer scheme per packet would be prohibitively expensive. The 4-step scheme is used for the **session handshake**, which derives a session key.

**Scope:** This applies to any situation where a direct tunnel cannot be established: store-and-forward delivery, proxy/relay delivery, deferred delivery, or any application needing its own cryptographic session independent of routing infrastructure. The session proposal is a blob payload encrypted via the four-layer scheme. It travels through store-and-forward, proxies, and arbitrary hops. A session is established purely through message exchange — no direct connection required.

**Distinct from WireGuard inner tunnel:** The WireGuard inner tunnel (§6.5) uses infrastructure mesh keys. Applications may need their own session keys with independent key material.

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

- **Per-message forward secrecy**: every message uses a unique `msg_key` derived by advancing the KDF chain; the chain key from step N cannot recover step N-1
- **Break-in recovery**: the DH ratchet step, triggered on each inbound ratchet key change, mixes fresh Diffie-Hellman output into the root key; an adversary who captured a chain key cannot predict future chain keys after the next DH step
- **No re-handshake required**: the ratchet is self-healing; a missed DH ratchet step is caught up automatically on the next received message carrying a new ratchet public key

For streaming sessions (§7.3), rekeying is counter- and time-bounded as specified above.

### 7.5 Reconnect and Sync

When a peer reconnects after being offline, the following mitigation layers prevent the reconnect event from being observable:

**Layer 1 — Push-based delivery:** Store-and-forward nodes push through established outer tunnels. The client does not query. Zero timing signal. Polling can be disabled entirely if push is available.

**Layer 2 — Continuous background polling:** Nodes poll at continuous random intervals regardless of whether messages are expected. A reconnect event produces no detectable spike.

**Layer 3 — Tunnel warmup before polling:** On reconnect, establish outer tunnel traffic first. The query is buried in already-flowing traffic.

**Layer 4 — Gossip-piggybacked queries:** Store-and-forward queries ride alongside regular topology gossip exchanges. Indistinguishable from normal gossip. Scoping happens automatically:
- General mesh gossip queries general store-and-forward nodes
- Group channel gossip queries group-scoped nodes
- LAN channel gossip queries LAN-scoped nodes

**Sync process:**
1. A re-handshake is performed to establish a fresh session key
2. The reconnecting peer sends a **sync request** with the timestamp of its last received message
3. The remote peer (or a store-and-forward server holding messages for it) sends any messages with timestamps after the sync point
4. Message ordering within a conversation is by timestamp; ties are broken by message ID (random 128-bit value assigned at send time)

**Deduplication:** Messages arriving from multiple sources are deduplicated by message ID (permanent per conversation). First delivery wins.

## 8. Peer Pairing and Trust

### 8.1 Trust Levels

Mesh Infinity uses an **8-level trust model** divided into two tiers. The lower tier (Levels 0–4) is "untrusted" — no private channel, no identity disclosure required. The upper tier (Levels 5–8) is "trusted" — a private channel is established, private profile is shared, and the peer has access to capabilities gated on trust.

**Effective access level** between any two peers is always **min(alice_trusts_bob, bob_trusts_alice)**. Trust levels are bilateral and independent — Alice may trust Bob at Level 7 while Bob trusts Alice at Level 5. Their effective mutual access is Level 5. Private profile exchange only occurs when BOTH parties are at Level 5 or above.

**Untrusted Tier (Levels 0–4):**

| Level | Name | Description |
|-------|------|-------------|
| 0 | `Unknown` | Complete stranger. No endorsement, no prior contact. Routed through for mesh connectivity but no privileged access. |
| 1 | `Public` | Self-introduced via public profile, or initiated contact. Known to exist but unverified. |
| 2 | `Vouched` | Endorsed by a Trusted-tier (Level 5–6) peer. Single endorser required (see §8.5). |
| 3 | `Referenced` | Endorsed by a HighlyTrusted-tier (Level 7) peer. Carries more weight than a Vouched endorsement. |
| 4 | `Ally` | Endorsed by an InnerCircle (Level 8) peer. "Operational ally I don't know personally." This is the most important level to handle correctly — it represents the highest trust achievable without direct personal verification. The attack cost to reach Level 4 requires compromising at least one InnerCircle node. |

**Trusted Tier (Levels 5–8):**

| Level | Name | Description |
|-------|------|-------------|
| 5 | `Trusted` | Entry trusted. Private channel established via X3DH (§7.0), private profile shared via cryptographic escrow (§8.4). Full messaging features enabled. |
| 6 | `CloseTrusted` | Mid trusted. Enhanced capabilities — eligible for wrapper node, store-and-forward duties. |
| 7 | `HighlyTrusted` | Top trusted below InnerCircle. Exit node eligibility, elevated capabilities. |
| 8 | `InnerCircle` | Maximum trust. Required for Friend-Disavowed votes and Compromised declarations. |

Elevating a peer to Level 5 or above requires identity disclosure: the local node shares its private channel address and private profile with the peer. The ACL system (§8.8) exists so that granting *access* to a resource does not require granting *identity*.

**Capability flags (per peer, independent of trust level):**

Certain privileged roles require an explicit capability grant in addition to a minimum trust level. A peer at the required trust level does not automatically receive these capabilities — the user must grant them individually:

| Capability | Minimum trust level required | What it enables |
|-----------|------------------------------|-----------------|
| `can_be_wrapper_node` | Level 5 (`Trusted`) | Allow this peer to be selected as a wrapper/relay for your outbound traffic |
| `can_be_exit_node` | Level 7 (`HighlyTrusted`) | Allow this peer to route your internet traffic (exit node) |
| `can_be_store_forward` | Level 5 (`Trusted`) | Allow this peer to cache your offline messages |
| `can_endorse_peers` | Level 5 (`Trusted`) | Accept WoT endorsements from this peer |
| `can_vote_disavow` | Level 8 (`InnerCircle`) | Allow this peer to cast Friend-Disavowed votes against your identity |

The capability flags are stored locally and are never gossiped. Granting a capability to a peer does not broadcast anything to the network. Default: all capabilities `false`; the user opts in per-peer.

### 8.2 Trust State Machine: Self-Disavowed, Friend-Disavowed, and Compromised

Trust levels (§8.1) represent positive trust. The trust state machine represents *negative* trust — states indicating that a peer's identity may be compromised or operating under adversary control. These states are orthogonal to trust levels and produce **public signed announcements gossiped to the entire network**. They are not private profile data — they are network-wide security signals that attach to network map entries. Even a Level 0 stranger can have negative markers attached.

#### Self-Disavowed

- **Triggered by:** Dead man's switch firing, manual killswitch activation (§3.9), or remote killswitch request from an InnerCircle peer
- **Self-declared** — one device, no peer involvement required
- **Effects:**
  - Automatically ejected from all groups
  - Shared service access revoked
  - LoSec/direct mode revoked
  - All privileged capabilities revoked
  - Inbound communications to explicitly targeted addresses still work — a Self-Disavowed peer can still be reached if someone knows where to send
- **Recoverable** — the Self-Disavowed state can be cleared by the identity owner with a signed reversal, subject to trust re-establishment with each peer
- **Only state from which Compromised can be reached** — this is a critical security property

#### Friend-Disavowed

- **Triggered by:** InnerCircle (Level 8) peers explicitly flagging the device as being in enemy hands
- **Requires actual ground-truth knowledge** — not triggered by silence, absence, or suspicion alone. This is a high-stakes claim that the peer has been seized by an adversary.
- Each node publishes its own `friend_disavow_threshold` — the number of InnerCircle votes required to enter Friend-Disavowed state
- **Threshold change cooldown:** Changes to `friend_disavow_threshold` have a minimum **1-week cooldown** before taking effect. This prevents a captured device from lowering its threshold in the final moments before the adversary gains control.
- Votes are timestamped and tagged with the threshold value known at the time of the vote. The gossip protocol handles eventual consistency — the network can briefly hold inconsistent state regarding whether the threshold has been met. This is an accepted distributed systems property.
- **Revealing affiliation to vote has a cost** — voting exposes the voter's InnerCircle relationship with the target. This is an intentional security mechanism against casual weaponized voting.
- **Recoverable** — Friend-Disavowed can be cleared through direct re-verification between the target and the voting peers

#### Compromised

- Requires **BOTH** Self-Disavowed **AND** Friend-Disavowed
- Self-Disavowed is a **mandatory prerequisite** — this prevents a bulk denial-of-service attack where two captured InnerCircle devices nuke all mutually trusted nodes by casting Friend-Disavowed votes without the target having declared Self-Disavowed first
- **One-way door:** Once Compromised, the identity's keys are permanently untrusted. The identity cannot be re-trusted via normal WoT mechanisms. The user must generate a new identity and re-pair with contacts.
- Only InnerCircle (Level 8) peers can vote toward Compromised

#### State Transition Diagram

```
Normal ──────────► Self-Disavowed ──────────┐
  │                     │                    │
  │                     │  (+ Friend-Disavowed)
  │                     │                    │
  │                     ▼                    │
  ├──────────► Friend-Disavowed ─────────────┤
  │                                          │
  │                                          ▼
  │                                    Compromised
  │                                    (one-way door)
  │
  │  (Self-Disavowed or Friend-Disavowed alone: recoverable)
  │  (Both together: Compromised — permanent)
```

### 8.3 Pairing Methods

Pairing is **identity verification** — not inherently trust assignment. The mandatory core is the Σ-protocol handshake (§3.5), which proves key possession. Trust assignment is an optional component that may happen during pairing, after pairing, or never. A node can exist in a contact record at Level 0 indefinitely.

All pairing methods achieve the same cryptographic result: mutual exchange of public keys, peer IDs, and a Σ-protocol proof of key possession. They differ in the out-of-band channel used to convey the initial key material and in their threat profiles.

**Optional components (negotiated contextually):**

| Component | When appropriate |
|-----------|-----------------|
| Map exchange | Almost always |
| Trust assignment | User decides — may happen now, later, or never |
| Verification passphrase | When future key change verification is anticipated (§4.6) |
| Group introductions | When being added to a group as part of pairing |
| Profile exchange | Only if mutual Level 5+ trust established (§8.4) |
| Capability grants | When pairing a server node |
| Preauth key exchange | Always — part of the contact record |

**Map merge rules during pairing:**
- Trusted entries: merged normally
- Untrusted entries: added to untrusted bucket, subject to LRU eviction cap
- The peer's own entry: always added regardless of trust level

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
  "display_name": "<optional, signed by private key>",
  "transport_hints": [...],
  "expiry": "<unix_timestamp>"
}
```

The `display_name` is signed by the private key — this proves the key holder chose the name and prevents tampering.

**QR expiry presets:**
- **30 seconds (live rotating):** Default for in-person pairing. Eliminates remote interception — the window is too short for relay attacks. QR code regenerates with a fresh `pairing_token` every 30 seconds.
- **5 minutes (quick share):** For rapid in-person exchange where live rotation is inconvenient.
- **1 hour (session):** For event-style pairing where the code is displayed persistently.
- **24 hours (event):** For multi-day events.
- **Permanent (until preauth key rotation):** For persistent display (e.g., a poster, business card). Valid until the underlying preauth key is rotated.

Expiry is encoded in the QR payload AND displayed visually in the UI as a countdown timer. After scanning, both sides perform a Σ-protocol handshake over any available transport to confirm mutual key possession.

**Threat profile:** Live rotating QR (30s) is the highest-security digital pairing method — window too short for remote interception. Longer expiry presets trade security for convenience. QR display is observable within visual range — shoulder-surfing is possible.

#### Pairing Code

A short alphanumeric code (default: 8 characters, Base32) derived from the public key and a random nonce. Suitable for verbal exchange or display in a UI.

The code encodes enough data to look up the peer in the network map and initiate a Σ-protocol handshake. The code expires after 10 minutes or first use. 32^8 ≈ 1 trillion combinations combined with 10-minute expiry makes brute force impractical.

**Threat profile:**
- Verbal in-person: secure — requires physical proximity
- Phone call: moderate risk — treat resulting contact as potentially known to call infrastructure
- Text message: low security — treat as potentially intercepted by carrier infrastructure

#### Link Share

A deep-link URL of the form:
```
meshinfinity://pair?v=1&peer_id=<hex>&ed25519=<hex>&x25519=<hex>&token=<hex>&name=<optional>
```

The link can be shared via SMS, email, any messaging app, or pasted into the app. The same Σ-protocol handshake follows.

**Threat profile:** Link share is **inherently the lowest-security pairing method**. The URL contains peer ID and key material in cleartext. Link interception, forwarding, and platform logging are all real risks. Contacts paired via link share should be assigned trust levels reflecting this. Short expiry is essential — links should die quickly after first use.

#### Key Export / Import

The full public key material exported as a text block (PEM-like format). Suitable for scripted deployment, infrastructure provisioning, and technically proficient users managing server nodes.

**Threat profile:** Should NOT be used for casual person-to-person pairing. No expiry — valid until preauth key rotation. The user must understand file security responsibility. The export file is key material that must be treated with appropriate care.

#### Proximity (Bluetooth)

When a user activates **pairing mode**, the device broadcasts a BLE advertisement including:
- Service UUID: Mesh Infinity pairing service UUID
- Pairing data: peer ID, Ed25519 public key, X25519 public key, pairing token (all truncated to fit the 31-byte advertisement payload; full data fetched via GATT on connection)

Other devices in range with Mesh Infinity running and pairing mode active see the advertisement, display the peer's name, and prompt the user to confirm. Confirmation triggers the Σ-protocol handshake over the BLE connection.

**Threat profile:** BLE pairing mode activation is itself observable — "this person is actively pairing right now." Activate pairing mode only when ready to pair immediately; disable immediately after. Not suitable for high-surveillance environments.

#### NFC

Near Field Communication pairing requires physical proximity (~5 cm). The initiating device presents its public key material via NFC; the receiving device reads it and initiates the Σ-protocol handshake.

**Threat profile:** The highest-security in-person pairing option. Proximity requirement IS the security — physical touch required. Observable as an NFC event but content is not readable without physical access. Harder to observe than QR, shorter range than Bluetooth.

Platform support: Android (full NFC API), iOS (NFC reader available since iPhone 7, limited write), Linux (libnfc).

#### Service Identity (Non-Interactive Pairing)

Networks and services have their own keypairs (group keypairs from §8.7). A service identity can complete Σ-protocol handshakes automatically for incoming join requests, enabling non-interactive pairing for public networks, open communities, and automated infrastructure.

- New members are added at the default trust level for the network type
- Join record stores: method, time, initial trust level
- Service identity is NOT a person — it represents the network or service itself
- All pairing methods must work with service identities

**Cross-cutting requirements for all pairing methods:**
1. Expiry visually displayed at all times during active pairing
2. Context annotation — user records why/how they paired; stored in the contact record for future reference
3. Verification passphrase prompt — strongly encouraged for in-person methods; noted as unavailable for digital methods
4. Join method recorded — the contact record stores how pairing occurred, enabling trust decisions informed by pairing provenance
5. Service identity support — all methods must work with service identities (above)

### 8.4 Mutual Trust Promotion Protocol

Promoting a peer to Level 5 (Trusted) triggers a mutual trust promotion protocol that ensures private profile exchange occurs only when both parties have independently decided to trust each other at Level 5 or above.

**Protocol flow:**

1. Alice locally promotes Bob to Level 5.
2. The system immediately queries Bob's current trust level for Alice (if Bob is online).
3. If Bob is online AND trusts Alice at Level 5+: proceed to cryptographic escrow exchange (below).
4. If Bob is online BUT below Level 5: Alice's promotion is recorded locally. Bob is notified without pressure — a simple informational signal, not a demand for reciprocation. When Bob independently reciprocates, the escrow exchange proceeds automatically.
5. If Bob is offline: Promotion is recorded locally as pending. The exchange runs automatically on Bob's next connection.

**Cryptographic escrow for simultaneous profile exchange:**

The Double Ratchet X3DH handshake (§7.0) serves as the synchronization mechanism — it is already an atomic mutual key exchange. Private profiles are attached to the handshake messages, encrypted such that neither party can decrypt the other's profile until the handshake completes on both sides. No trusted third party is required.

The escrow mechanism ensures that if Alice promotes Bob but Bob does not reciprocate, Alice's private profile is never delivered to Bob. The promotion decision is stored locally, but the cryptographic exchange only executes on mutual consent.

**Attack mitigations:**
1. **Profile size inference** — mitigated by profile padding (see below)
2. **Replay attacks** — commitments include session nonce and timestamp from the X3DH handshake
3. **Commitment DOS** — rate limit failed exchanges per peer per time window

**Profile padding requirements:**
- Compress profile content first
- Choose padded size randomly from the **upper half** of the available range:
  ```
  padded_size = uniform_random(
      actual_size + (64MB - actual_size) / 2,
      64MB
  )
  ```
- Maximum: 64 MB
- Bias toward the top half ensures small profiles appear indistinguishable from large ones
- Random padding bytes are cryptographically random and different on every exchange

### 8.5 Web of Trust and Trust Propagation

Beyond direct pairing, trust can propagate through the web of trust via endorsements. The endorsement model is designed to prevent trust laddering attacks while enabling legitimate introductions.

#### Endorsement Model

- **Single endorser required.** Aggregating multiple lower-trust endorsements does NOT grant upward movement. This prevents an adversary from using many compromised low-value nodes as a trust ladder — ten Level 1 nodes endorsing the same peer does not produce a Level 2 peer.
- **Endorser level sets the DEFAULT starting point** for the endorsed peer, not a hard ceiling or floor. The local user can adjust the trust level in either direction from the endorsement default.
- **Attack cost scales with trust level:** Reaching Level 4 requires compromising at least one InnerCircle (Level 8) node. This is the fundamental security property of the single-endorser model.

#### Endorsement Propagation Floor — Level 5 Minimum

Endorsements from peers below Level 5 are silently ignored. They do not reach the local node, do not affect trust calculations, and do not clutter the WoT graph. Only people the local user genuinely trusts (Level 5+) can introduce new contacts. This is operationally correct — there is no reason to accept an introduction from someone the user barely knows.

#### Endorsement Weight Scaling

Endorsements from higher-trust peers carry more weight in the recipient's trust calculation. An InnerCircle (Level 8) endorsement sets a higher default starting point than a Trusted (Level 5) endorsement. The endorser's trust level is factored into the default starting point calculation:

| Endorser level | Default starting point for endorsed peer |
|----------------|------------------------------------------|
| Level 5 (`Trusted`) | Level 2 (`Vouched`) |
| Level 6 (`CloseTrusted`) | Level 2 (`Vouched`) |
| Level 7 (`HighlyTrusted`) | Level 3 (`Referenced`) |
| Level 8 (`InnerCircle`) | Level 4 (`Ally`) |

These defaults are advisory. The local user can adjust in either direction.

#### Endorsement Records

A peer at Level 5 or above can endorse an unknown peer by signing a `TrustEndorsement` record and broadcasting it to their trusted contacts:

```
TrustEndorsement {
    endorsed_peer_id:  [u8; 32],
    endorser_peer_id:  [u8; 32],
    endorser_level:    u8,           // endorser's own trust level (for weight calculation)
    timestamp:         u64,
    sequence:          u64,          // monotonically increasing per endorser
    signature:         [u8; 64],     // Ed25519 signature by endorser
}
```

Trust propagation is strictly opt-in. Users can disable it entirely, or limit propagation depth, if they want a purely direct-pairing trust model.

#### Endorsement Revocation

A peer can revoke a previously issued endorsement by broadcasting a signed `TrustRevocation`:

```
TrustRevocation {
    endorsed_peer_id:  [u8; 32],
    endorser_peer_id:  [u8; 32],
    timestamp:         u64,
    sequence:          u64,          // incremented from the same endorsement counter
    signature:         [u8; 64],
}
```

Receiving peers remove the endorsement from their local WoT graph and recompute the endorsed peer's derived trust level. If the revocation drops the endorsed peer below Level 5, they are immediately downgraded — private channel access is revoked, private profile is no longer shared. Revocations are gossiped with the same rules as endorsements — the `sequence` number ensures a revocation cannot be replayed against a later, fresher endorsement.

#### Disavowed/Compromised Risk Evaluation

The Disavowed and Compromised states (§8.2) produce public signed announcements gossiped to the entire network. These interact with endorsement processing:

**Risk evaluation checks during endorsement processing:**
- Is the endorsed peer Self-Disavowed? → endorsement weight significantly reduced, user warned
- Is the endorsed peer Friend-Disavowed? → endorsement weight significantly reduced, user warned
- Is the endorsed peer Compromised? → endorsement rejected entirely, user warned
- Is the *endorser* Self-Disavowed? → endorsement weight significantly reduced
- Is the *endorser* Compromised? → endorsement rejected entirely

**Retroactive flagging:** When an endorsed peer's status changes negatively (becomes Disavowed or Compromised), all endorsements of that peer are automatically flagged for review. The endorsement is not automatically revoked — the local user reviews and decides — but it is no longer treated as a clean positive signal.

**Inverse of negative markers:** Absence of negative markers is not positive endorsement, but presence of negative markers IS a meaningful negative signal. A node with no Disavowed/Compromised markers and no endorsements is neutral. A node with negative markers is an active warning signal regardless of trust level.

#### Trusted Peer Reputation Queries

Mesh Infinity is collectively organized — the collective knowledge of trusted peers is the authority. A node can proactively query trusted peers for reputation information before deciding whether to act on an endorsement or accept a connection:

Query: "Do any of you know anything about peer ID X?"

Peers respond with:
- Their trust level for X (if any)
- Any negative markers they have observed
- Any endorsements they have issued or received for X
- Any informal observations about X's behavior

This query flows through trusted channels only — it is not broadcast to the general mesh. Responses are advisory — the local user always makes the final call.

**WoT graph privacy:** General WoT intersection (calculating mutual trusted contacts between strangers) is difficult because profiles and trust records are not shared publicly. The risk evaluation described above is specifically scoped to public signals (Disavowed/Compromised announcements) and trusted peer queries — not general social graph analysis.

### 8.6 Trust Revocation

A user can revoke trust in a peer at any time:

- Setting trust below Level 5 immediately removes the trusted-channel address, revokes private profile access, and stops routing through that peer
- For peers entering Disavowed or Compromised states, revocation is handled by the trust state machine (§8.2) — manual revocation via trust level reduction and automated state machine transitions are complementary mechanisms
- Revoked peers cannot be automatically re-trusted via trust propagation from other peers; re-trusting requires explicit direct action

### 8.7 Trusted Groups

Trusted groups are named collections of peers that share a group identity and communication channel.

#### Group Identity

Groups have **first-class network identities** enabling discovery through the same mechanisms as peer discovery. The group-as-identity analogy holds for discovery and endorsement — it breaks down precisely where security matters.

**Where the analogy holds:**
- Groups have addresses, appear in the network map, can be found
- Groups have public profiles: name, description, avatar, membership count
- A trusted peer can endorse a group as legitimate
- A group can be flagged as Disavowed (honeypot, compromised admin, etc.)

**Where the analogy breaks down — security boundaries that must hold:**
- **Trust levels:** You do not trust a group at Level 7 the way you trust a person. Group membership tiers are separate from peer trust levels.
- **Pairing:** Joining a group is not pairing with it. Network type (Public/Open/Closed/Private per §8.9) governs joining, not bilateral trust negotiation.
- **Merging:** Groups cannot merge. Two operational groups merging would collapse their security boundaries — separate membership lists, separate Sender Keys, separate governance suddenly mixed. Group merging is **prohibited**.
- **Profile exchange:** Groups do not exchange private profiles the way trusted peers do.

**Group membership and peer trust are orthogonal.** Being a member of a group does not grant any peer trust level to other members. Trusting someone highly does not automatically grant them group membership.

**Group public profile:**

```
GroupPublicProfile {
    group_id:         [u8; 32],
    display_name:     String,       // max 64 bytes
    description:      String,       // max 256 bytes
    avatar_hash:      Option<[u8; 32]>,
    network_type:     NetworkType,  // Private | Closed | Open | Public
    member_count:     Option<u32>,  // None for Private/Closed (membership count is hidden)
    created_at:       u64,
    signed_by:        [u8; 32],     // group admin's peer ID
    signature:        [u8; 64],
}
```

Visibility rules:
- Public/Open: full profile visible to anyone in the network map
- Closed: name and type visible, member count hidden
- Private: existence may be known but no profile data visible to non-members

#### Group Structure

- A group has a **group keypair** (Ed25519 + X25519) generated by the creator
- The group public key is shared with all members
- The group private key is held by **admin members** only
- Group encryption uses **Signal Sender Keys** (§7.0) — each member has a per-group Sender Key distributed to all other members via individual X3DH-encrypted direct messages

#### Membership Management

- The group creator is the initial admin
- Admins can add members (by sharing the group public key and Sender Key state over a trusted channel), remove non-admin members, and promote other members to admin (subject to quorum confirmation via vote-to-reject — see §8.10)
- When a member is removed, the **superset ring model** (§8.7.1) handles the transition period and Sender Key rekeying is triggered
- Member lists are shared only among members; non-members cannot enumerate the group

#### 8.7.1 Superset Ring Model for Member Removal

During the window between member removal and rekeying completing, the departed member remains cryptographically in the ring signature set. The superset ring model handles this:

- **First removal:** Content is encrypted for the reduced ring (excluding the removed member). The outer envelope still uses the full superset ring. External observers see no membership change; the removed member cannot read new content.
- **Second removal before rekeying completes:** Immediate forced rekeying. No third ring is maintained — the computational and storage cost is too high in large groups (200–300 nodes). The forced rekeying creates a clean new ring for all remaining members.
- Tolerates exactly one pending removal between rekeyings. The superset ring state is ephemeral — it exists only until the next successful rekeying.

#### Scheduled Rekeying

Rekeying triggers:
1. **Member removal** (existing) — immediate per superset ring model above
2. **Scheduled interval** — configurable per group, changeable by admin or quorum action. Default interval is group-configurable.
3. **On-demand** — any admin can trigger rekeying at any time

Old Sender Key state becomes undecryptable after rotation — this limits retrospective exposure if a member's device is later compromised.

#### Re-Inclusion of Absent Members

When a member has been offline through one or more rekeying events and their Sender Key state has fallen behind the current ratchet:

1. The member reconnects and detects they are behind the ratchet (cannot decrypt current group messages)
2. The member sends a signed re-inclusion request to the group
3. Any member with sufficient trust level (admin, or any member if no admin is available) can re-share the current Sender Key state
4. Re-inclusion is NOT automatic — it requires an active trust decision from at least one member
5. The requesting member's identity is verified before re-inclusion

Re-inclusion grants access to **new messages only** — not messages sent during the absence. The ratchet gap is permanent by design. This ensures that a compromised device that was offline during the compromise window cannot retroactively access messages sent in that window.

#### Group Message Delivery

- Messages addressed to the group are encrypted using the sender's Sender Key (§7.0)
- Each message is then individually wrapped (Step 4 of §7.1) for each group member's X25519 public key
- This means each member receives a copy wrapped specifically for them, rather than a single ciphertext that all members decrypt — preventing a compromised member from sharing a single decryption key

#### Group Features

- Group name, description, and avatar
- Group-scoped file sharing and hosted service access
- Admin controls: rename, set avatar, pin messages, remove members
- Group invites are sent via direct trusted-channel messages with a signed group credential
- Group endorsement and negative markers (Disavowed) follow the same model as peer endorsements (§8.5)

### 8.8 ACL / Firewall Model

Trust levels and ACLs are **independent axes**:
- **Trust level** — what this peer knows about you, and what default access they have
- **ACL** — what specific resources they can reach, regardless of trust level

The ACL system is a **firewall**: default deny, explicit allow.

```
ALLOW  service:git-server  TO  trust:Level5+
ALLOW  service:media       TO  peer:a1b2c3d4...
ALLOW  service:public-site TO  ANY
DENY   service:*           TO  *    // implicit default
```

**Key property:** ACL access can be granted to a Level 0 stranger without elevating their trust level, disclosing the local node's identity, or sharing the local node's private profile. This is the mesh equivalent of running a public website anonymously.

**Trust level gates identity disclosure:** Pushing a peer to Level 5+ means sharing the private channel address and private profile. The ACL system exists so that granting *access* does not require granting *identity*. A service can be fully functional and accessible to strangers while the service operator remains completely anonymous.

ACL rules are evaluated in order. The first matching rule determines the outcome. If no rule matches, the implicit default deny applies. Rules support:
- Trust level ranges: `trust:Level5+`, `trust:Level3-Level6`
- Specific peer IDs: `peer:<hex_peer_id>`
- Group membership: `group:<hex_group_id>`
- Wildcard: `ANY` (matches all peers regardless of trust level)
- Service targeting: `service:<service_name>`, `service:*` (all services)

### 8.9 Network Type Taxonomy

Groups and LANs are classified into four distinct network types, each with different joining, membership visibility, and governance properties:

| Type | Joining | Membership visibility | Ring signatures | Use cases |
|------|---------|----------------------|-----------------|-----------|
| **Private** | Admin-only invite | Cryptographically hidden | Yes | Home mesh, tight team, high-security operational group |
| **Closed** | Requires approval (admin OR quorum) | Cryptographically hidden | Yes | Invite-only community, private club |
| **Open** | Requires approval (admin OR quorum) | Not a cryptographic secret | No | Makerspace with vetting, conference network with approval |
| **Public** | Self-service joining (via service identity, §8.3) | Openly visible | No | Public venue LAN, open community, conference network |

**Type transition rules:**

Security increases require admin OR quorum approval:
```
Public → Open → Closed → Private
```

Security decreases require admin AND quorum approval:
```
Private → Closed → Open → Public
```

Security decreases are **blocked entirely without an admin present** — this prevents a compromised member quorum from downgrading the network's security posture.

**Grandfathering on Public → Open/Closed transition:**

No single correct policy is imposed. Operators have primitives to compose their own approach:

```
MembershipTools {
    list_members(filter: MemberFilter) -> Vec<MemberSummary>,
    set_trust_bulk(filter: MemberFilter, trust_level: TrustLevel),
    remove_bulk(filter: MemberFilter),
    request_reverification(filter: MemberFilter, grace_period_days: u32),
    grandfather_above_threshold(min_trust: TrustLevel),
}
```

The UI presents: membership summary, available tools, recommended approach, and consequences. The protocol provides tools; operators decide policy.

### 8.10 Group Governance

#### Admin vs. Quorum Actions

**Admin actions (unilateral):**
- Add members, remove non-admin members, trigger rekeying
- Rename group, set avatar, pin messages
- Promote members to admin (subject to quorum confirmation via vote-to-reject — see below)

**Always requires supermajority quorum, even with admin present:**
- Removing an admin — no exceptions

**Degraded operation (no admin present):**
- A standard quorum of non-admin members can perform all administrative actions
- Including promoting a new admin — but *only* when no admin exists

#### Quorum Rules

- **Non-admin members only vote** in quorum. Admins are explicitly excluded from quorum votes.
- **Default-allow model:** Members vote to *reject*, not to *allow*. Abstaining = approval. This ensures that governance does not stall when members are offline or unresponsive.
- When admins exceed 50% of total membership (configurable threshold), high-risk admin actions require an **admin quorum** (51% of admins, vote-to-reject).

**Thresholds:**
- **Standard quorum (51% non-admin members):** Promoting a member to admin, all degraded-mode actions
- **Supermajority quorum (67% non-admin members):** Removing an admin
- **All-admin groups:** Admin quorum (51% of admins, vote-to-reject) applies to all high-risk actions

---

## 9. Social Profile

Each node has a **profile hierarchy** rather than a simple public/private split. Profiles are per-context, cryptographically unlinkable by default, and trust travels across linked profiles — with the explicit exception of anonymous profiles.

### 9.1 Global Public Profile (Opt-In)

The global public profile is **explicitly opt-in** — many users, especially in hostile environments, should have no global public profile at all. When enabled, it is visible to anyone in the network map.

**Global public profile fields:**
- `identity_is_public` (bool) — controls whether this node has a public profile at all. Default: `false`. When `false`, the node has no public profile — no display name, bio, or avatar is propagated in the network map. The node still has public addresses and can be contacted by anyone who obtains an address, but nothing links that address to a human identity. When `true`, the public profile fields below are populated and gossiped.
- `public_display_name` (optional string) — a display name visible to anyone. May differ from the private display name shown to trusted peers.
- `public_bio` (optional string) — a short public description.
- `avatar_hash` (optional bytes) — SHA-256 hash of a publicly available avatar image. Fetched separately from the hosting node as a service (§12) or content-addressed file.
- `public_services` (list) — public service advertisements the user wants discoverable (§12).

**Address associability — `address_is_associable` per address:**

Each public address carries an independent `address_is_associable` flag (default: `true` for addresses linked to a public profile; `false` for all others).

- `address_is_associable = true` — this address is linked to the node's identity and public profile in the network map.
- `address_is_associable = false` — this address exists in the network map for routing purposes only. No profile information is attached to it.

This allows a node to have, for example, one address tied to its social identity (associable, used for chat) and one or more addresses exclusively for service hosting that cannot be linked back to the user by any observer of the network map. Because each address is backed by an independent keypair (§3.3), there is no cryptographic linkage between associable and non-associable addresses.

**Public profile propagation:**
- Nodes with `identity_is_public = true` have their public profile included in network map entries and gossiped to the whole network
- Nodes with `identity_is_public = false` have no public profile in the map; their addresses appear without profile data
- Addresses with `address_is_associable = false` appear in the map with no profile reference, even if the node has `identity_is_public = true`

#### Global Public Profile Erasure

Erasing a global public profile is a routine privacy tool, not an extreme action. The public and private profiles are cryptographically separate — erasure does not touch private identity or per-context relationships.

**What erasure does:**
1. Ratchets the old public identity to a **no-op** — the network sees "this identity is gone, stop gossiping it." A clean, network-friendly termination rather than a ghost entry that lingers.
2. Resets the public address — old address becomes unreachable
3. Breaks public discoverability — strangers can no longer find the node
4. WoT endorsements pointing at the old public identity are orphaned
5. Anyone who ONLY knew the public address loses contact — by design

**What erasure does NOT touch:**
- Private identity and private profile — completely unaffected
- Per-context profiles — completely unaffected
- Trust relationships established through private/trusted channels — completely unaffected
- Trusted peers' knowledge of the node — they still know it, just not via the old public address

**The no-op ratchet:**
Rather than simply abandoning the old identity (which leaves a stale, confusing network map entry), the node ratchets the old identity to a no-op entry:
- No transport hints
- No services
- No reachability
- Signed "this identity is retired" signal
- Entry eventually evicts naturally from the network map via staleness pruning

The new public identity (if created) has no cryptographic link to the old one — fresh start, zero provenance.

### 9.2 Global Private Profile

The global private profile is visible only to peers at mutual trust Level 5 or above. It is exchanged over the trusted channel via the cryptographic escrow mechanism (§8.4) after both parties have independently promoted each other to Level 5+.

**Global private profile fields:**
- `private_display_name` (optional string) — the preferred name for trusted peers to use. This is the name that appears in the chat UI for trusted contacts.
- `private_bio` (optional string) — a fuller, personal description shared only with trusted peers.
- `contact_hints` (optional list) — additional ways to reach this node (other mesh addresses, Tor addresses, etc.) that the user does not want in the public map. Contact hints in the global private profile are scoped to the global private context only.
- `avatar_override_hash` (optional bytes) — a different avatar shown only to trusted peers.

**The global private profile is NOT cryptographically linked to the global public profile.** Cross-profile linkage is opt-in (§9.5). A peer who knows the private profile does not automatically know that the public profile is the same person unless the node explicitly reveals that linkage.

**Private profile storage:**
- Private profile data is stored locally, encrypted at rest alongside the identity material
- It is transmitted only to peers who have been explicitly trusted at Level 5+
- Private profile updates are pushed to trusted peers over the trusted channel when the user saves changes

### 9.3 Per-Context and Per-Group Profiles

#### Per-Context Profiles

Each trust relationship can carry additional profile information beyond the global private profile. "Alice knows me as X, Bob knows me as Y" — both are legitimate, neither is more "real." Per-context profiles are tied to the trust relationship, not to any global identity.

No cross-context linkage exists unless explicitly opted into (§9.5). Alice's view of the node and Bob's view of the node are cryptographically separate presentations of the same underlying identity.

#### Per-Group Profiles

Custom identity within a specific group. Members see this version of the node. This enables operational separation — a protest group, professional contacts, and personal circle all see different identities.

Group identity acts the same way as any other per-context profile. It is tied to the group membership, and the group's profile is the one visible to other group members unless the node chooses to disclose more.

### 9.4 Anonymous Profiles

Anonymous profiles are completely decoupled from the core identity. Even trusted peers do not know an anonymous profile belongs to the node.

**Trust levels do NOT travel** — this is the explicit exception to the trust portability rule (§9.6). An anonymous profile starts at Level 0 with every peer, regardless of any trust relationships the underlying identity holds.

**Mandatory warning at creation:**

> *"This profile is cryptographically anonymous — it cannot be linked to your identity by anyone, including your trusted peers. Trust levels you hold with others do not apply here. Use this profile only when anonymity from everyone, including people you trust, is required."*

**Risk of anonymous profiles:** An adversary inside the user's trust circle can operate anonymously against the user using this mechanism. This is a genuinely double-edged sword — it enables legitimate whistleblowing, research, and operational separation, but also enables insider threats to hide their identity from the people who would otherwise recognize them.

Anonymous profiles cannot be linked to any other profile (§9.5). They are designed to be permanently unlinked.

### 9.5 Cross-Profile Linkage

Linking two profiles means revealing "these two identities are the same person."

- **Always opt-in** — never automatic, never inferred
- **Irreversible** — once a linkage is revealed to a peer, it cannot be un-revealed. The permanence property from Known Limitations applies: trust downgrade removes future access but not past access.
- Anonymous profiles **cannot** be linked — they are designed to be permanently unlinked. Attempting to link an anonymous profile is rejected by the system.

### 9.6 Trust Portability

Trust is tied to the cryptographic core identity, not to a specific profile presentation. If Alice trusts Bob at Level 7, and Bob reveals a per-context profile to Alice, Alice's Level 7 trust applies to that context. Trust travels with the self across profile presentations.

**The one exception:** Anonymous profiles. By design, the core identity is hidden — trust cannot travel because there is no verifiable link to the trusted identity. The anonymity is the feature. The risk is the feature.

### 9.7 Contact Hint Scoping

Contact hints live in the appropriate profile tier — not all in the global private profile. A contact hint linking the global identity to a group identity is only shared in the private profile of someone the node explicitly trusts with that linkage. Per-context contact hints live in the per-context profile for that relationship.

This means contact hint distribution is naturally scoped — a hint only travels as far as the profile tier it lives in. A contact hint shared with Alice in a per-context profile is invisible to Bob, even if Bob holds the same or higher trust level. Scoping is per-relationship, not per-trust-level.

### 9.8 Profile Update Propagation

**Global public profile:** Updates propagate via the self-ratcheted network map entry. Push to all peers who have the address.

**Global private profile:** Versioned with a timestamp. Trusted peers who hold a private profile can request an update when their version is stale. Updates are delivered via the same escrow mechanism as initial exchange — but without the full padding overhead for routine updates. The recipient detects staleness from the version timestamp in the profile header.

**Per-context profiles:** Updates are delivered through the relevant trusted channel. The context relationship is the delivery channel.

**Per-group profiles:** Updates are delivered through the group channel. All group members receive the update as part of normal group message delivery.

---

## 10. Integrated Social Channels

Mesh Infinity includes bundled social communication applications built on the mesh infrastructure. These are first-party applications that we develop and ship — not third-party plugins.

### 10.0 Common Rules

These rules apply to **all** §10.x applications. They are non-negotiable implementation requirements.

**Encryption:** All social channels use the four-layer scheme (§7.1) for discrete blob payloads. Streams (voice, video) use the WireGuard inner tunnel. No plaintext content ever leaves the application layer.

**Store-and-forward:** All §10.x applications use the general store-and-forward protocol (§6.6). No application implements its own queueing. Applications register with the S&F layer via `application_id` and receive delivered payloads through it.

**Trust gating:** All channels respect trust levels and ACLs (§8.8). Messages from peers below the channel's minimum trust threshold are rejected before reaching the application. Minimum trust level is configurable per channel per user.

**Profile context:** Each channel uses the correct profile tier (§9) automatically — per-relationship for direct messages, per-group for group channels, per-community for community channels, anonymous when operating under an anonymous profile. Applications do not select profiles — the profile system resolves context based on the communication channel.

**Notification routing:** All §10.x applications route notifications through §14. No application implements its own notification delivery.

**Common message envelope:**

```
SocialMessage {
    message_id:      [u8; 32],       // Random, for deduplication and threading
    application_id:  [u8; 16],       // Which §10.x application owns this message
    channel_id:      [u8; 32],       // Room/conversation/channel this belongs to
    sender_profile:  ProfileContext,  // Which profile tier the sender is using
    timestamp:       u64,            // Unix ms timestamp (sender's clock)
    payload:         Vec<u8>,        // Application-specific, opaque to infrastructure
    reply_to:        Option<[u8; 32]>, // Message ID being replied to
}
```

The `payload` is opaque to the infrastructure layer. The envelope is what store-and-forward, notifications, and routing operate on. Application-specific content (message text, reactions, typing indicators, call signals) is encoded within the payload by the owning application.

**Moderation primitives (available to all §10.x):**
- **Message reporting** — flags content for review by channel admins/moderators
- **Peer blocking** — local, blocks delivery from a specific peer ID
- **Channel trust floor** — minimum trust level to participate in a channel
- **Content filtering hooks** — application-level implementation using plugin API

### 10.1 Chat

Chat is the bundled direct and group messaging application — the primary user interface and the highest-priority application shipped with Mesh Infinity. It is the decentralized Signal equivalent.

**What Chat is:**
- Direct encrypted messaging between peers
- Group conversations using §8.7 group infrastructure
- Voice and video calls
- Push-to-talk
- File sharing via §11 infrastructure
- Message reactions, reply threading, forwarding
- Read receipts and typing indicators (opt-in, with honest warnings)
- Disappearing messages (local deletion, honestly documented)
- Multi-device support — all devices registered to an identity receive messages

**What Chat is NOT:**
- A public forum
- A broadcast channel
- A community platform (that is §10.2)

#### Direct Messaging

1:1 messaging between any two peers:

- Messages are addressed to the peer's **trusted-channel address** if a trust relationship exists (ensuring only the intended recipient can read them, and that the routing is via the private address not the public one)
- For initial contact with an unknown peer (e.g., someone found via public profile search), messages are addressed to their **public address**
- Message delivery confirmation: the recipient sends a delivery receipt (a small signed acknowledgement) on reception
- Offline delivery: if the recipient is unreachable, the message is passed to store-and-forward server nodes (§6.6)

#### Group Messaging

Group chats using trusted groups (§8.7):

- Messages are encrypted using Signal Sender Keys (§7.0) and individually wrapped per member
- Group admin controls: add/remove members, rename, set avatar, pin messages
- Group invites are delivered as direct messages to the invited peer
- Delivery receipts are per-member; the sender sees delivered/read status per group member (opt-out available)

#### Message Format

Every message, whether direct or group, carries:

```
ChatMessage {
    id:              [u8; 16],         // Random message ID (for deduplication, threading)
    conversation_id: [u8; 16],        // Room/conversation this belongs to
    sender_peer_id:  [u8; 32],        // Sender's peer ID
    timestamp:       u64,             // Unix ms timestamp (sender's clock)
    content_type:    ContentType,     // Text, Image, Video, Audio, File, Reaction, Receipt, Edit, Deletion, CallSignal, ...
    payload:         Vec<u8>,         // Content-type-specific payload
    reply_to:        Option<[u8; 16]>, // Message ID being replied to (for threads)
    expires_at:      Option<u64>,     // Unix ms timestamp for disappearing messages
}
```

#### Message Features

**Reactions:** Any peer in a conversation can react to any message with an emoji. Reactions are stored as a list of `(emoji, sender_peer_id)` pairs on the message. Reactions are propagated to all conversation participants.

**Read receipts:** The recipient sends a `MessageReceipt { message_id, status: Delivered | Read, timestamp }` back to the sender. Read receipts are visible per-participant in group chats. Users can disable sending read receipts globally or per-conversation. **Opt-in, disabled by default.** When enabling, the UI must clearly state: *"Read receipts reveal when you're active. In surveillance-heavy environments, this is a risk."*

**Typing indicators:** A `TypingIndicator { conversation_id, typing: bool }` is sent when the user starts or stops typing. Indicators expire automatically after 10 seconds without a refresh. **Opt-in, disabled by default.** Same honest warning as read receipts: *"Typing indicators reveal when you're active. In surveillance-heavy environments, this is a risk."*

**Disappearing messages:** Messages with `expires_at` set are deleted from the sender's local storage after the expiry time. Expiry is enforced locally by each client; there is no server-enforced deletion. Default expiry options: 1 hour, 24 hours, 7 days, 30 days, or off. Disappearing messages can be configured per-conversation. The UI must state this honestly: *"Disappearing messages reduce your local exposure. They cannot prevent the recipient from saving content."*

**Message editing:** Edits are delivered as a new message with `content_type: Edit` referencing the original `message_id`. Edit history is retained locally. The latest edit is displayed by default; users can view edit history.

**Message deletion:**
- *Delete for me*: removes the message from local storage only
- *Delete for everyone*: the sender broadcasts a signed `Deletion { message_id }` to all participants, who remove the message from local storage. Participants who are offline when the deletion is sent receive it on next sync.

**Reply threads:** Messages with `reply_to` set are displayed as inline replies, quoting the referenced message's preview. Thread depth is unlimited.

**Pinned messages:** Any admin (in groups) or participant (in DMs, by mutual agreement) can pin a message. Pinned messages are listed in a conversation-level index separate from the message stream.

**Message forwarding:** Any message can be forwarded to another conversation. Forwarded messages carry an attribution field indicating the original sender (their display name, not peer ID) unless the forwarder clears it.

**Search:** Full-text search across all local message history. Search is performed locally on the device; no search query leaves the device. The search index is encrypted at rest alongside the message database.

#### Media and File Sharing

**Images and video:** Sent as message attachments. The media is encrypted with the session key, chunked, and transferred over the best available transport. A thumbnail or preview is generated locally before sending and included in the message payload for immediate display.

**Audio:** Voice messages (short recordings) and audio files are sent as attachments. Playback is inline in the chat UI.

**Arbitrary files:** Any file can be sent as a message attachment. Files above a configurable size threshold (default: 50 MB for in-message transfer) are automatically promoted to a **file transfer session** (§11).

**Media compression:** The sender can choose whether to send media at original quality or compressed. Original quality is the default for files; compressed is the default for images shared in chat.

#### Voice and Video Calls

End-to-end encrypted voice and video calls:

- **Call signalling** is performed over the existing mesh messaging channel — a `CallSignal` message type is used for offer/answer/ice-candidate/hangup
- **Media streams** are transported over a dedicated WireGuard session established for the call, routed through the standard mesh path by default
- **Codec negotiation** is part of the call signalling: Opus for audio, VP8/VP9/AV1 for video
- **Group calls** are supported for trusted groups; each participant establishes individual WireGuard sessions to every other participant (mesh calls, no central media server)
- **Fallback to audio-only** when bandwidth or CPU is insufficient; the UI notifies the user
- **Call encryption** uses the same session key derivation as file transfer sessions (§7.3), separate from the messaging session key
- **LoSec for calls**: either party may request LoSec mode (§6.7) during call setup. The `CallSignal` offer includes an optional `losec_requested: bool` field. The remote party's LoSec policy (§6.7 negotiation) governs whether the request is accepted. If accepted, the media WireGuard session is routed via the agreed LoSec path for the duration of the call. The persistent amber or red indicator (§6.7 UI requirements) is displayed in the call UI throughout.
- **Push-to-talk (PTT):** Half-duplex voice mode suitable for walkie-talkie style communication. Operates over BLE connections for local mesh scenarios. Lower bandwidth and latency requirements than full-duplex calls.

#### Multi-Device Support

Each device registered to an identity has its own ratchet state. Messages are delivered to all registered devices via store-and-forward and the reconnect/sync mechanism. Device registration is a trust decision — adding a device to an identity requires verification (Σ-protocol handshake between the new device and the existing identity).

#### Presence and Status

- **Online/Away/Do Not Disturb/Offline** status is propagated to trusted peers over trusted channels
- **Custom status text** is included alongside the status enum
- **Last-seen timestamp** is shared with trusted peers, opt-out per-contact or globally
- Presence updates are pushed; no polling. When the user goes offline, a final `Offline` presence update is sent before disconnect.
- Presence information is never included in the public network map — it is only shared with trusted peers

### 10.2 Communities

Communities is the bundled persistent group communication platform — the decentralized Discord equivalent. It is the application for organized groups, projects, and public spaces.

**What Communities is:**
- Persistent named channels (text, voice, video)
- Member roles and permissions beyond simple admin/member
- Message history hosted by server-mode nodes
- Public and private channels within a Community
- Community discovery via the group identity model (§8.7)
- Member management and moderation tools
- Pinned messages, announcements
- Bots and automations (via the plugin system)
- Optional clearnet access alongside mesh access

**What Communities is NOT:**
- A replacement for Chat — direct messaging happens in Chat
- A public internet forum — it is mesh-native with an optional clearnet bridge

#### Hosting Model

Communities are hosted by server-mode nodes contributing storage and availability. The hosting node uses the store-and-forward infrastructure (§6.6) as the backbone for message persistence. Community members connect to hosting nodes to fetch history and deliver messages.

A Community can be hosted by:
- A dedicated server-mode node the Community admin controls
- A distributed set of volunteer server-mode nodes
- Any combination

#### Access Model

Communities use the network type taxonomy (§8.9) — Public, Open, Closed, Private. The network type governs joining. Within a Community, channel-level permissions use the role system.

#### Role System

Communities need a richer role model than admin/member. Roles have named permission sets:
- **Channel access:** read, write, react, attach files
- **Moderation capabilities:** delete messages, kick members, ban members
- **Administrative capabilities:** create channels, change settings, manage roles

Roles are Community-defined — the spec defines the permission primitives. Communities define their own role structures using these primitives to suit their needs.

#### Message History

Hosted on server-mode nodes, encrypted for Community members. Non-members cannot read history. History is paginated and fetched on demand — not bulk-downloaded on join.

#### Clearnet Bridge

A Community can optionally expose a clearnet-accessible interface alongside its mesh presence. Clearnet users interact via a standard web interface. Mesh users interact natively. The same backend serves both. Clearnet users are a distinct membership class with an appropriate trust level — they enter at the level defined by the Community's network type, with the additional annotation that their connection path does not benefit from mesh anonymization.

---

## 11. File Sharing

File sharing in Mesh Infinity consists of two separate systems: **direct transfer** (live, peer-to-peer) and **distributed storage** (async, content-addressed, Freenet-style). These systems share the same encryption model and content addressing scheme but are distinct delivery mechanisms. Publishing to one does not imply publishing to the other.

### 11.1 Direct File Transfer

Direct file transfers are live, peer-to-peer transfers where both parties are online simultaneously. No storage nodes are involved. Transport-layer chunking is handled by the underlying transport.

**Protocol:**

1. **Initiation:** The sender creates a `FileTransferOffer { file_id, name, size, sha256_hash, mime_type }` and sends it as a message.
2. **Acceptance:** The recipient replies with `FileTransferAccept { file_id }`, which triggers session key negotiation (§7.3).
3. **Transfer:** The file is split into chunks (default: 64 KB). Each chunk is encrypted with the session key, tagged with its chunk index, and sent. Chunks may be sent out of order.
4. **Completion:** On receipt of all chunks, the recipient verifies the SHA-256 hash of the reassembled file. On success, a `FileTransferComplete` message is sent.
5. **Resumption:** If the transfer is interrupted, the recipient sends a `FileTransferResume { file_id, received_chunks: bitfield }` on reconnect. The sender retransmits only the missing chunks.

A file shared via direct transfer does not exist in distributed storage unless explicitly published there by the recipient or sender as a separate action.

### 11.2 Distributed Object Storage

Nodes volunteer storage capacity. Content is stored as encrypted blobs, content-addressed by SHA-256 hash. Storage nodes are completely blind — they hold opaque encrypted data with no readable metadata (at security levels 2–4). This follows the Mega.nz model: encrypt client-side, distribute the blob, share the key separately.

#### Storage Types

- **Distributed object storage** — Freenet-style, probabilistic availability. Content is replicated across volunteering nodes. Availability is proportional to demand and node participation.
- **Sticky storage** — pinned to specific nodes, reliable availability. The node operator commits to hosting the content for a defined period.
- **Scoped distributed storage** — restricted to group or LAN. Content is replicated only within the group's member nodes or the LAN's participating nodes.

#### Content Security Levels

| Level | Name | Key distribution | Revocability |
|-------|------|-----------------|--------------|
| 0 | Public | Unencrypted content hash | Effectively irrevocable |
| 1 | Unlisted | Key shared ad-hoc, hash not indexed | Practically irrevocable |
| 2 | Trust-gated | Key via trusted channel | Best-effort via stop-storing signal |
| 3 | Group-scoped | Key via group key mechanism | Group can issue stop-storing |
| 4 | Direct | Key via direct trusted-channel | Reliable via stop-storing signal |

**Level 0 (Public):** Content and metadata are unencrypted. The content hash is published in indexes and the network map. Anyone can fetch and read. Effectively irrevocable once distributed.

**Level 1 (Unlisted):** Content and metadata are unencrypted — same as Level 0. The distinction is addressing only: the content address is NOT published in any index. Anyone with the address can fetch and read freely. Security is purely address obscurity, not encryption. Practically irrevocable because any node that has fetched the content can redistribute it.

**Level 2 (Trust-gated):** Content and metadata are encrypted with a file key. The file key is distributed through trusted channels to specific peers. Storage nodes hold only encrypted blobs. Best-effort revocability via stop-storing signal — cooperative nodes honor it, but copies already distributed to trusted peers cannot be recalled.

**Level 3 (Group-scoped):** Content and metadata are encrypted with a key distributed through the group key mechanism. Only group members can decrypt. The group can issue a stop-storing signal. Revocability is better than Level 2 because the key distribution is scoped to the group's Sender Key infrastructure.

**Level 4 (Direct):** Content and metadata are encrypted with a key distributed through a direct trusted-channel message. Only the specific recipient(s) can decrypt. Reliable revocability via stop-storing signal because the distribution is point-to-point and the number of key holders is minimal.

#### Chunking Model

**Chunk size:** Fixed per file, configurable at publish time, default 1 MB. Larger chunks produce fewer manifest entries and fewer round trips. Smaller chunks enable finer-grained parallel fetching and better partial recovery. 1 MB is a reasonable default for mesh bandwidth characteristics.

**Chunk addressing:** Each chunk is independently content-addressed by SHA-256 of its ciphertext. Chunks are stored as opaque encrypted blobs by storage nodes — nodes cannot distinguish chunks of the same file from chunks of different files.

**File manifest:**

```
FileManifest {
    version:         u32,
    file_name:       Option<Vec<u8>>,    // encrypted for Level 2-4, plaintext for Level 0-1
    mime_type:       Option<Vec<u8>>,    // same
    total_size:      u64,
    chunk_size:      u32,
    chunk_count:     u32,
    chunks:          Vec<ChunkEntry>,
    file_key_hint:   Option<Vec<u8>>,   // encrypted key hint for Level 1+
    security_level:  ContentSecurityLevel,
    created_at:      u64,
    publisher:       Option<[u8; 32]>,  // peer ID; None for fully anonymous publish
}

ChunkEntry {
    index:           u32,
    content_hash:    [u8; 32],          // SHA-256 of encrypted chunk ciphertext
    size:            u32,               // actual size of this chunk (last chunk may differ)
}
```

The manifest itself is content-addressed. Sharing a file means sharing the manifest hash (and the file key, for private files). Fetching the manifest gives everything needed to reconstruct the file.

#### Parallel Fetching and Resumable Transfers

Chunks can be fetched from different storage nodes simultaneously. The fetcher discovers which nodes hold which chunks via the routing layer — any node that has announced it holds a given content hash is a candidate. Chunks are verified against their `content_hash` before assembly. A corrupted or missing chunk triggers re-fetch from an alternate node.

A partial fetch is resumable — the fetcher records which chunks are already verified locally and resumes from the first missing chunk on reconnect. No restart is required.

#### Metadata Security Model

Metadata (file name, MIME type, size, thumbnail) follows the same security model as the file content:

- **Level 0 (Public):** Metadata is unencrypted in the manifest. Publicly readable by anyone with the manifest hash.
- **Level 1 (Unlisted):** Metadata is unencrypted — same as Level 0. Security is purely address obscurity. The manifest hash alone is the access control.
- **Level 2–4 (Trust-gated, Group-scoped, Direct):** Metadata is encrypted with the file key. File key distributed through the appropriate channel (trusted channel, group key mechanism, direct trusted-channel message). Storage nodes hold encrypted chunks with no readable metadata.

**Thumbnails:** For image and video files, a thumbnail can be generated and stored as a separate content-addressed blob. The thumbnail follows the same security level as the parent file — a private file's thumbnail is also private. The thumbnail hash is stored in the manifest alongside chunk entries.

#### Stickiness Metric

The stickiness metric is a computed user-facing score answering "how reversible is this sharing decision?"

```
Stickiness = f(storage_method, scope, security_level, estimated_node_count,
               time_since_share, content_size, observed_demand)
```

Output: 1–5 scale with plain-language description:
- **1:** Fully revocable — content can be reliably removed
- **2:** Mostly revocable — some copies may persist
- **3:** Partially revocable — removal is best-effort
- **4:** Mostly permanent — content is widely distributed
- **5:** Effectively permanent — removal is impractical

When publishing to distributed storage, the stickiness metric is computed and displayed before the publish completes. The user sees the expected stickiness score based on the content security level chosen, storage scope, and estimated network propagation. This is informational — the user makes the final call knowing the consequence.

#### Stop-Storing Signal Propagation

Stop-storing signals target the manifest hash. Storage nodes that receive a valid stop-storing signal for a manifest hash should also honor stop-storing for all chunk hashes listed in that manifest. This ensures the entire file is removable, not just the manifest.

Stop-storing for individual chunks (without a manifest) is also valid — for cases where a chunk is shared across multiple files (content-addressed deduplication means identical chunks have identical hashes).

The effectiveness of stop-storing depends on the content security level:
- Level 0–1: Effectively unenforceable — any node that already has the content can ignore the signal
- Level 2: Best-effort — cooperative nodes honor it, but previously distributed copies persist
- Level 3: Group-scoped enforcement — the group can collectively enforce via rekeying
- Level 4: Reliable — minimal key holders, point-to-point distribution

### 11.3 Public File Hosting

Files can be hosted publicly as a service (§12), making them accessible to any node that can reach the host:

- A publicly hosted file is served via the mesh HTTP layer (§12.2) at `public_address:port/path`
- The file is advertised in the host's public service list with its SHA-256 hash, size, MIME type, and optional description
- Clients fetch hosted files via the same session-encrypted channel used for all mesh connections
- Content addressing: files can optionally be addressed by their hash (`sha256:<hash>`) in addition to their host address, enabling content-addressed distribution across both the direct hosting and distributed storage systems

### 11.4 Private File Sharing

Files shared only with trusted contacts:

- Shared via the direct file transfer protocol (§11.1) to specific peers or groups
- Groups can have a **shared file repository**: a collection of files accessible to group members, hosted by one or more group members or published to group-scoped distributed storage (§11.2, Level 3)
- Private files published to distributed storage at Level 2–4 are encrypted and accessible only to key holders

---

## 12. Hosted Services

Any TCP or UDP service can be hosted over Mesh Infinity and made accessible to other nodes. This is the mechanism by which Mesh Infinity provides an alternative to web hosting, API services, SSH access, and any other internet service.

**Default model — services are private by default.** A service exists on an address and port. Nothing about its existence is announced unless the operator explicitly chooses to announce it. The service is reachable only if the connecting peer already knows the address and port.

Knowledge of a private address already implies knowledge of services on it — trusted peers who know the private addresses know the private services implicitly via the trust relationship. No additional announcement is needed for private services between trusted peers.

**The privacy property:** An adversary watching the mesh sees no service landscape unless nodes choose to announce. Probing for unknown services reveals the prober. The mesh does not leak service topology by default.

### 12.1 Service Addressing

Services are addressed by a **port number** combined with a node address:

```
service_address = device_address:port
```

- **Public services**: `public_address:port` — the `public_address` is in the network map; any node can look up the address and attempt connection
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

### 12.4 Service Registration, Exposure, and Announcement

**Exposure, announcement, and indexing are three distinct opt-in concepts:**

**Exposure:** The service listens on a specific address:port. The operator controls who knows that address. This is the only mandatory step — everything else is opt-in. A service can be fully private (address known only to the operator and explicitly shared peers) or semi-public (address on a public mesh address, reachable by anyone who tries).

**Announcement:** Explicitly publishing "this service exists" to an audience. Always opt-in. Announcement channels:
- Added to public network map entry → fully public, visible to anyone
- Shared in a group channel → group-scoped, visible to group members
- Sent directly to specific peers → point-to-point, visible only to those peers
- Published to a service index (see §12.5)

Announcement is about **discoverability**. Exposure is about **reachability**. These are independent — a service can be reachable but unannounced (security through obscurity + real access control), or announced but access-controlled (visible but not accessible without credentials/trust).

**Service record:**

```
ServiceRecord {
    service_id:          [u8; 16],      // Random service identifier
    owner_peer_id:       [u8; 32],
    address:             DeviceAddress,  // The mesh address (public or trusted-channel)
    port:                u32,
    protocol:            Protocol,       // TCP | UDP | Both
    name:                Option<String>, // None = anonymous service
    description:         Option<String>,
    transport_hint:      TransportHint,
    acl:                 Option<ACLRule>, // None = no mesh-level gating (service handles its own auth)
    announcement_scope:  AnnouncementScope, // Private by default
    application_id:      Option<[u8; 16]>, // which §10.x or plugin owns this
    losec_config:        ServiceLoSecConfig, // Host-side LoSec/direct toggles (both default false)
}

AnnouncementScope {
    Private,                              // default — not announced
    Peers(Vec<[u8; 32]>),               // specific peer IDs only
    Group(group_id: [u8; 32]),           // group members only
    Public,                               // network map entry
    Index(index_address: DeviceAddress), // specific service index
}
```

`acl: None` means no mesh-level access control — the service is open at the mesh layer. Application-level auth (if any) is entirely the service's concern.

`announcement_scope: Private` is the default — no announcement unless explicitly changed.

### 12.5 Service Indexes

Service indexes are opt-in curated directories of announced services. A node can run a service index — a list of services it knows about and chooses to share. Other nodes subscribe to indexes they trust.

Properties:
- **No central index** — anyone can run one
- **No mandatory participation** — operators choose which indexes to list in
- **No automatic inclusion** — listing requires explicit opt-in by the service operator
- **Index operators take responsibility for what they list** — an index is an implicit endorsement
- **Indexes can be public** (anyone can subscribe) **or private** (trusted peers only)

**Re-advertisement:** A group or network can include a service in its own announcements. Always opt-in by the re-advertiser — they choose to amplify. The original operator does not control re-advertisement but can request removal. Re-advertisement carries an implicit endorsement from the re-advertiser.

### 12.6 Service Access Model

The mesh provides the network layer. Services define their own access model. These are entirely independent.

| Access model | Who handles auth | Mesh involvement |
|-------------|-----------------|-----------------|
| **Open** | Nobody — connect and use | Route packets, nothing else |
| **Application-credentialed** | The service (Minecraft account, HTTP auth, custom login) | Route packets, nothing else |
| **Trust-gated** | Mesh ACL — only trusted peers can reach the address | Enforce ACL (§8.8), reject below threshold |
| **Key-required** | Mesh crypto — address knowledge IS the credential | Private address distribution handles access |
| **Combined** | Both mesh ACL AND application auth | Defense in depth |

A Minecraft server on the mesh is just a Minecraft server. The mesh delivers packets. Minecraft handles its own auth (or not, for an open server). The mesh does not care. The operator can optionally add a mesh-level trust gate to restrict who can even reach the server's address — but that is the operator's choice, not a requirement.

**The mesh's job:** Route packets to the right address. Enforce ACLs if configured. Nothing more.

### 12.7 Access Control Enforcement

Access control is enforced at the connection layer:

1. When a client connects to a service address, the WireGuard handshake identifies the client by their peer ID
2. The service host's proxy checks the client's peer ID against the service's `acl` rules (§8.8)
3. Connections from peers not meeting the ACL are rejected before any application data is exchanged
4. Application-level auth (HTTP authentication, etc.) is an additional layer entirely within the service's control

Services on private addresses use the private routing plane — an adversary monitoring the public routing plane cannot determine whether an endpoint is a final destination or a gateway, what private routing happens after handoff, or any relationship between public and private addresses.

### 12.8 Service Health and Availability

- Service hosts publish a **last-alive timestamp** alongside their service records, updated periodically
- Clients cache service records and fall back to alternative hosts for redundant services
- A service can be **mirrored**: multiple nodes host the same service and advertise the same service ID; clients pick the best-connected host
- The service proxy monitors the local backend (e.g., the local HTTP server) and marks the service unavailable if the backend is down

---

## 13. VPN and Exit Nodes

### 13.1 Overview

Mesh Infinity provides system-wide VPN functionality that gives users control over how all device traffic is routed. This is the PMWAN aspect of the system: not just a messaging app, but a replacement for the network layer itself. Exit node access follows the same opt-in access model as all services (§12) — private by default, access control via ACL.

### 13.2 Exit Node Capabilities

Any node can be an exit node. Exit nodes advertise their capabilities and available network profiles. Access to exit node capabilities follows the service access model (§12.6) — the operator configures access via ACL (trust level, specific peers, group membership, or open).

```
ExitNodeAdvertisement {
    peer_id:          [u8; 32],
    capabilities:     ExitCapabilities,
    network_profiles: Vec<NetworkProfile>,
}

ExitCapabilities {
    clearnet_exit:    bool,    // route traffic to clearnet directly
    tor_exit:         bool,    // route traffic through Tor then clearnet
    i2p_exit:         bool,    // route traffic through I2P then clearnet
    tor_i2p_combined: bool,   // Tor AND I2P layered before clearnet
    mesh_bridge:      Vec<MeshBridgeInfo>,  // bridges to other mesh networks
}

NetworkProfile {
    profile_id:           [u8; 16],
    name:                 String,
    description:          Option<String>,
    protocol:             VPNProtocol,      // WireGuard | OpenVPN | etc.
    region:               Option<GeoRegion>,
    requires_credentials: bool,
    mandatory:            bool,             // exit node requires use of this profile
    output_type:          OutputType,       // Clearnet | Tor | I2P | TorOverI2P | MeshBridge
}
```

### 13.3 Virtual Network Interface

Platform-specific virtual interface implementations:

- **Android**: VPN Service API (no root required). The app establishes a VPN interface that captures all device traffic.
- **iOS / macOS**: Network Extension framework (NEPacketTunnelProvider). Same capability as Android via the platform's official VPN API.
- **Linux**: TUN/TAP virtual interface. Requires either root or `CAP_NET_ADMIN` capability.
- **Windows**: WinTun virtual adapter (same driver used by WireGuard for Windows). No driver signing issues; WinTun is a well-established, signed driver.

The virtual interface intercepts outbound packets and routes them according to the current routing mode.

### 13.4 Traffic Routing Modes

| Mode | Behaviour |
|------|-----------|
| **Off** | No VPN active; Mesh Infinity runs as a messaging/service app only |
| **Mesh Only** | Only traffic destined for mesh addresses (`meshinfinity://` URLs, mesh service addresses) is routed through the mesh. All other traffic goes directly to the internet. |
| **Exit Node** | All internet traffic is forwarded through a selected exit node, which forwards it to the internet on the user's behalf. The user's internet-facing IP becomes the exit node's IP. |
| **Policy-Based** | User-defined routing rules determine which traffic goes where. Some traffic to the mesh, some to an exit node, some direct. |

### 13.5 Network Profiles

A network profile is a routing policy the exit node can apply to traffic. Profiles are defined by the exit node operator. Examples:

- "Mullvad NL" — route through Mullvad's Amsterdam endpoint via WireGuard
- "Corporate VPN" — route through corporate network, mandatory profile
- "Tor exit" — route through Tor before clearnet
- "Home network" — route into operator's home LAN
- "Yggdrasil bridge" — bridge to Yggdrasil mesh network

The exit node operator configures their own profiles. The spec defines the profile structure and protocol, not the profiles themselves.

**Mandatory profiles:** Some exit nodes require a specific profile — a corporate exit node might mandate the corporate VPN. The client must use it or not use the exit node. Declared in the `ExitNodeAdvertisement` via the `mandatory` flag on the `NetworkProfile`.

### 13.6 Client-Side Exit Node Selection

**Manual:** User picks an exit node from known nodes, sees available profiles, selects one. Full user control.

**Criteria-based search:** User specifies criteria — "UK exit with Tor routing", "lowest latency clearnet exit with VPN profile." The application queries known exit nodes, filters by capability and geography, and presents matching candidates. The user makes final selection from filtered results.

The application assists selection but never makes automatic trust decisions. The user always chooses the exit node.

### 13.7 Layered Anonymization — Tor/I2P via Exit Node

Tor and I2P are available as direct transports at all times (§5.2, §5.3). Exit nodes can additionally expose Tor and I2P as **output routes**, adding an extra anonymization layer:

```
Direct Tor:
  Your node → Tor → clearnet
  (Tor sees your mesh address as the origin)

Exit node via Tor:
  Your node → mesh → exit node → Tor → clearnet
  (Exit node doesn't know your identity — mesh routing hides origin)
  (Tor doesn't see your mesh identity at all)
  (Extra separation between mesh identity and clearnet activity)

Exit node via Tor+I2P combined:
  Your node → mesh → exit node → I2P → Tor → clearnet
  (Maximum layering — three distinct anonymization systems)
```

This is a meaningful security property: using Tor directly routes from the node's mesh address. Using an exit node via Tor separates the mesh identity from the Tor circuit entirely. The exit node is a relay between the mesh presence and the anonymizing network — the exit node knows traffic passed through, but mesh routing prevents reliable attribution of which mesh identity generated it.

### 13.8 Multi-Mesh Bridging

Exit nodes can bridge to other mesh networks:
- Another Mesh Infinity instance
- Yggdrasil
- Cjdns
- Any mesh network with an IP layer

**Trust model for bridged meshes:** Everything from a bridged mesh starts at Level 0 (Unknown). The bridge is a hard trust boundary. The bridged mesh's trust relationships are opaque and not inherited. A specific peer from the bridged mesh can be manually promoted by a user with out-of-band knowledge of them.

The bridge node itself is trusted by the operator for routing purposes — its access control follows the service access model (§12.6).

### 13.9 VPNset / Commercial VPN Provider Exposure

Building on the transport layer's native WireGuard support, exit nodes can expose access to commercial VPN provider infrastructure:

- The operator configures VPN provider credentials on the exit node
- The exit node exposes the provider's endpoint network as named profiles (§13.5)
- Clients connect to the exit node and select the desired provider endpoint
- Example: "Mullvad" VPNset with profiles for each available country

This gives any mesh node access to commercial VPN infrastructure without each node needing to configure provider credentials individually. The exit node operator manages the provider relationship; clients select a profile.

### 13.10 Two VPN Routing Flows

**Flow 1 — Your VPN config via exit node:**
```
Your node → [your WireGuard/OpenVPN session] → exit node → VPN endpoint
```
The user holds the credentials and negotiates directly with the VPN endpoint. The exit node is a transparent relay — it never participates in the VPN negotiation and never holds the user's VPN keys.

**Flow 2 — Exit node's VPN profile:**
```
Your node → exit node → [exit node's VPN session] → VPN endpoint
```
The exit node holds the VPN credentials and maintains the VPN session. Traffic enters the exit node encrypted via Mesh Infinity, exits via the exit node's VPN tunnel. The exit node is the VPN client — it negotiates with the VPN endpoint on the user's behalf.

In Flow 2, the exit node handles traffic at the Mesh Infinity / VPN transition point. This is inherent to using someone else's VPN profile — the same trust model as any exit node. Application-layer encryption (HTTPS, etc.) provides protection regardless of flow. The deniability property holds in both flows — the exit node knows traffic passed through, but Mesh Infinity's routing prevents reliable attribution.

Exit nodes require trust by definition. Both flows are valid depending on whether the user brings their own VPN credentials or uses the exit node operator's profile. They follow the service access model (§12.6) exactly:
- Private by default — not announced unless the operator chooses
- Access via trust level gate, explicit peer allowlist, group membership, or open
- A public exit node (open to anyone) is a valid configuration
- A corporate exit node (mandatory profile, specific peer allowlist) is equally valid

### 13.11 Exit Node Privacy and Kill Switch

**Exit node privacy:**
- The exit node sees the destination IP addresses of the client's internet traffic but does not see the client's mesh identity (mesh routing provides sender anonymity; the exit node sees only the last mesh hop)
- Wrapper node routing (§4.4) can be used to further hide the client's mesh identity from the exit node
- The exit node's ISP sees traffic from the exit node's IP, not the client's IP — this is the privacy benefit
- The client should trust exit nodes accordingly: they are a privileged position

**Kill switch:**
- If the exit node connection drops while the VPN is in Exit Node mode, traffic is halted by default (strict kill switch) until the connection is re-established or the user explicitly switches modes
- Users can configure the kill switch to permissive mode: on exit node disconnect, traffic falls back to direct internet rather than halting
- The kill switch state is displayed prominently in the UI

### 13.12 Split Tunneling and Policy-Based Routing

In policy-based mode, users define routing rules:

- Route by **destination IP range or domain**: e.g., all traffic to `10.0.0.0/8` through the mesh; all other traffic direct
- Route by **application** (Android/iOS): specific apps are routed through the mesh or exit node while others go direct
- Route by **service**: traffic to known mesh service addresses automatically routes through the mesh regardless of mode
- **Multiple exit nodes**: different traffic categories can be routed through different exit nodes (e.g., work traffic through exit A, streaming through exit B)

**DNS routing:**
- DNS queries for `.mesh` domains (or equivalent) are resolved locally via the mesh service directory
- When Exit Node mode is active, **all** DNS queries for internet domains are forwarded through the exit node by default (not optional) to prevent DNS leaks. The exit node uses DNS-over-HTTPS (DoH) for its upstream resolution — the exit node's ISP therefore sees HTTPS traffic to a DoH provider, not plaintext DNS queries. The DoH provider used by the exit node is configurable; default: the exit node operator's own DoH resolver or a well-known privacy-respecting provider.
- Users who do not want the exit node to see their DNS queries can configure the client to use a local DoH resolver tunnel that resolves queries before they reach the exit node — but this risks DNS/traffic destination correlation at the exit node level.
- A mesh-internal DNS resolver handles service address to peer ID resolution

### 13.13 Tailscale Feature Parity and Superset

Mesh Infinity is a **superset** of Tailscale's feature set. All Tailscale features are covered, with significant extensions:

| Tailscale Feature | Mesh Infinity Equivalent | Extensions |
|-------------------|--------------------------|------------|
| Exit nodes | §13.2 Exit Node Capabilities | Multi-protocol exit (Tor, I2P, bridged mesh), network profiles, VPNsets |
| Subnet routing | §13.12 policy-based routing | Per-app routing, multi-exit-node routing, service-aware routing |
| MagicDNS | Mesh service name resolution | Distributed, no central DNS authority |
| Access control lists | §8.8 ACL/Firewall Model | Trust-level integration, anonymous service hosting |
| Network topology view | UI network screen | Trust-weighted visualization, multi-transport display |
| Key rotation | §3.8 Key Compromise Recovery | WoT-corroborated rotation, two-channel verification |
| SSO/identity | §3.1 Identity Model | Self-sovereign identity, no SSO provider dependency |
| Coordination server | §4.3 Directory Nodes | No central coordinator, fully distributed |
| DERP relays | §4.4 Wrapper Nodes + §6.6 Store-and-Forward | Trust-selected relays, anonymous forwarding |

Mesh Infinity's key differentiators beyond Tailscale parity:
- **No central coordination server** — fully distributed, no single point of failure or trust
- **Transport anonymization** — Tor, I2P, wrapper nodes; Tailscale provides none
- **Trust-based routing** — routing through the social graph rather than through centrally provisioned relays
- **Multi-mesh bridging** — bridge to other mesh networks (§13.8)
- **Layered anonymization** — exit via Tor, exit via I2P, exit via both (§13.7)
- **Commercial VPN exposure** — VPNsets accessible through exit nodes (§13.9)
- **Self-sovereign identity** — no dependency on SSO providers or external identity systems

## 14. Notifications

Notification delivery in Mesh Infinity follows the same privacy-first, opt-in philosophy as every other subsystem. Notifications are **delivery hints**, not messages. The actual message content always travels via the mesh, always encrypted via the four-layer scheme (§7.1). A notification that fails to deliver does not affect message delivery -- the message is stored via store-and-forward (§6.6) and delivered when the app next connects.

Notification delivery is completely separate from message security.

### 14.1 Tier 1 -- Mesh-Native (Default, No Third Parties)

Messages arrive via persistent outer tunnels (§6, persistent tunnel model) when the app is active. No external notification infrastructure is involved. Zero metadata leakage to any third party.

Platform behaviour:

- **Android:** Persistent connection works in background with appropriate permissions -- full background delivery.
- **iOS:** Limited to when the app is active or recently foregrounded. iOS kills persistent connections aggressively. This limitation must be clearly explained to users at first install (see §16.3).
- **Desktop (Linux, macOS, Windows):** Persistent connection works in background.

This is the default for all platforms. No configuration required.

**Notification priority levels:**

| Priority | Examples | Delivery behaviour |
|----------|---------|-------------------|
| `Urgent` | Calls, pairing requests | Immediate delivery; will wake the app from background where platform allows |
| `High` | Direct messages from trusted peers | Processed promptly on next tunnel traffic cycle |
| `Normal` | Group messages, file transfer offers | May be batched with other Normal/Low notifications |
| `Low` | Presence updates, network map updates, background sync | Always batched; never triggers a standalone wake |

### 14.2 Tier 2 -- Self-Hosted Push (Opt-In, Android/Desktop)

The user configures a self-hosted push server ([ntfy](https://ntfy.sh), Gotify, or any UnifiedPush-compatible server). The app registers with the user's server. The push server delivers a wake signal when messages arrive. The app fetches actual content via the mesh on wake.

Properties:

- No Apple or Google involvement.
- Works reliably in Android background.
- Requires the user to run or trust a push server.
- **Not viable on iOS** -- platform restrictions prevent third-party background push mechanisms.
- Timing metadata (when a wake signal was delivered) is visible to the push server operator -- this is the user's trust decision.

The user enters their self-hosted push server URL in Settings > Notifications.

### 14.3 Tier 3 -- APNs/FCM Silent Push (Opt-In)

A silent push notification wakes the app. The app then fetches actual message content via the encrypted mesh channel. APNs (Apple) or FCM (Google) see only: "this device received a silent wake at this time."

Properties:

- **Works in iOS background** -- this is the primary reason to use this tier.
- Timing metadata visible to Apple (APNs) or Google (FCM).
- Message content and sender identity are **not** visible to Apple or Google.

**Required disclosure at opt-in:**

> "Apple/Google will know when you receive message notifications but not what they say or who they're from."

This disclosure must be presented and acknowledged before the tier is activated.

### 14.4 Tier 4 -- APNs/FCM Rich Push (Opt-In)

Full or partial notification content is delivered via Apple or Google infrastructure. Maximum delivery reliability and convenience; maximum metadata exposure.

Properties:

- Notification timing, frequency, and potentially sender name or message preview visible to Apple or Google.
- Maximum convenience -- visible notification without opening the app.
- Clearly marked as the least private option in the UI.

**Required disclosure at opt-in:**

> "Notification content and timing metadata are processed by Apple/Google infrastructure."

This disclosure must be presented and acknowledged before the tier is activated.

**Tier 4 content configuration (user-controlled):**

| Content level | What APNs/FCM sees |
|--------------|--------------------|
| Minimal | "New message" (no sender, no preview) |
| Standard | Sender name + "New message" (no preview) |
| Full | Sender name + message preview |

More content equals more convenience equals more metadata exposure. The UI labels these options honestly.

### 14.5 Platform Defaults

| Platform | Default tier | Background delivery at Tier 1 | Recommended upgrade path |
|----------|-------------|------------------------------|--------------------------|
| Android | Tier 1 | Yes (persistent connection) | Tier 2 (self-hosted push) |
| iOS | Tier 1 | No (active/foreground only) | Tier 3 (silent push) or Tier 4 |
| Desktop (Linux/macOS/Windows) | Tier 1 | Yes (persistent connection) | Tier 2 (self-hosted push) |

**iOS background limitation** must be surfaced honestly when the user first installs on iOS:

> "Mesh Infinity can deliver messages when the app is open. To receive messages in the background, you can optionally enable Apple push notifications -- Apple will see when you receive notifications but not their content."

### 14.6 Notification Content Model

Regardless of delivery tier, the notification content hierarchy is:

```
Tier 1/2/3 -- what the delivery mechanism sees:
  Silent wake signal only -- no content.

Tier 4 -- what APNs/FCM sees (configurable per §14.4):
  Minimal: "New message" (no sender, no preview)
  Standard: Sender name + "New message" (no preview)
  Full: Sender name + message preview
```

The message itself is always delivered via the encrypted mesh channel, never via the notification infrastructure.

### 14.7 Priority and Batching

Priority levels (`Urgent`, `High`, `Normal`, `Low`) affect each tier differently:

- **Tier 1:** How quickly the app processes incoming tunnel traffic.
- **Tier 2/3:** Whether a push wake is sent immediately or batched.
- **Tier 4:** APNs/FCM priority setting (affects delivery speed and battery cost).

**Batching:** `Normal` and `Low` priority notifications are batched -- the app wakes once for multiple pending messages rather than once per message. This reduces battery cost and reduces timing metadata granularity for Tiers 3 and 4.

### 14.8 Fundamental Principle

Notifications are not messages. They are delivery hints. A notification tells the device "you have something to pick up." The actual content always travels via the four-layer encryption scheme (§7.1) over the mesh. No notification tier changes this property.

---

## 15. Security Policies and Hardening

This section covers cross-cutting implementation requirements that enforce security properties regardless of user behaviour. The name "Security Policies and Hardening" distinguishes this from the cryptographic primitives defined in §3 and the operational security requirements defined in §16.

### 15.1 SecureBytes / Key Material Handling

**Scope of the SecureBytes requirement:**

Key material is defined functionally: anything that participates in a cryptographic operation producing key material IS key material. This includes:

- Long-term identity keypairs (root keypair, mask keypairs)
- Derived session keys
- HKDF inputs (`ikm`), outputs (`okm`), and salts when used in key derivation
- Intermediate Diffie-Hellman values
- Double Ratchet chain keys and message keys
- WireGuard PSK values (§3.2, §5.1)
- PIN-derived encryption keys (§3.10)
- Any ephemeral keypairs generated for a session

The definition is not structural -- it does not matter whether something is labelled "key." If it is used in key derivation, it is key material and must be held in `SecureBytes` wrappers that zeroize on drop.

**`SecureBytes` wrapper requirements:**

- Explicit zeroing on `Drop`
- Does not implement `Clone` or `Debug` to prevent accidental copies or logging
- `mlock` / `VirtualLock` is used to prevent sensitive pages from being swapped to disk

**FFI boundary -- explicit prohibition:**

Key material never crosses the FFI boundary to Flutter under any circumstances. The only key-derived data that may cross FFI is public key material for display purposes only (pairing QR codes, verification display codes, peer ID display). No private key material, no derived secrets, no intermediate values. This is a hard architectural rule enforced by the Rust backend. Flutter receives only pre-validated, display-safe data derived from public key material.

**Memory locking -- per platform:**

| Platform | Memory locking mechanism | Additional protections |
|----------|------------------------|----------------------|
| **Linux** | `mlock()` on pages containing key material. `mlockall(MCL_CURRENT \| MCL_FUTURE)` for the key management process in server-mode. | Prevents key material from being swapped to disk. |
| **macOS** | `mlock()` available, same as Linux. | `madvise(MADV_NOCORE)` on key material pages prevents inclusion in core dumps. |
| **iOS** | Keys stored in Secure Enclave (where supported) for long-term material. | `madvise(MADV_NOCORE)` equivalent for in-memory key material. Hardware-backed key storage via Secure Enclave; in-memory material must still be explicitly protected. |
| **Android** | Hardware-backed keys via Android Keystore for long-term material. | `madvise` equivalent via Android's memory protection APIs. `MADV_NOCORE` equivalent prevents core dumps. |
| **Windows** | `VirtualLock()` on key material pages (equivalent to `mlock()`). | `SetProcessWorkingSetSize()` to prevent working set trimming of key material pages. |

Memory locking is not optional -- it is a security requirement on all platforms that support it.

### 15.2 Ratchet Rotation Policy

The Double Ratchet (§7.0) advances automatically with every message. There is no timer-based or message-count-based rotation threshold. The ratchet is self-healing: a missed DH ratchet step is caught up automatically on the next received message carrying a new ratchet public key.

For streaming sessions (§7.3), rekeying is counter- and time-bounded: mandatory re-handshake at counter 2^48 or 1 hour, whichever comes first.

**Abandoned ratchet state cleanup:**

An X3DH session initiated but never responded to creates pending ratchet state on disk. This accumulates without cleanup. Lifecycle policy:

- If vanishing messages is enabled for the conversation: pending ratchet state expires on the same timer as the vanishing messages setting.
- **Hard cap:** 1 year from initialisation regardless of vanishing messages setting.
- After cap: pending ratchet state is deleted; the X3DH initiation is treated as failed.
- A new X3DH initiation is required to establish a session after cleanup.

**Killswitch and ratchet state:**

The killswitch (§3.9) broadcasts Self-Disavowed before wiping. Peers who receive the Self-Disavowed announcement must:

1. Stop advancing their ratchet for the old identity.
2. Discard pending outbound messages for the old identity.
3. Remove the old identity's ratchet state from local storage.

The new post-wipe identity starts with completely clean ratchet state. No continuity between old and new identity through ratchet state exists. The Self-Disavowed broadcast is the coordination mechanism -- peers handle their own cleanup independently.

### 15.3 Forward Secrecy

**PFS applies to encrypted content only.**

Forward Perfect Secrecy is a cryptographic property -- it applies to data that is actually encrypted. The "Secrecy" in PFS is literal. PFS cannot be claimed for metadata, network map entries, public profile data, or any information that was never secret to begin with.

**Correct PFS scope:**

| Data type | PFS applies | Mechanism |
|-----------|------------|-----------|
| Message content | Yes | Double Ratchet provides PFS per message |
| Private profile data | Yes | Exchanged via encrypted session, covered by session PFS |
| Trusted-channel communications | Yes | Covered by Double Ratchet PFS |
| Network map entries | No | Never encrypted to begin with |
| Public profile data | No | Public by definition |
| Communication metadata (who talked to whom, when) | No | Separate concern |

**Metadata minimisation is a separate property:**

The persistent tunnel model (§6) generates as little metadata as possible in the first place. Constant cover traffic, uniform packet sizes, and timing jitter minimise what metadata exists to be exposed. The goal is "negligible metadata generated," not "metadata protected by PFS."

> Forward secrecy (§15.3) applies to encrypted message content and trusted-channel communications via the Double Ratchet protocol. It does not apply to network metadata, routing information, or public data. Metadata minimisation is addressed separately via the persistent tunnel model (§6) and traffic obfuscation (§15.4).

These are distinct security properties. The spec must not conflate them. Claiming PFS for metadata that was never secret is misleading and dangerous -- users who believe PFS protects their communication graph are dangerously wrong.

### 15.4 Traffic Padding and Jitter

Padding and jitter are applied at two distinct layers addressing two distinct threat models.

#### 15.4.1 Tunnel-Level Padding and Jitter (Outer Tunnel)

**Threat model:** Observers outside the mesh -- ISPs, network monitors, anyone watching wire traffic between mesh nodes.

**Defence:** Persistent outer WireGuard tunnels maintain constant-rate traffic with uniform packet sizes. Jitter decorrelates tunnel traffic timing from actual communication events. Cover traffic fills gaps when no real traffic exists.

Properties:

- **Constant rate** -- observer sees consistent traffic volume regardless of actual communication.
- **Uniform packet size** -- observer cannot infer message size from packet size.
- **Cover traffic mixed continuously** -- no silence periods that reveal inactivity.
- **Timing decorrelated** -- burst patterns from actual communication are hidden.

This operates at the outer tunnel layer before inner tunnel packets are encapsulated.

#### 15.4.2 Packet-Level Padding and Jitter (Inner Tunnel)

**Threat model:** Unknown relay nodes inside the mesh that are forwarding inner tunnel traffic.

**Defence:** Inner tunnel packets are padded to fixed size tiers and sent with jitter before being handed to the outer tunnel. A relay node that can observe inner tunnel packet sizes and timing cannot infer communication patterns.

Properties:

- **Packet size bucketed to fixed tiers** -- relay nodes see uniform sizes within a tier.
- **Send timing jittered** -- relay nodes cannot correlate inner packet timing to communication events.
- **Applied before outer tunnel encapsulation** -- outer tunnel further obscures already-obfuscated inner traffic.

#### 15.4.3 Combined Property

- **Outside observer (ISP, monitor):** Sees outer tunnel cover traffic and a constant-rate, uniform-size stream.
- **Inside relay node:** Sees padded, jittered inner tunnel packets with no correlation to actual communication events.
- Both layers are needed: defeating one alone is insufficient.

#### 15.4.4 Implementation Order

1. Inner tunnel payload generated.
2. Packet-level padding applied (pad to nearest size tier).
3. Packet-level jitter applied (delay within configured window).
4. Packet handed to outer tunnel.
5. Outer tunnel cover traffic and rate control applied.
6. Transmitted on wire.

#### 15.4.5 Size Tiers for Packet-Level Padding

Configurable; defaults:

| Tier | Size (bytes) | Typical content |
|------|-------------|-----------------|
| 1 | 256 | Control messages, ACKs |
| 2 | 1024 | Short text messages |
| 3 | 4096 | Medium messages |
| 4 | 16384 | Large messages, file chunks |
| 5 | 65536 | Bulk transfers |

Each payload is padded up to the next tier boundary. A 300-byte message becomes 1024 bytes. A 5000-byte payload becomes 16384 bytes. Payloads larger than 65536 bytes are split into 65536-byte chunks, each padded independently.

#### 15.4.6 Timing Jitter

For messages at priority `Normal` or `Low` (§14.1), outbound transmission is delayed by a uniformly random value in the range **[0, 250 ms]**. For `High` priority, jitter is **[0, 50 ms]**. For `Urgent` (calls, pairing), jitter is zero. Jitter is applied independently per message; correlating two jittered transmissions requires observing the same message at multiple hops simultaneously.

### 15.5 Potential Extremes Security Menu

These are opt-in advanced security features, never defaults. Each requires specific, honest UI warnings -- not generic "this reduces privacy" language, but exactly *how* and *what an adversary learns*.

**Pre-committed distress message (dead man's switch):**

- A Self-Disavowed announcement is pre-signed and distributed to store-and-forward nodes.
- Periodically, the user's device sends a signed cancellation; if cancellation stops, the distress message releases.
- Viable because messages are stored by any capable node across all transports (including non-TCP/IP) -- an adversary cannot reliably suppress release.

**Mandatory UI warning:**

> "This feature sends periodic signals confirming you are safe. If the signals stop, your contacts are notified automatically. However: (1) The periodic signal itself is observable -- an adversary monitoring your network can see that you send regular heartbeat-like messages. (2) A false positive (you lose device access without being in danger) will trigger the distress message. (3) A stopped signal tells an adversary *when* something happened."

**Full cancellation protocol design is deferred (see Appendix B, DQ-4).**

**Periodic heartbeat / liveness signal:**

- Sends periodic signed liveness proofs to designated contacts.
- Absence of heartbeat triggers a configurable alert at the contact's end.

**Mandatory UI warning:**

> "Heartbeat signals create a regular timing pattern that can be used to fingerprint your device activity. An adversary performing timing analysis can use the heartbeat interval and pattern to identify you. Use this only when the liveness benefit outweighs the fingerprinting risk."

**Anonymous profiles (§9):**

Anonymous profiles are a double-edged addition to the security menu. They enable legitimate whistleblowing, research, and operational separation, but also enable insider threats to hide their identity from trusted peers. The mandatory warning at creation (§9) must be part of this menu.

### 15.6 Network Security

- WireGuard handshake authentication on every direct peer connection prevents impersonation.
- Transport-layer encryption (WireGuard) is present even when tunnelled over Tor or I2P -- defence in depth.
- Rate limiting: inbound connection attempts and message processing are rate-limited per peer ID to mitigate flood attacks.
- Connection validation: peer IDs are verified against the network map on every handshake; connections from unknown peer IDs are treated as `Untrusted` (Level 0).
- No persistent logs of connection events, message routing decisions, or peer activity.
- No analytics, telemetry, crash reporting, or usage metrics of any kind.
- Metadata minimisation: routing headers carry only what is necessary; sender identity is not included in forwarded packets.
- Plausible deniability at message level (HMAC), group membership level (ring signatures), and connection level (wrapper nodes, ephemeral addresses).
- Emergency data destruction via killswitch (§3.9) with cryptographic overwrite of key material.

---

## 16. Operational Security

This section specifies how the system surfaces security state to users in a way that enables good decisions. A technically correct system with bad security UX fails the people who need it most.

### 16.1 Foundational Principle

**Mesh Infinity is a chat app first.**

The default experience must look and feel like Signal or WhatsApp. You open it, you message people, it works. Security happens invisibly. Most users should never need to think about threat contexts, ratchets, or routing planes.

This is not a compromise -- it is a security requirement. **Ubiquity IS the security model.** If only activists and journalists use Mesh Infinity, every Mesh Infinity user is suspicious by association. If millions of people use it for gaming communities, family chats, and Minecraft servers, the people who genuinely need protection are invisible in the crowd. Growing the user base directly improves security for the people who need it most.

Every operational security UX decision must be evaluated against: "Can my non-technical friend who just wants to message people understand this?"

### 16.2 Plain Language Requirement

All security-related user-facing text must pass the plain language test. Technical accuracy is required; technical jargon is not.

| Technical | Plain language |
|-----------|---------------|
| "LoSec mode reduces anonymisation set via shortened inner tunnel path" | "Faster connection, slightly less private. Fine for everyday use." |
| "APNs silent push exposes notification timing metadata to Apple infrastructure" | "Apple will know when you get messages, but not what they say or who they're from." |
| "This connection uses an unverified public address without trusted-channel establishment" | "You haven't verified this person's identity yet." |
| "Self-Disavowed state broadcast to network" | "Your emergency erase has been activated. Your contacts have been notified." |
| "Cover traffic contributing to mesh anonymity set" | "Your app is sending privacy traffic to protect everyone on the network." |
| "Forward Perfect Secrecy via Double Ratchet protocol" | "Each message has its own encryption key. Old keys are automatically deleted." |
| "Inner tunnel via nested WireGuard through persistent outer tunnels" | "Your messages travel through multiple layers of encryption." |

The spec does not prescribe UI layouts or visual design -- those are frontend concerns. The spec requires that certain information be communicated in language meeting this standard.

### 16.3 Ambient State Disclosures and Onboarding

**Ambient state** disclosures describe things that are always true about the system. They are disclosed during onboarding, available in settings and help at any time, and not repeated on every action.

The following must be clearly communicated before a user first sends a message:

1. **Cover traffic:** "Your app sends extra data to keep your activity private. This uses some battery and data -- about X MB per day on average."
2. **Relay participation:** "Your device may help route other people's encrypted messages. You can't read them, and neither can anyone else."
3. **Store-and-forward:** "When your contacts are offline, their messages wait on trusted nodes until they reconnect."
4. **No central server:** "Mesh Infinity has no central servers. Your messages travel through the network itself."
5. **Trust model basics:** "You control who can contact you and what they can see. Strangers start with minimal access."

These are not scary warnings -- they are honest explanations of how the system works. Tone should be matter-of-fact and positive.

### 16.4 Event-Based Disclosures

**Event-based** disclosures describe something that just happened and the user needs to know now. They are surfaced via notification, indicator, or modal at the time of the event, with appropriate urgency based on severity, and actionable where possible.

#### 16.4.1 Security State Changes

- **Threat context change** (user-initiated): confirm the change.
- **Connection mode change to LoSec:** persistent amber indicator for the duration of the session.
- **Connection mode change to Direct:** persistent red indicator + full-screen warning (§6.7), persists during session.
- **Trusted peer becomes Disavowed:** notification: "A contact may be compromised."
- **Trusted peer becomes Compromised:** urgent notification: "A contact's device is compromised."
- **Key change approval pending:** actionable notification -- approve or decline.
- **Trust promotion request received:** actionable notification.
- **New device added to a known identity:** notification: "[Name] added a new device."

#### 16.4.2 Privacy-Reducing Actions (Require Acknowledgment Before Proceeding)

- Enabling APNs/FCM notifications (any tier above Tier 1).
- Enabling read receipts or typing indicators.
- Enabling LoSec for a service (first time per service).
- Activating direct mode (full-screen warning, §6.7).
- Cross-profile linkage (warning: irreversible).
- Sharing private profile (warning: permanent).
- Joining a Public network via QR.
- Using link share pairing (contextual warning per §8.2 threat profiles).

#### 16.4.3 Irreversible Actions (Require Explicit Confirmation)

- Public profile erasure.
- Compromised declaration.
- In-band key change approval (additional friction per §4.6).
- Killswitch activation.

#### 16.4.4 System Events (Informational, No Action Required)

- Self-Disavowed broadcast sent.
- Store-and-forward nodes holding messages for offline contacts.
- Transport migration (ambient indicator, not modal).

### 16.5 Metrics Screen

A dedicated metrics screen makes abstract security properties tangible. This is not a debugging tool -- it is a transparency tool that shows users the system working on their behalf. **Plain language labels throughout.**

**Privacy metrics:**

| Metric | Display label | Source |
|--------|-------------|--------|
| Cover traffic sent today / this week | "Privacy traffic" | Tunnel-level cover traffic counters |
| Cover packets sent vs real packets ratio | "Privacy ratio" | Packet counters |
| Peers routed for today | "Helping route messages" | Relay activity counter |
| Active outer tunnel connections | "Secure connections" | Tunnel manager state |

**Network metrics:**

| Metric | Display label | Source |
|--------|-------------|--------|
| Connected peers (direct) | "Connected friends" | Transport manager |
| Reachable peers (via mesh) | "Reachable contacts" | Routing table |
| Active transports in use | "Active transports" | Transport manager |
| Store-and-forward messages pending delivery | "Messages waiting for delivery" | S&F queue |

**Security state:**

| Metric | Display label | Source |
|--------|-------------|--------|
| Current threat context level | "Security level" | Global threat context |
| Active LoSec or Direct sessions | "Active fast connections" | Session manager |
| Pending approvals | "Pending approvals" | Key change / trust promotion queues |
| Recent security events (last 7 days) | "Recent security events" | Event log |

### 16.6 What the System Must Never Do Silently

These are hard prohibitions -- not defaults that can be changed, but behaviours that must never occur regardless of configuration:

1. Auto-downgrade security level for any connection.
2. Auto-accept any agreement, permission, or terms.
3. Auto-share location or presence information.
4. Auto-join any network or group.
5. Auto-enable any notification tier above Tier 1.
6. Auto-link profiles across contexts.
7. Auto-approve any key change.
8. Send any identifying information to any third party without explicit user awareness.
9. Enable any biometric authentication for security-critical paths (§3.10).

### 16.7 Onboarding Security Requirements

New users must complete a minimal security onboarding before first use:

1. **Ambient state disclosures** (§16.3) -- presented simply, not as a wall of text.
2. **PIN setup prompt** -- strongly encouraged, skippable with acknowledgment.
3. **Threat context selection** -- Normal / Elevated / Critical with plain-language explanations.
4. **Contact import or first pairing** -- gets the user connected immediately.

Onboarding must not:

- Require technical knowledge to complete.
- Present security choices as gatekeepers to using the app.
- Use fear-based language.
- Be skippable entirely (ambient disclosures are mandatory; the rest can be deferred).

---

## 17. Performance

Performance targets in Mesh Infinity cannot be defined against clearnet baselines -- the comparison is Mesh Infinity vs "being surveilled," not Mesh Infinity vs direct TCP. This section defines the security floor that optimisations cannot cross. Implementation decides specific targets above that floor based on real measurements.

LoSec mode (§6.7) is the correct tool for performance-sensitive sessions -- not disabling security mechanisms globally. LoSec is configured per-session, not globally.

### 17.1 Tunnel Count Model

**Recommended baseline (mobile, anonymity-prioritising users):** 2--4 tunnels.

This is a recommendation, not a hard limit. It represents the "blend into the crowd" setting -- enough tunnels to maintain mesh presence and cover traffic without standing out as a high-participation node.

**Above baseline:** Valid and beneficial. A server-mode node with gigabit connectivity and no battery constraints should have as many tunnels as makes sense for its capacity. High-participation nodes strengthen the anonymity set for everyone -- including the mobile user with 2 tunnels. The mesh is healthier when capable nodes contribute more.

**Below 2 tunnels:** Only acceptable when the user has explicitly disconnected. Not an automatic optimisation.

**ThreatContext guidance:**

| Threat context | Tunnel count guidance | Rationale |
|---------------|----------------------|-----------|
| `Critical` | Strongly prefer 2--4 | Minimise footprint, maximise anonymity |
| `Elevated` | 2--6 | Moderate participation |
| `Normal` | User/operator decides based on capacity -- no upper limit | Performance and contribution optimised freely |

**The socialist mesh principle:**

Different users have different capacities and needs. A server-mode node contributing 50 tunnels and routing for many peers is making the mesh better for everyone. Anomalous high-participation behaviour is acceptable and beneficial when:

- The user understands and accepts the reduced anonymity that comes with high visibility.
- The node is not prioritising personal anonymity.
- The increased participation provides real value to the mesh (more routing, more store-and-forward, more cover traffic for others).

"From each according to their ability" -- the mesh benefits from nodes that can do more contributing more.

### 17.2 Adaptive Cover Traffic Model

Cover traffic adapts to device state and active tunnel count. It never reaches zero -- zero cover traffic is itself a signal.

**Activity states and cover traffic:**

| Device state | Target tunnels | Cover traffic rate | Notes |
|-------------|---------------|-------------------|-------|
| Active conversation | 3--4 | Full rate | User is communicating; privacy matters now |
| App foreground, idle | 2--4 | Moderate | User may start a conversation at any moment |
| App backgrounded, phone in use | 2--3 | Reduced | Ambient activity sufficient |
| Phone idle / screen off | 2 | Minimal | Maintain mesh presence, avoid idle signal |
| Low battery mode | 2 | Minimal | User-visible indicator; never zero |
| Explicit disconnect (user-initiated) | 0 | Zero | User decision; clean disconnection, not a leak |

**Transition behaviour:** State transitions must be gradual -- not abrupt step changes that themselves become timing signals. "Screen off" followed by a sudden traffic drop is an attack surface. "Screen off" followed by a gradual drift to the minimal baseline over several minutes is correct.

**Cover traffic distribution:** Cover traffic is distributed across all active tunnels. 2 active tunnels means cover traffic is split across 2. 4 active tunnels means it is split across 4. Per-tunnel rate adjusts so total statistical plausibility is maintained regardless of tunnel count.

### 17.3 Tunnel Lifecycle

Tunnels are not permanent -- they have a lifecycle tied to actual usage and mesh conditions.

**Establishment:** New tunnels are established when:

- Routing discovers a useful new peer.
- Cover traffic diversity would benefit from another path.
- Active conversation would benefit from redundancy.
- Node is below its target tunnel count for current activity state.

**Teardown:** Tunnels are wound down when:

- No real traffic for an extended idle period (configurable, default: 30 minutes).
- Node is above its target tunnel count.
- Peer has become unreachable.
- Battery/power saving requires reduction.

**Reactivation:** Wound-down tunnels reactivate quickly when needed -- within seconds for a peer that was previously active. The tunnel state is remembered even after teardown, allowing fast re-establishment.

**Normal lifecycle churn is cover:** Routine tunnel establishment and teardown is normal mesh behaviour -- not a signal. A node with 50 tunnels establishing and tearing them down as peers come and go is indistinguishable from normal high-participation behaviour. This is intentional -- lifecycle churn adds to the ambient noise.

### 17.4 LoSec as Per-Session Optimisation

LoSec mode (§6.7) is the correct tool when a specific session needs lower latency or higher bandwidth. Key properties:

- Configured per-session, not globally.
- Only that session uses the shorter path.
- All other mesh activity continues at the appropriate security level for the current device state.
- LoSec is not "I've decided to be less secure" -- it is "this Minecraft session can use a shorter path."

The security model for the rest of the node's activity is unaffected by a LoSec session running simultaneously.

### 17.5 Security Floor

These constraints are non-negotiable regardless of battery state, user settings, or performance requirements:

1. **Cover traffic never reaches zero** -- even in minimal state, some cover traffic must flow.
2. **Padding cannot be disabled** -- packets must be padded to size tiers (§15.4) regardless of battery or performance mode.
3. **Jitter cannot be disabled** -- timing normalisation is required even in minimal state.
4. **Inner tunnel cannot be bypassed** -- nested WireGuard is not optional for standard mesh sessions.
5. **Minimum 2 tunnels** -- cannot drop below 2 except on explicit user-initiated disconnect.
6. **State transitions must be gradual** -- no abrupt traffic changes that create timing signals.
7. **Explicit disconnect is the only zero state** -- automatic reduction to zero is never permitted.

Any performance optimisation that would violate these constraints is prohibited. The implementation may optimise freely above this floor.

### 17.6 Network Performance

- Active WireGuard tunnels to frequently contacted peers are kept alive and pooled.
- Message batching: multiple small messages to the same peer may be batched into a single WireGuard packet when not latency-sensitive.
- MTU discovery per transport: BLE and RF transports have much smaller MTUs than TCP; the transport layer negotiates and fragments accordingly.
- QoS prioritisation: voice/video packets are marked urgent and processed ahead of file transfer and background sync traffic.
- Bandwidth estimation: the transport layer maintains per-peer bandwidth estimates using a passive three-class system (`Low`, `Medium`, `High`), refined by observation of actual transfers, with no active probing to eliminate regular-interval fingerprints.

### 17.7 Memory and CPU

- Async/await throughout the Rust backend via Tokio; no blocking the event loop on I/O.
- Work-stealing thread pools for CPU-bound cryptographic operations (encryption, signing, ratchet computation).
- SIMD acceleration: ChaCha20 and BLAKE3 have SIMD-optimised paths detected at runtime; AES-GCM uses hardware AES instructions where available.
- Lazy initialisation of transport backends: Tor client, I2P router, Bluetooth stack are initialised only when first needed.
- Memory pools for frequently allocated fixed-size structures (WireGuard packets, message headers) to reduce allocator pressure.

### 17.8 Flutter UI Performance

- All backend calls are asynchronous via the FFI event model; the UI never blocks on Rust operations.
- Widget lifecycle is managed explicitly: `TextEditingController`, `ScrollController`, `StreamSubscription`, and similar objects are disposed in `State.dispose()` to prevent leaks.
- Image and media caches are explicitly bounded (configurable; default 200 MB for images, 500 MB for video thumbnails) with LRU eviction.
- Message lists use lazy-loading with virtualised rendering (`ListView.builder`); only visible messages are rendered.
- Large media is loaded lazily and cached to disk; thumbnails are generated at display size and cached separately from originals.
- Dart's garbage collector is invoked explicitly after large operations (e.g., decrypting a large file) via `dart:developer`'s `NativeRuntime` hooks to avoid GC pauses during active UI interaction.

---

## 18. Platform and Backend Architecture

### 18.0 Rust-Authoritative Principle

**Foundational architectural rule:** Rust is the authoritative layer. Flutter is a view layer -- it renders what Rust tells it to render. Every security decision, every trust decision, every cryptographic operation, every state change happens in Rust. Flutter displays state but never determines it.

**Corollaries:**

- Flutter may never initiate a security-critical operation directly -- it requests; Rust decides and executes.
- If Flutter and Rust disagree on state, Rust wins -- always.
- Flutter receives only pre-validated, display-safe data across the FFI boundary.
- No security property depends on Flutter behaving correctly -- a compromised or buggy UI cannot compromise security.
- This principle is the source of: FFI key material prohibition (§15.1), PIN input bypassing Flutter (§3.10), all validation in Rust before FFI (§4).

**FFI model:** Rust exposes a defined FFI surface. Flutter calls into Rust for all operations. Rust calls into Flutter only to deliver display-safe data for rendering. The FFI surface is the security boundary.

**One codebase:** Flutter is cross-platform. There is no Swift code, no Kotlin code, no platform-specific native code for application logic. FFI goes Rust to Flutter on all platforms. Platform-specific native code exists only for platform integration (VPN APIs, keystore access, notification registration). Rust is authoritative on all platforms.

### 18.1 Single-Process Architecture

Mesh Infinity runs as a single process. The Rust backend and Flutter UI coexist in one process space.

**Rationale:** IPC is an attack surface. IPC is impossible on some platforms (iOS). Single process eliminates privilege escalation between components and the trust decisions IPC requires.

**Tradeoff:** A crash in any component crashes everything. Accepted -- a crashed app reveals less than a compromised IPC channel.

### 18.2 Self/Mask Identity Model

**Core concept -- self and masks:**

The **self** is the actual person -- the core cryptographic identity, the root of all trust relationships, the persistent entity that underlies all mesh activity. The self is never directly exposed to the mesh. It is the user as they actually are.

**Masks** are contextual presentations -- what the self shows in a given context. A mask is not a separate identity or account. It is a face the self wears. Examples:

- **Professional mask** -- used with work contacts, professional groups.
- **Personal mask** -- used with friends and family.
- **Operational mask** -- used in high-security contexts.
- **Public mask** -- the global public profile (opt-in, may not exist).
- **Per-group masks** -- specific presentations within specific groups.

The mask metaphor comes from real human social behaviour -- people naturally present differently in different contexts while remaining the same person. The app models this honestly rather than forcing a single coherent public identity.

**Simultaneous multi-mask operation:**

The self can wear multiple masks simultaneously. A user can:

- Receive a message through their professional mask.
- Reply through their personal mask.
- Participate in a group through a per-group mask.
- All at the same time, in the same app session.

The backend manages this transparently. The UI presents whichever mask is contextually relevant -- the conversation determines which mask is shown -- with easy navigation to view or switch between masks.

**What is shared across all masks (belongs to the self):**

- Core cryptographic root keypair -- never exposed to the mesh.
- Trust graph -- trust levels travel with the self, not with individual masks (§9).
- Network map -- the self's complete view of the mesh.
- Store-and-forward subscriptions -- all masks receive via the shared S&F infrastructure.
- Key store -- all mask keypairs stored in the single platform keystore.
- Threat context -- a global setting for the self, not per-mask.

**What is specific to each mask:**

- Address(es) -- each mask has its own mesh address(es).
- Outbound signing keypair -- messages are signed by the mask's key, not the self's root key.
- Profile data -- name, avatar, bio appropriate to that context.
- Group memberships -- which groups use this mask.
- Preauth key -- each mask has its own preauth key.
- Per-context trust expressions -- how the self presents trust through this mask.

**Root keypair isolation:**

The root keypair signs nothing on the mesh directly. All mesh-facing operations use mask keypairs. The root keypair's only function is to derive and authorise mask keypairs. Compromising any mask keypair reveals nothing about the root or other masks.

**Mask keypair derivation:**

```
mask_keypair = HKDF-SHA256(
    ikm  = root_secret,
    info = "meshinfinity-mask-v1" || mask_id,
    salt = root_public
)
```

Each mask has a cryptographically independent keypair. No observable relationship between mask keypairs exists. Deriving a mask keypair from the root is a one-way operation -- the root cannot be recovered from the mask keypair.

**Anonymous masks** are architecturally isolated from the self. They do not share the trust graph, do not share the network map, and their keypairs are generated independently (not derived from the root). The backend enforces this isolation -- there is no API call that links an anonymous mask to the self. The user can manage anonymous masks in the app, but the app itself cannot prove the linkage. This is the security guarantee.

**Backend data model:**

```rust
Self {
    root_keypair:     RootKeypair,         // never used directly on mesh
    masks:            Vec<Mask>,           // all contextual identities
    trust_graph:      TrustGraph,          // shared across all masks
    network_map:      NetworkMap,          // shared across all masks
    key_store:        PlatformKeyStore,    // shared storage for all mask keys
    threat_context:   ThreatContext,       // global setting
    anonymous_masks:  Vec<AnonymousMask>,  // isolated -- not linked to self
}

Mask {
    mask_id:          [u8; 16],
    name:             String,              // user-facing label
    addresses:        Vec<DeviceAddress>,
    keypair:          MaskKeypair,         // derived from root, independent on mesh
    profile:          MaskProfile,
    groups:           Vec<GroupId>,
    preauth_key:      PreAuthKey,
    active_sessions:  HashMap<PeerId, Session>,
}
```

### 18.3 Rust Backend Module Structure

Single Rust crate (`mesh-infinity`), compiled as `cdylib` / `staticlib` / `rlib` depending on platform:

```
src/
  lib.rs           -- top-level re-exports; module declarations
  runtime.rs       -- RuntimeConfig: node mode, UI-enabled flag, startup parameters

backend/
  lib.rs           -- public API surface re-exported from submodules
  service/
    mod.rs         -- MeshInfinityService: top-level service orchestrator
    types.rs       -- service-facing data types (Message, PeerSummary, Settings, ...)
    chat.rs        -- messaging: send/receive, rooms, sync
    files.rs       -- file transfer: initiation, chunking, progress, resume
    settings.rs    -- settings read/write
    peers.rs       -- peer management, trust operations
    trust.rs       -- trust level management, WoT propagation
    hosted.rs      -- hosted service proxy management
    masks.rs       -- mask management: creation, switching, derivation, profile resolution
  auth/
    identity.rs    -- Identity struct, IdentityManager: generate, load, sign, verify
    persistence.rs -- IdentityStore: keyfile encryption, save, load, destroy
    wot.rs         -- WebOfTrust: trust graph, endorsements, propagation
  crypto/
    backup.rs      -- BackupManager: EncryptedBackup creation and restore
    session.rs     -- session key derivation, ratchet
    signing.rs     -- message signing and verification helpers
    zkp.rs         -- Sigma protocol, ring signature primitives
    lib.rs         -- SecureBytes wrapper, key material zeroization
    x3dh.rs        -- X3DH session initiation
    double_ratchet.rs -- Double Ratchet implementation
    signal_session.rs -- Combined X3DH + DR session manager
    prekeys.rs     -- Pre-key bundle management and rotation
    message_crypto.rs -- Four-layer message encryption/decryption
    pfs.rs         -- Forward secrecy utilities
    deniable.rs    -- Deniable authentication (HMAC-based)
    vault.rs       -- Encrypted vault storage key derivation
  transport/
    mod.rs         -- TransportManager: selection, health, pooling
    core_manager.rs -- Transport solver: constraint elimination, scoring, composition
    wireguard.rs   -- WireGuard peer management
    tor.rs         -- Tor/arti client integration
    i2p.rs         -- I2P/SAM client
    bluetooth.rs   -- BLE GATT service
    rf.rs          -- Meshtastic serial integration
    clearnet.rs    -- Direct TCP/UDP
  discovery/
    lib.rs         -- Discovery module root
    catalog.rs     -- Service catalog / index
    map.rs         -- NetworkMap: storage, merge, gossip
    gossip.rs      -- GossipEngine: map exchange, merge, dedup, rate limiting, WoT key validation
    announce.rs    -- ReachabilityAnnouncement: generation, forwarding
    bootstrap.rs   -- startup bootstrap logic
    mdns.rs        -- mDNS (scoped to trusted interfaces, disabled in Elevated/Critical)
  core/
    mesh/
      routing.rs   -- hop-by-hop routing table, next-hop selection, two-plane routing
      wireguard.rs -- Nested WireGuard tunnel management (outer + inner tunnels)
    store_forward.rs -- store-and-forward queue (server mode)
  storage/
    mod.rs         -- module root
    blob_store.rs  -- BlobStore<T>, CollectionStore<K,V>: encrypted vault I/O
  ffi/
    lib.rs         -- all #[no_mangle] pub extern "C" functions
    context.rs     -- MeshContext: heap-allocated state held across FFI calls
    events.rs      -- async event push to Flutter
    error.rs       -- error code mapping

platforms/
  android/         -- Gradle project, VPN Service, JNI bridge
  apple/           -- Xcode project (Runner: macOS, RunnerIOS: iOS), Network Extension
  linux/           -- CMake + GTK runner
  windows/         -- CMake runner + WinTun, NSIS installer

frontend/          -- Flutter UI project (pubspec.yaml, lib/, assets/)
assets/            -- shared assets: logo.png, icons
```

### 18.4 Runtime Modes

The application is always built as a single binary bundle. The mode is determined at startup:

| Startup Condition | Default Mode |
|------------------|--------------|
| UI enabled | `Client` |
| UI enabled + dual-mode configured | `Dual` |
| UI disabled (headless/server) | `Server` |

Modes:

- **Client**: Full UI, messaging, VPN. Does not relay for the network by default. Connects to server nodes for store-and-forward.
- **Dual**: Full UI plus active mesh routing; relays messages for other peers. Contributes to the mesh as both a user node and a routing node.
- **Server**: No UI; runs as a mesh infrastructure node. Can be configured with any combination of: directory caching, store-and-forward, offline inbox, exit node, hosted services, wrapper node.

Mode can be toggled at runtime via `mi_set_node_mode`. Switching from Client to Server mode requires UI confirmation and disables the UI session.

### 18.5 FFI Boundary

The FFI layer exposes a C ABI consumed by Flutter via `dart:ffi`. Core design rules:

- Rust is the source of truth for all state.
- Flutter is treated as untrusted: it issues intent-based commands and receives display-safe data.
- No key material, plaintext message content, or internal cryptographic state crosses the FFI boundary (§15.1).
- All pointer parameters crossing the boundary are validated before use; null pointers and out-of-range lengths are rejected.
- FFI functions return integer status codes; `mi_get_last_error(ctx)` retrieves the error string for the last failure.
- All strings crossing the boundary are null-terminated UTF-8; lengths are validated.

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

Polling (background isolate):
```
mi_poll_events(ctx: *mut MeshContext) -> *const c_char  // JSON array of pending events
```

### 18.6 Mesh Address Format

Mesh addresses are **256-bit** (8 groups of 8 hexadecimal characters, colon-separated):

```
a1b2c3d4:e5f6a7b8:12345678:90abcdef:01234567:89abcdef:fedcba98:76543210
|_____________ device address (160 bits / 20 bytes) _____________||_ conversation ID (96 bits / 12 bytes) _|
```

- **Device address (160 bits)**: first 5 groups; identifies a specific node endpoint (one of the node's addresses). Addresses belong to masks (§18.2), not directly to the self.
- **Conversation ID (96 bits)**: last 3 groups; identifies a specific conversation or session on that endpoint.
- A service address appends a 32-bit port: `device_address:port32`.

Conversations are uniquely identified by `(source_address, destination_address, conversation_id)`. Multiple concurrent conversations between the same pair of nodes use different conversation IDs and are independently encrypted.

**Human-readable resolution (Mesh DNS):**

Raw hex addresses are used internally and are not intended for human memorisation. A short-name resolution layer maps human-friendly identifiers to raw addresses, operating on an opt-in approval model inspired by Tailscale's subnet route and exit node advertisement system:

- **Short-name advertisement**: A node may advertise a desired short name for one of its addresses (e.g. `alice` or `alice-laptop`). This advertisement is signed with the address keypair and gossiped to the node's trusted peers alongside the address entry.
- **Peer approval**: Receiving peers see the short-name request and individually choose to approve or deny it -- no name is accepted automatically. The approval decision is stored locally and is never gossiped; each peer maintains their own name resolution table.
- **Approved names are local**: Once a peer approves a short name, it is added to that peer's local Mesh DNS table and resolves to the corresponding hex address. Approved names are never re-gossiped as canonical -- they are local bindings only.
- **Conflict handling**: If two peers advertise the same short name, each receiving node resolves the conflict locally (first-approved wins, or user is prompted). There is no global name registry or first-come-first-served reservation.
- **Local pet names**: Any peer may also assign a private local alias to any address; these are never advertised or gossiped, and take precedence over approved short names in the local resolver.
- **Revocation**: An address owner may revoke a previously advertised short name by gossiping a signed revocation; peers that had approved it remove it from their local table.
- **Mesh DNS table**: The resolver checks, in order: (1) local pet names, (2) approved short names, (3) raw hex address. If a short name is unresolved or denied, the full hex address must be used.

### 18.7 Mesh URL Scheme

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

The double-slash after the protocol segment mirrors the `://` convention and makes the address visually distinct from the protocol. The `<address>` is either a raw hex mesh address or a resolved short name / local pet name (see §18.6 Mesh DNS).

URLs with the `pair` protocol are the standard format for all pairing link-share invitations (§8.2). URLs with `http` or `https` are what users share when pointing someone to a mesh-hosted website. The scheme is registered as a deep-link handler on all platforms so that tapping a `meshinfinity://` link opens the app and navigates to the appropriate resource.

### 18.8 Flutter UI Layer

- Flutter is the canonical UI across all platforms; Android is the primary target, iOS and desktop are secondary.
- Slint and SwiftUI are deprecated; any remaining references are archival only.
- Architecture: MVVM with `ChangeNotifier` and `Provider` for reactive state propagation.
- All backend calls are async; the UI registers an FFI event callback and processes backend events on the main isolate.
- No analytics, no third-party SDKs, no cloud service dependencies in the UI layer.
- The UI layer's responsibility is rendering state and issuing intent commands -- never performing business logic, cryptography, or network operations.
- The UI must support the self/mask model (§18.2): each mask has a user-chosen name and visual indicator; the current active mask context is always visible; switching is accessible but not prominent; a "view all masks" screen allows the user to see and manage their complete self.

### 18.9 Encrypted Vault Storage

All persistent data is stored as encrypted blobs. There is no database, no SQL, no queryable structure on disk. This is a deliberate design decision: on-disk data must be opaque to any tool except the running Mesh Infinity process with the correct identity key.

**Format:** Each data collection is a single file with extension `.vault`:

```
[24-byte XNonce][XChaCha20-Poly1305 ciphertext of JSON payload]
```

**Key derivation:** Per-collection encryption keys are derived from the identity master key (the same 32-byte key stored in the platform keystore, see §3.6) via HKDF-SHA256 with domain-separated info strings:

```
collection_key = HKDF-SHA256(
    salt = None,
    ikm  = identity_master_key,
    info = "meshinfinity-storage-v1-<collection_name>",
    len  = 32
)
```

Where `<collection_name>` is one of: `rooms`, `messages`, `peers`, `network_map`, `signal_sessions`, `settings`, `trust_endorsements`, `prekeys`, `file_transfers`.

Compromise of one collection file does not expose others (different derived keys). Compromise of the master key exposes all collections -- but the master key is protected by the platform keystore (§3.6).

**Collections:**

| Collection | Contents | Update frequency |
|-----------|----------|-----------------|
| `rooms.vault` | Room metadata (id, name, last message, unread count) | On every message |
| `messages.vault` | All message history, keyed by room_id + message_id | On every message |
| `peers.vault` | Known peers, trust levels, public keys, last seen | On peer events |
| `network_map.vault` | Full network map (peer entries, transport hints, profiles) | On gossip merge |
| `signal_sessions.vault` | Serialised Double Ratchet session state per peer | On every message |
| `settings.vault` | User settings (transports, privacy, node mode) | On settings change |
| `trust_endorsements.vault` | WoT endorsements and revocations | On trust events |
| `prekeys.vault` | Pre-key pool (SPK + OPK pool) | On key rotation |
| `file_transfers.vault` | Active and completed transfer metadata | On transfer events |

**Write semantics:** Writes are atomic (write to `.vault.tmp`, then `rename` to `.vault`). On crash, either the old or new version is intact -- never a partial write.

**Why not SQLite:** SQLite stores data in a well-documented, universally-readable format. An attacker with disk access gets structured, queryable data with no additional work. The vault format requires the identity master key to read anything -- and the master key is protected by hardware keystores on supported platforms. The trade-off is that the entire collection must be re-encrypted on each write, which is acceptable for the data sizes in a messaging application (even 100k messages serialise to tens of megabytes, encrypting in <100ms on modern hardware).

### 18.10 Mesh-Delivered Updates

Updates are delivered over the mesh itself -- signed by the project's release keypair, verifiable without a central server, distributed via the same store-and-forward and distributed storage infrastructure used for everything else.

This is a design goal, not a current implementation. Supply chain hardening (reproducible builds, signed releases, verification infrastructure) is a priority outside of spec scope.

---

## 19. Plugin System

### 19.0 Plugin API Versioning

The plugin API is versioned:

```
meshinfinity-plugin-api/v1
```

Plugins declare which API version they target. The runtime supports multiple API versions simultaneously for backward compatibility. A plugin targeting v1 gets v1 behaviour even after v2 ships. Breaking changes require a new major version. The runtime never silently upgrades a plugin's API version.

### 19.1 Three Tiers of Building on Mesh Infinity

**Tier 1 -- Service Layer Exposure:**

Any existing TCP/UDP service, with zero mesh awareness required. The service operator configures a local port to mesh address:port mapping via the service registration system (§12.4). The mesh delivers packets; the service handles everything else. A Minecraft server, an HTTP API, an SSH daemon -- any service that listens on a port can be exposed on the mesh with no code changes.

**Tier 2 -- Application Plugins (Mesh-Aware, Sandboxed):**

Plugins consume the Mesh Infinity API surface. They can send and receive messages, participate in groups, access file sharing infrastructure, and register services -- all through the versioned plugin API.

Constraints:

- Cannot access the crypto layer, private keys, or raw transport.
- Plugin identity is a keypair -- the plugin has its own mesh identity, distinct from the user's masks.
- Plugin permissions are granted explicitly by the user at install time and adjustable at any time after install.
- Plugins run in a sandboxed environment; they cannot access the host filesystem, other plugins' data, or Rust backend internals.

**Tier 3 -- Native Applications:**

Built against the Rust backend via FFI. Maximum capability. First-party applications only (Chat and Communities are Tier 3 applications). Third-party Tier 3 access is not available -- the FFI surface is the security boundary, and exposing it to arbitrary code would compromise the Rust-authoritative principle (§18.0).

### 19.2 Plugin Permission Framework

**Core principle:** Plugins operate against a versioned API. The API responds based on the permission system. Plugins never touch internals directly -- they make API calls, the runtime checks permissions, responds or rejects. No scope equals permission error, never silent failure or crash.

**Permission grant model:**

Permissions are granted at install time AND adjustable by the user at any time after install. When a plugin requests a scope, the user can:

- **Grant fully** -- unrestricted access to the scope.
- **Grant with restrictions** -- access scoped to specific resources, trust levels, time windows, rate limits, etc.
- **Deny** -- no access to the scope.

Restrictions are ultra-granular. Users can be as precise or imprecise as they want. A user can grant `scope:groups` restricted to exactly two specific group IDs, or grant it fully to all groups, or anything in between.

**Restriction axes (apply to any scope):**

| Axis | Description |
|------|------------|
| By identity/mask | Which of the user's masks the plugin can act as |
| By trust level floor | Minimum trust level of peers the plugin can interact with |
| By specific peer/group/network IDs | Explicit allowlist |
| By content security level | Maximum sensitivity of content the plugin can touch |
| By time window | Only active during certain hours |
| By rate limit | Maximum operations per time period |
| By direction | Read-only vs read-write vs execute |

**Scope categories:**

Every major system in Mesh Infinity has corresponding scopes. Each system requires read, write, execute, and admin variants. Scope categories include but are not limited to:

- Identity and masks
- Trust system
- Network map
- Routing
- Transport
- Store-and-forward
- File sharing and distributed storage
- Hosted services
- Exit nodes
- Chat and messaging
- Communities
- Groups and networks
- Notifications
- Calls (audio, video, PTT)
- Discovery and service indexing
- Social profiles
- Metrics and observability

The full scope list with all restriction axes per scope is a dedicated design document (§19 Plugin Permission Scope Reference). This requires exhaustive design to ensure no capability leaks and no legitimate use case is crippled. It will be completed as a separate design sprint after the spec rewrite.

### 19.3 Permanently Off-Limits

Regardless of permissions granted, the following are permanently inaccessible to all plugins:

1. **Key material of any kind** -- private keys, derived secrets, intermediate DH values, ratchet state, PSK values.
2. **Raw transport layer access** -- plugins cannot open raw WireGuard tunnels, Tor circuits, or BLE connections.
3. **Trust graph mutation** -- plugins cannot change trust levels, issue endorsements, or modify WoT state.
4. **Other plugins' data** -- complete isolation between plugins.
5. **Rust backend internals** -- no access to internal data structures, memory, or state beyond the API surface.
6. **Anonymous mask linkage to self** -- no API exists that reveals whether an anonymous mask belongs to a given self.
7. **Root keypair operations** -- the root keypair is accessible only to the core backend for mask derivation.
8. **Killswitch activation** -- only the user can trigger emergency data destruction.
9. **Threat context modification** -- only the user can change the global threat context level.

### 19.4 Hybrid Clearnet/Mesh Exposure

Any service at any tier can be simultaneously exposed via mesh AND clearnet. This is a natural consequence of the service layer accepting connections from any transport.

A Community (§10.2) can optionally expose a clearnet-accessible web interface alongside its mesh presence. A Tier 1 service (e.g., a web application) can listen on both a mesh address and a clearnet IP:port. The same backend serves both. Clearnet users are a distinct membership class with appropriate trust level (typically Level 0 unless elevated by the service operator).

The mesh's role is unchanged: route packets to the right address and enforce ACLs if configured. The clearnet interface is an additional access path, not a replacement for mesh access. Services that require mesh-level trust gating (§12.5) apply that gating only to mesh connections -- clearnet connections bypass mesh ACLs unless the service explicitly applies its own application-level authentication.

---

## Appendix A: Known Limitations

These problems are acknowledged but not fully solved. Users and implementers must not be misled about the boundaries of the system's protections.

**1. Ratchet window after device seizure.**

PFS protects the past. An adversary who seizes a device holds the current ratchet state (position N). When contacts send messages with new DH ratchet keys, the adversary can advance the ratchet forward and keep decrypting until contacts stop sending to the compromised identity. This compounds with the trusted peer device seizure problem (the adversary holds a live, authenticated, trusted node during the window between seizure and network awareness).

**2. Dead man's switch / liveness dilemma.**

Any periodic liveness signal is a deanonymisation vector. No liveness signals means no dead man's switch. These are in direct conflict. The pre-committed distress message (§15.5) is a partial mitigation, not a solution. The cancellation pattern is itself an observable signal, and a stopped cancellation tells an adversary *when* something happened. False positives (imprisonment without device compromise) trigger Self-Disavowed unintentionally.

**3. Physical seizure without killswitch activation.**

A sophisticated adversary images the device in a Faraday cage before powering it on. Remote killswitch signals cannot reach the device. Local data exposure (trusted-channel keys, local contact mappings, message history, the full local contact graph) is an accepted risk against this adversary class. No technical mitigation exists for a physical seizure by a sufficiently resourced adversary.

**4. The $5 hammer.**

No cryptographic system survives coercion. This is out of scope for technical mitigation. The system documents this honestly so that users who think they have protection they do not are not in a worse position.

**5. Friend-Disavowed threshold gossip consistency.**

The network can briefly hold inconsistent state about whether a threshold has been reached. This is an inherent distributed systems property accepted as unavoidable.

**6. Threshold manipulation window.**

A device has up to 1 week after a `friend_disavow_threshold` change before the cooldown kicks in. During this window, a captured device could manipulate its own threshold. Accepted.

**7. Profile sharing permanence.**

Once a private profile is shared with a trusted peer, that sharing is permanent regardless of subsequent trust level changes. Trust downgrade removes future access, not past access. The data has already been delivered and cannot be un-delivered.

**8. Social engineering.**

The mutual trust model protects against technical attacks. It cannot prevent users from granting high trust to malicious parties who gain trust through social manipulation. This is a human problem, not a protocol problem.

**9. Forgotten verification passphrase.**

If both parties forget the verification passphrase established at pairing, in-band approval with maximum friction (72-hour mandatory waiting period, explicit risk acknowledgment, PIN re-authentication) is the only recovery path. No cryptographic recovery exists for a forgotten passphrase.

---

## Appendix B: Deferred Questions

Topics flagged during review that require deeper design work. These are explicitly deferred -- not forgotten, not solved.

### DQ-1: Mathematical Definition of "Blends In" for Direct Connections -- RESOLVED

**Resolution:** "Blends in" means the statistical properties of a connection's traffic are indistinguishable from the ambient outer tunnel traffic distribution on the current network.

For LoSec and fast routing (short inner tunnels): traffic volume, timing, and packet size distribution must fall within the normal variance of outer tunnel traffic observed by nearby nodes. A 1--2 hop inner tunnel on a large busy network genuinely blends in. The same connection on a small sparse network stands out.

**Practical threshold:** LoSec and fast routing require a minimum ambient traffic threshold before being offered -- based on active outer tunnel count, ambient traffic volume, and traffic variance. Below threshold, the UI does not show these options -- not disabled, absent.

**Implementation:** The transport solver (§5.7) continuously monitors ambient traffic statistics. The threshold is an implementation constant, not user-reducible below the compiled default.

### DQ-2: Transport Layer Full Redesign as Pluggable Capability-Based System

Largely resolved through the transport solver redesign (§5.7) and the RF plugin interface (§5.6). Remaining question: formal plugin registration API and versioning for third-party transport plugins. To be addressed in conjunction with the plugin system (§19).

### DQ-3: Traffic Obfuscation Techniques Against Targeted Surveillance

**Context:** When an adversary is specifically watching a known node, mesh membership and network activity are essentially visible regardless of other mitigations. The goal shifts from invisibility to data poisoning -- making what is observable useless for traffic analysis.

**Open questions:**

- What is the optimal constant-rate tunnel baseline? Too low means obvious spikes when real traffic happens. Too high means battery/bandwidth prohibitive on mobile.
- How do we handle nodes that genuinely go offline without that offline event being a signal?
- Can timing decorrelation be applied consistently across all transport types including RF's extreme latency variance?
- What is the minimum cover traffic volume needed to provide meaningful statistical cover?
- How do we handle the "new node joining" event -- a node that suddenly appears generating traffic is itself a signal?
- Are there existing academic results on traffic analysis resistance that should be referenced?

### DQ-4: Dead Man's Switch Cancellation Protocol Design

**Context:** §15.5 adds `CancellationBased` as a `ReleaseCondition` for store-and-forward. The pre-committed distress message requires this. But the cancellation protocol needs dedicated design.

**Open questions:**

- How are cancellation signals authenticated without the store-and-forward node having the sender's private key?
- What is the cancellation window -- how long after the last cancellation does the message release?
- How do we prevent the cancellation signal itself from being a liveness fingerprint?
- What happens if the store-and-forward node goes offline?
- Can the release condition be updated without revealing that a distress message exists?
- How do multiple store-and-forward nodes coordinate?

---

## Appendix C: Open Questions

The following questions were identified during the threat model review and are pending resolution:

1. **Messages in flight during Self-Disavowed:** What happens to messages in flight or queued in store-and-forward when Self-Disavowed fires? Are they delivered, discarded, or held in limbo?

2. **Self-Disavowed to group ejection timing:** Is there a grace period between Self-Disavowed and group ejection, or is ejection immediate? An immediate ejection may prevent the Self-Disavowed broadcast from reaching all group members through the group channel.

3. **Local storage footprint:** What is actually stored locally and for how long? Can the local footprint be minimised further to reduce exposure in the event of physical seizure?

4. **iOS keychain accessibility:** §3.6 specifies `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` for iOS. A powered-on, previously-unlocked iPhone makes the keychain accessible to the OS and any process with the correct entitlements. This is an accepted platform limitation that should be documented explicitly rather than hidden.

5. **Trust revocation model:** §8.5 Trust Revocation is vestigial from the original 4-level trust model. It should be replaced with cross-references to the Disavowed/Compromised state machine (§8.x) and the key change verification protocol (§4.6).
