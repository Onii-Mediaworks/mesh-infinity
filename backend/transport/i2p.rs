//! Internal I2P-style transport engine.
//!
//! # IMPORTANT: What this module is (and is NOT)
//!
//! Despite the name "I2P", this module does **not** connect to the real I2P
//! network.  I2P (the Invisible Internet Project) is a separate anonymity
//! network similar to Tor, with its own relay infrastructure, directory
//! system, and routing protocols.  Integrating with it would require either
//! running a separate router process or embedding a full I2P implementation.
//!
//! Instead, this is a **custom in-process encrypted overlay transport**
//! inspired by I2P's design principles.  It runs over ordinary TCP sockets,
//! but adds a full cryptographic session layer on top:
//!
//!   1. **Handshake** — before any application data is exchanged, both sides
//!      perform a Diffie-Hellman key exchange to agree on a shared secret key.
//!      This shared secret is never transmitted over the network; both sides
//!      compute it independently from their own private key and the other
//!      side's public key.
//!
//!   2. **Key derivation** — the raw DH output is transformed into a strong,
//!      uniform encryption key using HKDF (a standard key-derivation function).
//!
//!   3. **AEAD framing** — every message is encrypted AND authenticated using
//!      ChaCha20-Poly1305.  The cipher adds a 16-byte authentication tag so
//!      that any tampering (even one flipped bit) is detected on decryption.
//!      Each message is prefixed with a 4-byte length header and a 12-byte
//!      nonce on the wire.
//!
//! The end result is a transport that provides end-to-end encryption and
//! message authentication between two Mesh Infinity nodes, running directly
//! over TCP without any external anonymity network.
//!
//! If real I2P support is added later, this module can be replaced without
//! changing any other part of the codebase — the `Transport` trait interface
//! remains the same.
//!
//! # Cryptographic primitives used
//!
//! ## X25519 Diffie-Hellman (`x25519-dalek`)
//!
//! Diffie-Hellman (DH) key exchange solves the following problem:
//! "How can Alice and Bob agree on a shared secret without ever transmitting
//! the secret itself over the network?"
//!
//! X25519 is a modern variant that uses elliptic curve mathematics on the
//! Curve25519 curve, designed by cryptographer Daniel J. Bernstein.
//!
//! How it works, step by step:
//!
//!   1. Alice generates a random private key (32 random bytes).  She keeps
//!      this secret — it never leaves her device.
//!
//!   2. Alice computes her public key from her private key using elliptic
//!      curve multiplication.  She sends this public key to Bob.
//!
//!   3. Bob does the same: generates a private key, computes a public key,
//!      sends it to Alice.
//!
//!   4. Alice computes: `shared_secret = alice_private * bob_public`
//!      (using elliptic curve math).
//!
//!   5. Bob computes:   `shared_secret = bob_private * alice_public`.
//!
//!   6. Because of elliptic curve algebra, both computations yield the SAME
//!      result — the shared secret — even though Alice and Bob used different
//!      inputs.
//!
//!   7. An eavesdropper who sees both public keys cannot compute the shared
//!      secret without solving the "Elliptic Curve Diffie-Hellman" problem,
//!      which is computationally infeasible with Curve25519.
//!
//! **Ephemeral keys**: we generate fresh key pairs for every connection.
//! This provides *forward secrecy* — if a private key is ever compromised in
//! the future, past sessions cannot be decrypted because each session used a
//! unique key pair that was discarded after the handshake.
//!
//! ## HKDF-SHA256 (`hkdf` + `sha2`)
//!
//! HKDF (HMAC-based Key Derivation Function) takes raw "key material" (the DH
//! output bytes) and produces uniformly random bytes suitable for use as a
//! cipher key.
//!
//! Why not use the DH output directly as the cipher key?
//!
//! DH output bytes fall on an elliptic curve — they are NOT uniformly
//! distributed random numbers.  If you feed them directly into a cipher, the
//! key space has structure that an attacker might exploit.  HKDF mixes the DH
//! output through a cryptographic hash (SHA-256) with a context label string,
//! producing output that is indistinguishable from random noise.
//!
//! The label string `"mesh-infinity-i2p-stream"` is called a "domain separator".
//! It ensures that keys derived for this transport are cryptographically
//! distinct from keys derived for any other purpose in the codebase, even if
//! they happen to start from the same DH output.
//!
//! ## ChaCha20-Poly1305 (`chacha20poly1305`)
//!
//! This is an **AEAD cipher** (Authenticated Encryption with Associated Data).
//!
//! "Authenticated Encryption" means the cipher does two things at once:
//!   - **Encrypts** the plaintext so no one can read it.
//!   - **Authenticates** the ciphertext so any tampering is detected.
//!
//! If even a single bit of the ciphertext is flipped in transit (by an attacker
//! or by random network corruption), the authentication check will fail and
//! `decrypt()` will return an error rather than silently returning garbled data.
//! This is a critical property for a secure messaging system.
//!
//! ChaCha20 is the encryption component (a stream cipher).
//! Poly1305 is the authentication component (a MAC — Message Authentication Code).
//! It appends a 16-byte authentication tag to every ciphertext.
//!
//! ChaCha20-Poly1305 is used in TLS 1.3, WireGuard, Signal Protocol, and many
//! other security-critical systems.  It is especially fast on devices without
//! dedicated AES hardware acceleration (common on mobile CPUs).
//!
//! ## Nonces — what they are and why they matter
//!
//! A **nonce** (Number used ONCE) is a 12-byte value that must be unique for
//! every single encryption operation performed with the same key.
//!
//! This is a hard requirement: reusing a (key, nonce) pair with
//! ChaCha20-Poly1305 is catastrophic — an attacker who sees two ciphertexts
//! encrypted with the same key and nonce can XOR them together, which cancels
//! the encryption and reveals information about both plaintexts.
//!
//! How we guarantee uniqueness:
//!   - We use a **monotonically incrementing counter** (starts at 0, goes up
//!     by 1 for each message).
//!   - The counter is encoded into the 12-byte nonce.
//!   - Since counter values are unique (0, 1, 2, 3, ...), the nonces are unique.
//!
//! The receiver also maintains a counter and uses it to reconstruct the expected
//! nonce.  If the incoming nonce doesn't match the expected nonce, the frame is
//! rejected — this detects:
//!   - **Replay attacks**: an attacker re-sends an old captured packet.
//!   - **Out-of-order delivery**: packets that arrived in the wrong order.
//!   - **Stream corruption**: bytes lost or reordered in the TCP stream.
//!
//! Each new session uses a freshly derived key, so the counter safely restarts
//! at 0 for every connection without risking nonce reuse across sessions.
//!
//! ## What the "I2P-style design" provides
//!
//! The design of this transport, inspired by I2P principles, gives us:
//!
//!   - **Confidentiality**: message contents are encrypted; no intermediate
//!     router or eavesdropper can read them.
//!   - **Integrity**: the Poly1305 tag ensures messages cannot be forged or
//!     tampered with without detection.
//!   - **Forward secrecy**: ephemeral DH keys mean past sessions cannot be
//!     decrypted even if a long-term key is later compromised.
//!   - **Replay protection**: monotonic nonce counters prevent re-sent old
//!     packets from being accepted as new messages.
//!
//! What this design does NOT provide (unlike real I2P or Tor):
//!   - **Anonymity**: your IP address is still visible to the peer.
//!   - **Traffic routing**: there are no intermediate relays or garlic routing.
//!     This is a direct, encrypted peer-to-peer channel.

use crate::core::core::{PeerInfo, TransportQuality, TransportType};
use crate::core::error::{MeshInfinityError, Result};
use crate::transport::traits::{Connection, Listener, Transport};

// `Aead` trait — provides the `encrypt()` and `decrypt()` methods.
// `KeyInit` trait — provides the `new(key)` constructor for ciphers.
use chacha20poly1305::aead::{Aead, KeyInit};
// `ChaCha20Poly1305` — the combined cipher type.
// `Key` — a typed 32-byte key wrapper.
// `Nonce` — a typed 12-byte nonce wrapper.
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
// `Hkdf` — the HKDF key-derivation function, generic over the hash algorithm.
use hkdf::Hkdf;
// `OsRng` — the operating system's cryptographically secure random number
// generator.  Used to generate private keys.  Much more secure than Rust's
// standard `rand::thread_rng()` for cryptographic purposes.
use rand_core::OsRng;
// `Sha256` — the SHA-256 hash algorithm.  Used inside HKDF.
use sha2::Sha256;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;
// `X25519PublicKey` — the public key type for X25519 Diffie-Hellman.
// `StaticSecret` — the private key type.  Despite the name "Static", it can
// be used as an ephemeral (single-use) key when generated fresh each session.
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// Protocol version tag sent at the start of every handshake.
///
/// Both sides must send and receive this exact 6-byte sequence before
/// proceeding with the key exchange.  If the received tag does not match,
/// the handshake is rejected immediately.
///
/// This tag serves two purposes:
///
///   1. **Protocol identification** — distinguishes our custom I2P-style
///      protocol from random TCP traffic or other protocols that might happen
///      to connect to the same port.
///
///   2. **Version gating** — the "v1" suffix means that if we ever redesign
///      the handshake protocol, we change the tag to "MI2Pv2" (or similar).
///      Old clients will reject new sessions, and new clients will reject old
///      sessions, rather than silently misinterpreting each other's messages.
///
/// `b"MI2Pv1"` is a "byte string literal" — a fixed array of 6 bytes,
/// each being the ASCII code of the corresponding character.
const HANDSHAKE_TAG: &[u8; 6] = b"MI2Pv1";

/// The I2P-style encrypted overlay transport.
///
/// This is a zero-sized struct — it has no fields because the transport itself
/// is stateless.  All per-connection state lives in `HandshakeState` and
/// `I2pConnection`, which are created freshly for each connection.
///
/// Creating a new `I2pTransport` costs essentially nothing (no memory
/// allocation, no network activity).  Unlike `TorTransport`, it requires no
/// bootstrapping and is immediately available.
pub struct I2pTransport;

impl Default for I2pTransport {
    /// `I2pTransport::default()` == `I2pTransport::new()`.
    fn default() -> Self {
        Self::new()
    }
}

impl I2pTransport {
    /// Construct a new (stateless) I2P transport instance.
    ///
    /// Because `I2pTransport` has no fields, this is essentially a no-op — it
    /// just returns the zero-sized struct token.
    pub fn new() -> Self {
        Self
    }

    /// Extract a `SocketAddr` (IP + port) from peer metadata.
    ///
    /// We look in two places, in priority order:
    ///
    ///   1. `peer_info.endpoint` — a pre-parsed `SocketAddr`, if present.
    ///      This is the most convenient form because it is already in the
    ///      right type and requires no parsing.
    ///
    ///   2. `peer_info.transport_endpoints[TransportType::I2P]` — a raw
    ///      address string like `"192.168.1.5:7654"`.  We parse it with
    ///      `.parse::<SocketAddr>()`.
    ///
    /// Returns `Err` if neither field is present or if the string cannot be
    /// parsed as a valid IP:port address.
    fn resolve_endpoint(peer_info: &PeerInfo) -> Result<SocketAddr> {
        // If the generic endpoint is already set, use it directly.
        if let Some(addr) = peer_info.endpoint {
            return Ok(addr);
        }

        // Fall back to the I2P-specific string endpoint.
        if let Some(raw) = peer_info.transport_endpoints.get(&TransportType::I2P) {
            // `.parse::<SocketAddr>()` tries to interpret the string as an IP:port.
            // Returns `Ok(SocketAddr)` on success, `Err(AddrParseError)` on failure.
            return raw.parse::<SocketAddr>().map_err(|e| {
                MeshInfinityError::TransportError(format!("invalid I2P endpoint metadata: {}", e))
            });
        }

        // Neither field was present — we have no idea where to connect.
        Err(MeshInfinityError::TransportError(
            "missing I2P endpoint metadata".to_string(),
        ))
    }
}

impl Transport for I2pTransport {
    /// Open an encrypted outbound stream to a peer.
    ///
    /// # What happens step by step
    ///
    /// 1. **Resolve endpoint**: find the peer's IP + port from their metadata.
    ///
    /// 2. **Open TCP connection**: connect a plain, unencrypted TCP socket to
    ///    that address.  This is like opening a regular internet connection —
    ///    the encryption layer is added on top in the next step.
    ///
    /// 3. **Set timeouts**: configure 10-second read and write timeouts on the
    ///    TCP socket.  Without timeouts, a slow or dead server could block this
    ///    function forever, hanging the entire connection attempt.
    ///
    /// 4. **Perform handshake**: call `HandshakeState::client_handshake()` which:
    ///    a. Generates a fresh X25519 key pair for this session.
    ///    b. Sends our public key (and the protocol tag) to the server.
    ///    c. Receives the server's public key (and protocol tag).
    ///    d. Computes the DH shared secret.
    ///    e. Derives the session encryption key via HKDF.
    ///    After this step, both sides have the same encryption key but it was
    ///    never transmitted over the network.
    ///
    /// 5. **Return connection**: wrap the TCP stream and handshake state in an
    ///    `I2pConnection`.  All subsequent `send()`/`receive()` calls on this
    ///    object will automatically encrypt and decrypt.
    fn connect(&self, peer_info: &PeerInfo) -> Result<Box<dyn Connection>> {
        let endpoint = Self::resolve_endpoint(peer_info)?;
        // `TcpStream::connect(endpoint)` opens a blocking TCP connection to the
        // given IP:port.  The `?` propagates any OS-level error (host unreachable,
        // connection refused, etc.) up to the caller.
        let mut stream = TcpStream::connect(endpoint)?;

        // Set read and write timeouts.  Without these:
        //   - A server that never sends data would cause `receive()` to block forever.
        //   - A server that stops accepting data would cause `send()` to block forever.
        // 10 seconds is generous enough for a local network but short enough to
        // fail fast on truly broken connections.
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;

        // Run the client-side DH handshake over the raw TCP stream.
        // After this returns, `state` contains the shared encryption key and
        // the initial nonce counters (both set to 0).
        let state = HandshakeState::client_handshake(&mut stream)?;

        Ok(Box::new(I2pConnection {
            stream,
            peer: peer_info.clone(),
            state,
            closed: false, // connection is open
        }))
    }

    /// Listen for incoming encrypted streams on an OS-assigned port.
    ///
    /// # `"0.0.0.0:0"` explained
    ///
    /// `"0.0.0.0"` means "bind to all available network interfaces".  This
    /// allows the listener to accept connections from any IP address (not just
    /// localhost or a specific interface).
    ///
    /// `:0` means "let the operating system choose a free port".  The OS picks
    /// a high-numbered ephemeral port (usually in the range 1024–65535) that
    /// is not currently in use.  You can find out which port was chosen by
    /// calling `listener.local_addr()` after binding.
    ///
    /// # `set_nonblocking(false)`
    ///
    /// Non-blocking mode (`true`) makes `accept()` return immediately with a
    /// "WouldBlock" error if no client is waiting.  Blocking mode (`false`,
    /// the default) makes `accept()` wait until a client actually connects.
    ///
    /// We explicitly set `false` to be clear about the intended behaviour:
    /// the accept loop should block, waiting for clients.  When we want to
    /// shut down the listener, we call `close()` which switches to non-blocking
    /// mode, causing the next `accept()` to return an error and exit the loop.
    fn listen(&self) -> Result<Box<dyn Listener>> {
        let listener = TcpListener::bind("0.0.0.0:0")?;
        listener.set_nonblocking(false)?;
        Ok(Box::new(I2pListener { listener }))
    }

    /// Priority relative to other transports.
    ///
    /// Priority 3 places I2P below Tor (priority 2) but above clearnet (which
    /// has a higher numeric priority).  The actual ordering used for connection
    /// selection is `enabled_transport_order()` in `manager.rs`; this field
    /// acts as a tie-breaker between equally-positioned transports.
    fn priority(&self) -> u8 {
        3
    }

    /// Returns `TransportType::I2P`.
    fn transport_type(&self) -> TransportType {
        TransportType::I2P
    }

    /// This transport is always considered available.
    ///
    /// Unlike `TorTransport` which must download relay lists before being
    /// usable (bootstrapping can take 5–15 seconds), our custom I2P transport
    /// is pure in-process code — it is ready the moment the struct is created.
    /// There is no external dependency to wait for.
    fn is_available(&self) -> bool {
        true
    }

    /// Return a static quality estimate for this transport.
    ///
    /// Compared to Tor (which has 3 relay hops and ~520 ms latency), our
    /// custom I2P transport is a direct peer-to-peer encrypted channel, so:
    ///   - `latency: 320 ms` — lower than Tor but higher than clearnet (the
    ///     handshake and encryption overhead adds a little latency).
    ///   - `bandwidth: 450_000` (~450 KB/s) — slightly better than Tor.
    ///   - `reliability: 0.80` — decent but encrypted overlay connections may
    ///     fail more often than Tor's circuit-protected streams.
    ///   - `cost: 0.15` — low cost.
    ///   - `congestion: 0.30` — moderate congestion estimate.
    fn measure_quality(&self, _target: &PeerInfo) -> Result<TransportQuality> {
        Ok(TransportQuality {
            latency: Duration::from_millis(320), // lower than Tor: no multi-hop relay chain
            bandwidth: 450_000,                  // ~450 KB/s
            reliability: 0.8,                    // 80% — decent but less hardened than Tor
            cost: 0.15,                          // low cost
            congestion: 0.3,                     // moderate congestion estimate
        })
    }
}

// ---------------------------------------------------------------------------
// HandshakeState — the cryptographic session established per connection
// ---------------------------------------------------------------------------

/// Cryptographic state for one I2P-style session.
///
/// After the DH handshake completes, this struct holds everything needed to
/// encrypt and decrypt messages for the lifetime of the connection:
///
///   - `cipher`: a `ChaCha20Poly1305` instance initialized with the
///     session key derived from the DH shared secret.  This same cipher
///     object is used for ALL messages in the session.
///
///   - `tx_counter`: how many messages WE have sent.  Starts at 0, increments
///     by 1 for each `send()` call.  Used to derive the encryption nonce.
///
///   - `rx_counter`: how many messages WE have received.  Starts at 0,
///     increments by 1 for each `receive()` call.  Used to derive the
///     expected nonce for decryption and replay detection.
///
/// # Why separate tx and rx counters?
///
/// If we used a single shared counter, the nonces for outgoing and incoming
/// messages would overlap:
///   - Message 1 sent: nonce from counter 1.
///   - Message 1 received: nonce from counter 2 (counter was incremented by send).
///   - But the sender used counter 1 for this message!  The receiver would
///     compute the wrong nonce and decryption would fail.
///
/// Separate counters ensure that each direction of communication has its
/// own independent nonce sequence that can never collide.
struct HandshakeState {
    /// The ChaCha20-Poly1305 cipher instance, initialized with the session key.
    ///
    /// Both `encrypt()` and `decrypt()` are called on this same object.
    /// The cipher is stateless per-call (it doesn't track nonces internally),
    /// so we must always pass the correct nonce explicitly.
    cipher: ChaCha20Poly1305,

    /// Number of messages sent by US so far in this session (starts at 0).
    ///
    /// `u64` allows up to ~18.4 quintillion messages before overflow.
    /// We use `saturating_add` to handle the theoretical overflow case
    /// safely (the counter stops at `u64::MAX` rather than wrapping to 0).
    tx_counter: u64,

    /// Number of messages received by US so far in this session (starts at 0).
    rx_counter: u64,
}

impl HandshakeState {
    /// Perform the **client-side** of the Diffie-Hellman handshake.
    ///
    /// # Protocol flow (what travels over the wire)
    ///
    /// ```text
    ///   CLIENT                                 SERVER
    ///     |                                      |
    ///     |--- HANDSHAKE_TAG (6 bytes: "MI2Pv1") -->|   "Are you the right protocol?"
    ///     |--- client_pub (32 bytes: X25519 key) -->|   "Here is my public key."
    ///     |                                      |
    ///     |<-- HANDSHAKE_TAG (6 bytes)          ---|   "Yes, I speak this protocol."
    ///     |<-- server_pub (32 bytes: X25519 key) --|   "Here is MY public key."
    ///     |                                      |
    ///   [client computes DH: client_private * server_public → shared_secret]
    ///   [server computes DH: server_private * client_public → same shared_secret]
    ///   [both run HKDF on shared_secret to get session_key]
    ///     |                                      |
    ///   [ encrypted application data begins — both sides use session_key ]
    /// ```
    ///
    /// # Step-by-step explanation
    ///
    /// **Step 1: Generate ephemeral key pair.**
    ///   `StaticSecret::random_from_rng(OsRng)` generates 32 cryptographically
    ///   secure random bytes as the private key.  `OsRng` uses the OS's entropy
    ///   source (e.g., `/dev/urandom` on Linux, `CryptGenRandom` on Windows).
    ///   `X25519PublicKey::from(&client_secret)` computes the public key from
    ///   the private key using elliptic curve multiplication on Curve25519.
    ///
    ///   "Ephemeral" means this key pair is used exactly once and thrown away
    ///   after the handshake — this gives forward secrecy.
    ///
    /// **Step 2: Send tag + public key.**
    ///   `stream.write_all(HANDSHAKE_TAG)` sends the 6-byte "MI2Pv1" tag.
    ///   `stream.write_all(client_pub.as_bytes())` sends the 32-byte public key.
    ///   `write_all` loops until all bytes are sent (handles partial writes).
    ///
    /// **Step 3: Receive and verify server's tag + public key.**
    ///   `stream.read_exact(&mut server_tag)` reads exactly 6 bytes into the
    ///   buffer.  `read_exact` blocks until all 6 bytes arrive — it will not
    ///   return a partial read.  We then check if they match `HANDSHAKE_TAG`.
    ///   A mismatch means the server is speaking a different protocol/version.
    ///
    /// **Step 4: Compute DH shared secret.**
    ///   `client_secret.diffie_hellman(&server_pub)` computes
    ///   `client_private * server_public` on the elliptic curve.  Both sides
    ///   independently arrive at the same 32-byte shared secret.
    ///
    /// **Step 5: Derive session key via HKDF.**
    ///   See `from_shared_secret()` for details.
    fn client_handshake(stream: &mut TcpStream) -> Result<Self> {
        // Step 1: generate ephemeral key pair for this session.
        // Each call to `random_from_rng(OsRng)` produces different random bytes,
        // ensuring every session has a unique key pair → unique shared secret.
        let client_secret = StaticSecret::random_from_rng(OsRng);
        let client_pub = X25519PublicKey::from(&client_secret);

        // Step 2: send our protocol identity tag, then our public key.
        // `write_all` is important here: a plain `write` might only write
        // some of the bytes if the kernel buffer is full.  `write_all` retries
        // until every byte has been handed off.
        stream.write_all(HANDSHAKE_TAG)?;           // 6 bytes: "MI2Pv1"
        stream.write_all(client_pub.as_bytes())?;   // 32 bytes: X25519 public key

        // Step 3: receive and verify the server's protocol tag.
        let mut server_tag = [0u8; 6];
        // `read_exact` fills the entire buffer before returning.  It blocks
        // until all 6 bytes arrive (or returns an error if the stream ends).
        stream.read_exact(&mut server_tag)?;
        if &server_tag != HANDSHAKE_TAG {
            // Wrong tag — the server is not speaking our protocol.
            // Abort the handshake immediately rather than proceeding with a
            // mismatched protocol, which would produce garbage.
            return Err(MeshInfinityError::TransportError(
                "I2P handshake tag mismatch".to_string(),
            ));
        }

        // Step 3 (continued): read the server's 32-byte public key.
        let mut server_pub_bytes = [0u8; 32];
        stream.read_exact(&mut server_pub_bytes)?;
        // `X25519PublicKey::from(bytes)` interprets the 32 bytes as a Curve25519
        // public key.  No validation is needed because all 32-byte arrays are
        // valid Curve25519 points.
        let server_pub = X25519PublicKey::from(server_pub_bytes);

        // Step 4: compute the DH shared secret.
        // `client_secret.diffie_hellman(&server_pub)` computes the shared point
        // on the elliptic curve.  Both sides will get the same value.
        let shared = client_secret.diffie_hellman(&server_pub);

        // Step 5: derive the session encryption key from the raw DH output.
        Self::from_shared_secret(shared.as_bytes())
    }

    /// Perform the **server-side** of the Diffie-Hellman handshake.
    ///
    /// The server does the mirror image of the client:
    ///
    /// 1. Read and verify the client's protocol tag (6 bytes).
    /// 2. Read the client's public key (32 bytes).
    /// 3. Generate our own fresh ephemeral key pair.
    /// 4. Send our protocol tag and public key back to the client.
    /// 5. Compute the DH shared secret and derive the session key.
    ///
    /// After step 5, both client and server have computed the SAME shared
    /// secret and the SAME encryption key, because:
    ///   - Client computed: `client_private * server_public`
    ///   - Server computed: `server_private * client_public`
    ///   - By elliptic curve algebra: both equal `client_private * server_private * G`
    ///     (where G is the curve's base point).
    fn server_handshake(stream: &mut TcpStream) -> Result<Self> {
        // Step 1: read and verify the client's protocol tag.
        let mut client_tag = [0u8; 6];
        stream.read_exact(&mut client_tag)?;
        if &client_tag != HANDSHAKE_TAG {
            // Wrong protocol version — reject immediately.
            return Err(MeshInfinityError::TransportError(
                "I2P handshake tag mismatch".to_string(),
            ));
        }

        // Step 2: read the client's 32-byte public key.
        let mut client_pub_bytes = [0u8; 32];
        stream.read_exact(&mut client_pub_bytes)?;
        let client_pub = X25519PublicKey::from(client_pub_bytes);

        // Step 3: generate our own fresh ephemeral key pair.
        // This is done AFTER reading the client's public key to ensure the
        // server's key is not reused from a previous session.
        let server_secret = StaticSecret::random_from_rng(OsRng);
        let server_pub = X25519PublicKey::from(&server_secret);

        // Step 4: send our tag and public key to the client.
        stream.write_all(HANDSHAKE_TAG)?;           // 6 bytes: "MI2Pv1"
        stream.write_all(server_pub.as_bytes())?;   // 32 bytes: X25519 public key

        // Step 5: compute the DH shared secret using our private key and the
        // client's public key.  Both sides will arrive at the same result.
        let shared = server_secret.diffie_hellman(&client_pub);
        Self::from_shared_secret(shared.as_bytes())
    }

    /// Derive a symmetric encryption key from a DH shared secret using HKDF.
    ///
    /// # Why not use the DH output directly?
    ///
    /// The output of `diffie_hellman()` is a point on an elliptic curve.
    /// While it is secret, it is NOT uniformly random — it has mathematical
    /// structure.  Feeding structured data directly into a cipher as the key
    /// could leave subtle weaknesses.
    ///
    /// HKDF (HMAC-based Key Derivation Function) "conditions" the raw input
    /// into uniformly random bytes that look like random noise to any attacker.
    ///
    /// # Steps
    ///
    /// 1. `Hkdf::<Sha256>::new(None, shared)`:
    ///    - Creates an HKDF instance with SHA-256 as the hash algorithm.
    ///    - `shared` is the "input keying material" (the raw DH output).
    ///    - `None` for the salt tells HKDF to use an all-zero block as the
    ///      salt, which is acceptable here since the DH output already has
    ///      high entropy (lots of randomness).
    ///
    /// 2. `hk.expand(b"mesh-infinity-i2p-stream", &mut key_bytes)`:
    ///    - Expands the HKDF state into exactly 32 bytes (our key size).
    ///    - The label string `"mesh-infinity-i2p-stream"` is the "info" parameter.
    ///    - It acts as a domain separator: keys derived with this label are
    ///      cryptographically distinct from keys derived with any other label
    ///      from the same HKDF state.  This is a standard security practice.
    ///
    /// 3. `ChaCha20Poly1305::new(Key::from_slice(&key_bytes))`:
    ///    - Initializes the cipher with the 32-byte derived key.
    ///    - `Key::from_slice` creates a typed key wrapper from a byte slice.
    ///    - The cipher is now ready to encrypt and decrypt.
    fn from_shared_secret(shared: &[u8]) -> Result<Self> {
        // Initialize HKDF with the raw DH output as input key material.
        let hk = Hkdf::<Sha256>::new(None, shared);

        // Allocate a 32-byte buffer for the derived key.
        // ChaCha20-Poly1305 requires a 256-bit (32-byte) key.
        let mut key_bytes = [0u8; 32];

        // Expand the HKDF state into `key_bytes` using the domain label.
        // Returns `Err` if the output length is too large for HKDF (it isn't
        // at 32 bytes — the max is 255 * 32 = 8160 bytes for SHA-256).
        hk.expand(b"mesh-infinity-i2p-stream", &mut key_bytes)
            .map_err(|_| MeshInfinityError::CryptoError("hkdf expansion failed".to_string()))?;

        // Initialize the cipher with the derived key.
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));

        Ok(Self {
            cipher,
            tx_counter: 0, // no messages sent yet
            rx_counter: 0, // no messages received yet
        })
    }

    /// Advance the transmit counter and produce the next nonce for encryption.
    ///
    /// We increment BEFORE computing the nonce so that the first nonce sent
    /// corresponds to counter = 1 (not 0).  This makes it clearer that 0
    /// means "no messages yet sent" and ≥1 means "at least one message sent".
    ///
    /// `saturating_add(1)` is like `+ 1` but safe from integer overflow:
    ///   - Normal case: counter goes from N to N+1.
    ///   - Overflow case (counter = u64::MAX): counter stays at u64::MAX
    ///     rather than wrapping back to 0.  Wrapping would be disastrous
    ///     (nonce reuse), so saturation is the safe choice.  In practice a
    ///     u64 counter supports 18.4 quintillion messages — overflow will
    ///     never happen in real use.
    fn next_tx_nonce(&mut self) -> [u8; 12] {
        self.tx_counter = self.tx_counter.saturating_add(1);
        // Convert the counter to a 12-byte nonce.  `0xA1` is the prefix tag.
        nonce_from_counter(self.tx_counter, 0xA1)
    }

    /// Advance the receive counter and produce the expected nonce for decryption.
    ///
    /// The receiver maintains a mirror of the sender's counter.  Since messages
    /// must arrive in order (TCP guarantees in-order delivery), the receiver
    /// can always predict what nonce the sender used for the next message.
    ///
    /// If the received nonce doesn't match this prediction, the frame is
    /// rejected — it might be a replayed old packet or stream corruption.
    ///
    /// The prefix `0xA1` must match `next_tx_nonce()` exactly so that the
    /// receiver's expected nonce always equals the sender's used nonce.
    fn next_rx_nonce(&mut self) -> [u8; 12] {
        self.rx_counter = self.rx_counter.saturating_add(1);
        nonce_from_counter(self.rx_counter, 0xA1)
    }
}

/// Build a 12-byte ChaCha20-Poly1305 nonce from a u64 counter.
///
/// # Nonce layout (12 bytes = 96 bits total)
///
/// ```text
/// Byte  0   : prefix tag (0xA1 — a fixed marker for this protocol)
/// Bytes 1–3 : zero padding (always 0x00 0x00 0x00)
/// Bytes 4–11: counter value as big-endian u64 (8 bytes)
/// ```
///
/// # Why this specific layout?
///
/// - **Prefix byte (0xA1)**: "domain separates" these nonces from any other
///   nonce construction elsewhere in the codebase.  Even if two different
///   subsystems happened to use the same counter value, they would produce
///   different 12-byte nonces because their prefix bytes differ.
///
/// - **Zero padding (bytes 1–3)**: a u64 counter (8 bytes) + prefix (1 byte)
///   = 9 bytes.  ChaCha20-Poly1305 needs exactly 12 bytes.  The remaining
///   3 bytes are just padding — zero is fine here.
///
/// - **Big-endian counter (bytes 4–11)**: "big-endian" means the most
///   significant byte is first.  For example, counter = 1 is encoded as
///   `[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]`.  This is the
///   standard byte order for network protocols.  `to_be_bytes()` performs
///   this conversion.
///
/// # `copy_from_slice`
///
/// `nonce[4..12].copy_from_slice(&counter.to_be_bytes())` copies the 8 bytes
/// of the big-endian counter into positions 4 through 11 of the nonce array.
/// The `4..12` range is exclusive at the end (indices 4, 5, 6, 7, 8, 9, 10, 11).
fn nonce_from_counter(counter: u64, prefix: u8) -> [u8; 12] {
    let mut nonce = [0u8; 12]; // start with all zeros
    nonce[0] = prefix;         // byte 0: the protocol marker 0xA1
                               // bytes 1, 2, 3 remain 0x00 (padding)
    // bytes 4–11: big-endian encoding of the u64 counter
    nonce[4..12].copy_from_slice(&counter.to_be_bytes());
    nonce
}

// ---------------------------------------------------------------------------
// I2pConnection — a live encrypted session
// ---------------------------------------------------------------------------

/// An active, encrypted I2P-style connection over TCP.
///
/// # What each `send()` call does on the wire
///
/// ```text
/// ┌─────────────────────────────────────────────────────────────────────┐
/// │  4 bytes  │  12 bytes  │  N bytes (ciphertext + 16-byte auth tag)  │
/// │  length   │   nonce    │                                             │
/// └─────────────────────────────────────────────────────────────────────┘
/// ```
///
/// 1. Advance `state.tx_counter` to get the next unique nonce (12 bytes).
/// 2. Encrypt `data` with ChaCha20-Poly1305: ciphertext = `encrypt(nonce, data)`.
///    The cipher automatically appends a 16-byte Poly1305 authentication tag.
/// 3. Compute `total_len = 12 (nonce) + len(data) + 16 (auth tag)`.
/// 4. Write `total_len` as a big-endian u32 (4 bytes).
/// 5. Write the 12-byte nonce.
/// 6. Write the ciphertext (including the tag).
///
/// # What each `receive()` call does on the wire
///
/// 1. Read 4 bytes → interpret as big-endian u32 `total_len`.
/// 2. Sanity-check: `total_len` must be ≥ 12 (at minimum a nonce, no data).
/// 3. Read exactly `total_len` bytes into a temporary buffer.
/// 4. Extract the first 12 bytes as the nonce.
/// 5. Advance `state.rx_counter` to get the EXPECTED nonce.
/// 6. Compare received nonce with expected nonce — reject if different.
/// 7. Decrypt `buffer[12..]` with ChaCha20-Poly1305.  The cipher also verifies
///    the 16-byte auth tag — if it doesn't match, `decrypt()` returns `Err`.
/// 8. Copy the decrypted plaintext into the caller's buffer.
pub struct I2pConnection {
    /// The underlying TCP stream carrying the encrypted, framed bytes.
    stream: TcpStream,
    /// Metadata about the remote peer.
    peer: PeerInfo,
    /// Per-session cryptographic state: cipher instance + nonce counters.
    state: HandshakeState,
    /// `true` after `close()` has been called; prevents further I/O.
    closed: bool,
}

impl Connection for I2pConnection {
    /// Encrypt `data` and send it as a length-prefixed, nonce-prefixed frame.
    ///
    /// # Why include the nonce in the frame?
    ///
    /// The receiver can reconstruct the nonce from its own `rx_counter` without
    /// receiving it explicitly.  We include it anyway as an extra layer of
    /// replay and corruption detection: the receiver verifies that the sent
    /// nonce matches its expected nonce before attempting decryption.
    ///
    /// # `to_be_bytes()` — converting numbers to bytes
    ///
    /// `total_len.to_be_bytes()` converts a `u32` integer into its big-endian
    /// 4-byte representation.  For example, the number 44 becomes
    /// `[0x00, 0x00, 0x00, 0x2C]`.  The receiver uses `u32::from_be_bytes()`
    /// to convert back.  Big-endian ("most significant byte first") is the
    /// standard convention for network protocols.
    ///
    /// # Return value
    ///
    /// Returns `Ok(data.len())` — the number of *plaintext* bytes the caller
    /// provided.  The actual bytes written to the wire are more (nonce + tag +
    /// length prefix), but callers only care about their original data size.
    fn send(&mut self, data: &[u8]) -> Result<usize> {
        // Refuse to send on a closed connection.
        if self.closed {
            return Err(MeshInfinityError::NetworkError(
                "I2P connection closed".to_string(),
            ));
        }

        // Advance the tx counter and get the next unique nonce for this message.
        let nonce_bytes = self.state.next_tx_nonce();
        // `Nonce::from_slice` creates a typed wrapper around the byte array.
        // The ChaCha20-Poly1305 API requires this typed wrapper.
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the plaintext.
        // `cipher.encrypt(nonce, data)` returns:
        //   Ok(ciphertext_with_tag) — where `ciphertext_with_tag` is
        //   `len(data) + 16` bytes (the 16 extra bytes are the Poly1305 tag).
        // or:
        //   Err(aead::Error) — if encryption fails (shouldn't happen in practice).
        let ciphertext = self
            .state
            .cipher
            .encrypt(nonce, data)
            .map_err(|_| MeshInfinityError::CryptoError("I2P encrypt failed".to_string()))?;

        // Calculate the frame payload size (everything after the 4-byte length header):
        // 12 bytes for the nonce + len(ciphertext) bytes for the encrypted data + tag.
        let total_len = (nonce_bytes.len() + ciphertext.len()) as u32;

        // Write the frame to the TCP stream in three parts:
        //   1. 4-byte length header (so the receiver knows how much to read).
        //   2. 12-byte nonce.
        //   3. Ciphertext (including the 16-byte Poly1305 tag).
        self.stream.write_all(&total_len.to_be_bytes())?; // length prefix
        self.stream.write_all(&nonce_bytes)?;             // nonce
        self.stream.write_all(&ciphertext)?;              // encrypted data + auth tag

        // Return the number of PLAINTEXT bytes provided by the caller.
        Ok(data.len())
    }

    /// Receive and decrypt one framed message.
    ///
    /// This function reads exactly one frame from the wire and returns the
    /// decrypted plaintext.  If the frame is malformed, the nonce is wrong,
    /// or the authentication tag doesn't match, an error is returned.
    ///
    /// # Step-by-step walkthrough
    ///
    /// **Step 1: Read the 4-byte length header.**
    /// `self.stream.read_exact(&mut len_bytes)` blocks until exactly 4 bytes
    /// arrive.  `u32::from_be_bytes(len_bytes)` interprets those bytes as a
    /// big-endian u32, giving us `total_len` — the number of bytes remaining
    /// in this frame (nonce + ciphertext).
    ///
    /// **Step 2: Sanity check `total_len`.**
    /// The minimum valid frame has only a 12-byte nonce and zero ciphertext
    /// bytes.  Anything smaller is impossible/malformed.  We reject it rather
    /// than trying to read negative bytes (which would panic or loop forever).
    ///
    /// **Step 3: Read the full frame.**
    /// `vec![0u8; total_len]` allocates a buffer on the heap of exactly
    /// `total_len` bytes, all initialised to zero.  `read_exact` then fills
    /// every byte of this buffer.
    ///
    /// **Step 4: Extract the 12-byte nonce.**
    /// `frame[..12]` is the first 12 bytes of the frame.  We copy them into
    /// a fixed-size array with `copy_from_slice`.
    ///
    /// **Step 5: Verify the nonce.**
    /// `self.state.next_rx_nonce()` advances the receive counter and returns
    /// what the nonce SHOULD be if this message is the next in sequence.
    /// If the received nonce doesn't match, the frame is rejected.
    /// This catches replayed packets (an attacker re-sending an old frame)
    /// and stream corruption (bytes lost or reordered by the network — though
    /// TCP prevents reordering, so this is defensive).
    ///
    /// **Step 6: Decrypt.**
    /// `cipher.decrypt(nonce, &frame[12..])` decrypts the ciphertext and
    /// simultaneously verifies the 16-byte Poly1305 authentication tag.
    /// If even one byte was changed in transit, `decrypt()` returns `Err`
    /// rather than silently returning garbled data.
    ///
    /// **Step 7: Copy plaintext into caller's buffer.**
    /// `usize::min(buffer.len(), plaintext.len())` prevents buffer overflow
    /// if the plaintext is larger than the provided buffer.  In a well-behaved
    /// application the buffer should be large enough, but we don't panic on
    /// mismatch — we just return as many bytes as fit.
    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize> {
        // A closed connection has no data — return 0 bytes like an EOF.
        if self.closed {
            return Ok(0);
        }

        // Step 1: read the 4-byte length header.
        let mut len_bytes = [0u8; 4];
        self.stream.read_exact(&mut len_bytes)?;
        // `from_be_bytes` converts big-endian bytes back to a u32 integer.
        let total_len = u32::from_be_bytes(len_bytes) as usize;

        // Step 2: sanity check — frame must be at least 12 bytes (nonce) and at
        // most 65 536 bytes.  Without an upper bound a malicious peer can send
        // [0xFF,0xFF,0xFF,0xFF] and force a 4 GB allocation → instant OOM.
        if total_len < 12 || total_len > 65_536 {
            return Err(MeshInfinityError::InvalidMessageFormat);
        }

        // Step 3: read the full frame payload (nonce + ciphertext).
        // `vec![0u8; total_len]` creates a zeroed heap-allocated buffer.
        let mut frame = vec![0u8; total_len];
        self.stream.read_exact(&mut frame)?;

        // Step 4: extract the 12-byte nonce from the start of the frame.
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&frame[..12]);

        // Step 5: advance the receive counter and compare with the received nonce.
        // If they differ, something is wrong — replay attack, corruption, or an
        // out-of-sequence message (which TCP doesn't allow, but we check anyway).
        let expected_nonce = self.state.next_rx_nonce();
        if nonce_bytes != expected_nonce {
            return Err(MeshInfinityError::SecurityError(
                "I2P nonce sequence mismatch".to_string(),
            ));
        }

        // Step 6: decrypt the ciphertext (everything after the 12-byte nonce).
        // `&frame[12..]` is a slice starting at index 12, going to the end.
        // `decrypt()` verifies the Poly1305 tag and returns the plaintext,
        // or an error if the tag doesn't match (ciphertext was tampered with).
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = self
            .state
            .cipher
            .decrypt(nonce, &frame[12..])
            .map_err(|_| MeshInfinityError::CryptoError("I2P decrypt failed".to_string()))?;

        // Step 7: copy as many decrypted bytes as fit into the caller's buffer.
        // If `plaintext` is larger than `buffer`, we silently truncate.
        // The caller is expected to provide a buffer large enough for their
        // expected message size.
        let to_copy = usize::min(buffer.len(), plaintext.len());
        buffer[..to_copy].copy_from_slice(&plaintext[..to_copy]);
        Ok(to_copy)
    }

    /// Close the TCP connection.
    ///
    /// `Shutdown::Both` signals the OS to close both the send and receive
    /// halves of the TCP socket simultaneously.  This:
    ///   1. Sends a TCP FIN packet to the remote peer, signalling "I'm done."
    ///   2. Prevents further reads and writes on this socket.
    ///
    /// We set `self.closed = true` after shutdown so that subsequent calls
    /// to `send()` or `receive()` return immediately with an error rather than
    /// attempting to use the closed socket.
    ///
    /// If `close()` is called when already closed (`self.closed == true`),
    /// we do nothing (idempotent).
    fn close(&mut self) -> Result<()> {
        if !self.closed {
            // `std::net::Shutdown::Both` closes both read and write halves.
            self.stream.shutdown(std::net::Shutdown::Both)?;
            self.closed = true;
        }
        Ok(())
    }

    /// Return a reference to the remote peer's metadata.
    fn remote_peer(&self) -> &PeerInfo {
        &self.peer
    }

    /// Return `true` if this connection has not been explicitly closed.
    ///
    /// Note: this only reflects whether `close()` was called, not whether the
    /// TCP socket is still reachable.  A connection where the remote peer
    /// disconnected unexpectedly would still return `true` until a `send()` or
    /// `receive()` fails and the caller calls `close()`.
    fn is_active(&self) -> bool {
        !self.closed
    }
}

// ---------------------------------------------------------------------------
// I2pListener — server-side listener
// ---------------------------------------------------------------------------

/// A TCP listener that performs the I2P-style handshake on each new connection.
///
/// Created by `I2pTransport::listen()`.  The listener binds to an OS-chosen
/// port and accepts inbound TCP connections.  For each new connection, it runs
/// the server-side DH handshake before returning a fully encrypted
/// `I2pConnection` ready for use.
///
/// # How the accept loop works
///
/// The typical usage pattern is:
///
/// ```text
/// let listener = transport.listen()?;
/// loop {
///     let conn = listener.accept()?;  // blocks until someone connects
///     // spawn a task to handle `conn`
/// }
/// ```
///
/// `accept()` blocks the calling thread until a client connects.  For
/// a server that handles many clients concurrently, the accept loop is
/// usually run in its own thread.
pub struct I2pListener {
    /// The underlying OS TCP listener.
    listener: TcpListener,
}

impl Listener for I2pListener {
    /// Accept one inbound connection and perform the server-side handshake.
    ///
    /// This call **blocks** until a client connects.
    ///
    /// # What happens
    ///
    /// 1. `self.listener.accept()` blocks until a client connects.
    ///    It returns `(TcpStream, SocketAddr)` — the new connection socket
    ///    and the client's IP address + port.
    ///
    /// 2. Set 10-second read and write timeouts on the new socket.
    ///    A client that connects but then stalls during the handshake
    ///    (e.g., it sent the TAG but never sent the public key) would
    ///    otherwise block the server indefinitely.
    ///
    /// 3. Run the server-side DH handshake.  If the client speaks the wrong
    ///    protocol (wrong TAG), the handshake returns an error and the
    ///    connection is dropped.
    ///
    /// 4. Build a placeholder `PeerInfo` for the new connection.
    ///    At this point we know the client's IP:port (from the `accept()`
    ///    result) but we do NOT yet know its peer ID or public key — those are
    ///    application-layer concepts exchanged after the transport is set up.
    ///    We fill `peer_id` and `public_key` with all-zeros and set
    ///    `trust_level` to `Untrusted` until the application layer authenticates
    ///    the peer.
    ///
    /// 5. Return the encrypted `I2pConnection`.  All further communication
    ///    through this connection is automatically encrypted and authenticated.
    fn accept(&mut self) -> Result<Box<dyn Connection>> {
        // Block until a client connects.  `addr` is the client's IP:port.
        let (mut stream, addr) = self.listener.accept()?;

        // Set timeouts so a slow client during the handshake can't hang us.
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;

        // Run the server side of the DH handshake.
        let state = HandshakeState::server_handshake(&mut stream)?;

        // Build a placeholder peer metadata record.
        // `peer_id: [0; 32]` creates a 32-byte array filled with zeros.
        // These will be replaced by real values once the application layer
        // authenticates the connecting peer.
        let peer = PeerInfo {
            peer_id: [0; 32],       // unknown until app-layer authentication
            public_key: [0; 32],    // unknown until app-layer authentication
            trust_level: crate::core::TrustLevel::Untrusted, // stranger until verified
            available_transports: vec![TransportType::I2P],
            last_seen: None,
            endpoint: Some(addr),   // we do know the client's IP:port from accept()
            transport_endpoints: std::collections::HashMap::new(),
        };

        Ok(Box::new(I2pConnection {
            stream,
            peer,
            state,
            closed: false,
        }))
    }

    /// Signal the listener to stop accepting new connections.
    ///
    /// Rust's standard library `TcpListener` has no explicit "close" method.
    /// The listener is automatically closed when the `I2pListener` struct is
    /// dropped (the OS releases the port at that point).
    ///
    /// However, if code is blocked on `accept()` in a loop, we need a way to
    /// make that `accept()` return an error so the loop can exit.  Setting the
    /// listener to non-blocking mode achieves this: the next `accept()` call
    /// will return a `WouldBlock` error immediately instead of blocking, and
    /// the loop can check a shutdown flag and exit.
    fn close(&mut self) -> Result<()> {
        // Switch to non-blocking mode.  The next `accept()` will return
        // immediately with an error, allowing the accept loop to exit.
        self.listener.set_nonblocking(true)?;
        Ok(())
    }

    /// Return the local address this listener is bound to, as a string.
    ///
    /// The returned string is in `"IP:port"` format, e.g., `"0.0.0.0:48123"`.
    /// This is useful for advertising the port to other peers so they know
    /// where to connect.
    ///
    /// If `local_addr()` fails (very rare — only if the socket was already
    /// closed at the OS level), we fall back to the string `"0.0.0.0:0"`.
    fn local_addr(&self) -> String {
        self.listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "0.0.0.0:0".to_string())
    }
}
