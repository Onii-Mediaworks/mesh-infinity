// ============================================================================
// message_crypto.rs — Multi-layer Message Signing and Encryption
// ============================================================================
//
// OVERVIEW FOR BEGINNERS
// ----------------------
// This file is the heart of how Mesh Infinity protects every message it sends.
// Before a message travels over the network, it passes through four distinct
// layers of protection — think of them like four nested envelopes, each sealed
// in a different way.  When the recipient receives the message, they peel off
// the envelopes in reverse order.
//
// The four steps (applied when SENDING):
//
//   Step 1 — Inner signature
//       The sender signs the raw message bytes with their private key.
//       This proves the message genuinely came from them, like a handwritten
//       signature that nobody else can forge.
//
//   Step 2 — Trust-pair encryption  (only for "trusted" peers)
//       If the two peers have explicitly trusted each other (e.g. via QR
//       pairing), the signed message is further encrypted with a shared
//       symmetric key that only those two peers can derive.  This provides an
//       extra layer of confidentiality even before the outer envelope is applied.
//       Untrusted peers skip this step.
//
//   Step 3 — Outer signature
//       The result of step 2 is signed *again* by the sender.  This lets the
//       recipient confirm, even before fully decrypting, that the outer
//       envelope has not been tampered with.
//
//   Step 4 — Public-key encryption with an ephemeral key
//       Finally, everything is encrypted using the recipient's public DH key,
//       combined with a brand-new random "ephemeral" key pair that is generated
//       fresh for every single message.  This is what gives us Perfect Forward
//       Secrecy (explained in detail below).
//
// The reverse of these steps happens when RECEIVING.
//
// WHY SO MANY LAYERS?
// -------------------
// Each layer serves a distinct security goal:
//   • The inner signature proves who sent the plaintext.
//   • The trust layer provides additional confidentiality between known peers.
//   • The outer signature proves the encrypted blob was not modified in transit.
//   • The outer encryption hides the sender's identity from eavesdroppers —
//     only the recipient can decrypt and then see who signed the inner layer.
//
// CRYPTOGRAPHIC PRIMITIVES USED (plain-English glossary)
// -------------------------------------------------------
//
// Ed25519   — A digital signature algorithm.  Each peer has a "signing key"
//             (kept secret) and a "verifying key" (shared publicly).  Signing
//             a message with the secret key produces a 64-byte signature that
//             anyone holding the verifying key can check — but nobody without
//             the secret key can forge.  Ed25519 is fast and produces very
//             small signatures.
//
//             ANALOGY: Think of a wax seal on an envelope.  Anyone can look
//             at the seal and check whether it matches your personal signet
//             ring.  But only you have the ring, so only you can make that seal.
//
// X25519    — A Diffie-Hellman (DH) key-exchange algorithm.  Two parties can
//             each hold a private number and a corresponding public number.
//             By combining YOUR private number with THEIR public number (and
//             vice versa), both sides arrive at the same "shared secret"
//             without ever transmitting that secret over the network.  This is
//             how two people can agree on a symmetric key even on a network
//             full of eavesdroppers.
//
//             ANALOGY: Imagine you and a friend want to agree on a secret
//             paint colour without anyone overhearing.  You each start with
//             the same base paint (a public value).  You each mix in your own
//             secret colour (your private key) and send the result.  Your
//             friend mixes their secret into YOUR mixture; you mix your secret
//             into THEIR mixture.  Both end up with the same final colour —
//             but no single intercepted mixture reveals the final blend.
//
// Ephemeral key
//             A key pair that is generated fresh for a single use and then
//             immediately discarded.  Using an ephemeral key in the outer
//             encryption layer means that even if an attacker later steals
//             your long-term private key, they still cannot decrypt past
//             messages — the ephemeral private half no longer exists.
//
//             ANALOGY: Each message is like a locker at a train station.
//             A new locker is used for every single message, and the key to
//             that locker is thrown away the moment the message is sealed.
//             Even if someone breaks into your house and finds all your keys,
//             the locker keys are already gone.
//
// Perfect Forward Secrecy (PFS)
//             The property that compromising today's keys cannot decrypt
//             yesterday's messages.  Because each message uses a different
//             ephemeral key pair whose private half is thrown away immediately
//             after encryption, there is no key to steal that would unlock
//             old ciphertext.
//
//             WHY THIS MATTERS: Passive adversaries often record everything
//             they see on a network, hoping to decrypt it later when they
//             acquire the right key.  PFS defeats this "record-now, decrypt-
//             later" strategy.
//
// HKDF (Hash-based Key Derivation Function)
//             A standard algorithm for turning raw key material (e.g. a DH
//             shared secret) into a properly formatted, safe-to-use
//             cryptographic key.  Raw DH output is not uniformly random
//             enough to use directly as a symmetric key, so we always run
//             it through HKDF first.  You can think of HKDF as a very
//             carefully designed blender: messy input goes in, clean and
//             uniform output comes out.
//
//             HKDF has two internal stages:
//               Extract — "compress" the input into a fixed-size pseudorandom
//                         value (even if the input has structure or biases).
//               Expand  — "stretch" that value into as many key bytes as you
//                         need, mixing in a domain-separation label at each step.
//
//             DOMAIN SEPARATION: Each use of HKDF includes a different label
//             string (e.g. "meshinfinity-trust-key-v1" vs
//             "meshinfinity-message-key-v1").  This ensures that two different
//             uses of the same shared secret produce completely different keys,
//             even though the underlying material is the same.  This prevents
//             one key from accidentally being used where another was intended.
//
// ChaCha20-Poly1305 (AEAD)
//             An "Authenticated Encryption with Associated Data" cipher.
//             "Authenticated" means it not only hides the plaintext but also
//             detects any tampering with the ciphertext — if even one bit is
//             changed after encryption, decryption will fail with an error
//             rather than silently returning garbled data.  ChaCha20 is the
//             stream cipher (the part that scrambles the data); Poly1305 is
//             the message-authentication code (the part that detects tampering).
//             Together they are the AEAD construction used throughout this file.
//
//             WHY AEAD INSTEAD OF SEPARATE ENCRYPT+MAC?
//             Combining encryption and authentication into one primitive (AEAD)
//             is safer than doing them separately.  Subtle mistakes in the
//             ordering of "encrypt then MAC" vs "MAC then encrypt" have caused
//             real-world vulnerabilities.  AEAD forces the correct composition.
//
//             HOW THE TAG WORKS: Poly1305 is a polynomial-evaluation MAC.
//             After encryption, it evaluates a polynomial (whose coefficients
//             are blocks of the ciphertext) at a point derived from the key.
//             The result is the 16-byte tag.  Changing ANY byte of the
//             ciphertext changes the polynomial evaluation, so the tag will
//             no longer match — the receiver will detect the tampering and
//             refuse to output the plaintext.
//
// Nonce      A "number used once" — a unique value that must never be reused
//             with the same key.  Reusing a nonce with ChaCha20-Poly1305 would
//             catastrophically break confidentiality.  Here we combine a
//             monotonically increasing counter with random bytes to ensure
//             nonces are both unique and unpredictable.
//
//             WHY IS NONCE REUSE SO BAD?
//             ChaCha20 generates a keystream (a deterministic pseudorandom
//             sequence) from the key+nonce pair.  If you use the same nonce
//             twice, you get the same keystream twice.  XOR-ing two different
//             plaintexts with the same keystream lets an attacker cancel the
//             keystream out entirely: C1 XOR C2 = P1 XOR P2.  With both
//             plaintexts XOR-ed together, statistical analysis can often
//             recover both messages, especially if one contains known text.
//
// Zeroizing  A Rust type that automatically overwrites sensitive byte arrays
//             with zeros when they are dropped (freed from memory).  This
//             prevents keys from lingering in RAM where a memory-dumping
//             attacker could find them.
//
//             WHY ZEROING MATTERS: Even after a variable goes out of scope,
//             its bytes may remain in physical RAM until overwritten.  If an
//             attacker can read process memory (e.g. through a vulnerability
//             or after a process crash dump), unzeroed key material could be
//             extracted.  `Zeroizing` makes the window of exposure as short
//             as possible.

// --- Standard library imports ---
use std::collections::HashMap;

// --- ChaCha20-Poly1305 AEAD cipher (encryption + authentication) ---
// `Aead`    — the trait that gives us `.encrypt()` and `.decrypt()` methods.
// `KeyInit` — the trait that gives us `.new(key)` to construct a cipher object.
// `ChaCha20Poly1305` — the concrete cipher type (implements both traits).
// `Key`     — a newtype around a 32-byte array used as the symmetric key.
// `Nonce`   — a newtype around a 12-byte array used as the per-encryption nonce.
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};

// --- Ed25519 digital signature types ---
// `SigningKey`   — the secret half of an Ed25519 key pair.  Used to produce
//                  signatures.  Must NEVER be transmitted.
// `VerifyingKey` — the public half.  Used to check (verify) signatures.
//                  Safe to share with anyone.
// `Signature`    — the 64-byte output of a signing operation.
// `Signer`       — a trait (interface) that adds the `.sign(message)` method.
// `Verifier`     — a trait that adds the `.verify(message, sig)` method.
// `SIGNATURE_LENGTH` — the constant 64 (bytes in every Ed25519 signature).
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey, SIGNATURE_LENGTH};

// --- HKDF (key derivation function) parameterised over SHA-256 ---
// `Hkdf::<Sha256>` is "HKDF using SHA-256 as its underlying hash function".
// SHA-256 is the specific hash used in the Extract and Expand steps.
use hkdf::Hkdf;

// --- OsRng: the operating system's cryptographically secure random number generator ---
// `OsRng` draws entropy from the OS kernel's secure random pool:
//   /dev/urandom on Linux, CryptGenRandom on Windows, SecRandomCopyBytes on Apple.
// It is "cryptographically secure" meaning its output is statistically
// indistinguishable from true randomness and cannot be predicted by an attacker.
use rand_core::OsRng;

// --- SHA-256 hash function (used internally by HKDF) ---
// SHA-256 maps any input to a 32-byte "digest".  Changing even one bit of the
// input completely changes the output.  It is a one-way function: you cannot
// reverse it to recover the input.
use sha2::Sha256;

// --- X25519 Diffie-Hellman types ---
// `EphemeralSecret` — a one-shot DH private key that is automatically consumed
//                     (and thus cannot be reused) after one Diffie-Hellman call.
//                     The Rust type system enforces that you cannot call
//                     `.diffie_hellman()` twice on the same `EphemeralSecret`.
// `StaticSecret`    — a long-lived DH private key that can be reused across
//                     many Diffie-Hellman operations.  Stored persistently.
// `PublicKey`       — the corresponding DH public key (32 bytes).  This is
//                     what you share with other peers so they can send you
//                     encrypted messages.
//
// NOTE: `PublicKey` is imported as `X25519PublicKey` to avoid ambiguity with
// the Ed25519 public key type (`VerifyingKey`).  Naming collisions between
// different "PublicKey" types are a common pitfall in cryptography code.
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

// --- Zeroizing wrapper: zeroes memory when the value is dropped ---
// `Zeroizing<T>` is a transparent wrapper — it behaves exactly like `T` in
// normal use, but when it is dropped (goes out of scope), it fills its memory
// with 0x00 bytes BEFORE the allocator reclaims that memory.  This limits
// the time window during which sensitive key material exists in RAM.
use zeroize::Zeroizing;

// --- Internal application types ---
// `PeerId` is a 32-byte identifier for a peer node on the network.
// `MeshInfinityError` and `Result` are our application's error types.
use crate::core::core::PeerId;
use crate::core::error::{MeshInfinityError, Result};

// ============================================================================
// Size constants
// ============================================================================
// These are all fixed by the cryptographic standards we use.
// Hardcoding them as named constants (rather than magic numbers scattered
// through the code) makes the layout of messages easy to understand and
// less error-prone to maintain.

/// An Ed25519 signature is always exactly 64 bytes.
///
/// This is dictated by the Ed25519 standard (RFC 8032).  No matter how long
/// or short the message being signed, the signature is always 64 bytes.
const SIGNATURE_SIZE: usize = 64;

/// A ChaCha20-Poly1305 nonce is always exactly 12 bytes.
///
/// This is the value mandated by the RFC 8439 standard.  A shorter nonce
/// would be guessable; a longer one would require a different cipher variant.
const NONCE_SIZE: usize = 12;

/// An X25519 public key is always exactly 32 bytes.
///
/// Both `StaticSecret` and `EphemeralSecret` produce a 32-byte public key.
/// This is inherent to the Curve25519 elliptic curve that X25519 uses.
const X25519_PUBLIC_KEY_SIZE: usize = 32;

/// Poly1305 appends a 16-byte authentication tag to every ciphertext.
///
/// The tag is a cryptographic "fingerprint" of the ciphertext.  If the
/// ciphertext is modified after encryption, the tag will no longer match
/// and decryption will fail.  If a ciphertext blob is shorter than 16 bytes,
/// there is not even room for the tag, so it is definitely corrupt.
const TAG_SIZE: usize = 16;

// ============================================================================
// MessageCrypto — the main struct
// ============================================================================

/// The cryptographic engine for a single local node.
///
/// Holds all of the long-term key material for this device and maintains a
/// table of derived symmetric keys for each "trusted" peer.  All message
/// encryption and decryption operations go through this struct.
///
/// # Key material overview
///
/// Every node has two separate key pairs, each serving a different purpose:
///
/// 1. **Ed25519 signing key pair** — used for digital signatures.  The private
///    half (`signing_keypair`) signs messages to prove authorship.  The public
///    half is shared so that others can verify those signatures.
///
/// 2. **X25519 DH key pair** — used for key agreement.  The private half
///    (`static_dh_key`) is combined with another peer's public DH key to
///    derive a shared secret that nobody else knows.  The public half
///    (`static_dh_public`) is advertised so that senders can encrypt messages
///    that only this node can decrypt.
///
/// # Why keep signing and encryption keys separate?
///
/// It is a widely recommended practice to not use the same key pair for both
/// signing and encryption.  The reasons include:
///   * Different algorithms (Ed25519 vs X25519) have different mathematical
///     properties and security assumptions.  Mixing their key material can
///     introduce subtle vulnerabilities.
///   * If one key is compromised, the attacker gains only one capability
///     (either forge signatures OR decrypt messages) rather than both.
///   * Regulatory / auditing clarity: it is clear from the code which key
///     is used for what purpose.
pub struct MessageCrypto {
    /// Our Ed25519 signing key (the secret half).
    ///
    /// This 32-byte scalar is used to produce signatures that prove a message
    /// came from us.  It is NEVER transmitted — only the corresponding
    /// `verifying_key()` (the public half) is shared with peers.
    ///
    /// The `SigningKey` type from `ed25519-dalek` actually stores 64 bytes
    /// internally: the 32-byte scalar (the "real" private key) plus the
    /// 32-byte public key cached alongside it for efficiency.  The extra
    /// 32 bytes are not secret — they are just the public half.
    signing_keypair: SigningKey,

    /// Our X25519 static Diffie-Hellman private key.
    ///
    /// "Static" means this key persists across many messages (unlike an
    /// ephemeral key, which is discarded after one use).  It is combined with
    /// a sender's ephemeral public key (inside `decrypt_message`) to recreate
    /// the per-message shared secret.
    ///
    /// Like the signing key, this is NEVER transmitted.
    ///
    /// IMPORTANT: Because this key is used in every DH exchange with every
    /// peer, it must be treated with the highest level of care.  If it were
    /// ever leaked, an attacker could retroactively decrypt ANY message
    /// ever sent to this node (unlike the ephemeral keys, which are gone).
    static_dh_key: StaticSecret,

    /// The public half of our X25519 static DH key pair.
    ///
    /// This is derived mathematically from `static_dh_key` and is safe to
    /// share publicly.  Senders use it as the "destination" for their
    /// ephemeral DH operation so that only we can decrypt the result.
    ///
    /// WHY STORE IT? Deriving the public key from the private key is cheap,
    /// but we compute it once here to avoid repeating the derivation on every
    /// call to `public_dh_key()`.
    static_dh_public: X25519PublicKey,

    /// A map from peer ID → 32-byte symmetric key, one entry per trusted peer.
    ///
    /// When two peers establish trust (e.g. by scanning each other's QR codes),
    /// each side performs a Diffie-Hellman between its own *static* DH key and
    /// the other side's *static* DH public key.  Both sides arrive at the same
    /// shared secret, which is then run through HKDF to produce a stable,
    /// well-distributed 32-byte symmetric key stored here.
    ///
    /// This key is used for the "trust-pair encryption" layer (step 2 / step 2
    /// in reverse).  `Zeroizing` ensures the key bytes are wiped from memory
    /// when the entry is removed from the map.
    ///
    /// ANALOGY: This is like a private phone book where each contact has a
    /// secret handshake that only the two of you know.
    trust_keys: HashMap<PeerId, Zeroizing<[u8; 32]>>,

    /// A monotonically increasing counter used to help construct unique nonces.
    ///
    /// ChaCha20-Poly1305 requires that the same key is NEVER paired with the
    /// same nonce twice.  We build each nonce from the lower 8 bytes of this
    /// counter (always increasing) plus 4 random bytes (unpredictable).
    /// The combination makes accidental nonce reuse essentially impossible.
    ///
    /// WHY A COUNTER PLUS RANDOM?
    ///   * The counter alone would be deterministic — if the counter state
    ///     were somehow reset (e.g. by loading old state from disk), you could
    ///     produce duplicate nonces.
    ///   * Random alone has a non-zero collision probability (birthday paradox:
    ///     after ~2^48 messages with a 96-bit nonce, collision probability
    ///     becomes non-trivial).
    ///   * The combination: the counter guarantees no two calls in the same
    ///     session reuse a nonce; the random part handles the cross-session
    ///     case and makes nonces unpredictable to an observer.
    nonce_counter: u64,
}

impl MessageCrypto {
    // ========================================================================
    // Construction
    // ========================================================================

    /// Build a `MessageCrypto` from existing key bytes.
    ///
    /// `signing_keypair` — a previously generated Ed25519 signing key.
    /// `dh_secret`       — the raw 32-byte X25519 private key scalar.
    ///
    /// This constructor is used when loading a persisted identity from disk.
    /// The keys are passed in from secure storage rather than generated fresh.
    ///
    /// # Why not generate keys here?
    ///
    /// Keys must be the same across app restarts — the user's identity on the
    /// network is defined by their public keys.  If we generated new keys here,
    /// every launch would produce a different identity, and no other peer would
    /// recognize this device.  So when an identity already exists, we load the
    /// stored keys and pass them in.
    pub fn new(signing_keypair: SigningKey, dh_secret: [u8; 32]) -> Self {
        // Wrap the raw bytes in the StaticSecret type, which knows how to
        // perform X25519 Diffie-Hellman operations safely.
        // `StaticSecret::from([u8; 32])` takes ownership of the array and
        // stores it in a type that exposes `.diffie_hellman()`.
        let static_dh_key = StaticSecret::from(dh_secret);

        // Derive the public key from the private key.
        // This is a one-way mathematical operation: multiplying the private
        // scalar by the curve's generator point.  Knowing the public key does
        // not let you recover the private key (that would require solving the
        // discrete logarithm problem on an elliptic curve — computationally
        // infeasible for Curve25519).
        let static_dh_public = X25519PublicKey::from(&static_dh_key);

        Self {
            signing_keypair,
            static_dh_key,
            static_dh_public,
            // Start with no trusted peers — they are registered individually
            // via `register_trust()` as trust relationships are established.
            trust_keys: HashMap::new(),
            // Start the nonce counter at zero; it will increment by 1 with
            // every call to `aead_encrypt`.  The starting value does not
            // matter because the random portion of each nonce is also fresh
            // on every call.
            nonce_counter: 0,
        }
    }

    /// Generate a brand-new `MessageCrypto` with freshly randomised keys.
    ///
    /// Used when a node is created for the first time and has no stored identity.
    /// `OsRng` and `getrandom` both draw entropy from the operating system's
    /// secure random source (e.g. `/dev/urandom` on Linux, `CryptGenRandom` on
    /// Windows).
    ///
    /// # Why use the OS random source?
    ///
    /// Cryptographic keys must be completely unpredictable.  A bad random
    /// number generator is a catastrophic vulnerability — if an attacker can
    /// predict your private key, all security collapses.  The operating system
    /// collects entropy from hardware events (disk timings, network interrupts,
    /// mouse movements, etc.) and mixes them into a secure pool.  We use that
    /// pool rather than any user-space pseudo-random generator.
    pub fn generate() -> Result<Self> {
        // Generate a new Ed25519 signing key from the OS random source.
        // Internally this generates 32 random bytes and uses them as the
        // private scalar.  The `&mut OsRng` tells the function to use our
        // OS-backed secure random source.
        let signing_keypair = SigningKey::generate(&mut OsRng);

        // Generate 32 random bytes for the X25519 DH private key.
        // We use `getrandom::fill` rather than OsRng here because StaticSecret
        // expects a plain byte array, not a typed RNG.  Both ultimately call
        // the same OS entropy source.
        let mut dh_secret_bytes = [0u8; 32];
        getrandom::fill(&mut dh_secret_bytes).map_err(|_| {
            MeshInfinityError::CryptoError("Failed to generate random bytes".into())
        })?;

        Ok(Self::new(signing_keypair, dh_secret_bytes))
    }

    // ========================================================================
    // Public key accessors
    // ========================================================================

    /// Return the public half of our Ed25519 signing key.
    ///
    /// This is the key we share with peers so they can verify our signatures.
    /// It is 32 bytes in the Ed25519 "compressed Edwards point" format.
    ///
    /// "Compressed" refers to the way the elliptic curve point (x, y) is stored:
    /// the y-coordinate is stored directly, and the sign of x is packed into
    /// the highest bit.  This halves the storage compared to storing both
    /// coordinates.
    ///
    /// The return type is a plain `[u8; 32]` (a stack-allocated byte array)
    /// rather than `VerifyingKey`.  This makes it easy to serialize, transmit
    /// over the network, or store in a database without needing to import
    /// ed25519-dalek types at the call site.
    pub fn public_signing_key(&self) -> [u8; 32] {
        self.signing_keypair.verifying_key().to_bytes()
    }

    /// Return the public half of our X25519 static DH key.
    ///
    /// This is the key we share with peers so they can encrypt messages that
    /// only we can decrypt.  It is 32 bytes in the X25519 Montgomery point
    /// format (a different coordinate system from Ed25519's Edwards format —
    /// Curve25519 and Ed25519 both live on the same mathematical curve but
    /// use different point representations).
    ///
    /// Any peer who wants to send us a message will use this key as the
    /// "target" for their ephemeral DH operation (step 4 of encryption).
    pub fn public_dh_key(&self) -> [u8; 32] {
        self.static_dh_public.to_bytes()
    }

    // ========================================================================
    // Trust management
    // ========================================================================

    /// Establish a trust relationship with `peer_id` using their DH public key.
    ///
    /// # How it works
    ///
    /// 1. We perform a Diffie-Hellman operation: our static private key ×
    ///    their static public key.  Both sides do the same computation in
    ///    opposite directions and arrive at the same 32-byte shared secret.
    ///    An eavesdropper who sees both public keys cannot compute this secret
    ///    without one of the private keys.
    ///
    /// 2. The raw DH output is passed through HKDF with a domain-separation
    ///    label ("meshinfinity-trust-key-v1") to produce a clean, uniformly
    ///    random 32-byte key.  The label ensures that the same DH output used
    ///    for a different purpose would produce a completely different key —
    ///    preventing cross-protocol attacks.
    ///
    /// 3. The derived key is stored in `trust_keys` keyed by `peer_id` and
    ///    will be used as the symmetric key for step-2 trust-pair encryption
    ///    in `encrypt_message` / `decrypt_message`.
    ///
    /// # When is this called?
    ///
    /// After two peers complete a pairing ceremony (e.g. scanning each
    /// other's QR codes), the app calls `register_trust` on each side.
    /// Because both sides perform the SAME DH operation (Alice uses
    /// `Alice_private × Bob_public`; Bob uses `Bob_private × Alice_public`,
    /// which equals the same result), they independently arrive at the same
    /// `trust_key` without ever transmitting it.
    pub fn register_trust(&mut self, peer_id: PeerId, their_public_dh: &[u8; 32]) {
        // Parse the peer's raw 32-byte public key into the X25519 type.
        // `X25519PublicKey::from([u8; 32])` just wraps the bytes; it does
        // not validate them further (Curve25519 accepts any 32-byte string).
        let their_public = X25519PublicKey::from(*their_public_dh);

        // Diffie-Hellman: our static private key × their public key.
        // Mathematically: our_private_scalar × their_curve_point.
        // The result is another curve point, serialised to 32 bytes.
        // Neither party transmitted this result; they each computed it
        // independently using their own private scalar.
        let shared_secret = self.static_dh_key.diffie_hellman(&their_public);

        // HKDF Extract step: "compress" the DH output into a proper pseudorandom key.
        // `None` for the salt means HKDF uses an all-zero salt.
        // The salt is a secondary source of randomness.  Since the DH output
        // (the IKM, "Input Key Material") is already high-entropy, an all-zero
        // salt is acceptable here — RFC 5869 allows it.
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());

        // Allocate a Zeroizing buffer to hold the derived key.
        // When this value is dropped (e.g. when removed from trust_keys),
        // its 32 bytes are automatically zeroed in memory.
        let mut trust_key = Zeroizing::new([0u8; 32]);

        // HKDF Expand step: derive the final 32-byte key.
        // The label b"meshinfinity-trust-key-v1" is the "info" string in
        // HKDF terminology.  It serves as a domain separator: even if
        // two different uses happen to share the same DH output, the different
        // labels ensure they produce different expanded keys.
        // "v1" makes it easy to change the scheme in future versions without
        // colliding with existing keys.
        // The `.expect()` here: HKDF expand only fails if the requested output
        // length is too long (more than 255 × hash-length bytes).  Since we
        // request exactly 32 bytes, this cannot fail.
        hkdf.expand(b"meshinfinity-trust-key-v1", trust_key.as_mut())
            .expect("HKDF expand failed");

        // Store the derived key indexed by this peer's ID.
        // Inserting a new entry for an existing peer_id replaces the old key.
        self.trust_keys.insert(peer_id, trust_key);
    }

    /// Remove a previously established trust relationship.
    ///
    /// Dropping the `Zeroizing` value from the map causes the derived key
    /// bytes to be immediately overwritten with zeros in memory.
    ///
    /// After this call, messages from/to this peer are no longer encrypted
    /// with the trust layer (step 2).  They can still be exchanged using the
    /// outer ephemeral DH layer (step 4), but without the extra inner
    /// confidentiality that trusted peers enjoy.
    pub fn remove_trust(&mut self, peer_id: &PeerId) {
        // `HashMap::remove` returns `Some(value)` if the key existed, or
        // `None` if it did not.  We discard the return value because we do
        // not need it.  Dropping the `Zeroizing<[u8; 32]>` here causes the
        // key bytes to be zeroed before the memory is freed.
        self.trust_keys.remove(peer_id);
    }

    /// Return `true` if we have a stored trust key for this peer.
    ///
    /// Used by `encrypt_message` to decide whether to apply step-2 encryption,
    /// and by `decrypt_message` to decide whether to apply step-2 decryption.
    /// The two uses MUST be consistent: if the sender applies trust encryption,
    /// the recipient must also attempt trust decryption, or the inner signature
    /// will fail.
    pub fn is_trusted(&self, peer_id: &PeerId) -> bool {
        self.trust_keys.contains_key(peer_id)
    }

    // ========================================================================
    // Core encryption
    // ========================================================================

    /// Encrypt a message using the full four-layer scheme.
    ///
    /// # Arguments
    /// * `message`            — the raw plaintext bytes to protect.
    /// * `recipient_public_dh`— the recipient's static X25519 public key (32 bytes).
    ///                          Used in step 4 so only they can decrypt.
    /// * `recipient_peer_id`  — used to look up a trust key in step 2.
    ///
    /// # Return value
    /// A byte vector laid out as:
    ///
    /// ```text
    /// [ ephemeral_public (32 B) | nonce (12 B) | ciphertext + tag (variable) ]
    /// ```
    ///
    /// The ephemeral public key is prepended in the clear so the recipient
    /// knows which key to use for step-4 decryption.
    ///
    /// # Takes `&mut self` because
    /// The nonce counter (`self.nonce_counter`) is incremented on every call.
    /// A mutable reference is required to modify state on `self`.
    pub fn encrypt_message(
        &mut self,
        message: &[u8],
        recipient_public_dh: &[u8; 32],
        recipient_peer_id: &PeerId,
    ) -> Result<Vec<u8>> {
        // ----------------------------------------------------------------
        // Step 1: Sign the plaintext with our Ed25519 signing key.
        //
        // `self.signing_keypair.sign(message)` produces a 64-byte signature
        // that any peer holding our verifying key can check.  We then
        // append the signature to the message itself, creating a
        // "message + signature" blob.
        //
        // WHY append rather than prepend? Either would work; append is
        // slightly easier to split on the recipient side because the
        // signature is always the last 64 bytes.  No parsing ambiguity.
        //
        // WHY sign the PLAINTEXT (before any encryption)?
        // The inner signature proves "the sender wrote THIS specific content".
        // If we signed the ciphertext instead, a relay or attacker could
        // strip the signature and add a forged one without changing the
        // payload — signing the plaintext prevents such subtleties.
        // ----------------------------------------------------------------
        let inner_signature = self.signing_keypair.sign(message);
        let mut signed_message = message.to_vec();
        signed_message.extend_from_slice(&inner_signature.to_bytes());
        // `signed_message` is now: [ plaintext | 64-byte signature ]

        // ----------------------------------------------------------------
        // Step 2: Trust-pair encryption (applied only if this peer is trusted).
        //
        // We look up the pre-derived symmetric key for this recipient.
        // `.map(|k| **k)` dereferences through both the HashMap value and the
        // Zeroizing wrapper to get a plain [u8; 32] — this copy is needed
        // because we cannot hold a reference into `self.trust_keys` while also
        // calling `self.aead_encrypt` (which takes `&mut self`).  Rust's borrow
        // checker prevents aliasing mutable references.
        //
        // If no trust key exists for this peer, we skip this layer entirely —
        // the signed message passes through unchanged.
        //
        // WHAT THIS PROVIDES: Even if the outer encryption (step 4) were somehow
        // broken (e.g. by a future quantum computer), a trusted peer's messages
        // would still be protected by this additional symmetric layer.  The
        // outer layer hides the message from everyone; the trust layer provides
        // an extra security margin specifically between paired peers.
        // ----------------------------------------------------------------
        let trust_key_opt = self.trust_keys.get(recipient_peer_id).map(|k| **k);
        let trust_encrypted = if let Some(trust_key) = trust_key_opt {
            // AEAD-encrypt the signed message under the shared trust key.
            // `aead_encrypt` prepends a nonce and appends a Poly1305 tag.
            self.aead_encrypt(&trust_key, &signed_message)?
        } else {
            // No trust relationship: pass through without step-2 encryption.
            // The message is still protected by steps 3 and 4.
            signed_message
        };

        // ----------------------------------------------------------------
        // Step 3: Sign the (possibly encrypted) output of step 2.
        //
        // This "outer signature" covers the trust-encrypted blob.  The
        // recipient verifies this signature BEFORE attempting to decrypt the
        // trust layer — if the outer envelope was tampered with in transit,
        // this check will fail immediately and we avoid wasting time on
        // decryption.
        //
        // This also means the recipient can confirm that the outer encryption
        // really does contain something signed by us, which prevents an
        // attacker from substituting a different outer blob.
        //
        // WHY SIGN TWICE?
        //   Inner signature (step 1): proves the CONTENT is authentic.
        //   Outer signature (step 3): proves the PACKAGING is authentic.
        //
        //   Together they provide what cryptographers call "non-repudiation":
        //   the sender cannot later deny having sent the message, because their
        //   private key was used to produce both signatures and nobody else
        //   has that key.
        // ----------------------------------------------------------------
        let outer_signature = self.signing_keypair.sign(&trust_encrypted);
        let mut double_signed = trust_encrypted;
        // Append the 64-byte outer signature at the end, same layout as step 1.
        double_signed.extend_from_slice(&outer_signature.to_bytes());
        // `double_signed` is now: [ step2_output | 64-byte outer signature ]

        // ----------------------------------------------------------------
        // Step 4: Encrypt with the recipient's static DH key using an
        //         ephemeral key pair.
        //
        // "Ephemeral" means we generate a brand-new X25519 key pair right
        // now, use it exactly once, and then let Rust drop it — the private
        // half is gone forever after this function returns.
        //
        // WHY ephemeral?  Perfect Forward Secrecy.
        //     If an attacker records all our encrypted traffic today and later
        //     steals our long-term private key, they still cannot decrypt any
        //     of those past messages.  Each message used a different ephemeral
        //     private key, and those keys no longer exist anywhere.
        //
        //     Without ephemeral keys (if we reused our static DH key for
        //     encryption), a stolen static private key would unlock every
        //     past message.  Ephemeral keys prevent this "decrypt-the-archive"
        //     attack.
        //
        // The X25519 DH operation:
        //     ephemeral_private × recipient_static_public
        //     = shared_secret
        //
        // The recipient will reverse it:
        //     recipient_static_private × ephemeral_public
        //     = the same shared_secret
        //
        //     (DH is symmetric: A_priv × B_pub = B_priv × A_pub)
        //
        // We send `ephemeral_public` in the clear so the recipient can
        // perform their half of the DH.  The ephemeral public key is not
        // secret — it is just a one-time public key that expires immediately.
        // ----------------------------------------------------------------
        let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
        // The public half is derived from the private half automatically.
        // This is cheap (one curve multiplication) and safe to transmit.
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

        // Parse the recipient's static DH public key from raw bytes.
        // The 32 raw bytes are a Montgomery-form x-coordinate on Curve25519.
        let recipient_public = X25519PublicKey::from(*recipient_public_dh);

        // Perform the Diffie-Hellman.  `ephemeral_secret` is consumed here —
        // after this call, the private half no longer exists in this process.
        // This is enforced by the Rust type system: `EphemeralSecret::diffie_hellman`
        // takes `self` by value, so the compiler will not allow a second call.
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public);

        // Derive a 32-byte AEAD encryption key from the raw DH shared secret.
        // Same HKDF pattern as `register_trust`, but with a different label so
        // the keys are domain-separated even if the same DH shared secret were
        // somehow reused (it won't be for ephemeral keys, but defence-in-depth
        // is good practice — the label also serves as documentation of intent).
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut final_key = Zeroizing::new([0u8; 32]);
        // "meshinfinity-message-key-v1" distinguishes this from a trust key or
        // session key derived from the same material.
        hkdf.expand(b"meshinfinity-message-key-v1", final_key.as_mut())
            .expect("HKDF expand failed");

        // AEAD-encrypt the double-signed blob under the derived key.
        // `aead_encrypt` returns: [ nonce (12 B) | ciphertext + Poly1305 tag ]
        let final_ciphertext = self.aead_encrypt(&final_key, &double_signed)?;

        // ----------------------------------------------------------------
        // Package the final output:
        //     [ ephemeral_public (32 B) | nonce (12 B) | ciphertext+tag ]
        //
        // The ephemeral public key is sent in the clear — it is not secret.
        // It is the public half of a one-time key pair.  The recipient needs
        // it to recompute the shared secret on their end.
        //
        // NOTE: We do NOT transmit the nonce separately; it is already
        // embedded at the start of `final_ciphertext` by `aead_encrypt`.
        // ----------------------------------------------------------------
        let mut result = Vec::with_capacity(X25519_PUBLIC_KEY_SIZE + final_ciphertext.len());
        // Prepend the 32-byte ephemeral public key.
        result.extend_from_slice(ephemeral_public.as_bytes());
        // Append the nonce + ciphertext + tag blob produced by aead_encrypt.
        result.extend(final_ciphertext);

        Ok(result)
    }

    // ========================================================================
    // Core decryption
    // ========================================================================

    /// Decrypt and authenticate a message encrypted with `encrypt_message`.
    ///
    /// Steps are applied in the exact reverse order of `encrypt_message`.
    ///
    /// # Arguments
    /// * `ciphertext`           — the full encrypted blob from the network.
    /// * `sender_public_signing`— the sender's Ed25519 verifying key (32 bytes).
    ///                            Used to verify both signatures.
    /// * `sender_peer_id`       — used to look up a trust key in step 2 reverse.
    ///
    /// # Return value
    /// The original plaintext on success, or an error if any authentication
    /// check fails or the ciphertext is malformed.
    ///
    /// # Fail-fast design
    ///
    /// The steps are ordered to fail as early as possible with as little
    /// work done as possible.  The outer AEAD check (step 4 reverse) happens
    /// first — it is cheap and catches random network corruption or totally
    /// wrong recipients immediately.  The outer signature check (step 3
    /// reverse) comes next, verifying the sender's identity before we touch
    /// the trust layer.  Only if those pass do we attempt trust decryption
    /// and the inner signature check.
    ///
    /// This ordering also prevents "padding oracle" and "decryption oracle"
    /// attacks where an attacker probes the system's reaction to crafted
    /// ciphertexts to extract information.
    ///
    /// # Takes `&self` (not `&mut self`) because
    /// Decryption does not change any state.  The nonce counter is only
    /// updated by encryption.  Immutable borrow allows decryption to be
    /// called from multiple threads simultaneously.
    pub fn decrypt_message(
        &self,
        ciphertext: &[u8],
        sender_public_signing: &[u8; 32],
        sender_peer_id: &PeerId,
    ) -> Result<Vec<u8>> {
        // Basic length sanity: the minimum valid message is the ephemeral key
        // (32 B) + nonce (12 B) + Poly1305 tag (16 B).  Anything shorter
        // cannot possibly be a valid ciphertext.  We check this before any
        // expensive operations to fail fast on garbage input.
        if ciphertext.len() < X25519_PUBLIC_KEY_SIZE + NONCE_SIZE + TAG_SIZE {
            return Err(MeshInfinityError::CryptoError("Message too short".into()));
        }

        // ----------------------------------------------------------------
        // Step 4 (reverse): Decrypt the outer layer using our static DH key.
        //
        // We extract the sender's ephemeral public key from the first 32
        // bytes of the message.  Then we perform our half of the DH:
        //     our_static_private × sender_ephemeral_public = shared_secret
        //
        // This gives us the same shared_secret that `encrypt_message`
        // computed on the sender's side, because DH is symmetric:
        //     A_private × B_public  =  B_private × A_public
        //
        // WHY CAN WE RECONSTRUCT THE SHARED SECRET?
        //     The ephemeral public key was sent in the clear (prepended to
        //     the message).  We have our static private key (stored on this
        //     device).  DH gives us the same result as the sender got when
        //     they combined THEIR ephemeral private key with OUR static
        //     public key.
        // ----------------------------------------------------------------
        let mut ephemeral_public_bytes = [0u8; 32];
        ephemeral_public_bytes.copy_from_slice(&ciphertext[..X25519_PUBLIC_KEY_SIZE]);
        let ephemeral_public = X25519PublicKey::from(ephemeral_public_bytes);

        // Compute the shared secret: our static private key × sender's ephemeral public key.
        // This mirrors the sender's: ephemeral_private × our_static_public.
        let shared_secret = self.static_dh_key.diffie_hellman(&ephemeral_public);

        // Derive the same 32-byte AEAD key that the sender derived, using the
        // identical HKDF label.  Both sides must use the same label for HKDF
        // to produce the same output.  If any input differs (wrong key,
        // different label), a completely different derived key results, and
        // the AEAD authentication tag check will fail.
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut final_key = Zeroizing::new([0u8; 32]);
        hkdf.expand(b"meshinfinity-message-key-v1", final_key.as_mut())
            .expect("HKDF expand failed");

        // Decrypt everything after the 32-byte ephemeral public key.
        // This recovers the "double signed" blob (step 3 output from encryption).
        // If the AEAD tag does not match (wrong recipient, tampered message),
        // `aead_decrypt` returns an error here and we stop immediately.
        let double_signed = self.aead_decrypt(&final_key, &ciphertext[X25519_PUBLIC_KEY_SIZE..])?;

        // ----------------------------------------------------------------
        // Step 3 (reverse): Verify the outer Ed25519 signature.
        //
        // The outer signature covers everything EXCEPT the trailing 64-byte
        // signature itself.  We split the decrypted blob into:
        //   - `trust_encrypted`:  the content that was signed (step 3 output)
        //   - `outer_signature_bytes`:  the 64-byte signature appended in step 3
        //
        // WHY verify the outer signature before decrypting the trust layer?
        //   1. Efficiency: fail fast.  Verifying a signature is cheap; trust
        //      decryption is an AEAD operation.  If the signature fails, we
        //      skip the decryption entirely.
        //   2. Security: prevents "padding oracle" style attacks where an
        //      attacker probes what happens during decryption of crafted
        //      ciphertexts.  By checking authenticity before decryption,
        //      we never feed attacker-controlled data into the trust cipher.
        // ----------------------------------------------------------------
        if double_signed.len() < SIGNATURE_SIZE {
            return Err(MeshInfinityError::CryptoError(
                "Missing outer signature".into(),
            ));
        }

        // The signature is always the last 64 bytes; everything before it is
        // the signed content.  This split was established in step 3 of encryption.
        let outer_sig_start = double_signed.len() - SIGNATURE_SIZE;
        let trust_encrypted = &double_signed[..outer_sig_start];
        let outer_signature_bytes = &double_signed[outer_sig_start..];

        // Parse the sender's Ed25519 verifying key from their raw 32-byte key.
        // `VerifyingKey::from_bytes` checks that the bytes form a valid
        // compressed Edwards point on Ed25519's curve.  Malformed keys
        // (e.g. all zeros, not on the curve) are rejected here.
        let sender_public = VerifyingKey::from_bytes(sender_public_signing)
            .map_err(|_| MeshInfinityError::CryptoError("Invalid sender public key".into()))?;

        // Copy the signature bytes into a fixed-size array (required by the
        // ed25519-dalek API which works with [u8; 64] rather than slices).
        let mut outer_sig_array = [0u8; SIGNATURE_LENGTH];
        outer_sig_array.copy_from_slice(outer_signature_bytes);
        let outer_signature = Signature::from_bytes(&outer_sig_array);

        // Verify: the signature must have been made by `sender_public` over
        // exactly these bytes.  Ed25519 verification is deterministic: given
        // the message, the public key, and the signature, it returns either
        // Ok (valid) or an error (invalid).  Any mismatch (wrong sender,
        // tampered content, replayed signature from a different message)
        // returns an error.
        sender_public
            .verify(trust_encrypted, &outer_signature)
            .map_err(|_| {
                MeshInfinityError::CryptoError("Outer signature verification failed".into())
            })?;

        // ----------------------------------------------------------------
        // Step 2 (reverse): Trust-pair decryption.
        //
        // If we have a trust key for this sender, use it to decrypt the blob.
        // If we do not, we assume step 2 was skipped during encryption and
        // pass the bytes through unchanged.
        //
        // NOTE: This must be consistent with what `encrypt_message` did.  If
        // the sender is in our trust_keys we decrypt; if not we pass through.
        // A mismatch (e.g. sender encrypted with trust, but we have no trust
        // key) would cause the inner signature check to fail in step 1 reverse,
        // because the "decrypted" data would actually be ciphertext that only
        // looks like noise to the signature verifier.
        //
        // WHY IS CONSISTENCY GUARANTEED?
        //     Trust is established mutually: if peer A has peer B in their
        //     trust_keys, then peer B also has peer A.  The only way A would
        //     have a trust key for B but B would not have one for A is if the
        //     trust relationship was established on one side but interrupted
        //     before completing on the other — in that case, the outer
        //     signature would still verify (it covers the trust-encrypted blob),
        //     but the inner signature check would fail, signalling the mismatch.
        // ----------------------------------------------------------------
        let signed_message = if let Some(trust_key) = self.trust_keys.get(sender_peer_id) {
            // Decrypt with the pre-derived symmetric trust key.
            // `trust_key` is a `&Zeroizing<[u8; 32]>`.  Dereferencing with `*`
            // gives `[u8; 32]`.  `aead_decrypt` takes `&[u8; 32]`, so we pass
            // `trust_key` directly (the Zeroizing wrapper implements Deref).
            self.aead_decrypt(trust_key, trust_encrypted)?
        } else {
            // No trust relationship: pass through unchanged.
            // `.to_vec()` copies the slice into a new owned Vec so the return
            // type matches the `if` branch above (which returns a Vec).
            trust_encrypted.to_vec()
        };

        // ----------------------------------------------------------------
        // Step 1 (reverse): Verify the inner Ed25519 signature.
        //
        // This signature covers the raw plaintext message.  Verifying it
        // confirms that:
        //   a) The message content has not been modified.
        //   b) The message was originally composed by the sender (who holds
        //      the private key corresponding to `sender_public`).
        //
        // The inner signature provides authenticity of the PLAINTEXT even
        // after all layers of encryption are removed.  It answers the question:
        // "Did this exact content come from this exact sender?" — independently
        // of all the encryption wrapping.
        //
        // WHY is this necessary if the outer signature already verified?
        //     The outer signature verified that the ENCRYPTED blob came from
        //     the sender.  But what if the sender legitimately sent a different
        //     plaintext, and an attacker re-encrypted it in a trust layer
        //     before re-signing?  The inner signature catches this: it verifies
        //     that the sender signed the exact bytes that ended up as the
        //     plaintext, not just the encrypted form.
        // ----------------------------------------------------------------
        if signed_message.len() < SIGNATURE_SIZE {
            return Err(MeshInfinityError::CryptoError(
                "Missing inner signature".into(),
            ));
        }

        // Split: everything before the last 64 bytes is the plaintext.
        // The last 64 bytes are the inner signature appended in step 1.
        let inner_sig_start = signed_message.len() - SIGNATURE_SIZE;
        let message = &signed_message[..inner_sig_start];
        let inner_signature_bytes = &signed_message[inner_sig_start..];

        // Same fixed-size copy pattern as for the outer signature above.
        let mut inner_sig_array = [0u8; SIGNATURE_LENGTH];
        inner_sig_array.copy_from_slice(inner_signature_bytes);
        let inner_signature = Signature::from_bytes(&inner_sig_array);

        // Verify that the plaintext was signed by the claimed sender.
        // We reuse `sender_public` — the same verifying key used for the outer
        // signature check.  Both signatures were made with the same private key.
        sender_public
            .verify(message, &inner_signature)
            .map_err(|_| {
                MeshInfinityError::CryptoError("Inner signature verification failed".into())
            })?;

        // All four checks passed:
        //   ✓ Outer AEAD tag (message was encrypted for us and not tampered with)
        //   ✓ Outer Ed25519 signature (packaging is authentic)
        //   ✓ Trust AEAD tag (only if trusted peer — inner confidentiality intact)
        //   ✓ Inner Ed25519 signature (plaintext content is authentic)
        //
        // Return the verified plaintext.
        Ok(message.to_vec())
    }

    // ========================================================================
    // Session keys (for persistent connections)
    // ========================================================================

    /// Derive a session key for use in an ongoing encrypted channel.
    ///
    /// Once two peers complete a handshake and establish a shared secret
    /// (e.g. from a DH exchange), it is more efficient to derive a single
    /// symmetric key and use it for all subsequent messages in that session,
    /// rather than performing a full four-layer encrypt/decrypt cycle every
    /// time.
    ///
    /// # What is a "session"?
    ///
    /// A session is an ongoing, persistent connection between two peers.
    /// Once the session key is established, both peers can encrypt and decrypt
    /// many messages quickly using just the symmetric key, without repeating
    /// the asymmetric DH handshake.  This is the same idea behind TLS session
    /// resumption: the expensive public-key work is done once, and fast
    /// symmetric encryption handles the bulk data.
    ///
    /// # `session_id` parameter
    ///
    /// `session_id` acts as a "nonce" or "context" for HKDF — mixing it into
    /// the key derivation ensures that two different sessions using the same
    /// underlying shared secret produce different keys.  This is the "salt"
    /// parameter of HKDF.
    ///
    /// For example, if you establish two sessions with the same peer one after
    /// another (e.g. after a reconnect), the new session_id produces a new
    /// key that is completely unrelated to the old one.  Compromise of one
    /// session's key does not compromise the other.
    ///
    /// # Return type
    ///
    /// The result is a `Zeroizing<[u8; 32]>` so the key is wiped from memory
    /// when the caller drops it.  Callers should store it in a `Zeroizing`
    /// wrapper or pass it immediately to `session_encrypt`/`session_decrypt`.
    pub fn derive_session_key(
        &self,
        shared_secret: &[u8],
        session_id: &[u8],
    ) -> Zeroizing<[u8; 32]> {
        // Use `session_id` as the HKDF salt (the first argument).
        // When a salt is provided it is mixed into the initial "extract" step
        // of HKDF, binding the derived key to this particular session.
        // Different session_ids → different salts → completely different output.
        let hkdf = Hkdf::<Sha256>::new(Some(session_id), shared_secret);
        let mut session_key = Zeroizing::new([0u8; 32]);
        // The label distinguishes this key from trust keys or message keys
        // derived from the same material.  Using "session" in the label makes
        // it impossible to accidentally confuse this with a trust key, even
        // if the same DH output were used as input to HKDF for both purposes.
        hkdf.expand(b"meshinfinity-session-key-v1", session_key.as_mut())
            .expect("HKDF expand failed");
        session_key
    }

    /// Encrypt a single chunk of data with a pre-derived session key.
    ///
    /// This is a thin wrapper around `aead_encrypt` and is used for
    /// efficient encryption of stream data once a session is established.
    ///
    /// PERFORMANCE NOTE: Using a session key avoids the asymmetric DH and
    /// HKDF operations of `encrypt_message`, making it much cheaper for
    /// frequent small messages (e.g. typing indicators, keepalives) once
    /// a session is already established.
    pub fn session_encrypt(&mut self, session_key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
        self.aead_encrypt(session_key, data)
    }

    /// Decrypt a single chunk of data with a pre-derived session key.
    ///
    /// This is a thin wrapper around `aead_decrypt`.
    ///
    /// The session key must be the same one used by the peer's `session_encrypt`
    /// call.  If the key does not match, or if the ciphertext was tampered
    /// with, `aead_decrypt` will return an error.
    pub fn session_decrypt(&self, session_key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.aead_decrypt(session_key, ciphertext)
    }

    // ========================================================================
    // Private helpers: raw AEAD encrypt / decrypt
    // ========================================================================

    /// Encrypt `plaintext` with ChaCha20-Poly1305 under the given 32-byte key.
    ///
    /// # How ChaCha20-Poly1305 works (simplified)
    ///
    /// 1. A 12-byte nonce is constructed (see below).
    /// 2. ChaCha20 uses the key and nonce to generate a pseudorandom keystream.
    ///    The keystream is essentially an infinite sequence of "random-looking"
    ///    bytes determined entirely by the key+nonce pair.
    /// 3. The keystream is XOR-ed with the plaintext to produce the ciphertext.
    ///    XOR-ing a known-random stream with plaintext "scrambles" it.
    ///    (If you XOR the same keystream bytes with the ciphertext, you get back
    ///    the plaintext — that is how the decryption works.)
    /// 4. Poly1305 computes a 16-byte authentication tag over the ciphertext.
    ///    This tag is appended to the ciphertext.  If ANY byte of the ciphertext
    ///    is changed, the tag will not match and decryption will fail.
    ///
    /// # Why ChaCha20 over AES?
    ///
    /// Both are excellent choices.  ChaCha20-Poly1305 was chosen here because:
    ///   * It is fast in software on devices without hardware AES acceleration
    ///     (e.g. older Android devices, embedded CPUs).
    ///   * It has no known timing-side-channel vulnerabilities in software
    ///     implementations — AES software implementations can leak key bits
    ///     through cache-timing attacks if not carefully written.
    ///   * It is universally supported by modern Rust crypto crates.
    ///
    /// # Nonce construction
    ///
    /// The nonce combines:
    ///   - Bytes 0..8: the 8-byte little-endian encoding of `nonce_counter`
    ///     (which increments by 1 with every call).
    ///   - Bytes 8..12: 4 random bytes from the OS CSPRNG.
    ///
    /// The counter ensures we never accidentally reuse a nonce within a single
    /// session.  The random portion makes nonces unpredictable (useful against
    /// certain timing attacks where an adversary can observe whether nonces
    /// are sequential).  Together they are astronomically unlikely to repeat.
    ///
    /// # Output layout
    /// ```text
    /// [ nonce (12 B) | ciphertext + Poly1305 tag (plaintext.len() + 16 B) ]
    /// ```
    ///
    /// The nonce is sent in the clear (prepended) so the decryptor can use it.
    /// A nonce is not secret — it just must not repeat for a given key.
    /// Knowing the nonce does not help an attacker without the key.
    fn aead_encrypt(&mut self, key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
        // Construct the ChaCha20-Poly1305 cipher object with the given key.
        // `Key::from_slice(key)` wraps the 32-byte array in the `Key` newtype
        // that the cipher API expects.
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

        // Build the 12-byte nonce: 8 bytes of counter + 4 bytes of randomness.
        //
        // `wrapping_add(1)` increments the counter without panicking on overflow.
        // After 2^64 encryptions the counter wraps back to 0 — at that point
        // the random portion still prevents a collision with overwhelming
        // probability (2^32 random bytes means ~2^-32 collision chance even
        // if the counter wraps).  In practice 2^64 messages is unreachable.
        self.nonce_counter = self.nonce_counter.wrapping_add(1);
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        // Write the counter into the first 8 bytes in little-endian order.
        // Little-endian means the least-significant byte is first.  This is
        // just a convention; big-endian would work equally well.
        nonce_bytes[..8].copy_from_slice(&self.nonce_counter.to_le_bytes());
        // Fill the remaining 4 bytes with OS random bytes.
        // `getrandom::fill` writes directly into the provided slice.
        getrandom::fill(&mut nonce_bytes[8..])
            .map_err(|_| MeshInfinityError::CryptoError("Failed to generate nonce".into()))?;

        let nonce = Nonce::from_slice(&nonce_bytes);

        // Perform the AEAD encryption.
        // The output is the ciphertext with the 16-byte Poly1305 tag appended.
        // Layout: [ encrypted_bytes | 16-byte authentication tag ]
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| MeshInfinityError::CryptoError("Encryption failed".into()))?;

        // Prepend the nonce so the decryptor can find it.
        // We build the full result in a single Vec to avoid multiple allocations.
        // Final layout: [ nonce (12 B) | ciphertext+tag (variable) ]
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend(ciphertext);

        Ok(result)
    }

    /// Decrypt a blob produced by `aead_encrypt`.
    ///
    /// Extracts the nonce from the first 12 bytes, then passes the remainder
    /// to ChaCha20-Poly1305 for authenticated decryption.  If the Poly1305 tag
    /// does not match (i.e. the ciphertext was tampered with), this returns an
    /// error without revealing any partial plaintext.
    ///
    /// # Why does AEAD return an opaque error on failure?
    ///
    /// The AEAD API intentionally does not tell you WHY decryption failed
    /// (wrong key? wrong nonce? tampered bytes?).  This is deliberate: if
    /// the error message distinguished "wrong key" from "tampered ciphertext",
    /// an attacker could probe the system to learn information about the key
    /// or the plaintext ("decryption oracle" attacks).  The opaque error
    /// prevents this entire class of attack.
    ///
    /// # `&self` rather than `&mut self`
    ///
    /// Decryption does not update the nonce counter — only encryption does.
    /// Taking an immutable reference allows decryption to be called concurrently
    /// from multiple threads without a mutex, which can be valuable for
    /// high-throughput message processing.
    fn aead_decrypt(&self, key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
        // A valid AEAD ciphertext is at minimum the nonce (12 B) plus the
        // Poly1305 authentication tag (16 B).  Anything shorter is invalid.
        // We check here to provide a clear error rather than panicking on
        // an out-of-bounds slice index below.
        if ciphertext.len() < NONCE_SIZE + TAG_SIZE {
            return Err(MeshInfinityError::CryptoError(
                "Ciphertext too short".into(),
            ));
        }

        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

        // The first 12 bytes are the nonce that was prepended during encryption.
        // We must use the EXACT same nonce that was used to encrypt, otherwise
        // the keystream will be different and decryption will produce garbage.
        // Since we prepended the nonce during encryption, we always know it.
        let nonce = Nonce::from_slice(&ciphertext[..NONCE_SIZE]);
        // Everything after the nonce is the actual AEAD ciphertext + tag.
        // This is what ChaCha20-Poly1305 will verify and decrypt.
        let actual_ciphertext = &ciphertext[NONCE_SIZE..];

        // Decrypt and verify the authentication tag in one atomic step.
        // ChaCha20-Poly1305 first regenerates the expected Poly1305 tag and
        // compares it to the tag at the end of `actual_ciphertext`.  Only
        // if they match (constant-time comparison to prevent timing attacks)
        // does it return the decrypted plaintext.  If verification fails,
        // `decrypt` returns an opaque error — it does not reveal which byte
        // was wrong, preventing information leakage.
        cipher
            .decrypt(nonce, actual_ciphertext)
            .map_err(|_| MeshInfinityError::CryptoError("Decryption failed".into()))
    }
}

// ============================================================================
// MessageHeader — lightweight routing metadata
// ============================================================================

/// A parsed view of the first few bytes of an encrypted message.
///
/// When a node receives a raw packet from the network, it does not immediately
/// decrypt the whole thing.  Instead it parses just the header to find out:
///   1. Which ephemeral public key was used (needed for step-4 decryption).
///   2. How many bytes of ciphertext follow (for buffer management).
///
/// The header contains no secret data — the ephemeral public key is public.
///
/// # Why have a separate header type?
///
/// Parsing only the header is cheap and lets the routing layer make decisions
/// (e.g. "is this destined for me?", "how much buffer space do I need?")
/// without committing to a full decryption.  It also provides a clear API
/// boundary: the `MessageHeader` communicates layout information, while
/// `MessageCrypto::decrypt_message` handles the cryptographic logic.
#[derive(Debug, Clone)]
pub struct MessageHeader {
    /// The sender's ephemeral X25519 public key (32 bytes).
    ///
    /// This is the public half of the throwaway key pair generated in step 4
    /// of `encrypt_message`.  The recipient uses this to compute the shared
    /// secret: `recipient_static_private × ephemeral_public`.
    ///
    /// This field is NOT secret — it is sent in the clear as the first 32
    /// bytes of every encrypted message.
    pub ephemeral_public: [u8; 32],

    /// The number of bytes of encrypted content that follow the ephemeral key.
    ///
    /// Includes the 12-byte nonce, the ciphertext, and the 16-byte
    /// Poly1305 authentication tag.
    ///
    /// This is useful for pre-allocating receive buffers or verifying that
    /// a complete message has arrived before attempting decryption.
    pub encrypted_size: usize,
}

impl MessageHeader {
    /// Parse a `MessageHeader` from the beginning of a raw encrypted message.
    ///
    /// Returns an error if `data` is shorter than 32 bytes (the minimum length
    /// of a valid message — just the ephemeral public key with no ciphertext).
    ///
    /// NOTE: This function does NOT verify that the ephemeral public key is a
    /// valid curve point.  That validation happens implicitly during the
    /// Diffie-Hellman operation in `decrypt_message`.  Invalid curve points
    /// result in an unusable shared secret, which causes the AEAD check to fail.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < X25519_PUBLIC_KEY_SIZE {
            return Err(MeshInfinityError::CryptoError(
                "Message too short for header".into(),
            ));
        }

        // Copy the first 32 bytes into a fixed-size array.
        // `copy_from_slice` requires that the source and destination have the
        // same length — the length check above guarantees this.
        let mut ephemeral_public = [0u8; 32];
        ephemeral_public.copy_from_slice(&data[..X25519_PUBLIC_KEY_SIZE]);

        Ok(Self {
            ephemeral_public,
            // Everything after the ephemeral public key is the encrypted payload.
            // `encrypted_size` is used by callers for buffer allocation; it
            // does not change any cryptographic semantics.
            encrypted_size: data.len() - X25519_PUBLIC_KEY_SIZE,
        })
    }
}

// ============================================================================
// Tests
// ============================================================================
//
// These tests verify that the encryption and decryption paths are mutually
// consistent and that various error conditions are properly detected.
// They use in-process `MessageCrypto` instances rather than real network peers.
//
// HOW TO READ THESE TESTS:
// Each test creates one or more `MessageCrypto` instances (simulating
// separate devices), has one encrypt a message, and checks whether the other
// can (or cannot) decrypt it correctly.  The tests cover the normal happy
// path as well as adversarial scenarios (wrong key, tampered message).

#[cfg(test)]
mod tests {
    use super::*;

    /// Construct a deterministic fake `PeerId` from a single seed byte.
    ///
    /// PeerIds are 32-byte arrays; we put the seed in the first byte so
    /// different seeds always produce different IDs.  This is only for
    /// testing — real PeerIds are derived from Ed25519 public keys.
    fn make_peer_id(seed: u8) -> PeerId {
        let mut id = [0u8; 32];
        id[0] = seed;
        id
    }

    /// Verify that a message encrypted for an untrusted peer (no trust key)
    /// can be decrypted by the correct recipient.
    ///
    /// This exercises the three-layer path: inner sign, outer sign, outer
    /// encrypt — step 2 (trust encryption) is skipped.
    ///
    /// This is the "stranger" scenario: two peers have not paired with each
    /// other but can still communicate securely via the outer DH encryption.
    #[test]
    fn test_encrypt_decrypt_untrusted() {
        // Create two independent MessageCrypto instances with freshly
        // generated random keys — simulating two separate devices.
        let mut sender = MessageCrypto::generate().unwrap();
        let recipient = MessageCrypto::generate().unwrap();

        let message = b"Hello, untrusted world!";
        // A fake peer ID for the recipient — step 2 will look this up in
        // trust_keys, find nothing, and skip the trust layer.
        let recipient_peer_id = make_peer_id(2);

        // Encrypt: sender locks the message for recipient's DH public key.
        let ciphertext = sender
            .encrypt_message(message, &recipient.public_dh_key(), &recipient_peer_id)
            .unwrap();

        // Decrypt: recipient unlocks using their static DH key.
        // They need the sender's verifying key to check the signatures.
        let sender_peer_id = make_peer_id(1);
        let plaintext = recipient
            .decrypt_message(&ciphertext, &sender.public_signing_key(), &sender_peer_id)
            .unwrap();

        // The decrypted plaintext must exactly equal the original message.
        assert_eq!(plaintext, message);
    }

    /// Verify that a message encrypted for a trusted peer (trust key present)
    /// can be decrypted by the correct recipient.
    ///
    /// This exercises all four layers, including step-2 trust-pair encryption.
    /// Both sides must call `register_trust` with the other's DH public key
    /// before encryption/decryption.
    ///
    /// This is the "known friend" scenario: two peers have completed a pairing
    /// ceremony (e.g. QR code scan) and now benefit from the extra trust layer.
    #[test]
    fn test_encrypt_decrypt_trusted() {
        let mut sender = MessageCrypto::generate().unwrap();
        let mut recipient = MessageCrypto::generate().unwrap();

        let sender_peer_id = make_peer_id(1);
        let recipient_peer_id = make_peer_id(2);

        // Each side registers the other's static DH public key.
        // Both will independently derive the same trust symmetric key
        // from their respective DH operations:
        //   sender:    sender_private × recipient_public  → shared_secret
        //   recipient: recipient_private × sender_public  → same shared_secret
        // HKDF then turns that shared secret into the same trust_key on both sides.
        sender.register_trust(recipient_peer_id, &recipient.public_dh_key());
        recipient.register_trust(sender_peer_id, &sender.public_dh_key());

        let message = b"Hello, trusted friend!";

        // Encrypt: all four layers applied (sender has a trust key for recipient).
        let ciphertext = sender
            .encrypt_message(message, &recipient.public_dh_key(), &recipient_peer_id)
            .unwrap();

        // Decrypt: all four layers reversed (recipient has a trust key for sender).
        let plaintext = recipient
            .decrypt_message(&ciphertext, &sender.public_signing_key(), &sender_peer_id)
            .unwrap();

        assert_eq!(plaintext, message);
    }

    /// Verify that the session key helpers produce a working encrypt/decrypt pair.
    ///
    /// Session keys are derived from a shared secret established by a handshake;
    /// here we use a hardcoded byte array to simulate that handshake output.
    ///
    /// In production, `shared_secret` would come from an X25519 DH exchange
    /// performed as part of a transport-layer handshake.
    #[test]
    fn test_session_encryption() {
        let mut crypto = MessageCrypto::generate().unwrap();

        // A fake 32-byte shared secret — in production this comes from a DH handshake.
        // `[0x42u8; 32]` creates an array of 32 bytes each with the value 0x42.
        let shared_secret = [0x42u8; 32];
        let session_id = b"test-session";

        // Derive a 32-byte session key from the shared secret and session ID.
        // The result is Zeroizing, so its memory will be zeroed when it is dropped.
        let session_key = crypto.derive_session_key(&shared_secret, session_id);

        let data = b"Session data to encrypt";
        // Encrypt using the session key (fast symmetric AEAD, no DH).
        let ciphertext = crypto.session_encrypt(&session_key, data).unwrap();
        // Decrypt using the same session key.
        let plaintext = crypto.session_decrypt(&session_key, &ciphertext).unwrap();

        assert_eq!(plaintext, data);
    }

    /// Verify that decryption fails when a different recipient (wrong DH key)
    /// attempts to decrypt a message.
    ///
    /// `wrong_recipient` has a different static DH key, so the DH shared secret
    /// they compute will differ from what the sender computed.  The AEAD
    /// authentication tag check will therefore fail.
    ///
    /// This test confirms that the encryption truly "addresses" a specific
    /// recipient — no other device can decrypt it, even if they intercept the
    /// message on the network.
    #[test]
    fn test_wrong_key_fails() {
        let mut sender = MessageCrypto::generate().unwrap();
        let recipient = MessageCrypto::generate().unwrap();
        // A third party who should NOT be able to read this message.
        let wrong_recipient = MessageCrypto::generate().unwrap();

        let message = b"Secret message";
        let recipient_peer_id = make_peer_id(2);

        // Encrypt for `recipient` (using their DH public key).
        let ciphertext = sender
            .encrypt_message(message, &recipient.public_dh_key(), &recipient_peer_id)
            .unwrap();

        // `wrong_recipient` tries to decrypt — this must fail.
        // Their `static_dh_key` is different from `recipient`'s, so the DH
        // operation produces a different shared secret, which produces a
        // different AEAD key, which means the Poly1305 tag check fails.
        let sender_peer_id = make_peer_id(1);
        let result = wrong_recipient.decrypt_message(
            &ciphertext,
            &sender.public_signing_key(),
            &sender_peer_id,
        );

        // Decryption must return an error — NOT silently return garbage.
        assert!(result.is_err());
    }

    /// Verify that decryption fails when even one byte of the ciphertext is
    /// flipped (bitwise XOR with 0xFF).
    ///
    /// This tests the AEAD authentication property: Poly1305 detects any
    /// modification to the ciphertext and causes `decrypt` to return an error
    /// rather than silently producing garbage plaintext.
    ///
    /// This simulates an "active attacker" who intercepts a message and
    /// modifies it before forwarding it to the recipient.  Without AEAD,
    /// the recipient might silently accept the garbled message.  With AEAD,
    /// the modification is detected and the message is rejected.
    #[test]
    fn test_tampered_message_fails() {
        let mut sender = MessageCrypto::generate().unwrap();
        let recipient = MessageCrypto::generate().unwrap();

        let message = b"Original message";
        let recipient_peer_id = make_peer_id(2);

        let mut ciphertext = sender
            .encrypt_message(message, &recipient.public_dh_key(), &recipient_peer_id)
            .unwrap();

        // Flip all bits of byte 50 to simulate an attacker modifying the
        // ciphertext in transit.  XOR with 0xFF flips every bit:
        //   0b10110011 XOR 0b11111111 = 0b01001100.
        // We use `get_mut` so the test gracefully skips the flip if the
        // message happens to be shorter than 51 bytes (which in practice it
        // never will be, given the protocol overhead, but defensive code is
        // good practice in tests too).
        if let Some(byte) = ciphertext.get_mut(50) {
            *byte ^= 0xFF;
        }

        let sender_peer_id = make_peer_id(1);
        let result =
            recipient.decrypt_message(&ciphertext, &sender.public_signing_key(), &sender_peer_id);

        // The Poly1305 tag check must catch the modification and return an error.
        // If this assert failed, it would mean the AEAD authentication is broken —
        // a catastrophic security bug.
        assert!(result.is_err());
    }
}
