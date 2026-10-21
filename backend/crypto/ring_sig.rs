//! Unlinkable AOS ring signatures, profile `MI-AOS-R255-1` (SPEC §3.5.2).
//!
//! # What is a ring signature?
//!
//! A ring signature lets one member of a set of public keys (the "ring")
//! sign a message so that any verifier can confirm *some* ring member
//! signed, while no verifier — not even another ring member — can tell
//! *which* one.  Mesh Infinity uses this as the anonymous outer
//! authentication layer of Private and Closed groups: a group envelope is
//! provably from a current member, but routing nodes and recipients cannot
//! attribute it from the outer layer alone.
//!
//! # The construction
//!
//! This is the Abe–Ohkubo–Suzuki (AOS, 2002) cyclic Schnorr 1-out-of-n
//! proof, exactly as profiled by SPEC §3.5.2:
//!
//! * **Group:** prime-order ristretto255 (RFC 9496) with its standard
//!   generator `G` and scalar order `l`.  Ristretto has no cofactor, so
//!   there are no small-subgroup or equivalent-encoding ambiguities to
//!   police; every valid encoding is one unique group element.
//! * **Keys:** each member holds a dedicated uniform nonzero scalar `x`
//!   with public key `P = xG`.  Identity, session and signing scalars are
//!   never reused for the ring (see [`generate_ring_keypair`]).
//! * **Transcript `T`:** the suite id, group id, content epoch, roster
//!   commit hash, the sorted ring, the context type and a hash of the
//!   envelope being authenticated.  Binding all of these means a signature
//!   cannot be replayed into another group, epoch, roster or context.
//! * **Challenge:** `H(T, i, R) = SHA-512(T || u16be(i) || encode(R)) mod l`.
//! * **Wire form:** `c[0] || s[0] || ... || s[n-1]`, exactly `32(n+1)` bytes,
//!   every scalar canonical.  The intermediate challenges are *not* sent —
//!   the verifier recomputes them, which is what makes the chain closure
//!   the only accepting condition.
//!
//! Linkable variants (LSAG/CLSAG) are prohibited by the spec; this module
//! deliberately produces no key image or signer tag.
//!
//! # Release gate
//!
//! SPEC §3.5.2 requires independent review before this profile is enabled
//! outside isolated tests.  The arithmetic is therefore compiled in, but
//! [`ring_sign`] and [`ring_verify`] refuse to run unless the build opted
//! in: the crate's unit tests, the `fuzzing` harness feature, or the
//! explicit `ring-sig-unreviewed` cargo feature.  Production builds get
//! [`RingSigError::ProfileNotEnabled`] and must handle it.
//!
//! # Side channels
//!
//! All scalar arithmetic goes through `curve25519-dalek`, which is
//! constant-time.  The signer's ring index is located and the closing
//! response is written with `subtle` constant-time selection rather than
//! early-exit searches.  One residual is inherent to AOS: the simulated
//! positions are walked cyclically starting after the signer, so the order
//! in which ring entries are *read from memory* depends on the signer
//! index.  The number of operations does not.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha512};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// Profile constants
// ---------------------------------------------------------------------------

/// The suite identifier that opens every transcript (SPEC §3.5.2).
///
/// It is length-prefixed into `T`, so a future profile with a different
/// name can never collide with this one even if every other field matches.
pub const SUITE_ID: &[u8] = b"MeshInfinity/MI-AOS-R255-1";

/// Smallest ring the profile accepts.
///
/// A ring of one is cryptographically a plain Schnorr proof; the spec keeps
/// it legal (and requires test vectors for it) so a group of one member
/// still produces well-formed envelopes.
pub const MIN_RING_SIZE: usize = 1;

/// Largest ring the profile accepts.
///
/// Verification is O(n) point operations on every recipient, so the bound
/// is a denial-of-service limit as much as a protocol constant.
pub const MAX_RING_SIZE: usize = 300;

/// Size of one canonical scalar or point encoding on the wire.
pub const ELEMENT_LEN: usize = 32;

/// Whether this build is allowed to run the profile at all.
///
/// SPEC §3.5.2's release gate forbids enabling the construction outside
/// isolated tests before independent review.  Unit tests (`cfg(test)`) and
/// the out-of-tree fuzz harnesses (`fuzzing`) are those isolated tests; the
/// `ring-sig-unreviewed` feature is the explicit, off-by-default opt-in for
/// anyone who needs the production paths live before review lands.
const PROFILE_ENABLED: bool = cfg!(any(
    test,
    feature = "ring-sig-unreviewed",
    feature = "fuzzing"
));

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Every way a ring operation can fail.
///
/// The variants are deliberately specific so call sites can tell "this
/// build may not use rings" from "this signature is forged" from "this
/// roster is malformed" without parsing strings.  None of them carries
/// secret material.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RingSigError {
    /// The build has not opted in to the unreviewed profile (SPEC §3.5.2
    /// release gate).  Callers must fall back or surface this; they must
    /// never treat it as a verified signature.
    #[error("ring signature profile MI-AOS-R255-1 is not enabled in this build")]
    ProfileNotEnabled,

    /// The ring has fewer than [`MIN_RING_SIZE`] or more than
    /// [`MAX_RING_SIZE`] members.
    #[error("ring size {0} is outside {MIN_RING_SIZE}..={MAX_RING_SIZE}")]
    RingSize(usize),

    /// A ring entry (at the caller's index) is not a canonical ristretto255
    /// encoding.  Non-canonical or off-curve bytes are rejected outright
    /// rather than reinterpreted.
    #[error("ring member {0} is not a canonical ristretto255 point")]
    InvalidPoint(usize),

    /// A ring entry decodes to the identity element.  `P = 0` would let
    /// anyone "prove" membership since `c·P` vanishes.
    #[error("ring member {0} is the identity point")]
    IdentityPoint(usize),

    /// Two ring entries are the same key.  Duplicates would let one member
    /// inflate the apparent anonymity set.
    #[error("ring contains a duplicate public key")]
    DuplicateKey,

    /// The public key derived from the supplied secret is not in the ring.
    #[error("signer's ring public key is not in the ring")]
    SignerNotInRing,

    /// The secret is not a canonical nonzero scalar.  Zero would make
    /// `P` the identity; a non-canonical encoding would be ambiguous.
    #[error("ring secret is not a canonical nonzero scalar")]
    InvalidSecret,

    /// The signature is not exactly `32(n+1)` bytes for the ring given.
    #[error("signature is {got} bytes, expected {expected}")]
    BadLength {
        /// `32(n+1)` for the ring the verifier was given.
        expected: usize,
        /// What actually arrived.
        got: usize,
    },

    /// Scalar number `index` (0 is `c[0]`, then `s[0..]`) is not a canonical
    /// little-endian integer below `l`.  Accepting it would give each
    /// signature many byte encodings (scalar malleability).
    #[error("signature scalar {0} is not canonical")]
    NonCanonicalScalar(usize),

    /// Everything parsed, but the challenge chain did not close.
    #[error("ring signature does not verify")]
    Invalid,

    /// The operating system refused to supply randomness.  Signing without
    /// a fresh nonce would reveal the secret, so this is fatal.
    #[error("system randomness unavailable for ring nonce")]
    Rng,
}

// ---------------------------------------------------------------------------
// Context and transcript
// ---------------------------------------------------------------------------

/// The two uses the profile is defined for (SPEC §3.5.2).
///
/// "Other uses require a new profile", so this is a closed enum rather
/// than a free string.  The label is what goes into `T`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RingContextType {
    /// An application envelope (a group message).
    Application,
    /// A membership operation (a governance proposal over the roster).
    Membership,
}

impl RingContextType {
    /// The exact ASCII label the spec writes into the transcript.
    fn label(self) -> &'static [u8] {
        match self {
            Self::Application => b"application",
            Self::Membership => b"membership",
        }
    }
}

/// The locally authenticated context a ring signature is bound to.
///
/// Every field comes from the verifier's own group record — never from the
/// frame being verified — so an attacker cannot pick the roster or epoch a
/// signature is checked against.  Two contexts that differ in any field
/// produce unrelated transcripts, which is what blocks cross-group,
/// cross-epoch and cross-context replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingContext {
    /// The group's 32-byte identifier.
    pub group_id: [u8; 32],
    /// The content epoch the envelope belongs to.
    pub content_epoch: u64,
    /// Hash of the committed roster the ring was built from.
    pub roster_commit_hash: [u8; 32],
    /// Whether this is an application or membership envelope.
    pub context_type: RingContextType,
}

/// Append `LP(b) = u32be(len(b)) || b` to a transcript buffer.
///
/// Length-prefixing makes the transcript a prefix-free encoding, so no
/// choice of neighbouring fields can be re-parsed as a different one.
fn push_length_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    // Lengths are bounded well below u32::MAX by construction (the suite id
    // and the context labels are compile-time constants).
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Build the canonical transcript `T` for a sorted, validated ring.
///
/// ```text
/// T = LP("MeshInfinity/MI-AOS-R255-1")
///     || group_id[32] || u64be(content_epoch) || roster_commit_hash[32]
///     || u16be(n) || P[0] || ... || P[n-1]
///     || LP(context_type) || u64be(len(ciphertext)) || SHA512(ciphertext)
/// ```
///
/// `ring` must already be sorted and deduplicated ([`parse_ring`] does
/// that), because the spec fixes the order the points are hashed in.
fn transcript(context: &RingContext, ring: &[[u8; ELEMENT_LEN]], ciphertext: &[u8]) -> Vec<u8> {
    // Pre-size: fixed header + the ring + the ciphertext hash.
    let mut t = Vec::with_capacity(
        4 + SUITE_ID.len() + 32 + 8 + 32 + 2 + ring.len() * ELEMENT_LEN + 4 + 16 + 8 + 64,
    );

    // Suite id first so a different profile diverges at byte zero.
    push_length_prefixed(&mut t, SUITE_ID);

    // Group, epoch and roster: the "where and when" of the envelope.
    t.extend_from_slice(&context.group_id);
    t.extend_from_slice(&context.content_epoch.to_be_bytes());
    t.extend_from_slice(&context.roster_commit_hash);

    // The ring itself.  n <= MAX_RING_SIZE so the u16 cannot truncate.
    t.extend_from_slice(&(ring.len() as u16).to_be_bytes());
    for point in ring {
        t.extend_from_slice(point);
    }

    // Context type as a length-prefixed label, then the envelope digest.
    push_length_prefixed(&mut t, context.context_type.label());
    t.extend_from_slice(&(ciphertext.len() as u64).to_be_bytes());
    t.extend_from_slice(&Sha512::digest(ciphertext));

    t
}

/// The challenge function `H(T, i, R) = SHA-512(T || u16be(i) || encode(R)) mod l`.
///
/// Including the position `i` means the same commitment `R` yields a
/// different challenge at every ring slot, which closes the "rotate the
/// ring" class of forgeries.  The 64-byte digest is reduced as a
/// little-endian integer, so the result is uniform modulo `l`.
fn challenge(t: &[u8], index: usize, r: &RistrettoPoint) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(t);
    // index < MAX_RING_SIZE, so the u16 cast is exact.
    hasher.update((index as u16).to_be_bytes());
    hasher.update(r.compress().as_bytes());
    let digest = hasher.finalize();

    // SHA-512 output is exactly 64 bytes; copy into the wide-reduction form.
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

// ---------------------------------------------------------------------------
// Ring parsing
// ---------------------------------------------------------------------------

/// A ring after validation: sorted encodings alongside their decoded points.
///
/// `encodings[i]` and `points[i]` always describe the same key, and the
/// vector is in the canonical lexicographic order the transcript uses.
struct ParsedRing {
    /// Sorted 32-byte canonical encodings.
    encodings: Vec<[u8; ELEMENT_LEN]>,
    /// The decoded points in the same order.
    points: Vec<RistrettoPoint>,
}

/// Validate and canonicalise a ring (SPEC §3.5.2 "Canonical transcript").
///
/// Rejects a size outside `1..=300`, any non-canonical or off-curve
/// encoding, the identity point and duplicates.  Error indices refer to
/// the caller's order, before sorting.  Callers may pass the ring in any
/// order; the output is always sorted so signer and verifier agree on `T`
/// regardless of how each assembled the roster.
fn parse_ring(ring: &[[u8; ELEMENT_LEN]]) -> Result<ParsedRing, RingSigError> {
    let n = ring.len();
    if !(MIN_RING_SIZE..=MAX_RING_SIZE).contains(&n) {
        return Err(RingSigError::RingSize(n));
    }

    // Decode every entry in the caller's order so error indices are useful.
    let mut members: Vec<([u8; ELEMENT_LEN], RistrettoPoint)> = Vec::with_capacity(n);
    for (index, encoding) in ring.iter().enumerate() {
        // `decompress` returns None for anything that is not the unique
        // canonical encoding of a ristretto255 element (RFC 9496 §4.3.1).
        let point = CompressedRistretto(*encoding)
            .decompress()
            .ok_or(RingSigError::InvalidPoint(index))?;
        if point.is_identity() {
            return Err(RingSigError::IdentityPoint(index));
        }
        members.push((*encoding, point));
    }

    // Canonical order is lexicographic on the encodings.  Sorting the
    // pairs keeps each point attached to its bytes.
    members.sort_unstable_by_key(|member| member.0);

    // After sorting, duplicates are adjacent.
    if members.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(RingSigError::DuplicateKey);
    }

    let (encodings, points) = members.into_iter().unzip();
    Ok(ParsedRing { encodings, points })
}

/// Check that `bytes` is an acceptable ring public key on its own.
///
/// Used when a member commits their key to the group, so a malformed or
/// identity key is refused at the door instead of poisoning every later
/// ring (which would make the whole group unable to verify).
pub fn validate_ring_public_key(bytes: &[u8; ELEMENT_LEN]) -> Result<(), RingSigError> {
    // A single-element ring exercises exactly the per-point checks.
    parse_ring(std::slice::from_ref(bytes)).map(|_| ())
}

/// Parse a secret scalar canonically and reject zero.
fn parse_secret(secret: &[u8; ELEMENT_LEN]) -> Result<Scalar, RingSigError> {
    // `from_canonical_bytes` refuses any encoding >= l.
    let scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(*secret))
        .ok_or(RingSigError::InvalidSecret)?;
    // Zero is canonical but useless: P would be the identity.
    if bool::from(scalar.ct_eq(&Scalar::ZERO)) {
        return Err(RingSigError::InvalidSecret);
    }
    Ok(scalar)
}

// ---------------------------------------------------------------------------
// Randomness
// ---------------------------------------------------------------------------

/// A fallible randomness source for signing.
///
/// Abstracted so the RNG-failure path (a spec-required negative vector) is
/// testable: production uses the OS RNG; tests can plug in one that fails.
pub trait RingRng {
    /// Fill `dest` with uniform random bytes, or fail without touching it.
    fn try_fill(&mut self, dest: &mut [u8]) -> Result<(), RingSigError>;
}

impl RingRng for rand_core::OsRng {
    fn try_fill(&mut self, dest: &mut [u8]) -> Result<(), RingSigError> {
        // `try_fill_bytes` is the non-panicking entry point; any OS error
        // maps to the typed failure so signing aborts cleanly.
        rand_core::RngCore::try_fill_bytes(self, dest).map_err(|_| RingSigError::Rng)
    }
}

/// Draw a uniform scalar modulo `l` from 64 random bytes.
///
/// Wide reduction of 512 bits gives negligible bias (2^-256), which is
/// what "uniform" requires; reducing 256 bits directly would not.
fn random_scalar<R: RingRng>(rng: &mut R) -> Result<Scalar, RingSigError> {
    let mut wide = [0u8; 64];
    rng.try_fill(&mut wide)?;
    let scalar = Scalar::from_bytes_mod_order_wide(&wide);
    // The raw bytes are as sensitive as the scalar they produced.
    wide.zeroize();
    Ok(scalar)
}

/// Draw a uniform *nonzero* scalar, as the spec requires for `x` and `u`.
///
/// Zero occurs with probability 2^-252; rather than loop (which would make
/// the operation count data-dependent) a zero draw is reported as an RNG
/// failure, which is the only realistic way it happens.
fn random_nonzero_scalar<R: RingRng>(rng: &mut R) -> Result<Scalar, RingSigError> {
    let scalar = random_scalar(rng)?;
    if bool::from(scalar.ct_eq(&Scalar::ZERO)) {
        return Err(RingSigError::Rng);
    }
    Ok(scalar)
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// A member's dedicated ring keypair for one group.
///
/// The secret is zeroised on drop.  It is generated independently of every
/// other key the device holds (SPEC §3.5.2: "MUST NOT reuse identity,
/// session, or signing scalars"), so compromise of a ring key reveals
/// nothing about the identity, and vice versa.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RingKeypair {
    /// Canonical little-endian encoding of the nonzero scalar `x`.
    pub secret: [u8; ELEMENT_LEN],
    /// Canonical ristretto255 encoding of `P = xG`.
    pub public: [u8; ELEMENT_LEN],
}

/// Generate a fresh ring keypair from the operating-system RNG.
pub fn generate_ring_keypair() -> Result<RingKeypair, RingSigError> {
    generate_ring_keypair_with_rng(&mut rand_core::OsRng)
}

/// Generate a fresh ring keypair from the supplied RNG.
///
/// Separate from [`generate_ring_keypair`] so the failure path is testable.
pub fn generate_ring_keypair_with_rng<R: RingRng>(
    rng: &mut R,
) -> Result<RingKeypair, RingSigError> {
    let mut x = random_nonzero_scalar(rng)?;
    let public = (RISTRETTO_BASEPOINT_TABLE * &x).compress().to_bytes();
    let secret = x.to_bytes();
    // The scalar copy is no longer needed; only the byte form is returned.
    x.zeroize();
    Ok(RingKeypair { secret, public })
}

/// Derive the ring public key for a stored secret.
///
/// Fails if the secret is not a canonical nonzero scalar, which would mean
/// the stored record is corrupt rather than merely stale.
pub fn ring_public_key(secret: &[u8; ELEMENT_LEN]) -> Result<[u8; ELEMENT_LEN], RingSigError> {
    let mut x = parse_secret(secret)?;
    let public = (RISTRETTO_BASEPOINT_TABLE * &x).compress().to_bytes();
    x.zeroize();
    Ok(public)
}

// ---------------------------------------------------------------------------
// Signature wire form
// ---------------------------------------------------------------------------

/// A ring signature in its wire form: `c[0] || s[0] || ... || s[n-1]`.
///
/// Always exactly `32(n+1)` bytes for a ring of `n`.  Serialises as a hex
/// string in JSON so group frames and governance records carry it as one
/// opaque field; parsing enforces the length rule so malformed records are
/// rejected before any arithmetic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingSignature {
    /// The raw bytes.  Private so every instance went through `from_bytes`.
    bytes: Vec<u8>,
}

impl RingSignature {
    /// Parse wire bytes, enforcing the `32(n+1)` shape for some `1 <= n <= 300`.
    ///
    /// This is the untrusted-byte boundary: it checks the length only.
    /// Scalar canonicality is checked by [`ring_verify`], which also knows
    /// the ring the length must match.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RingSigError> {
        let len = bytes.len();
        // Length must be 32 * (n + 1): a multiple of 32 covering c[0] plus
        // between MIN and MAX responses.
        let min = ELEMENT_LEN * (MIN_RING_SIZE + 1);
        let max = ELEMENT_LEN * (MAX_RING_SIZE + 1);
        if !len.is_multiple_of(ELEMENT_LEN) || len < min || len > max {
            return Err(RingSigError::BadLength {
                expected: min,
                got: len,
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// The wire bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The ring size this signature was produced for: `len / 32 - 1`.
    pub fn ring_size(&self) -> usize {
        self.bytes.len() / ELEMENT_LEN - 1
    }
}

impl Serialize for RingSignature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Lower-case hex keeps it a single JSON string with no escaping.
        serializer.serialize_str(&hex::encode(&self.bytes))
    }
}

impl<'de> Deserialize<'de> for RingSignature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        let bytes = hex::decode(encoded).map_err(DeError::custom)?;
        // Re-run the length rule so a deserialised value is as trustworthy
        // as one built through `from_bytes`.
        Self::from_bytes(&bytes).map_err(DeError::custom)
    }
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// Sign `ciphertext` as an anonymous member of `ring` under `context`.
///
/// `secret` is the signer's dedicated ring scalar; its public key must be
/// one of `ring`.  The ring may be supplied in any order.
///
/// # Errors
///
/// [`RingSigError::ProfileNotEnabled`] in builds that have not opted in;
/// otherwise any roster, secret or RNG failure.  Nothing is returned on
/// error, and all intermediate scalars are erased.
pub fn ring_sign(
    secret: &[u8; ELEMENT_LEN],
    ring: &[[u8; ELEMENT_LEN]],
    context: &RingContext,
    ciphertext: &[u8],
) -> Result<RingSignature, RingSigError> {
    ring_sign_with_rng(&mut rand_core::OsRng, secret, ring, context, ciphertext)
}

/// [`ring_sign`] with an explicit randomness source.
pub fn ring_sign_with_rng<R: RingRng>(
    rng: &mut R,
    secret: &[u8; ELEMENT_LEN],
    ring: &[[u8; ELEMENT_LEN]],
    context: &RingContext,
    ciphertext: &[u8],
) -> Result<RingSignature, RingSigError> {
    sign_gated(PROFILE_ENABLED, rng, secret, ring, context, ciphertext)
}

/// Scalars that must not outlive signing.
///
/// Bundling them in one `ZeroizeOnDrop` value means every exit path —
/// including the `?` early returns — erases `x`, the nonce `u` and the
/// whole challenge/response chain.
#[derive(Zeroize, ZeroizeOnDrop)]
struct SigningScratch {
    /// The signer's secret scalar.
    x: Scalar,
    /// The fresh nonce; reuse across two signatures would reveal `x`.
    u: Scalar,
    /// The challenge chain `c[0..n]`.
    c: Vec<Scalar>,
    /// The responses `s[0..n]`.
    s: Vec<Scalar>,
}

/// The signing algorithm behind the release gate.
///
/// `enabled` is passed in (rather than read from the constant) so tests can
/// exercise the refusal path in a build where the profile is otherwise on.
fn sign_gated<R: RingRng>(
    enabled: bool,
    rng: &mut R,
    secret: &[u8; ELEMENT_LEN],
    ring: &[[u8; ELEMENT_LEN]],
    context: &RingContext,
    ciphertext: &[u8],
) -> Result<RingSignature, RingSigError> {
    if !enabled {
        return Err(RingSigError::ProfileNotEnabled);
    }

    // --- Roster and key validation ---------------------------------------
    let parsed = parse_ring(ring)?;
    let n = parsed.points.len();
    let x = parse_secret(secret)?;

    // Everything secret lives in the scratch so any early return wipes it.
    let mut scratch = SigningScratch {
        x,
        u: Scalar::ZERO,
        c: vec![Scalar::ZERO; n],
        s: vec![Scalar::ZERO; n],
    };

    // --- Locate the signer in constant time --------------------------------
    // Compare our public key against every ring entry and fold the match
    // into `j` with constant-time selection, so neither the loop length nor
    // its exit depends on where we sit in the ring.
    let own_public = (RISTRETTO_BASEPOINT_TABLE * &scratch.x).compress();
    let mut j = 0u32;
    let mut found = Choice::from(0u8);
    for (index, encoding) in parsed.encodings.iter().enumerate() {
        let hit = own_public.as_bytes().ct_eq(encoding);
        // index < 300, so the u32 cast is exact.
        j.conditional_assign(&(index as u32), hit);
        found |= hit;
    }
    if !bool::from(found) {
        return Err(RingSigError::SignerNotInRing);
    }
    let j = j as usize;

    // --- Transcript and nonce --------------------------------------------
    let t = transcript(context, &parsed.encodings, ciphertext);
    scratch.u = random_nonzero_scalar(rng)?;

    // --- Open the chain at the signer ------------------------------------
    // c[(j+1) mod n] = H(T, j, uG).  The commitment uses the real nonce;
    // this is the one place the secret-side randomness enters the chain.
    let opening = challenge(&t, j, &(RISTRETTO_BASEPOINT_TABLE * &scratch.u));
    let opening_slot = (j + 1) % n;
    for (index, slot) in scratch.c.iter_mut().enumerate() {
        // Constant-time write: every slot is touched, one is changed.
        slot.conditional_assign(&opening, (index as u32).ct_eq(&(opening_slot as u32)));
    }

    // --- Simulate every other position -----------------------------------
    // Walk cyclically from j+1 through j-1.  For each, pick a uniform
    // response s[i] and derive the next challenge from the verification
    // equation R = s[i]G + c[i]P[i].  Those positions never need a secret:
    // choosing s[i] first and solving for the next c is what hides which
    // slot was "real".  The iteration count is n-1 for every signer.
    for step in 1..n {
        let i = (j + step) % n;
        let s_i = random_scalar(rng)?;
        scratch.s[i] = s_i;
        let r = RISTRETTO_BASEPOINT_TABLE * &s_i + scratch.c[i] * parsed.points[i];
        scratch.c[(i + 1) % n] = challenge(&t, i, &r);
    }

    // --- Close the ring at the signer ------------------------------------
    // After the walk, c[j] is fixed by the last simulated position.  The
    // real response is s[j] = u - c[j]·x, which makes the verifier's
    // R = s[j]G + c[j]P = uG — exactly the commitment that opened the chain.
    // Read c[j] and write s[j] with constant-time selection over all slots.
    let mut c_j = Scalar::ZERO;
    for (index, value) in scratch.c.iter().enumerate() {
        c_j.conditional_assign(value, (index as u32).ct_eq(&(j as u32)));
    }
    let mut closing = scratch.u - c_j * scratch.x;
    for (index, slot) in scratch.s.iter_mut().enumerate() {
        slot.conditional_assign(&closing, (index as u32).ct_eq(&(j as u32)));
    }
    // These two are copies of secret-derived values; erase them now rather
    // than relying on scope exit.
    c_j.zeroize();
    closing.zeroize();

    // --- Serialise: c[0] || s[0] || ... || s[n-1] ------------------------
    let mut bytes = Vec::with_capacity(ELEMENT_LEN * (n + 1));
    bytes.extend_from_slice(&scratch.c[0].to_bytes());
    for s_i in &scratch.s {
        bytes.extend_from_slice(&s_i.to_bytes());
    }

    // `scratch` drops here and zeroises x, u, c and s.
    Ok(RingSignature { bytes })
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify `signature` over `ciphertext` for `ring` under `context`.
///
/// `ring` and `context` must come from the verifier's own authenticated
/// group record, never from the message being checked.  Returns `Ok(())`
/// only if every byte parsed canonically and the challenge chain closes.
pub fn ring_verify(
    ring: &[[u8; ELEMENT_LEN]],
    context: &RingContext,
    ciphertext: &[u8],
    signature: &RingSignature,
) -> Result<(), RingSigError> {
    verify_gated(PROFILE_ENABLED, ring, context, ciphertext, signature)
}

/// The verification algorithm behind the release gate.
fn verify_gated(
    enabled: bool,
    ring: &[[u8; ELEMENT_LEN]],
    context: &RingContext,
    ciphertext: &[u8],
    signature: &RingSignature,
) -> Result<(), RingSigError> {
    if !enabled {
        return Err(RingSigError::ProfileNotEnabled);
    }

    // --- Roster validation (cheap, before any point arithmetic) ----------
    let parsed = parse_ring(ring)?;
    let n = parsed.points.len();

    // --- Length: exactly 32(n+1) for *this* ring ---------------------------
    let expected = ELEMENT_LEN * (n + 1);
    let got = signature.bytes.len();
    if got != expected {
        return Err(RingSigError::BadLength { expected, got });
    }

    // --- Canonical scalar parsing ----------------------------------------
    // Every 32-byte chunk must be a little-endian integer below l.  A
    // non-canonical encoding (e.g. s + l) would otherwise verify, giving
    // one signature many wire forms.
    let mut scalars = Vec::with_capacity(n + 1);
    // The length check above guarantees an exact split into 32-byte chunks.
    let (chunks, _) = signature.bytes.as_chunks::<ELEMENT_LEN>();
    for (index, encoding) in chunks.iter().enumerate() {
        let scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(*encoding))
            .ok_or(RingSigError::NonCanonicalScalar(index))?;
        scalars.push(scalar);
    }
    let c0 = scalars[0];
    let responses = &scalars[1..];

    // --- Walk the chain --------------------------------------------------
    // Starting from the supplied c[0], recompute R_i = s[i]G + c[i]P[i] and
    // c[i+1] = H(T, i, R_i) for every position.  All inputs here are
    // public, so the faster variable-time double-scalar multiplication is
    // appropriate.
    let t = transcript(context, &parsed.encodings, ciphertext);
    let mut c = c0;
    for (i, (s_i, p_i)) in responses.iter().zip(parsed.points.iter()).enumerate() {
        let r = RistrettoPoint::vartime_double_scalar_mul_basepoint(&c, p_i, s_i);
        c = challenge(&t, i, &r);
    }

    // --- Accept only if the ring closes ----------------------------------
    if bool::from(c.ct_eq(&c0)) {
        Ok(())
    } else {
        Err(RingSigError::Invalid)
    }
}

// ---------------------------------------------------------------------------
// Deterministic fixtures for tests and fuzz harnesses
// ---------------------------------------------------------------------------

/// A reproducible ring for tests and fuzz corpora.
///
/// Secrets are small fixed integers (never used outside test builds), so
/// the same ring, context and seed signature can be regenerated on any
/// machine.  `secrets[k]` corresponds to `ring[k]` in the *unsorted* order
/// returned; sign/verify sort internally.
#[cfg(any(test, feature = "fuzzing"))]
pub struct RingFixture {
    /// One canonical secret per member, aligned with `ring`.
    pub secrets: Vec<[u8; ELEMENT_LEN]>,
    /// The members' public keys (unsorted).
    pub ring: Vec<[u8; ELEMENT_LEN]>,
    /// A fixed application context.
    pub context: RingContext,
}

/// Build the fixture for a ring of `n` members.
#[cfg(any(test, feature = "fuzzing"))]
pub fn ring_fixture(n: usize) -> RingFixture {
    let mut secrets = Vec::with_capacity(n);
    let mut ring = Vec::with_capacity(n);
    for k in 0..n {
        // Secret = 1 + 65536·(k+1): nonzero, far below l, canonical.
        let mut secret = [0u8; ELEMENT_LEN];
        secret[0] = 1;
        secret[2] = ((k + 1) & 0xff) as u8;
        secret[3] = ((k + 1) >> 8) as u8;
        // Small fixed integers are canonical and nonzero by construction,
        // so derivation cannot fail; a failure here is a fixture bug.
        let public = ring_public_key(&secret).unwrap_or([0u8; ELEMENT_LEN]);
        secrets.push(secret);
        ring.push(public);
    }
    RingFixture {
        secrets,
        ring,
        context: RingContext {
            group_id: [0x11; 32],
            content_epoch: 7,
            roster_commit_hash: [0x22; 32],
            context_type: RingContextType::Application,
        },
    }
}

/// The envelope bytes the fixture signatures cover.
#[cfg(any(test, feature = "fuzzing"))]
pub const FIXTURE_CIPHERTEXT: &[u8] = b"MI-AOS-R255-1 fixture envelope";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Shorthand: sign with the fixture member `k`.
    fn sign_as(fixture: &RingFixture, k: usize, ciphertext: &[u8]) -> RingSignature {
        ring_sign(
            &fixture.secrets[k],
            &fixture.ring,
            &fixture.context,
            ciphertext,
        )
        .expect("fixture signing must succeed")
    }

    /// Shorthand: verify against the fixture.
    fn verify_with(
        fixture: &RingFixture,
        ciphertext: &[u8],
        signature: &RingSignature,
    ) -> Result<(), RingSigError> {
        ring_verify(&fixture.ring, &fixture.context, ciphertext, signature)
    }

    /// An RNG that always fails, for the spec's "RNG failure" vector.
    struct FailingRng;

    impl RingRng for FailingRng {
        fn try_fill(&mut self, _dest: &mut [u8]) -> Result<(), RingSigError> {
            Err(RingSigError::Rng)
        }
    }

    /// An RNG that fails after `budget` successful fills, so each draw in
    /// the signing walk can be made to fail in turn.
    struct BudgetRng {
        budget: usize,
    }

    impl RingRng for BudgetRng {
        fn try_fill(&mut self, dest: &mut [u8]) -> Result<(), RingSigError> {
            if self.budget == 0 {
                return Err(RingSigError::Rng);
            }
            self.budget -= 1;
            rand_core::OsRng.try_fill(dest)
        }
    }

    /// The ristretto255 group order `l`, little-endian, for malleability tests.
    const GROUP_ORDER_LE: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];

    /// Add `l` to a canonical scalar encoding (no reduction), producing a
    /// non-canonical encoding of the same residue.
    ///
    /// A canonical scalar is below `l < 2^253`, so the sum is below `2^254`
    /// and never overflows 256 bits.
    fn add_group_order(scalar: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut carry = 0u16;
        for (i, (lhs, rhs)) in scalar.iter().zip(GROUP_ORDER_LE.iter()).enumerate() {
            let sum = *lhs as u16 + *rhs as u16 + carry;
            out[i] = (sum & 0xff) as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0, "canonical scalar + l cannot overflow");
        out
    }

    // -----------------------------------------------------------------------
    // Positive vectors: ring sizes and every signer position
    // -----------------------------------------------------------------------

    #[test]
    fn round_trip_n1() {
        let fixture = ring_fixture(1);
        let sig = sign_as(&fixture, 0, b"n=1");
        assert_eq!(sig.as_bytes().len(), 64);
        assert_eq!(sig.ring_size(), 1);
        assert_eq!(verify_with(&fixture, b"n=1", &sig), Ok(()));
    }

    #[test]
    fn round_trip_n2() {
        let fixture = ring_fixture(2);
        for k in 0..2 {
            let sig = sign_as(&fixture, k, b"n=2");
            assert_eq!(sig.as_bytes().len(), 96);
            assert_eq!(verify_with(&fixture, b"n=2", &sig), Ok(()));
        }
    }

    #[test]
    fn round_trip_n300_both_ends() {
        let fixture = ring_fixture(MAX_RING_SIZE);
        for k in [0, MAX_RING_SIZE / 2, MAX_RING_SIZE - 1] {
            let sig = sign_as(&fixture, k, b"n=300");
            assert_eq!(sig.as_bytes().len(), 32 * 301);
            assert_eq!(verify_with(&fixture, b"n=300", &sig), Ok(()));
        }
    }

    #[test]
    fn every_signer_position_small_rings() {
        // Off-by-one errors in the cyclic walk show up as a specific
        // position failing, so cover all of them for several sizes.
        for n in 1..=7 {
            let fixture = ring_fixture(n);
            for k in 0..n {
                let sig = sign_as(&fixture, k, b"all positions");
                assert_eq!(
                    verify_with(&fixture, b"all positions", &sig),
                    Ok(()),
                    "n={n} signer={k}"
                );
            }
        }
    }

    #[test]
    fn empty_ciphertext_is_signable() {
        let fixture = ring_fixture(3);
        let sig = sign_as(&fixture, 1, b"");
        assert_eq!(verify_with(&fixture, b"", &sig), Ok(()));
    }

    #[test]
    fn ring_order_does_not_matter() {
        // Signer and verifier may assemble the roster in different orders;
        // both canonicalise to the same sorted ring and transcript.
        let fixture = ring_fixture(5);
        let sig = sign_as(&fixture, 2, b"order");
        let mut reversed = fixture.ring.clone();
        reversed.reverse();
        assert_eq!(
            ring_verify(&reversed, &fixture.context, b"order", &sig),
            Ok(())
        );
    }

    #[test]
    fn fresh_randomness_gives_distinct_signatures() {
        let fixture = ring_fixture(4);
        let a = sign_as(&fixture, 1, b"same");
        let b = sign_as(&fixture, 1, b"same");
        assert_ne!(a, b, "nonce must be fresh per signature");
        assert_eq!(verify_with(&fixture, b"same", &a), Ok(()));
        assert_eq!(verify_with(&fixture, b"same", &b), Ok(()));
    }

    #[test]
    fn no_linkable_material_in_output() {
        // Unlinkable by construction: the wire form is exactly c[0] plus
        // one response per member, nothing else (no key image).
        let fixture = ring_fixture(6);
        let sig = sign_as(&fixture, 3, b"shape");
        assert_eq!(sig.as_bytes().len(), ELEMENT_LEN * (6 + 1));
        let json = serde_json::to_value(&sig).expect("serialise");
        assert!(json.is_string(), "wire form is one opaque hex string");
    }

    // -----------------------------------------------------------------------
    // Transcript binding: message, group, epoch, roster, context
    // -----------------------------------------------------------------------

    #[test]
    fn transcript_change_message() {
        let fixture = ring_fixture(3);
        let sig = sign_as(&fixture, 0, b"original");
        assert_eq!(
            verify_with(&fixture, b"altered", &sig),
            Err(RingSigError::Invalid)
        );
    }

    #[test]
    fn cross_group_replay_rejected() {
        let fixture = ring_fixture(3);
        let sig = sign_as(&fixture, 0, b"replay");
        let mut other = fixture.context;
        other.group_id[0] ^= 1;
        assert_eq!(
            ring_verify(&fixture.ring, &other, b"replay", &sig),
            Err(RingSigError::Invalid)
        );
    }

    #[test]
    fn cross_epoch_replay_rejected() {
        let fixture = ring_fixture(3);
        let sig = sign_as(&fixture, 0, b"replay");
        let mut other = fixture.context;
        other.content_epoch += 1;
        assert_eq!(
            ring_verify(&fixture.ring, &other, b"replay", &sig),
            Err(RingSigError::Invalid)
        );
    }

    #[test]
    fn cross_roster_replay_rejected() {
        let fixture = ring_fixture(3);
        let sig = sign_as(&fixture, 0, b"replay");
        let mut other = fixture.context;
        other.roster_commit_hash[31] ^= 0x80;
        assert_eq!(
            ring_verify(&fixture.ring, &other, b"replay", &sig),
            Err(RingSigError::Invalid)
        );
    }

    #[test]
    fn cross_context_replay_rejected() {
        // An application envelope must not verify as a membership one.
        let fixture = ring_fixture(3);
        let sig = sign_as(&fixture, 0, b"replay");
        let mut other = fixture.context;
        other.context_type = RingContextType::Membership;
        assert_eq!(
            ring_verify(&fixture.ring, &other, b"replay", &sig),
            Err(RingSigError::Invalid)
        );
    }

    #[test]
    fn different_ring_rejected() {
        let fixture = ring_fixture(3);
        let sig = sign_as(&fixture, 0, b"ring");
        let bigger = ring_fixture(4);
        assert!(matches!(
            ring_verify(&bigger.ring, &fixture.context, b"ring", &sig),
            Err(RingSigError::BadLength { .. })
        ));
        // Same size, one member swapped: the transcript differs.
        let mut swapped = fixture.ring.clone();
        swapped[2] = bigger.ring[3];
        assert_eq!(
            ring_verify(&swapped, &fixture.context, b"ring", &sig),
            Err(RingSigError::Invalid)
        );
    }

    // -----------------------------------------------------------------------
    // Roster validation
    // -----------------------------------------------------------------------

    #[test]
    fn ring_size_bounds() {
        let fixture = ring_fixture(1);
        assert_eq!(
            ring_sign(&fixture.secrets[0], &[], &fixture.context, b""),
            Err(RingSigError::RingSize(0))
        );
        let too_big = ring_fixture(MAX_RING_SIZE + 1);
        assert_eq!(
            ring_sign(&too_big.secrets[0], &too_big.ring, &too_big.context, b""),
            Err(RingSigError::RingSize(MAX_RING_SIZE + 1))
        );
        let sig = sign_as(&fixture, 0, b"");
        assert_eq!(
            ring_verify(&[], &fixture.context, b"", &sig),
            Err(RingSigError::RingSize(0))
        );
    }

    #[test]
    fn duplicate_keys_rejected() {
        let fixture = ring_fixture(3);
        let mut ring = fixture.ring.clone();
        ring[2] = ring[0];
        assert_eq!(
            ring_sign(&fixture.secrets[0], &ring, &fixture.context, b""),
            Err(RingSigError::DuplicateKey)
        );
        let sig = sign_as(&fixture, 0, b"");
        assert_eq!(
            ring_verify(&ring, &fixture.context, b"", &sig),
            Err(RingSigError::DuplicateKey)
        );
    }

    #[test]
    fn invalid_points_rejected() {
        let fixture = ring_fixture(3);
        // All-0xff is not a canonical ristretto255 encoding.
        let mut ring = fixture.ring.clone();
        ring[1] = [0xff; 32];
        assert_eq!(
            ring_sign(&fixture.secrets[0], &ring, &fixture.context, b""),
            Err(RingSigError::InvalidPoint(1))
        );
        let sig = sign_as(&fixture, 0, b"");
        assert_eq!(
            ring_verify(&ring, &fixture.context, b"", &sig),
            Err(RingSigError::InvalidPoint(1))
        );
        // A non-canonical encoding of a valid point: the field prime p added
        // to the first coordinate byte pattern is rejected by decompress.
        let mut non_canonical = fixture.ring[0];
        non_canonical[31] |= 0x80;
        assert_eq!(
            validate_ring_public_key(&non_canonical),
            Err(RingSigError::InvalidPoint(0))
        );
    }

    #[test]
    fn identity_point_rejected() {
        let fixture = ring_fixture(3);
        let mut ring = fixture.ring.clone();
        // The all-zero encoding is the canonical identity element.
        ring[0] = [0u8; 32];
        assert_eq!(
            ring_sign(&fixture.secrets[1], &ring, &fixture.context, b""),
            Err(RingSigError::IdentityPoint(0))
        );
        assert_eq!(
            validate_ring_public_key(&[0u8; 32]),
            Err(RingSigError::IdentityPoint(0))
        );
        assert_eq!(validate_ring_public_key(&fixture.ring[0]), Ok(()));
    }

    #[test]
    fn signer_not_in_ring() {
        let fixture = ring_fixture(3);
        let outsider = ring_fixture(4);
        assert_eq!(
            ring_sign(&outsider.secrets[3], &fixture.ring, &fixture.context, b""),
            Err(RingSigError::SignerNotInRing)
        );
    }

    #[test]
    fn invalid_secret_rejected() {
        let fixture = ring_fixture(2);
        assert_eq!(
            ring_sign(&[0u8; 32], &fixture.ring, &fixture.context, b""),
            Err(RingSigError::InvalidSecret)
        );
        // l itself is not canonical.
        assert_eq!(
            ring_sign(&GROUP_ORDER_LE, &fixture.ring, &fixture.context, b""),
            Err(RingSigError::InvalidSecret)
        );
        assert_eq!(
            ring_public_key(&[0u8; 32]),
            Err(RingSigError::InvalidSecret)
        );
    }

    // -----------------------------------------------------------------------
    // Signature parsing: malleability and truncation
    // -----------------------------------------------------------------------

    #[test]
    fn scalar_malleability_rejected() {
        let fixture = ring_fixture(3);
        let sig = sign_as(&fixture, 1, b"malleable");
        let bytes = sig.as_bytes();

        // Re-encode each scalar as (value + l): same residue, different
        // bytes.  Every such variant must be refused, not accepted.
        for slot in 0..4 {
            let mut mutated = bytes.to_vec();
            let mut scalar = [0u8; 32];
            scalar.copy_from_slice(&bytes[slot * 32..(slot + 1) * 32]);
            let bumped = add_group_order(&scalar);
            mutated[slot * 32..(slot + 1) * 32].copy_from_slice(&bumped);
            let parsed = RingSignature::from_bytes(&mutated).expect("length unchanged");
            assert_eq!(
                verify_with(&fixture, b"malleable", &parsed),
                Err(RingSigError::NonCanonicalScalar(slot)),
                "slot {slot}"
            );
        }

        // Setting the top bit makes the value >= 2^255 > l.
        let mut high_bit = bytes.to_vec();
        high_bit[63] |= 0x80;
        let parsed = RingSignature::from_bytes(&high_bit).expect("length unchanged");
        assert_eq!(
            verify_with(&fixture, b"malleable", &parsed),
            Err(RingSigError::NonCanonicalScalar(1))
        );
    }

    #[test]
    fn tampered_scalars_rejected() {
        let fixture = ring_fixture(3);
        let sig = sign_as(&fixture, 1, b"tamper");
        for byte in [0usize, 33, 70, 127] {
            let mut mutated = sig.as_bytes().to_vec();
            mutated[byte] ^= 0x01;
            let parsed = RingSignature::from_bytes(&mutated).expect("length unchanged");
            assert_eq!(
                verify_with(&fixture, b"tamper", &parsed),
                Err(RingSigError::Invalid),
                "byte {byte}"
            );
        }
    }

    #[test]
    fn truncation_and_extension_rejected() {
        let fixture = ring_fixture(3);
        let sig = sign_as(&fixture, 1, b"len");
        let bytes = sig.as_bytes();

        // One byte short is not a multiple of 32.
        assert!(matches!(
            RingSignature::from_bytes(&bytes[..bytes.len() - 1]),
            Err(RingSigError::BadLength { .. })
        ));
        // One whole scalar short parses as an n=2 signature but must fail
        // against the n=3 ring.
        let short = RingSignature::from_bytes(&bytes[..bytes.len() - 32]).expect("n=2 shape");
        assert_eq!(
            verify_with(&fixture, b"len", &short),
            Err(RingSigError::BadLength {
                expected: 128,
                got: 96
            })
        );
        // Extended by a scalar: n=4 shape, same failure.
        let mut long = bytes.to_vec();
        long.extend_from_slice(&[0u8; 32]);
        let long = RingSignature::from_bytes(&long).expect("n=4 shape");
        assert!(matches!(
            verify_with(&fixture, b"len", &long),
            Err(RingSigError::BadLength { .. })
        ));
        // Empty and below-minimum inputs never construct.
        assert!(RingSignature::from_bytes(&[]).is_err());
        assert!(RingSignature::from_bytes(&[0u8; 32]).is_err());
        assert!(RingSignature::from_bytes(&[0u8; 32 * 302]).is_err());
    }

    #[test]
    fn serde_round_trip_and_rejections() {
        let fixture = ring_fixture(2);
        let sig = sign_as(&fixture, 0, b"serde");
        let json = serde_json::to_string(&sig).expect("serialise");
        let back: RingSignature = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(back, sig);
        assert_eq!(verify_with(&fixture, b"serde", &back), Ok(()));

        // Non-hex, odd length and wrong size are all refused at parse time.
        assert!(serde_json::from_str::<RingSignature>("\"zz\"").is_err());
        assert!(serde_json::from_str::<RingSignature>("\"abc\"").is_err());
        assert!(serde_json::from_str::<RingSignature>("\"00\"").is_err());
        assert!(serde_json::from_str::<RingSignature>("42").is_err());
    }

    // -----------------------------------------------------------------------
    // RNG failure and release gate
    // -----------------------------------------------------------------------

    #[test]
    fn rng_failure_aborts_signing() {
        let fixture = ring_fixture(3);
        // Immediate failure: the nonce draw.
        assert_eq!(
            ring_sign_with_rng(
                &mut FailingRng,
                &fixture.secrets[0],
                &fixture.ring,
                &fixture.context,
                b"rng"
            ),
            Err(RingSigError::Rng)
        );
        // Failure part-way through the simulated walk: still a clean abort,
        // and the preceding draws never leak as a partial signature.
        for budget in 0..3 {
            assert_eq!(
                ring_sign_with_rng(
                    &mut BudgetRng { budget },
                    &fixture.secrets[0],
                    &fixture.ring,
                    &fixture.context,
                    b"rng"
                ),
                Err(RingSigError::Rng),
                "budget {budget}"
            );
        }
        // Enough draws (1 nonce + n-1 responses) and it succeeds.
        let sig = ring_sign_with_rng(
            &mut BudgetRng { budget: 3 },
            &fixture.secrets[0],
            &fixture.ring,
            &fixture.context,
            b"rng",
        )
        .expect("three draws suffice for n=3");
        assert_eq!(verify_with(&fixture, b"rng", &sig), Ok(()));
        // Keypair generation fails the same way.
        assert!(matches!(
            generate_ring_keypair_with_rng(&mut FailingRng),
            Err(RingSigError::Rng)
        ));
    }

    #[test]
    fn release_gate_refuses_when_disabled() {
        let fixture = ring_fixture(2);
        assert_eq!(
            sign_gated(
                false,
                &mut rand_core::OsRng,
                &fixture.secrets[0],
                &fixture.ring,
                &fixture.context,
                b"gate"
            ),
            Err(RingSigError::ProfileNotEnabled)
        );
        let sig = sign_as(&fixture, 0, b"gate");
        assert_eq!(
            verify_gated(false, &fixture.ring, &fixture.context, b"gate", &sig),
            Err(RingSigError::ProfileNotEnabled)
        );
        // The gate is open under cfg(test): the public entry points, which
        // consult the constant, both succeed on the same inputs.
        let signed = ring_sign(
            &fixture.secrets[0],
            &fixture.ring,
            &fixture.context,
            b"gate",
        )
        .expect("profile enabled in test builds");
        assert_eq!(verify_with(&fixture, b"gate", &signed), Ok(()));
    }

    #[test]
    fn generated_keypairs_are_distinct_and_usable() {
        let a = generate_ring_keypair().expect("os rng");
        let b = generate_ring_keypair().expect("os rng");
        assert_ne!(a.secret, b.secret);
        assert_ne!(a.public, b.public);
        assert_eq!(ring_public_key(&a.secret), Ok(a.public));
        assert_eq!(validate_ring_public_key(&a.public), Ok(()));

        let ring = [a.public, b.public];
        let context = ring_fixture(1).context;
        let sig = ring_sign(&b.secret, &ring, &context, b"generated").expect("sign");
        assert_eq!(ring_verify(&ring, &context, b"generated", &sig), Ok(()));
    }

    // -----------------------------------------------------------------------
    // Corpus replay (TESTING_METHODOLOGY "corpus replay test coverage")
    // -----------------------------------------------------------------------

    /// Replay the committed fuzz seed corpus through the in-tree harness.
    ///
    /// Every seed must parse-or-fail and verify-or-fail without panicking;
    /// exactly one seed (`seed_01_valid_n2`) is a genuine signature over
    /// the fixture and must verify.
    #[test]
    fn test_ring_corpus_replay() {
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus/fuzz_ring_verify");
        crate::testing::corpus::assert_corpus_dir_exists(&dir);
        let entries = crate::testing::corpus::load_corpus_entries(&dir).expect("read corpus");
        assert!(!entries.is_empty(), "corpus must have seeds");

        let mut valid_seen = Vec::new();
        for (path, bytes) in entries {
            // The harness must be total over every seed.
            assert!(
                crate::testing::fuzz::fuzz_ring_verify(&bytes),
                "harness panicked on {path:?}"
            );
            // Independently check which seeds are real signatures: the
            // harness layout is one size byte then the signature.
            let Some((&size_byte, signature)) = bytes.split_first() else {
                continue;
            };
            let fixture = ring_fixture(crate::testing::fuzz::ring_fuzz_size(size_byte));
            let Ok(parsed) = RingSignature::from_bytes(signature) else {
                continue;
            };
            if verify_with(&fixture, FIXTURE_CIPHERTEXT, &parsed).is_ok() {
                valid_seen.push(path);
            }
        }
        assert_eq!(
            valid_seen.len(),
            1,
            "exactly one valid seed expected: {valid_seen:?}"
        );
        assert!(
            valid_seen[0].ends_with("seed_01_valid_n2"),
            "unexpected valid seed: {valid_seen:?}"
        );
    }
}
