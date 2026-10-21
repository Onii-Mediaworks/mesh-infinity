//! Authenticated link identification for framed TCP links (§5.1, §5.2).
//!
//! # Why this exists
//!
//! Every clearnet and Tor connection carries length-prefixed JSON frames whose
//! handlers key routing, isolation, trust and contact decisions on a `sender`
//! field.  §2.0 treats every non-contact as hostile, so a connection may only
//! be keyed on a peer id after the remote side has *proved* possession of the
//! Ed25519 identity key that id is derived from.  This module is that proof.
//!
//! # Protocol (suite `MI-LINK-1`: Ed25519 signatures, SHA-256 peer ids)
//!
//! ```text
//! initiator -> responder : link_hello { sender, ed25519_public, nonce_i }
//! responder -> initiator : link_auth  { sender, ed25519_public, nonce_r,
//!                                       sig_r = Sign_r("responder" || nonce_i || nonce_r
//!                                                      || pub_r || id_i) }
//! initiator -> responder : link_auth  { sender, ed25519_public, nonce_i,
//!                                       sig_i = Sign_i("initiator" || nonce_i || nonce_r
//!                                                      || pub_i || id_r) }
//! ```
//!
//! Each side signs the other side's fresh nonce, so a recorded exchange cannot
//! be replayed, and each signature binds the counterpart's peer id, so a relay
//! cannot splice two honest sessions together.  The sender field is always
//! recomputed from the presented public key (`PeerId::from_ed25519_pub`) and
//! never trusted on its own.
//!
//! This module is pure: it parses frames, builds frames and verifies
//! signatures.  Socket handling lives in `service::poll`.  Nonces are passed
//! in by the caller so the state machine stays deterministic and fuzzable.

use std::fmt;

use serde_json::Value;
use zeroize::Zeroizing;

use crate::crypto::signing::{self, DOMAIN_LINK_AUTH};
use crate::identity::peer_id::PeerId;

/// Length in bytes of the per-side link nonce.
///
/// 256 bits of freshness: the nonce is the anti-replay input to the
/// counterpart's signature, so it must be unguessable, not merely unique.
pub const LINK_NONCE_LEN: usize = 32;

/// Largest link handshake frame a peer may send before being authenticated.
///
/// Hello and auth frames are a few hundred bytes of hex; anything larger is a
/// malformed client or a memory-exhaustion attempt from an unauthenticated
/// socket, and the socket is closed.
pub const MAX_LINK_AUTH_FRAME_BYTES: usize = 1024;

/// Frame type string of the initiator's opening message.
pub const LINK_HELLO_TYPE: &str = "link_hello";

/// Frame type string of both signed authentication messages.
pub const LINK_AUTH_TYPE: &str = "link_auth";

/// Role tag mixed into the responder's signature preimage.
const RESPONDER_TAG: &[u8] = b"responder";

/// Role tag mixed into the initiator's signature preimage.
const INITIATOR_TAG: &[u8] = b"initiator";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a link handshake frame was rejected.
///
/// Every variant maps to "close the socket, keep no state".  The variants
/// are distinct so tests and diagnostics can tell a wire-format problem from
/// a cryptographic one, but none of them is ever reported to the peer (§7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkAuthError {
    /// The frame is not a JSON object or is larger than the handshake cap.
    MalformedFrame,
    /// The `type` field is not the one this step expects.
    UnexpectedFrameType,
    /// A required field is absent.
    MissingField(&'static str),
    /// A field is present but not the expected hex length / shape.
    MalformedField(&'static str),
    /// `sender` is not the SHA-256 of the presented Ed25519 key, or the
    /// key/nonce in the auth frame differs from the hello it answers.
    IdentityMismatch,
    /// The authenticated peer is not the one the caller intended to reach.
    UnexpectedPeer,
    /// The Ed25519 signature does not verify under the presented key.
    BadSignature,
    /// The local identity is locked, so there is no key to sign with.
    NoLocalIdentity,
    /// The OS random source failed while drawing a nonce.
    RandomFailure,
    /// The socket failed or timed out mid-handshake.
    Io(std::io::ErrorKind),
}

impl fmt::Display for LinkAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedFrame => write!(f, "malformed link handshake frame"),
            Self::UnexpectedFrameType => write!(f, "unexpected link handshake frame type"),
            Self::MissingField(name) => write!(f, "link handshake frame missing `{name}`"),
            Self::MalformedField(name) => write!(f, "link handshake field `{name}` malformed"),
            Self::IdentityMismatch => write!(f, "link identity does not match presented key"),
            Self::UnexpectedPeer => write!(f, "authenticated peer is not the expected peer"),
            Self::BadSignature => write!(f, "link handshake signature invalid"),
            Self::NoLocalIdentity => write!(f, "local identity locked; cannot authenticate link"),
            Self::RandomFailure => write!(f, "random number generation failed"),
            Self::Io(kind) => write!(f, "link handshake socket error: {kind:?}"),
        }
    }
}

impl std::error::Error for LinkAuthError {}

// ---------------------------------------------------------------------------
// Local signing identity
// ---------------------------------------------------------------------------

/// The local Ed25519 identity used to sign link handshakes.
///
/// A snapshot of the three values the handshake needs, taken under the
/// identity lock once so the handshake itself never holds that lock.  The
/// secret key is zeroized on drop.
pub struct LinkSigner {
    /// Our peer id (SHA-256 of `ed25519_public`).
    pub peer_id: PeerId,
    /// Our Ed25519 verifying key, sent in the clear so the peer can verify.
    pub ed25519_public: [u8; 32],
    /// Our Ed25519 signing seed; never leaves this struct.
    signing_key: Zeroizing<[u8; 32]>,
}

impl LinkSigner {
    /// Build a signer from the identity's public key and signing seed.
    ///
    /// The peer id is derived here rather than passed in so the signer can
    /// never advertise an id that does not match the key it signs with.
    pub fn new(ed25519_public: [u8; 32], signing_key: [u8; 32]) -> Self {
        Self {
            peer_id: PeerId::from_ed25519_pub(&ed25519_public),
            ed25519_public,
            signing_key: Zeroizing::new(signing_key),
        }
    }

    /// Sign a handshake transcript under the link-auth domain.
    fn sign(&self, transcript: &[u8]) -> Vec<u8> {
        signing::sign(&self.signing_key, DOMAIN_LINK_AUTH, transcript)
    }
}

// ---------------------------------------------------------------------------
// Wire frames
// ---------------------------------------------------------------------------

/// A parsed `link_hello` frame: the initiator's claimed identity and nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkHello {
    /// Peer id recomputed from `ed25519_public` (the claimed one must match).
    pub peer_id: PeerId,
    /// The initiator's Ed25519 verifying key.
    pub ed25519_public: [u8; 32],
    /// The initiator's fresh nonce, which the responder must sign.
    pub nonce: [u8; LINK_NONCE_LEN],
}

/// A parsed `link_auth` frame: a signed identity assertion from either role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkAuth {
    /// Peer id recomputed from `ed25519_public` (the claimed one must match).
    pub peer_id: PeerId,
    /// The signer's Ed25519 verifying key.
    pub ed25519_public: [u8; 32],
    /// The signer's own nonce (fresh for the responder, echoed by the
    /// initiator so the responder can match it to its pending hello).
    pub nonce: [u8; LINK_NONCE_LEN],
    /// Ed25519 signature over the role transcript.
    pub signature: Vec<u8>,
}

/// Decode a hex string field into a fixed-size array.
///
/// Returns a typed error naming the field so a dropped handshake can be
/// diagnosed without ever echoing the offending value.
fn hex_field<const N: usize>(frame: &Value, name: &'static str) -> Result<[u8; N], LinkAuthError> {
    let text = frame
        .get(name)
        .and_then(|v| v.as_str())
        .ok_or(LinkAuthError::MissingField(name))?;
    let bytes = hex::decode(text).map_err(|_| LinkAuthError::MalformedField(name))?;
    bytes
        .try_into()
        .map_err(|_| LinkAuthError::MalformedField(name))
}

/// Check the frame's `type` field against the expected handshake step.
fn expect_frame_type(frame: &Value, expected: &str) -> Result<(), LinkAuthError> {
    let actual = frame
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or(LinkAuthError::MissingField("type"))?;
    if actual == expected {
        Ok(())
    } else {
        Err(LinkAuthError::UnexpectedFrameType)
    }
}

/// Parse the identity pair (`sender`, `ed25519_public`) and verify that the
/// claimed sender is the hash of the presented key.
fn parse_identity(frame: &Value) -> Result<(PeerId, [u8; 32]), LinkAuthError> {
    let claimed: [u8; 32] = hex_field(frame, "sender")?;
    let ed25519_public: [u8; 32] = hex_field(frame, "ed25519_public")?;
    let derived = PeerId::from_ed25519_pub(&ed25519_public);
    // SECURITY: the claimed id is informational only; the key decides.
    if derived.0 != claimed {
        return Err(LinkAuthError::IdentityMismatch);
    }
    Ok((derived, ed25519_public))
}

/// Parse a `link_hello` frame.
pub fn parse_hello(frame: &Value) -> Result<LinkHello, LinkAuthError> {
    if !frame.is_object() {
        return Err(LinkAuthError::MalformedFrame);
    }
    expect_frame_type(frame, LINK_HELLO_TYPE)?;
    let (peer_id, ed25519_public) = parse_identity(frame)?;
    let nonce = hex_field(frame, "nonce")?;
    Ok(LinkHello {
        peer_id,
        ed25519_public,
        nonce,
    })
}

/// Parse a `link_auth` frame (signature is decoded but not yet verified).
pub fn parse_auth(frame: &Value) -> Result<LinkAuth, LinkAuthError> {
    if !frame.is_object() {
        return Err(LinkAuthError::MalformedFrame);
    }
    expect_frame_type(frame, LINK_AUTH_TYPE)?;
    let (peer_id, ed25519_public) = parse_identity(frame)?;
    let nonce = hex_field(frame, "nonce")?;
    let sig_hex = frame
        .get("sig")
        .and_then(|v| v.as_str())
        .ok_or(LinkAuthError::MissingField("sig"))?;
    let signature = hex::decode(sig_hex).map_err(|_| LinkAuthError::MalformedField("sig"))?;
    // Ed25519 signatures are exactly 64 bytes; reject early so the verifier
    // never sees a length it has to special-case.
    if signature.len() != 64 {
        return Err(LinkAuthError::MalformedField("sig"));
    }
    Ok(LinkAuth {
        peer_id,
        ed25519_public,
        nonce,
        signature,
    })
}

/// Build the signed transcript for one role.
///
/// Layout: `tag || nonce_i || nonce_r || signer_pub || counterpart_id`.  All
/// parts are fixed-length, so the concatenation is unambiguous without
/// length prefixes.
fn transcript(
    tag: &[u8],
    nonce_i: &[u8; LINK_NONCE_LEN],
    nonce_r: &[u8; LINK_NONCE_LEN],
    signer_pub: &[u8; 32],
    counterpart: &PeerId,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(tag.len() + 2 * LINK_NONCE_LEN + 64);
    msg.extend_from_slice(tag);
    msg.extend_from_slice(nonce_i);
    msg.extend_from_slice(nonce_r);
    msg.extend_from_slice(signer_pub);
    msg.extend_from_slice(&counterpart.0);
    msg
}

/// Serialise a `link_auth` frame for the wire.
fn auth_frame(signer: &LinkSigner, nonce: &[u8; LINK_NONCE_LEN], signature: &[u8]) -> Value {
    serde_json::json!({
        "type":           LINK_AUTH_TYPE,
        "sender":         signer.peer_id.to_hex(),
        "ed25519_public": hex::encode(signer.ed25519_public),
        "nonce":          hex::encode(nonce),
        "sig":            hex::encode(signature),
    })
}

// ---------------------------------------------------------------------------
// Initiator role (the side that opened the TCP connection)
// ---------------------------------------------------------------------------

/// Initiator-side handshake state: our signer, our nonce, and who we expect.
pub struct InitiatorLink {
    /// Local signing identity.
    signer: LinkSigner,
    /// Our fresh nonce; the responder must sign it.
    nonce: [u8; LINK_NONCE_LEN],
    /// The peer we dialled.  `None` only when the caller genuinely does not
    /// know who answers (never the case for contact endpoints).
    expected: Option<PeerId>,
}

impl InitiatorLink {
    /// Start an initiator handshake with a caller-supplied fresh nonce.
    pub fn new(signer: LinkSigner, nonce: [u8; LINK_NONCE_LEN], expected: Option<PeerId>) -> Self {
        Self {
            signer,
            nonce,
            expected,
        }
    }

    /// The opening `link_hello` frame.
    pub fn hello_frame(&self) -> Value {
        serde_json::json!({
            "type":           LINK_HELLO_TYPE,
            "sender":         self.signer.peer_id.to_hex(),
            "ed25519_public": hex::encode(self.signer.ed25519_public),
            "nonce":          hex::encode(self.nonce),
        })
    }

    /// Verify the responder's `link_auth` and produce our own.
    ///
    /// Returns the authenticated responder id and the `link_auth` frame the
    /// caller must send back to complete mutual authentication.
    pub fn accept_response(&self, frame: &Value) -> Result<(PeerId, Value), LinkAuthError> {
        let auth = parse_auth(frame)?;
        // The dialled peer must be the one answering; otherwise the endpoint
        // hint we followed was wrong or hijacked, and nothing may be keyed
        // on this socket.
        if let Some(expected) = &self.expected {
            if *expected != auth.peer_id {
                return Err(LinkAuthError::UnexpectedPeer);
            }
        }
        let msg = transcript(
            RESPONDER_TAG,
            &self.nonce,
            &auth.nonce,
            &auth.ed25519_public,
            &self.signer.peer_id,
        );
        if !signing::verify(
            &auth.ed25519_public,
            DOMAIN_LINK_AUTH,
            &msg,
            &auth.signature,
        ) {
            return Err(LinkAuthError::BadSignature);
        }
        // Our proof: sign the responder's nonce, bound to the responder's id.
        let ours = transcript(
            INITIATOR_TAG,
            &self.nonce,
            &auth.nonce,
            &self.signer.ed25519_public,
            &auth.peer_id,
        );
        let sig = self.signer.sign(&ours);
        Ok((auth.peer_id, auth_frame(&self.signer, &self.nonce, &sig)))
    }
}

// ---------------------------------------------------------------------------
// Responder role (the side that accepted the TCP connection)
// ---------------------------------------------------------------------------

/// Responder-side handshake state after a hello has been answered.
pub struct ResponderLink {
    /// Local signing identity.
    signer: LinkSigner,
    /// Our fresh nonce; the initiator must sign it.
    nonce: [u8; LINK_NONCE_LEN],
    /// The hello we are answering (key and nonce the auth must echo).
    hello: LinkHello,
}

impl ResponderLink {
    /// Answer a parsed hello: returns the state to keep and the `link_auth`
    /// frame to send.  `nonce` must be freshly drawn by the caller.
    pub fn answer(
        signer: LinkSigner,
        hello: LinkHello,
        nonce: [u8; LINK_NONCE_LEN],
    ) -> (Self, Value) {
        let msg = transcript(
            RESPONDER_TAG,
            &hello.nonce,
            &nonce,
            &signer.ed25519_public,
            &hello.peer_id,
        );
        let sig = signer.sign(&msg);
        let frame = auth_frame(&signer, &nonce, &sig);
        (
            Self {
                signer,
                nonce,
                hello,
            },
            frame,
        )
    }

    /// Verify the initiator's `link_auth`; on success the link is bound to
    /// the returned peer id.
    pub fn accept_auth(&self, frame: &Value) -> Result<PeerId, LinkAuthError> {
        let auth = parse_auth(frame)?;
        // The auth must come from the same key, id and nonce as the hello;
        // a different key here means two parties are sharing the socket.
        if auth.ed25519_public != self.hello.ed25519_public
            || auth.peer_id != self.hello.peer_id
            || auth.nonce != self.hello.nonce
        {
            return Err(LinkAuthError::IdentityMismatch);
        }
        let msg = transcript(
            INITIATOR_TAG,
            &self.hello.nonce,
            &self.nonce,
            &auth.ed25519_public,
            &self.signer.peer_id,
        );
        if !signing::verify(
            &auth.ed25519_public,
            DOMAIN_LINK_AUTH,
            &msg,
            &auth.signature,
        ) {
            return Err(LinkAuthError::BadSignature);
        }
        Ok(auth.peer_id)
    }
}

// ---------------------------------------------------------------------------
// Post-handshake sender binding
// ---------------------------------------------------------------------------

/// Whether a frame received on a link authenticated as `link_peer` claims a
/// consistent origin.
///
/// Frames name their origin in a top-level `sender` (most types) or `from`
/// (route announcements).  Either field, when present, must decode to the
/// link peer's 32 bytes; a frame naming someone else is a spoofing attempt
/// and must not reach any handler.  Frames with neither field (for example
/// `sf_deliver`) carry no origin claim and pass.
pub fn claimed_sender_matches(frame: &Value, link_peer: &PeerId) -> bool {
    ["sender", "from"]
        .iter()
        .all(|field| match frame.get(*field) {
            None => true,
            Some(value) => value
                .as_str()
                .and_then(|text| PeerId::from_hex(text).ok())
                .is_some_and(|claimed| claimed == *link_peer),
        })
}

/// Whether a frame type belongs to the link handshake itself.
///
/// Such frames are consumed by the pending-link state machine; on an
/// already-authenticated link they are protocol noise and are dropped
/// before dispatch.
pub fn is_link_handshake_frame(frame: &Value) -> bool {
    matches!(
        frame.get("type").and_then(|t| t.as_str()),
        Some(LINK_HELLO_TYPE) | Some(LINK_AUTH_TYPE)
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::self_identity::SelfIdentity;

    /// A signer for a freshly generated identity.
    fn signer_for(id: &SelfIdentity) -> LinkSigner {
        LinkSigner::new(id.ed25519_pub, id.ed25519_signing.to_bytes())
    }

    /// Both sides authenticate each other and agree on the peer ids.
    #[test]
    fn honest_parties_authenticate_mutually() {
        let alice = SelfIdentity::generate(None);
        let bob = SelfIdentity::generate(None);
        let init = InitiatorLink::new(signer_for(&alice), [1u8; 32], Some(bob.peer_id()));
        let hello = parse_hello(&init.hello_frame()).unwrap();
        let (resp, challenge) = ResponderLink::answer(signer_for(&bob), hello, [2u8; 32]);
        let (bob_id, proof) = init.accept_response(&challenge).unwrap();
        assert_eq!(bob_id, bob.peer_id());
        assert_eq!(resp.accept_auth(&proof), Ok(alice.peer_id()));
    }

    /// A hello whose `sender` is not the hash of its key is rejected; the
    /// claimed id is never an authority.
    #[test]
    fn hello_with_mismatched_sender_is_rejected() {
        let alice = SelfIdentity::generate(None);
        let init = InitiatorLink::new(signer_for(&alice), [1u8; 32], None);
        let mut hello = init.hello_frame();
        hello["sender"] = serde_json::json!(hex::encode([0x42u8; 32]));
        assert_eq!(parse_hello(&hello), Err(LinkAuthError::IdentityMismatch));
    }

    /// An attacker who saw Alice's hello cannot finish the exchange with a
    /// different key: the responder pins the hello key, and a forged auth
    /// claiming Alice's id without her key fails the id/key binding.
    ///
    /// Mallory cannot even run the honest initiator code here: Bob's
    /// challenge signature binds Alice's id, so `accept_response` as Mallory
    /// fails.  The forged auth is therefore assembled by hand with the
    /// module's own transcript helpers, exactly as a hostile client would.
    #[test]
    fn auth_from_different_key_than_hello_is_rejected() {
        let alice = SelfIdentity::generate(None);
        let bob = SelfIdentity::generate(None);
        let mallory = SelfIdentity::generate(None);
        let init = InitiatorLink::new(signer_for(&alice), [1u8; 32], Some(bob.peer_id()));
        let hello = parse_hello(&init.hello_frame()).unwrap();
        let (resp, challenge) = ResponderLink::answer(signer_for(&bob), hello, [2u8; 32]);
        let bob_auth = parse_auth(&challenge).unwrap();

        // Mallory signs a correct initiator transcript for her own key and
        // Alice's nonce: a well-formed auth for the wrong identity.
        let mallory_signer = signer_for(&mallory);
        let msg = transcript(
            INITIATOR_TAG,
            &[1u8; 32],
            &bob_auth.nonce,
            &mallory.ed25519_pub,
            &bob.peer_id(),
        );
        let sig = mallory_signer.sign(&msg);
        let mallory_auth = auth_frame(&mallory_signer, &[1u8; 32], &sig);
        assert_eq!(
            resp.accept_auth(&mallory_auth),
            Err(LinkAuthError::IdentityMismatch)
        );

        // Mallory relabels her auth with Alice's id and key: signature fails.
        let mut relabelled = mallory_auth.clone();
        relabelled["sender"] = serde_json::json!(alice.peer_id().to_hex());
        relabelled["ed25519_public"] = serde_json::json!(hex::encode(alice.ed25519_pub));
        assert_eq!(
            resp.accept_auth(&relabelled),
            Err(LinkAuthError::BadSignature)
        );
    }

    /// A responder answer recorded from one session fails verification in
    /// a later session because the initiator nonce differs.
    #[test]
    fn replayed_responder_auth_is_rejected() {
        let alice = SelfIdentity::generate(None);
        let bob = SelfIdentity::generate(None);
        let first = InitiatorLink::new(signer_for(&alice), [1u8; 32], Some(bob.peer_id()));
        let hello = parse_hello(&first.hello_frame()).unwrap();
        let (_, challenge) = ResponderLink::answer(signer_for(&bob), hello, [2u8; 32]);
        let second = InitiatorLink::new(signer_for(&alice), [9u8; 32], Some(bob.peer_id()));
        assert_eq!(
            second.accept_response(&challenge).map(|(id, _)| id),
            Err(LinkAuthError::BadSignature)
        );
    }

    /// Dialling Bob but being answered by Carol is refused even though
    /// Carol's signature is valid for her own key.
    #[test]
    fn unexpected_peer_is_rejected() {
        let alice = SelfIdentity::generate(None);
        let bob = SelfIdentity::generate(None);
        let carol = SelfIdentity::generate(None);
        let init = InitiatorLink::new(signer_for(&alice), [1u8; 32], Some(bob.peer_id()));
        let hello = parse_hello(&init.hello_frame()).unwrap();
        let (_, challenge) = ResponderLink::answer(signer_for(&carol), hello, [2u8; 32]);
        assert_eq!(
            init.accept_response(&challenge).map(|(id, _)| id),
            Err(LinkAuthError::UnexpectedPeer)
        );
    }

    /// Garbage, wrong types and short fields all produce typed errors.
    #[test]
    fn malformed_frames_produce_typed_errors() {
        assert_eq!(
            parse_hello(&Value::Null),
            Err(LinkAuthError::MalformedFrame)
        );
        assert_eq!(
            parse_hello(&serde_json::json!({"type": "keepalive"})),
            Err(LinkAuthError::UnexpectedFrameType)
        );
        assert_eq!(
            parse_hello(&serde_json::json!({"type": "link_hello"})),
            Err(LinkAuthError::MissingField("sender"))
        );
        assert_eq!(
            parse_auth(&serde_json::json!({
                "type": "link_auth", "sender": "zz", "ed25519_public": "00", "nonce": "00", "sig": "00"
            })),
            Err(LinkAuthError::MalformedField("sender"))
        );
    }

    /// Sender binding: matching, absent and foreign origins.
    #[test]
    fn sender_binding_checks_sender_and_from() {
        let link = PeerId([7u8; 32]);
        let other = PeerId([8u8; 32]);
        assert!(claimed_sender_matches(
            &serde_json::json!({"sender": link.to_hex()}),
            &link
        ));
        assert!(claimed_sender_matches(
            &serde_json::json!({"type": "sf_deliver"}),
            &link
        ));
        assert!(!claimed_sender_matches(
            &serde_json::json!({"sender": other.to_hex()}),
            &link
        ));
        assert!(!claimed_sender_matches(
            &serde_json::json!({"from": other.to_hex()}),
            &link
        ));
        assert!(!claimed_sender_matches(
            &serde_json::json!({"sender": "nothex"}),
            &link
        ));
    }
}
