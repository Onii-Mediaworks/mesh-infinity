//! Spike S5: the UI protocol sample on the core side.
//!
//! - The generated types (`v1`), from `proto/mesh/ui/v1/spike.proto`.
//! - Framing: each frame is a u32 big-endian length, then an `Envelope`.
//!   A frame longer than [`MAX_FRAME`] is a protocol error.
//! - Strict decoding: the UI is untrusted, and it ships in the same bundle
//!   as the core, so the core accepts only the canonical encoding of a
//!   known message. prost drops unknown fields silently, so strictness is
//!   checked by re-encoding: any unknown field, duplicate field, explicit
//!   default or over-long varint makes the re-encoded length differ.

use prost::Message;
use sha2::{Digest, Sha256};

/// The generated protocol types.
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/mesh.ui.v1.rs"));
}

/// The largest frame the core accepts, in bytes.
pub const MAX_FRAME: usize = 1024 * 1024;

/// The descriptor set the schema hash is taken over.
const SCHEMA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/schema.bin"));

/// The handshake's `schema_hash`: SHA-256 of the descriptor set.
pub fn schema_hash() -> [u8; 32] {
    Sha256::digest(SCHEMA).into()
}

/// Why a frame was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    /// Fewer bytes than the length prefix or the frame needs; wait for more.
    Incomplete,
    /// The length prefix exceeds [`MAX_FRAME`].
    TooLarge(usize),
    /// Not a valid `Envelope`.
    Malformed,
    /// Valid, but not the canonical encoding (unknown or duplicate fields).
    NotCanonical,
}

/// Appends `envelope` to `out` as one frame.
pub fn write_frame(envelope: &v1::Envelope, out: &mut Vec<u8>) {
    let body = envelope.encode_to_vec();
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
}

/// Reads one frame from the start of `input`: the envelope and the bytes used.
pub fn read_frame(input: &[u8]) -> Result<(v1::Envelope, usize), FrameError> {
    // The length prefix.
    let prefix: [u8; 4] = input.get(..4).ok_or(FrameError::Incomplete)?.try_into().map_err(|_| FrameError::Incomplete)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME {
        return Err(FrameError::TooLarge(length));
    }
    // The body, decoded strictly.
    let body = input.get(4..4 + length).ok_or(FrameError::Incomplete)?;
    Ok((decode_strict(body)?, 4 + length))
}

/// Decodes `body` as an `Envelope`, accepting only its canonical encoding.
pub fn decode_strict(body: &[u8]) -> Result<v1::Envelope, FrameError> {
    let envelope = v1::Envelope::decode(body).map_err(|_| FrameError::Malformed)?;
    // Unknown fields are dropped by decode, so they shorten the re-encoding.
    if envelope.encode_to_vec() != body {
        return Err(FrameError::NotCanonical);
    }
    Ok(envelope)
}

/// Reads every frame of a stream; stops at the first error.
pub fn read_stream(mut input: &[u8]) -> Result<Vec<v1::Envelope>, FrameError> {
    let mut frames = Vec::new();
    while !input.is_empty() {
        let (envelope, used) = read_frame(input)?;
        frames.push(envelope);
        input = &input[used..];
    }
    Ok(frames)
}
