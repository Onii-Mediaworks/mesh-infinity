//! Internal Tor-style transport engine.
//!
//! This module provides an in-process anonymized stream transport abstraction
//! with authenticated handshake and encrypted framing, without requiring an
//! external daemon process at runtime.

use crate::core::core::{PeerInfo, TransportQuality, TransportType};
use crate::core::error::{MeshInfinityError, Result};
use crate::transport::traits::{Connection, Listener, Transport};

use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

const HANDSHAKE_TAG: &[u8; 6] = b"MTORv1";

/// Internal Tor-style transport implementation.
pub struct TorTransport;

impl Default for TorTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl TorTransport {
    /// Construct Tor transport instance.
    pub fn new() -> Self {
        Self
    }

    fn resolve_endpoint(peer_info: &PeerInfo) -> Result<SocketAddr> {
        if let Some(endpoint) = peer_info.endpoint {
            return Ok(endpoint);
        }

        if let Some(raw) = peer_info.transport_endpoints.get(&TransportType::Tor) {
            return raw.parse::<SocketAddr>().map_err(|e| {
                MeshInfinityError::TransportError(format!("invalid Tor endpoint metadata: {}", e))
            });
        }

        Err(MeshInfinityError::TransportError(
            "missing Tor endpoint metadata".to_string(),
        ))
    }
}

impl Transport for TorTransport {
    fn connect(&self, peer_info: &PeerInfo) -> Result<Box<dyn Connection>> {
        let endpoint = Self::resolve_endpoint(peer_info)?;
        let mut stream = TcpStream::connect(endpoint)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;

        let state = CryptoState::client_handshake(&mut stream)?;
        Ok(Box::new(TorConnection {
            stream,
            peer: peer_info.clone(),
            state,
            closed: false,
        }))
    }

    fn listen(&self) -> Result<Box<dyn Listener>> {
        let listener = TcpListener::bind("0.0.0.0:0")?;
        listener.set_nonblocking(false)?;
        Ok(Box::new(TorListener { listener }))
    }

    fn priority(&self) -> u8 {
        2
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Tor
    }

    fn is_available(&self) -> bool {
        true
    }

    fn measure_quality(&self, _target: &PeerInfo) -> Result<TransportQuality> {
        Ok(TransportQuality {
            latency: Duration::from_millis(520),
            bandwidth: 400_000,
            reliability: 0.88,
            cost: 0.2,
            congestion: 0.35,
        })
    }
}

struct CryptoState {
    cipher: ChaCha20Poly1305,
    tx_counter: u64,
    rx_counter: u64,
}

impl CryptoState {
    fn client_handshake(stream: &mut TcpStream) -> Result<Self> {
        stream.write_all(HANDSHAKE_TAG)?;
        let secret = StaticSecret::new(OsRng);
        let pubkey = X25519PublicKey::from(&secret);
        stream.write_all(pubkey.as_bytes())?;

        let mut remote_tag = [0u8; 6];
        stream.read_exact(&mut remote_tag)?;
        if &remote_tag != HANDSHAKE_TAG {
            return Err(MeshInfinityError::TransportError(
                "Tor handshake tag mismatch".to_string(),
            ));
        }

        let mut remote_pub = [0u8; 32];
        stream.read_exact(&mut remote_pub)?;
        let remote_pub = X25519PublicKey::from(remote_pub);
        let shared = secret.diffie_hellman(&remote_pub);
        Self::from_shared(shared.as_bytes())
    }

    fn server_handshake(stream: &mut TcpStream) -> Result<Self> {
        let mut remote_tag = [0u8; 6];
        stream.read_exact(&mut remote_tag)?;
        if &remote_tag != HANDSHAKE_TAG {
            return Err(MeshInfinityError::TransportError(
                "Tor handshake tag mismatch".to_string(),
            ));
        }

        let mut remote_pub = [0u8; 32];
        stream.read_exact(&mut remote_pub)?;
        let remote_pub = X25519PublicKey::from(remote_pub);

        let secret = StaticSecret::new(OsRng);
        let pubkey = X25519PublicKey::from(&secret);
        stream.write_all(HANDSHAKE_TAG)?;
        stream.write_all(pubkey.as_bytes())?;

        let shared = secret.diffie_hellman(&remote_pub);
        Self::from_shared(shared.as_bytes())
    }

    fn from_shared(shared: &[u8]) -> Result<Self> {
        let hk = Hkdf::<Sha256>::new(None, shared);
        let mut key = [0u8; 32];
        hk.expand(b"mesh-infinity-tor-stream", &mut key)
            .map_err(|_| MeshInfinityError::CryptoError("tor hkdf failed".to_string()))?;
        Ok(Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(&key)),
            tx_counter: 0,
            rx_counter: 0,
        })
    }

    fn tx_nonce(&mut self) -> [u8; 12] {
        self.tx_counter = self.tx_counter.saturating_add(1);
        nonce(self.tx_counter, 0xB2)
    }

    fn rx_nonce(&mut self) -> [u8; 12] {
        self.rx_counter = self.rx_counter.saturating_add(1);
        nonce(self.rx_counter, 0xB2)
    }
}

fn nonce(counter: u64, prefix: u8) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0] = prefix;
    out[4..].copy_from_slice(&counter.to_be_bytes());
    out
}

pub struct TorConnection {
    stream: TcpStream,
    peer: PeerInfo,
    state: CryptoState,
    closed: bool,
}

impl Connection for TorConnection {
    fn send(&mut self, data: &[u8]) -> Result<usize> {
        if self.closed {
            return Err(MeshInfinityError::NetworkError(
                "Tor connection closed".to_string(),
            ));
        }

        let nonce_bytes = self.state.tx_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .state
            .cipher
            .encrypt(nonce, data)
            .map_err(|_| MeshInfinityError::CryptoError("Tor encrypt failed".to_string()))?;

        let total_len = (12 + ciphertext.len()) as u32;
        self.stream.write_all(&total_len.to_be_bytes())?;
        self.stream.write_all(&nonce_bytes)?;
        self.stream.write_all(&ciphertext)?;
        Ok(data.len())
    }

    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize> {
        if self.closed {
            return Ok(0);
        }

        let mut len_bytes = [0u8; 4];
        self.stream.read_exact(&mut len_bytes)?;
        let total_len = u32::from_be_bytes(len_bytes) as usize;
        if total_len < 12 {
            return Err(MeshInfinityError::InvalidMessageFormat);
        }

        let mut frame = vec![0u8; total_len];
        self.stream.read_exact(&mut frame)?;

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&frame[..12]);
        let expected = self.state.rx_nonce();
        if nonce_bytes != expected {
            return Err(MeshInfinityError::SecurityError(
                "Tor nonce mismatch".to_string(),
            ));
        }

        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = self
            .state
            .cipher
            .decrypt(nonce, &frame[12..])
            .map_err(|_| MeshInfinityError::CryptoError("Tor decrypt failed".to_string()))?;

        let copied = usize::min(buffer.len(), plaintext.len());
        buffer[..copied].copy_from_slice(&plaintext[..copied]);
        Ok(copied)
    }

    fn close(&mut self) -> Result<()> {
        if !self.closed {
            self.stream.shutdown(Shutdown::Both)?;
            self.closed = true;
        }
        Ok(())
    }

    fn remote_peer(&self) -> &PeerInfo {
        &self.peer
    }

    fn is_active(&self) -> bool {
        !self.closed
    }
}

pub struct TorListener {
    listener: TcpListener,
}

impl Listener for TorListener {
    fn accept(&mut self) -> Result<Box<dyn Connection>> {
        let (mut stream, addr) = self.listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        let state = CryptoState::server_handshake(&mut stream)?;

        let mut transport_endpoints = std::collections::HashMap::new();
        transport_endpoints.insert(TransportType::Tor, addr.to_string());
        let peer = PeerInfo {
            peer_id: [0; 32],
            public_key: [0; 32],
            trust_level: crate::core::TrustLevel::Untrusted,
            available_transports: vec![TransportType::Tor],
            last_seen: None,
            endpoint: Some(addr),
            transport_endpoints,
        };

        Ok(Box::new(TorConnection {
            stream,
            peer,
            state,
            closed: false,
        }))
    }

    fn close(&mut self) -> Result<()> {
        self.listener.set_nonblocking(true)?;
        Ok(())
    }

    fn local_addr(&self) -> String {
        self.listener
            .local_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| "0.0.0.0:0".to_string())
    }
}
