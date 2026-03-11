//! Internal I2P-style transport engine.
//!
//! This module implements an in-process secure stream transport with explicit
//! session handshake, key derivation, and AEAD framing.

use crate::core::core::{PeerInfo, TransportQuality, TransportType};
use crate::core::error::{MeshInfinityError, Result};
use crate::transport::traits::{Connection, Listener, Transport};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

const HANDSHAKE_TAG: &[u8; 6] = b"MI2Pv1";

/// Internal I2P-style transport with authenticated stream encryption.
pub struct I2pTransport;

impl Default for I2pTransport {
    /// Construct transport instance.
    fn default() -> Self {
        Self::new()
    }
}

impl I2pTransport {
    /// Construct transport instance.
    pub fn new() -> Self {
        Self
    }

    fn resolve_endpoint(peer_info: &PeerInfo) -> Result<SocketAddr> {
        if let Some(addr) = peer_info.endpoint {
            return Ok(addr);
        }

        if let Some(raw) = peer_info.transport_endpoints.get(&TransportType::I2P) {
            return raw.parse::<SocketAddr>().map_err(|e| {
                MeshInfinityError::TransportError(format!("invalid I2P endpoint metadata: {}", e))
            });
        }

        Err(MeshInfinityError::TransportError(
            "missing I2P endpoint metadata".to_string(),
        ))
    }
}

impl Transport for I2pTransport {
    /// Open encrypted outbound stream to peer.
    fn connect(&self, peer_info: &PeerInfo) -> Result<Box<dyn Connection>> {
        let endpoint = Self::resolve_endpoint(peer_info)?;
        let mut stream = TcpStream::connect(endpoint)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;

        let state = HandshakeState::client_handshake(&mut stream)?;
        Ok(Box::new(I2pConnection {
            stream,
            peer: peer_info.clone(),
            state,
            closed: false,
        }))
    }

    /// Listen for encrypted inbound streams.
    fn listen(&self) -> Result<Box<dyn Listener>> {
        let listener = TcpListener::bind("0.0.0.0:0")?;
        listener.set_nonblocking(false)?;
        Ok(Box::new(I2pListener { listener }))
    }

    /// Transport priority in selection order.
    fn priority(&self) -> u8 {
        3
    }

    /// Identify transport type.
    fn transport_type(&self) -> TransportType {
        TransportType::I2P
    }

    /// Internal engine availability.
    fn is_available(&self) -> bool {
        true
    }

    /// Static quality estimate for encrypted relay-like paths.
    fn measure_quality(&self, _target: &PeerInfo) -> Result<TransportQuality> {
        Ok(TransportQuality {
            latency: Duration::from_millis(320),
            bandwidth: 450_000,
            reliability: 0.8,
            cost: 0.15,
            congestion: 0.3,
        })
    }
}

struct HandshakeState {
    cipher: ChaCha20Poly1305,
    tx_counter: u64,
    rx_counter: u64,
}

impl HandshakeState {
    fn client_handshake(stream: &mut TcpStream) -> Result<Self> {
        stream.write_all(HANDSHAKE_TAG)?;

        let client_secret = StaticSecret::random_from_rng(OsRng);
        let client_pub = X25519PublicKey::from(&client_secret);
        stream.write_all(client_pub.as_bytes())?;

        let mut server_tag = [0u8; 6];
        stream.read_exact(&mut server_tag)?;
        if &server_tag != HANDSHAKE_TAG {
            return Err(MeshInfinityError::TransportError(
                "I2P handshake tag mismatch".to_string(),
            ));
        }

        let mut server_pub_bytes = [0u8; 32];
        stream.read_exact(&mut server_pub_bytes)?;
        let server_pub = X25519PublicKey::from(server_pub_bytes);

        let shared = client_secret.diffie_hellman(&server_pub);
        Self::from_shared_secret(shared.as_bytes())
    }

    fn server_handshake(stream: &mut TcpStream) -> Result<Self> {
        let mut client_tag = [0u8; 6];
        stream.read_exact(&mut client_tag)?;
        if &client_tag != HANDSHAKE_TAG {
            return Err(MeshInfinityError::TransportError(
                "I2P handshake tag mismatch".to_string(),
            ));
        }

        let mut client_pub_bytes = [0u8; 32];
        stream.read_exact(&mut client_pub_bytes)?;
        let client_pub = X25519PublicKey::from(client_pub_bytes);

        let server_secret = StaticSecret::random_from_rng(OsRng);
        let server_pub = X25519PublicKey::from(&server_secret);

        stream.write_all(HANDSHAKE_TAG)?;
        stream.write_all(server_pub.as_bytes())?;

        let shared = server_secret.diffie_hellman(&client_pub);
        Self::from_shared_secret(shared.as_bytes())
    }

    fn from_shared_secret(shared: &[u8]) -> Result<Self> {
        let hk = Hkdf::<Sha256>::new(None, shared);
        let mut key_bytes = [0u8; 32];
        hk.expand(b"mesh-infinity-i2p-stream", &mut key_bytes)
            .map_err(|_| MeshInfinityError::CryptoError("hkdf expansion failed".to_string()))?;

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        Ok(Self {
            cipher,
            tx_counter: 0,
            rx_counter: 0,
        })
    }

    fn next_tx_nonce(&mut self) -> [u8; 12] {
        self.tx_counter = self.tx_counter.saturating_add(1);
        nonce_from_counter(self.tx_counter, 0xA1)
    }

    fn next_rx_nonce(&mut self) -> [u8; 12] {
        self.rx_counter = self.rx_counter.saturating_add(1);
        nonce_from_counter(self.rx_counter, 0xA1)
    }
}

fn nonce_from_counter(counter: u64, prefix: u8) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0] = prefix;
    nonce[4..12].copy_from_slice(&counter.to_be_bytes());
    nonce
}

pub struct I2pConnection {
    stream: TcpStream,
    peer: PeerInfo,
    state: HandshakeState,
    closed: bool,
}

impl Connection for I2pConnection {
    /// Encrypt and send a framed payload.
    fn send(&mut self, data: &[u8]) -> Result<usize> {
        if self.closed {
            return Err(MeshInfinityError::NetworkError(
                "I2P connection closed".to_string(),
            ));
        }

        let nonce_bytes = self.state.next_tx_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .state
            .cipher
            .encrypt(nonce, data)
            .map_err(|_| MeshInfinityError::CryptoError("I2P encrypt failed".to_string()))?;

        let total_len = (nonce_bytes.len() + ciphertext.len()) as u32;
        self.stream.write_all(&total_len.to_be_bytes())?;
        self.stream.write_all(&nonce_bytes)?;
        self.stream.write_all(&ciphertext)?;

        Ok(data.len())
    }

    /// Receive and decrypt a framed payload.
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

        let expected_nonce = self.state.next_rx_nonce();
        if nonce_bytes != expected_nonce {
            return Err(MeshInfinityError::SecurityError(
                "I2P nonce sequence mismatch".to_string(),
            ));
        }

        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = self
            .state
            .cipher
            .decrypt(nonce, &frame[12..])
            .map_err(|_| MeshInfinityError::CryptoError("I2P decrypt failed".to_string()))?;

        let to_copy = usize::min(buffer.len(), plaintext.len());
        buffer[..to_copy].copy_from_slice(&plaintext[..to_copy]);
        Ok(to_copy)
    }

    /// Close stream.
    fn close(&mut self) -> Result<()> {
        if !self.closed {
            self.stream.shutdown(std::net::Shutdown::Both)?;
            self.closed = true;
        }
        Ok(())
    }

    /// Return peer metadata.
    fn remote_peer(&self) -> &PeerInfo {
        &self.peer
    }

    /// Return active state.
    fn is_active(&self) -> bool {
        !self.closed
    }
}

pub struct I2pListener {
    listener: TcpListener,
}

impl Listener for I2pListener {
    /// Accept and handshake an inbound I2P-style connection.
    fn accept(&mut self) -> Result<Box<dyn Connection>> {
        let (mut stream, addr) = self.listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;

        let state = HandshakeState::server_handshake(&mut stream)?;

        let peer = PeerInfo {
            peer_id: [0; 32],
            public_key: [0; 32],
            trust_level: crate::core::TrustLevel::Untrusted,
            available_transports: vec![TransportType::I2P],
            last_seen: None,
            endpoint: Some(addr),
            transport_endpoints: std::collections::HashMap::new(),
        };

        Ok(Box::new(I2pConnection {
            stream,
            peer,
            state,
            closed: false,
        }))
    }

    /// Close listener.
    fn close(&mut self) -> Result<()> {
        self.listener.set_nonblocking(true)?;
        Ok(())
    }

    /// Return local listen address.
    fn local_addr(&self) -> String {
        self.listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "0.0.0.0:0".to_string())
    }
}
