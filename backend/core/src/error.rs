// Error handling for Mesh Infinity
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MeshInfinityError {
    // Core errors
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
    
    #[error("Authentication failed: {0}")]
    AuthError(String),
    
    #[error("Transport error: {0}")]
    TransportError(String),
    
    #[error("WireGuard error: {0}")]
    WireGuardError(String),
    
    #[error("Discovery error: {0}")]
    DiscoveryError(String),
    
    #[error("File transfer error: {0}")]
    FileTransferError(String),
    
    #[error("Exit node error: {0}")]
    ExitNodeError(String),
    
    #[error("Application gateway error: {0}")]
    AppGatewayError(String),
    
    #[error("Security policy violation: {0}")]
    SecurityError(String),
    
    // Specific errors
    #[error("No available transport for peer")]
    NoAvailableTransport,
    
    #[error("No active session with peer")]
    NoActiveSession,
    
    #[error("Peer not found: {0}")]
    PeerNotFound(String),
    
    #[error("Connection timeout")]
    ConnectionTimeout,
    
    #[error("Invalid message format")]
    InvalidMessageFormat,
    
    #[error("Insufficient trust level")]
    InsufficientTrust,
    
    #[error("Resource not available")]
    ResourceUnavailable,
    
    #[error("Operation not supported")]
    OperationNotSupported,
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
}

pub type Result<T> = std::result::Result<T, MeshInfinityError>;