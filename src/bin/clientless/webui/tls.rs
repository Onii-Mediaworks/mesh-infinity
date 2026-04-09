//! TLS certificate management for the clientless WebUI HTTPS server.
//!
//! # What this module does
//!
//! The Node Management Interface WebUI (§17.12) is always served over HTTPS.
//! On first run this module generates a self-signed X.509 certificate via
//! `rcgen` and persists it alongside the private key in the data directory.
//! On subsequent runs it loads the persisted certificate and key.
//!
//! # Certificate properties
//!
//! - **Algorithm**: ECDSA P-256 (same curve used for mesh identity keys)
//! - **Validity**: 10 years (the certificate never auto-expires during normal
//!   node operation; operators who need rotation can delete the files and
//!   restart the daemon)
//! - **Subject Alt Names**: `localhost`, `127.0.0.1`, and the machine hostname
//!   (so the certificate matches regardless of which address the client uses)
//!
//! # Trust store
//!
//! The generated certificate must be added to the operator's OS trust store
//! or browser exception list before the WebUI can be accessed without a
//! security warning.  The shell UI (tray popover / Android Activity) shows the
//! certificate fingerprint and instructions for doing this.
//!
//! TODO: display certificate fingerprint in the shell UI and WebUI.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

// File names for the persisted certificate and key.
const CERT_FILENAME: &str = "webui-cert.pem";
const KEY_FILENAME:  &str = "webui-key.pem";

// ---------------------------------------------------------------------------
// load_or_generate_cert
// ---------------------------------------------------------------------------

/// Load the WebUI TLS certificate from disk, or generate and persist a new one.
///
/// Returns a `TlsAcceptor` ready to wrap TCP connections with TLS.
///
/// # Arguments
///
/// * `data_dir` — path to the directory where the cert and key are stored.
///   The directory must already exist (created by `ClientlessConfig::save()`).
pub fn load_or_generate_cert(data_dir: &str) -> Result<TlsAcceptor> {
    let dir = Path::new(data_dir);
    let cert_path = dir.join(CERT_FILENAME);
    let key_path  = dir.join(KEY_FILENAME);

    let (cert_pem, key_pem) = if cert_path.exists() && key_path.exists() {
        // Load the persisted certificate and key.
        let cert = std::fs::read_to_string(&cert_path)
            .with_context(|| format!("failed to read {}", cert_path.display()))?;
        let key  = std::fs::read_to_string(&key_path)
            .with_context(|| format!("failed to read {}", key_path.display()))?;
        (cert, key)
    } else {
        // First run: generate a new self-signed certificate.
        let (cert, key) = generate_self_signed()
            .context("failed to generate self-signed TLS certificate")?;

        // Persist so we reuse the same certificate across restarts.
        // The shell UI will display this certificate's fingerprint.
        std::fs::write(&cert_path, &cert)
            .with_context(|| format!("failed to write {}", cert_path.display()))?;
        std::fs::write(&key_path, &key)
            .with_context(|| format!("failed to write {}", key_path.display()))?;

        tracing::info!(
            cert = %cert_path.display(),
            "generated new self-signed TLS certificate"
        );

        (cert, key)
    };

    build_tls_acceptor(&cert_pem, &key_pem)
        .context("failed to build TLS acceptor from certificate")
}

// ---------------------------------------------------------------------------
// generate_self_signed
// ---------------------------------------------------------------------------

/// Generate a self-signed ECDSA P-256 certificate for the WebUI HTTPS server.
///
/// Returns `(cert_pem, key_pem)` — both as PEM-encoded strings ready to
/// be written to disk or fed directly to rustls.
fn generate_self_signed() -> Result<(String, String)> {
    // Generate a fresh ECDSA P-256 key pair.
    let key_pair = KeyPair::generate()
        .context("failed to generate ECDSA key pair")?;

    // Build the certificate parameters.
    let mut params = CertificateParams::default();

    // Subject distinguished name — the node name used in the certificate.
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Mesh Infinity Node");
    dn.push(DnType::OrganizationName, "mesh-infinity-clientless");
    params.distinguished_name = dn;

    // Subject Alternative Names — allows the certificate to match both
    // `localhost` and the raw loopback address.
    params.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into().context("invalid SAN: localhost")?),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
    ];

    // 10-year validity window.  Not auto-renewed; deletion + restart rotates.
    params.not_before = rcgen::date_time_ymd(2025, 1, 1);
    params.not_after  = rcgen::date_time_ymd(2035, 1, 1);

    // Self-sign the certificate with its own key pair.
    let cert = params
        .self_signed(&key_pair)
        .context("failed to self-sign certificate")?;

    Ok((cert.pem(), key_pair.serialize_pem()))
}

// ---------------------------------------------------------------------------
// build_tls_acceptor
// ---------------------------------------------------------------------------

/// Build a `TlsAcceptor` from PEM-encoded certificate and private key strings.
fn build_tls_acceptor(cert_pem: &str, key_pem: &str) -> Result<TlsAcceptor> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls_pemfile::{certs, pkcs8_private_keys};

    // Parse the certificate chain from PEM.
    let cert_chain: Vec<CertificateDer<'static>> = {
        let mut reader = std::io::BufReader::new(cert_pem.as_bytes());
        certs(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to parse certificate PEM")?
    };

    // Parse the private key from PEM (PKCS#8 format, which rcgen produces).
    // The key must be extracted into a local binding before the reader is
    // dropped — the iterator borrows the reader, so we collect first.
    let private_key: PrivateKeyDer<'static> = {
        let mut reader = std::io::BufReader::new(key_pem.as_bytes());
        let key = pkcs8_private_keys(&mut reader)
            .next()
            .context("no private key found in PEM")?
            .map(PrivateKeyDer::Pkcs8)
            .context("failed to parse private key PEM")?;
        key   // reader drops here, before key is moved out
    };

    // Build the rustls ServerConfig.
    let config = ServerConfig::builder()
        .with_no_client_auth()           // No mutual TLS; password auth instead.
        .with_single_cert(cert_chain, private_key)
        .context("failed to build rustls ServerConfig")?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}
