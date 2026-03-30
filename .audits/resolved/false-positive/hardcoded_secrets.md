## Resolution Status: FALSE POSITIVE

# Hardcoded Secrets Audit Findings

## Summary
- **Severity**: Critical
- **Affected Files**: 8
- **Critical Issues**: 5
- **High Risk**: 2
- **Medium Risk**: 1

## Detailed Findings

### 1. Peer ID Derivation Salt
- **File**: backend/identity/peer_id.rs:4-6
- **Line**: 5
- **Issue**: Hardcoded SHA-256 salt `"meshinfinity-peer-id-v1"` used for peer ID derivation
- **Risk**: Predictable peer IDs enable targeted attacks and network mapping
- **Impact**: An attacker can precompute peer IDs or correlate identities across networks
- **Mitigation**: Use per-deployment random salt stored in secure configuration
- **Code Reference**:
```rust
//! peer_id = SHA-256("meshinfinity-peer-id-v1" || ed25519_public_key_bytes)
```

### 2. Test Key Material in Production Code
- **File**: backend/identity/killswitch.rs:582-588
- **Lines**: 582, 587, 588
- **Issue**: Hardcoded test keys in killswitch test fixtures
```rust
fs::write(dir.path().join("identity.key"), [0x42u8; 32]).unwrap();
fs::write(dir.path().join("peers.vault"), b"encrypted peers").unwrap();
fs::write(dir.path().join("mesh_identity.key"), [0x01u8; 32]).unwrap();
```
- **Risk**: Test secrets could be accidentally deployed to production
- **Mitigation**: Separate test fixtures from production code; use test-only modules

### 3. Hardcoded Device Tokens
- **File**: backend/notifications/mod.rs:895-896, 1015-1016
- **Lines**: 895-896, 1015-1016
- **Issue**: Hardcoded test device tokens in notification tests
```rust
device_token: vec![0x01; 32],
device_token: vec![0xAB; 32],
```
- **Risk**: Test data could be mistaken for real tokens
- **Mitigation**: Use generated test tokens with clear naming

### 4. Hardcoded Signing Keys for Testing
- **File**: backend/announcement.rs:854-857, 1031-1046
- **Lines**: 854-857, 1031-1046
- **Issue**: Test uses hardcoded secret `[dest; 32]` for signing
```rust
let secret = [dest; 32];
let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
```
- **Risk**: Weak test keys could be confused with production keys
- **Mitigation**: Use proper key generation in tests, never hardcoded secrets

### 5. Hardcoded Relay Test Keys
- **File**: backend/routing/relay.rs:1153-1156, 1183-1186
- **Lines**: 1153-1156, 1183-1186
- **Issue**: Hardcoded test key `[0x55u8; 32]` for relay signature tests
```rust
let raw_key = [0x55u8; 32];
let signing_key = SigningKey::from_bytes(&raw_key);
```
- **Risk**: Test key material in codebase increases attack surface
- **Mitigation**: Generate test keys at runtime with clear documentation

### 6. Hardcoded Network Map Test Keys
- **File**: backend/network/map.rs:1084-1088, 1113-1117, 1142-1146
- **Lines**: 1084-1088, 1113-1117, 1142-1146
- **Issue**: Multiple hardcoded test keys in unit tests
```rust
let raw_key = [0x7au8; 32];
let raw_key = [0x3bu8; 32];
```
- **Risk**: Accumulation of hardcoded secrets in test code
- **Mitigation**: Implement test-only key generation utilities

### 7. Hardcoded Pairing Token
- **File**: backend/pairing/methods.rs:595-597
- **Lines**: 595-597
- **Issue**: Test uses hardcoded pairing token `[0x44; 32]`
```rust
pairing_token: [0x44; 32],
```
- **Risk**: Predictable test tokens could weaken test isolation
- **Mitigation**: Generate random tokens for each test run

### 8. Hardcoded SDR Hop Keys
- **File**: backend/transport/rf_sdr.rs:914-927, 995-1007
- **Lines**: 914-927, 995-1007
- **Issue**: Hardcoded hop keys in SDR transport profiles
```rust
hop_key,
```
- **Risk**: If hop keys are static, compromises forward secrecy
- **Mitigation**: Derive hop keys from session keys dynamically

## Recommendations

### Immediate Actions
1. **Remove all hardcoded secrets from production code paths**
2. **Implement secret management system** using platform keystore/secure enclave
3. **Add CI/CD checks** to detect hardcoded secrets before merge
4. **Separate test fixtures** into dedicated test-only modules with clear naming

### Long-term Improvements
1. **Adopt secret scanning tools** (truffleHog, git-secrets) in pre-commit hooks
2. **Implement secret rotation policies** for all cryptographic material
3. **Use environment-specific configuration** with secure defaults
4. **Add code review checklist item** for hardcoded secrets
5. **Conduct regular security audits** focusing on secret management

### Code Changes Required

#### Example Fix for Peer ID Derivation
```rust
// Before (backend/identity/peer_id.rs:4-6)
//! peer_id = SHA-256("meshinfinity-peer-id-v1" || ed25519_public_key_bytes)

// After - use per-deployment salt
use once_cell::sync::Lazy;
static PEER_ID_SALT: Lazy<[u8; 32]> = Lazy::new(|| {
    // Load from secure configuration or generate on first run
    // Stored in platform keystore with AfterFirstUnlock protection
    load_or_generate_salt()
});

//! peer_id = SHA-256(PEER_ID_SALT || ed25519_public_key_bytes)
```

#### Example Fix for Test Keys
```rust
// Before (backend/identity/killswitch.rs:582)
fs::write(dir.path().join("identity.key"), [0x42u8; 32]).unwrap();

// After - use test-only key generator
#[cfg(test)]
mod test_utils {
    use rand::RngCore;
    pub fn generate_test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }
}

// In test
fs::write(dir.path().join("identity.key"), test_utils::generate_test_key()).unwrap();
```

## Severity Justification

- **Critical**: Hardcoded secrets in cryptographic contexts (peer ID salt, test keys)
- **High**: Configuration hardcoding that could lead to security bypasses
- **Medium**: Test-only hardcoded values that could leak into production

## Compliance Notes

This audit aligns with:
- OWASP Top 10: A02:2021 – Cryptographic Failures
- OWASP Top 10: A05:2021 – Security Misconfiguration
- CWE-798: Use of Hard-coded Credentials
- CWE-259: Use of Hard-coded Password

## Status
[x] Initial audit completed
[x] All findings documented with file:line references
[x] Mitigation strategies provided
[-] Awaiting implementation of fixes
[-] Verification testing required