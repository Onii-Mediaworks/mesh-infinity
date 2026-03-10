//! Platform keystore integration for identity key material.

use crate::core::error::{MeshInfinityError, Result};

#[cfg(target_os = "android")]
mod android {
    use super::{MeshInfinityError, Result};
    use jni::objects::{JByteArray, JClass, JValue};
    use jni::sys::{jsize, JavaVM as SysJavaVM, JNI_GetCreatedJavaVMs};
    use jni::{JNIEnv, JavaVM};

    const KEYSTORE_CLASS: &str = "com/oniimediaworks/meshinfinity/KeystoreBridge";

    fn get_vm() -> Result<std::mem::ManuallyDrop<JavaVM>> {
        let mut vm: *mut SysJavaVM = std::ptr::null_mut();
        let mut count: jsize = 0;
        let status = unsafe { JNI_GetCreatedJavaVMs(&mut vm, 1, &mut count) };
        if status != 0 || count < 1 || vm.is_null() {
            return Err(MeshInfinityError::CryptoError(
                "Android JVM not available for keystore operations".to_string(),
            ));
        }
        let java_vm = unsafe { JavaVM::from_raw(vm) }.map_err(|e| {
            MeshInfinityError::CryptoError(format!(
                "Failed to access Android JVM for keystore: {}",
                e
            ))
        })?;
        Ok(std::mem::ManuallyDrop::new(java_vm))
    }

    fn with_env<T>(f: impl FnOnce(&mut JNIEnv) -> Result<T>) -> Result<T> {
        let vm = get_vm()?;
        let mut env = vm
            .attach_current_thread()
            .map_err(|e| MeshInfinityError::CryptoError(format!("JNI attach failed: {}", e)))?;
        f(&mut env)
    }

    fn call_static_wrap(env: &mut JNIEnv, method: &str, input: &[u8]) -> Result<Vec<u8>> {
        let class: JClass = env
            .find_class(KEYSTORE_CLASS)
            .map_err(|e| MeshInfinityError::CryptoError(format!("JNI class lookup failed: {}", e)))?;
        let input_array = env
            .byte_array_from_slice(input)
            .map_err(|e| MeshInfinityError::CryptoError(format!("JNI byte array failed: {}", e)))?;
        let output = env
            .call_static_method(
                class,
                method,
                "([B)[B",
                &[JValue::Object(&*input_array)],
            )
            .map_err(|e| MeshInfinityError::CryptoError(format!("JNI call failed: {}", e)))?
            .l()
            .map_err(|e| MeshInfinityError::CryptoError(format!("JNI return failed: {}", e)))?;
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_describe();
            let _ = env.exception_clear();
            return Err(MeshInfinityError::CryptoError(
                "Android keystore raised exception".to_string(),
            ));
        }
        let output_array = JByteArray::from(output);
        let bytes = env
            .convert_byte_array(output_array)
            .map_err(|e| MeshInfinityError::CryptoError(format!("JNI read bytes failed: {}", e)))?;
        Ok(bytes)
    }

    fn call_static_delete(env: &mut JNIEnv) -> Result<()> {
        let class: JClass = env
            .find_class(KEYSTORE_CLASS)
            .map_err(|e| MeshInfinityError::CryptoError(format!("JNI class lookup failed: {}", e)))?;
        let result = env
            .call_static_method(class, "deleteKey", "()Z", &[])
            .map_err(|e| MeshInfinityError::CryptoError(format!("JNI call failed: {}", e)))?
            .z()
            .map_err(|e| MeshInfinityError::CryptoError(format!("JNI return failed: {}", e)))?;
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_describe();
            let _ = env.exception_clear();
            return Err(MeshInfinityError::CryptoError(
                "Android keystore raised exception".to_string(),
            ));
        }
        if !result {
            return Err(MeshInfinityError::CryptoError(
                "Android keystore delete returned false".to_string(),
            ));
        }
        Ok(())
    }

    pub fn wrap_key(bytes: &[u8]) -> Result<Vec<u8>> {
        with_env(|env| call_static_wrap(env, "wrapKey", bytes))
    }

    pub fn unwrap_key(bytes: &[u8]) -> Result<Vec<u8>> {
        with_env(|env| call_static_wrap(env, "unwrapKey", bytes))
    }

    pub fn delete_key() -> Result<()> {
        with_env(call_static_delete)
    }
}

#[cfg(target_os = "android")]
pub fn wrap_key_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
    android::wrap_key(bytes)
}

#[cfg(target_os = "android")]
pub fn unwrap_key_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
    android::unwrap_key(bytes)
}

#[cfg(target_os = "android")]
pub fn delete_key_alias() -> Result<()> {
    android::delete_key()
}

// ── Non-Android: platform keyring (macOS Keychain / iOS Keychain /
//    Windows Credential Manager / Linux Secret Service) ──────────────────────
//
// The raw 32-byte encryption key is stored directly as a binary secret inside
// the platform keystore.  On Linux, if the Secret Service daemon is not
// reachable (e.g. headless server), the functions return an error and the
// caller (persistence.rs) falls back to a 0600-restricted filesystem file.

#[cfg(not(target_os = "android"))]
const KEYRING_SERVICE: &str = "mesh-infinity";
#[cfg(not(target_os = "android"))]
const KEYRING_USER: &str = "identity-key";

/// Store `key` bytes in the platform keystore.
///
/// Returns an error if the keystore is unavailable (e.g. headless Linux
/// without Secret Service); callers should fall back to a restricted file.
#[cfg(not(target_os = "android"))]
pub fn store_key(key: &[u8]) -> Result<()> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .map_err(|e| MeshInfinityError::CryptoError(format!("keyring init: {e}")))?;
    entry
        .set_secret(key)
        .map_err(|e| MeshInfinityError::CryptoError(format!("keyring store: {e}")))
}

/// Load the key bytes from the platform keystore.
///
/// Returns an error if the keystore is unavailable or the entry does not exist.
#[cfg(not(target_os = "android"))]
pub fn load_key() -> Result<Vec<u8>> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .map_err(|e| MeshInfinityError::CryptoError(format!("keyring init: {e}")))?;
    entry
        .get_secret()
        .map_err(|e| MeshInfinityError::CryptoError(format!("keyring load: {e}")))
}

/// Returns `true` if the platform keystore holds an identity key entry.
#[cfg(not(target_os = "android"))]
pub fn key_in_keystore() -> bool {
    keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .ok()
        .and_then(|e| e.get_secret().ok())
        .is_some()
}

/// Remove the identity key entry from the platform keystore.
///
/// This is the critical first step of the emergency destroy sequence — once
/// deleted, the `identity.dat` ciphertext becomes permanently unreadable.
/// Ignores "entry not found" errors so the destroy path is always idempotent.
#[cfg(not(target_os = "android"))]
pub fn delete_key() -> Result<()> {
    if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER) {
        // Ignore errors: the entry may already be absent.
        let _ = entry.delete_credential();
    }
    Ok(())
}
