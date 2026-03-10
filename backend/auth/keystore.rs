//! Platform keystore integration for identity key material.

use crate::core::error::{MeshInfinityError, Result};

#[cfg(target_os = "android")]
mod android {
    use super::{MeshInfinityError, Result};
    use jni::objects::{JByteArray, JClass, JValue};
    use jni::sys::{jint, jsize, JavaVM as SysJavaVM, JNI_GetCreatedJavaVMs};
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

    fn with_env<T>(f: impl FnOnce(&JNIEnv) -> Result<T>) -> Result<T> {
        let vm = get_vm()?;
        let env = unsafe { (&*vm).attach_current_thread() }
            .map_err(|e| MeshInfinityError::CryptoError(format!("JNI attach failed: {}", e)))?;
        f(&env)
    }

    fn call_static_wrap(env: &JNIEnv, method: &str, input: &[u8]) -> Result<Vec<u8>> {
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
                &[JValue::from(JByteArray::from(input_array))],
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

    fn call_static_delete(env: &JNIEnv) -> Result<()> {
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

#[cfg(not(target_os = "android"))]
pub fn wrap_key_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
    Ok(bytes.to_vec())
}

#[cfg(not(target_os = "android"))]
pub fn unwrap_key_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
    Ok(bytes.to_vec())
}

#[cfg(not(target_os = "android"))]
pub fn delete_key_alias() -> Result<()> {
    Ok(())
}
