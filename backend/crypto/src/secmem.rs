// Secure memory management for cryptographic keys
// Prevents keys from being swapped to disk or recovered from memory dumps

use std::ops::{Deref, DerefMut};
use std::ptr;
use zeroize::Zeroize;

#[cfg(unix)]
use libc::{mlock, munlock, ENOMEM};

/// Secure memory container that:
/// 1. Locks memory to prevent swapping (mlock)
/// 2. Zeroizes on drop
/// 3. Prevents accidental copying
pub struct SecureMemory<T: Zeroize> {
    data: Box<T>,
    #[cfg(unix)]
    locked: bool,
}

impl<T: Zeroize> SecureMemory<T> {
    /// Create new secure memory region
    pub fn new(value: T) -> Result<Self, SecureMemoryError> {
        let mut data = Box::new(value);

        #[cfg(unix)]
        {
            let ptr = data.as_mut() as *mut T as *mut libc::c_void;
            let size = std::mem::size_of::<T>();

            // Lock memory to prevent swapping
            let result = unsafe { mlock(ptr, size) };

            if result != 0 {
                let errno = std::io::Error::last_os_error();
                if errno.raw_os_error() == Some(ENOMEM) {
                    eprintln!("Warning: Could not lock memory (ENOMEM). Keys may be swapped to disk.");
                    return Ok(Self {
                        data,
                        locked: false,
                    });
                }
                return Err(SecureMemoryError::LockFailed(errno));
            }

            Ok(Self { data, locked: true })
        }

        #[cfg(not(unix))]
        {
            // On non-Unix platforms, we can't mlock, but still provide zeroization
            eprintln!("Warning: Memory locking not available on this platform");
            Ok(Self { data })
        }
    }

    /// Emergency wipe - immediately zeroize and unlock
    pub fn emergency_wipe(&mut self) {
        self.data.zeroize();

        #[cfg(unix)]
        if self.locked {
            let ptr = self.data.as_mut() as *mut T as *mut libc::c_void;
            let size = std::mem::size_of::<T>();
            unsafe {
                munlock(ptr, size);
            }
            self.locked = false;
        }
    }

    /// Get a reference to the data
    /// Warning: Be careful not to copy the data
    pub fn as_ref(&self) -> &T {
        &self.data
    }

    /// Get a mutable reference to the data
    pub fn as_mut(&mut self) -> &mut T {
        &mut self.data
    }
}

impl<T: Zeroize> Drop for SecureMemory<T> {
    fn drop(&mut self) {
        // Zeroize the data
        self.data.zeroize();

        // Unlock memory
        #[cfg(unix)]
        if self.locked {
            let ptr = self.data.as_mut() as *mut T as *mut libc::c_void;
            let size = std::mem::size_of::<T>();
            unsafe {
                munlock(ptr, size);
            }
        }
    }
}

impl<T: Zeroize> Deref for SecureMemory<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T: Zeroize> DerefMut for SecureMemory<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

/// Secure byte array specifically for cryptographic keys
pub type SecureBytes = SecureMemory<Vec<u8>>;

impl SecureBytes {
    /// Create from a slice, copying the data into secure memory
    pub fn from_slice(slice: &[u8]) -> Result<Self, SecureMemoryError> {
        Self::new(slice.to_vec())
    }

    /// Create with specific size, filled with zeros
    pub fn zeros(size: usize) -> Result<Self, SecureMemoryError> {
        Self::new(vec![0u8; size])
    }
}

/// Secure storage for a 32-byte key
#[derive(Zeroize)]
pub struct SecureKey32(pub [u8; 32]);

impl SecureKey32 {
    pub fn new(key: [u8; 32]) -> Result<SecureMemory<Self>, SecureMemoryError> {
        SecureMemory::new(SecureKey32(key))
    }

    pub fn random() -> Result<SecureMemory<Self>, SecureMemoryError> {
        use rand_core::{OsRng, RngCore};
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self::new(key)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Secure storage for a 64-byte key
#[derive(Zeroize)]
pub struct SecureKey64(pub [u8; 64]);

impl SecureKey64 {
    pub fn new(key: [u8; 64]) -> Result<SecureMemory<Self>, SecureMemoryError> {
        SecureMemory::new(SecureKey64(key))
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

#[derive(Debug)]
pub enum SecureMemoryError {
    LockFailed(std::io::Error),
}

impl std::fmt::Display for SecureMemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecureMemoryError::LockFailed(e) => write!(f, "Failed to lock memory: {}", e),
        }
    }
}

impl std::error::Error for SecureMemoryError {}

/// Secure overwrite of memory region
/// Performs multiple passes to prevent forensic recovery
pub unsafe fn secure_overwrite(ptr: *mut u8, len: usize) {
    if len == 0 {
        return;
    }

    // Pass 1: Write zeros
    ptr::write_bytes(ptr, 0x00, len);

    // Pass 2: Write ones
    ptr::write_bytes(ptr, 0xFF, len);

    // Pass 3: Write zeros again
    ptr::write_bytes(ptr, 0x00, len);

    // Compiler fence to prevent optimization
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Emergency panic handler - wipes all registered secure memory
/// Call this during panic or emergency shutdown
pub fn emergency_wipe_all() {
    // In a full implementation, this would track all SecureMemory instances
    // and wipe them during panic
    // For now, this is a placeholder for the panic handler integration
    eprintln!("EMERGENCY WIPE TRIGGERED");
    // Individual SecureMemory instances will be zeroized on drop
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_memory_zeroizes() {
        let key = [0x42u8; 32];
        let mut secure = SecureMemory::new(SecureKey32(key)).unwrap();

        // Verify data is accessible
        assert_eq!(secure.as_bytes(), &key);

        // Emergency wipe
        secure.emergency_wipe();

        // Verify data is zeroed
        assert_eq!(secure.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_secure_bytes() {
        let data = b"sensitive data";
        let secure = SecureBytes::from_slice(data).unwrap();
        assert_eq!(&**secure, data);
    }

    #[test]
    fn test_random_key() {
        let key1 = SecureKey32::random().unwrap();
        let key2 = SecureKey32::random().unwrap();

        // Keys should be different
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }
}
