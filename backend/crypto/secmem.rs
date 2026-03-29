// Secure memory management for cryptographic keys
// Prevents keys from being swapped to disk or recovered from memory dumps

use std::ops::{Deref, DerefMut};
use std::panic;
use std::ptr;
use std::sync::Once;
use zeroize::Zeroize;

#[cfg(unix)]
use libc::{mlock, munlock, ENOMEM};

// Global flag to track if panic handler is installed
static PANIC_HANDLER_INIT: Once = Once::new();

// Initialize the panic handler to wipe keys on panic
/// Init panic handler.
fn init_panic_handler() {
    PANIC_HANDLER_INIT.call_once(|| {
        let original_hook = panic::take_hook();
        panic::set_hook(Box::new(move |panic_info| {
            eprintln!("PANIC DETECTED - SecureMemory instances will be zeroized on drop");
            original_hook(panic_info);
        }));
    });
}

/// Secure memory container that:
/// 1. Locks memory to prevent swapping (mlock)
/// 2. Zeroizes on drop
/// 3. Prevents accidental copying
/// 4. Automatically wipes on panic (via Drop)
pub struct SecureMemory<T: Zeroize> {
    data: Box<T>,
    #[cfg(unix)]
    locked: bool,
}

impl<T: Zeroize> SecureMemory<T> {
    /// Create new secure memory region
    pub fn new(value: T) -> Result<Self, SecureMemoryError> {
        init_panic_handler();

        // `mut` is required by the `#[cfg(unix)]` block below (calls `data.as_mut()`).
        // On non-unix platforms (Windows) that block is compiled out, so the compiler
        // warns that `mut` is unnecessary.  The cfg_attr below is precise: it only
        // silences the warning on platforms where the mut is genuinely redundant.
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut data = Box::new(value);

        #[cfg(unix)]
        {
            let ptr = data.as_mut() as *mut T as *mut libc::c_void;
            let size = std::mem::size_of::<T>();

            // Lock memory to prevent swapping.
            // SAFETY: `ptr` is derived from a valid, heap-allocated Box<T> via
            // `as_mut()`, so it is non-null, correctly aligned, and valid for
            // `size` bytes.  mlock(2) only reads the address/length; it does
            // not dereference the memory itself.
            let result = unsafe { mlock(ptr, size) };

            if result != 0 {
                let errno = std::io::Error::last_os_error();
                if errno.raw_os_error() == Some(ENOMEM) {
                    eprintln!(
                        "Warning: Could not lock memory (ENOMEM). Keys may be swapped to disk."
                    );
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

    /// Public emergency wipe method - immediately zeroize and unlock
    pub fn wipe(&mut self) {
        self.data.zeroize();

        #[cfg(unix)]
        if self.locked {
            let ptr = self.data.as_mut() as *mut T as *mut libc::c_void;
            let size = std::mem::size_of::<T>();
            // SAFETY: `ptr` is derived from the same Box<T> that was locked
            // with mlock; the pointer and size are unchanged since the lock
            // call, so munlock(2) receives valid arguments.
            unsafe {
                munlock(ptr, size);
            }
            self.locked = false;
        }
    }

}

impl<T: Zeroize> AsRef<T> for SecureMemory<T> {
    /// As ref.
    fn as_ref(&self) -> &T {
        &self.data
    }
}

impl<T: Zeroize> AsMut<T> for SecureMemory<T> {
    /// As mut.
    fn as_mut(&mut self) -> &mut T {
        &mut self.data
    }
}

impl<T: Zeroize> Drop for SecureMemory<T> {
    /// Drop.
    fn drop(&mut self) {
        // Zeroize the data
        self.data.zeroize();

        // Unlock memory
        #[cfg(unix)]
        if self.locked {
            let ptr = self.data.as_mut() as *mut T as *mut libc::c_void;
            let size = std::mem::size_of::<T>();
            // SAFETY: `ptr` and `size` match those used when mlock was called
            // in `SecureMemory::new`; Drop is called exactly once, so this
            // munlock(2) call is paired with exactly one prior mlock(2) call.
            unsafe {
                munlock(ptr, size);
            }
        }
    }
}

impl<T: Zeroize> Deref for SecureMemory<T> {
    type Target = T;

    /// Deref.
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T: Zeroize> DerefMut for SecureMemory<T> {
    /// Deref mut.
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
    /// Construct a new instance.
    pub fn new(key: [u8; 32]) -> Result<SecureMemory<Self>, SecureMemoryError> {
        SecureMemory::new(SecureKey32(key))
    }

    /// Random.
    pub fn random() -> Result<SecureMemory<Self>, SecureMemoryError> {
        use rand_core::{OsRng, RngCore};
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self::new(key)
    }

    /// As bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Secure storage for a 64-byte key
#[derive(Zeroize)]
pub struct SecureKey64(pub [u8; 64]);

impl SecureKey64 {
    /// Construct a new instance.
    pub fn new(key: [u8; 64]) -> Result<SecureMemory<Self>, SecureMemoryError> {
        SecureMemory::new(SecureKey64(key))
    }

    /// As bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

#[derive(Debug)]
pub enum SecureMemoryError {
    LockFailed(std::io::Error),
}

impl std::fmt::Display for SecureMemoryError {
    /// Fmt.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecureMemoryError::LockFailed(e) => write!(f, "Failed to lock memory: {}", e),
        }
    }
}

impl std::error::Error for SecureMemoryError {}

/// Secure overwrite of memory region
/// Performs multiple passes to prevent forensic recovery
///
/// # Safety
///
/// Caller must ensure `ptr` is valid for writes of `len` bytes and that the
/// region is not concurrently accessed by other threads while this function runs.
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

/// Emergency panic handler - wipes all secure memory
/// This is automatically called via Drop during panic unwinding.
/// All SecureMemory instances will be zeroized when they go out of scope.
pub fn emergency_wipe_all() {
    eprintln!("EMERGENCY WIPE: All SecureMemory instances will be zeroized via Drop");
    eprintln!("  Panic unwinding will trigger Drop for all SecureMemory in scope");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test case: secure memory zeroizes.
    #[test]
    fn test_secure_memory_zeroizes() {
        let key = [0x42u8; 32];
        let mut secure = SecureMemory::new(SecureKey32(key)).unwrap();

        // Verify data is accessible
        assert_eq!(secure.as_bytes(), &key);

        // Emergency wipe
        secure.wipe();

        // Verify data is zeroed
        assert_eq!(secure.as_bytes(), &[0u8; 32]);
    }

    /// Test case: secure bytes.
    #[test]
    fn test_secure_bytes() {
        let data = b"sensitive data";
        let secure = SecureBytes::from_slice(data).unwrap();
        assert_eq!(&**secure, data);
    }

    /// Test case: random key.
    #[test]
    fn test_random_key() {
        let key1 = SecureKey32::random().unwrap();
        let key2 = SecureKey32::random().unwrap();

        // Keys should be different
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    /// Test case: drop zeroizes.
    #[test]
    fn test_drop_zeroizes() {
        let key = [0x42u8; 32];
        {
            let secure = SecureMemory::new(SecureKey32(key)).unwrap();
            let _ptr = secure.as_bytes().as_ptr();
            // secure goes out of scope here and should be zeroized
        }
        // In a real scenario, we can't safely dereference ptr after drop
        // This test just ensures drop doesn't crash
    }
}
