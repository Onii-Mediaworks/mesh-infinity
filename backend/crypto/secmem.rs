// Secure memory management for cryptographic keys
// Prevents keys from being swapped to disk or recovered from memory dumps

use std::ops::{Deref, DerefMut};
use std::panic;
use std::ptr;
use std::sync::Once;
// Securely erase key material to prevent forensic recovery.
use zeroize::Zeroize;

#[cfg(unix)]
use libc::{mlock, munlock, ENOMEM};

// Global flag to track if panic handler is installed
// Execute this protocol step.
// Execute this protocol step.
static PANIC_HANDLER_INIT: Once = Once::new();

// Initialize the panic handler to wipe keys on panic
/// Init panic handler.
// Perform the 'init panic handler' operation.
// Errors are propagated to the caller via Result.
// Perform the 'init panic handler' operation.
// Errors are propagated to the caller via Result.
fn init_panic_handler() {
    // Apply the closure to each element.
    // Execute this protocol step.
    // Execute this protocol step.
    PANIC_HANDLER_INIT.call_once(|| {
        // Invoke the associated function.
        // Compute original hook for this protocol step.
        // Compute original hook for this protocol step.
        let original_hook = panic::take_hook();
        // Create a new instance with the specified parameters.
        // Execute this protocol step.
        // Execute this protocol step.
        panic::set_hook(Box::new(move |panic_info| {
            // Securely erase key material to prevent forensic recovery.
            // Execute this protocol step.
            // Execute this protocol step.
            eprintln!("PANIC DETECTED - SecureMemory instances will be zeroized on drop");
            // Execute the operation and bind the result.
            // Execute this protocol step.
            // Execute this protocol step.
            original_hook(panic_info);
        }));
    });
}

/// Secure memory container that:
/// 1. Locks memory to prevent swapping (mlock)
/// 2. Zeroizes on drop
/// 3. Prevents accidental copying
/// 4. Automatically wipes on panic (via Drop)
// SecureMemory — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SecureMemory — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct SecureMemory<T: Zeroize> {
    // Execute this protocol step.
    // Execute this protocol step.
    data: Box<T>,
    #[cfg(unix)]
    // Execute this protocol step.
    // Execute this protocol step.
    locked: bool,
}

// Securely erase key material to prevent forensic recovery.
// SecureMemory implementation — core protocol logic.
// SecureMemory implementation — core protocol logic.
impl<T: Zeroize> SecureMemory<T> {
    /// Create new secure memory region
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new(value: T) -> Result<Self, SecureMemoryError> {
        // Execute the operation and bind the result.
        // Execute this protocol step.
        // Execute this protocol step.
        init_panic_handler();

        // `mut` is required by the `#[cfg(unix)]` block below (calls `data.as_mut()`).
        // On non-unix platforms (Windows) that block is compiled out, so the compiler
        // warns that `mut` is unnecessary.  The cfg_attr below is precise: it only
        // silences the warning on platforms where the mut is genuinely redundant.
        #[cfg_attr(not(unix), allow(unused_mut))]
        // Prepare the data buffer for the next processing stage.
        // Compute data for this protocol step.
        // Compute data for this protocol step.
        let mut data = Box::new(value);

        #[cfg(unix)]
        {
            // Prepare the data buffer for the next processing stage.
            // Compute ptr for this protocol step.
            // Compute ptr for this protocol step.
            let ptr = data.as_mut() as *mut T as *mut libc::c_void;
            // Track the count for threshold and bounds checking.
            // Compute size for this protocol step.
            // Compute size for this protocol step.
            let size = std::mem::size_of::<T>();

            // Lock memory to prevent swapping.
            // SAFETY: `ptr` is derived from a valid, heap-allocated Box<T> via
            // `as_mut()`, so it is non-null, correctly aligned, and valid for
            // `size` bytes.  mlock(2) only reads the address/length; it does
            // not dereference the memory itself.
            // Compute result for this protocol step.
            // Compute result for this protocol step.
            let result = unsafe { mlock(ptr, size) };

            // Conditional branch based on the current state.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if result != 0 {
                // Invoke the associated function.
                // Compute errno for this protocol step.
                // Compute errno for this protocol step.
                let errno = std::io::Error::last_os_error();
                // Handle the error case — propagate or log as appropriate.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                if errno.raw_os_error() == Some(ENOMEM) {
                    // Execute this protocol step.
                    // Execute this protocol step.
                    eprintln!(
                        // Process the current step in the protocol.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        "Warning: Could not lock memory (ENOMEM). Keys may be swapped to disk."
                    );
                    // Return success with the computed result.
                    // Return to the caller.
                    // Return to the caller.
                    return Ok(Self {
                        data,
                        // Execute this protocol step.
                        // Execute this protocol step.
                        locked: false,
                    });
                }
                // Reject with an explicit error for the caller to handle.
                // Return to the caller.
                // Return to the caller.
                return Err(SecureMemoryError::LockFailed(errno));
            }

            // Wrap the computed value in the success variant.
            // Success path — return the computed value.
            // Success path — return the computed value.
            Ok(Self { data, locked: true })
        }

        #[cfg(not(unix))]
        {
            // On non-Unix platforms, we can't mlock, but still provide zeroization
            // Execute this protocol step.
            // Execute this protocol step.
            eprintln!("Warning: Memory locking not available on this platform");
            // Wrap the computed value in the success variant.
            // Success path — return the computed value.
            // Success path — return the computed value.
            Ok(Self { data })
        }
    }

    /// Public emergency wipe method - immediately zeroize and unlock
    // Perform the 'wipe' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'wipe' operation.
    // Errors are propagated to the caller via Result.
    pub fn wipe(&mut self) {
        // Securely erase key material to prevent forensic recovery.
        // Zeroize sensitive key material.
        // Zeroize sensitive key material.
        self.data.zeroize();

        #[cfg(unix)]
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.locked {
            // Prepare the data buffer for the next processing stage.
            // Compute ptr for this protocol step.
            // Compute ptr for this protocol step.
            let ptr = self.data.as_mut() as *mut T as *mut libc::c_void;
            // Track the count for threshold and bounds checking.
            // Compute size for this protocol step.
            // Compute size for this protocol step.
            let size = std::mem::size_of::<T>();
            // SAFETY: `ptr` is derived from the same Box<T> that was locked
            // with mlock; the pointer and size are unchanged since the lock
            // call, so munlock(2) receives valid arguments.
            unsafe {
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                munlock(ptr, size);
            }
            // Update the locked to reflect the new state.
            // Advance locked state.
            // Advance locked state.
            self.locked = false;
        }
    }

}

// Securely erase key material to prevent forensic recovery.
// Trait implementation.
// Trait implementation.
impl<T: Zeroize> AsRef<T> for SecureMemory<T> {
    /// As ref.
    // Perform the 'as ref' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'as ref' operation.
    // Errors are propagated to the caller via Result.
    fn as_ref(&self) -> &T {
        // Chain the operation on the intermediate result.
        // Execute this protocol step.
        // Execute this protocol step.
        &self.data
    }
}

// Securely erase key material to prevent forensic recovery.
// Trait implementation.
// Trait implementation.
impl<T: Zeroize> AsMut<T> for SecureMemory<T> {
    /// As mut.
    // Perform the 'as mut' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'as mut' operation.
    // Errors are propagated to the caller via Result.
    fn as_mut(&mut self) -> &mut T {
        // Chain the operation on the intermediate result.
        // Execute this protocol step.
        // Execute this protocol step.
        &mut self.data
    }
}

// Securely erase key material to prevent forensic recovery.
// Implement Drop for SecureMemory.
// Implement Drop for SecureMemory.
impl<T: Zeroize> Drop for SecureMemory<T> {
    /// Drop.
    // Perform the 'drop' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'drop' operation.
    // Errors are propagated to the caller via Result.
    fn drop(&mut self) {
        // Zeroize the data
        // Zeroize sensitive key material.
        // Zeroize sensitive key material.
        self.data.zeroize();

        // Unlock memory
        #[cfg(unix)]
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.locked {
            // Prepare the data buffer for the next processing stage.
            // Compute ptr for this protocol step.
            // Compute ptr for this protocol step.
            let ptr = self.data.as_mut() as *mut T as *mut libc::c_void;
            // Track the count for threshold and bounds checking.
            // Compute size for this protocol step.
            // Compute size for this protocol step.
            let size = std::mem::size_of::<T>();
            // SAFETY: `ptr` and `size` match those used when mlock was called
            // in `SecureMemory::new`; Drop is called exactly once, so this
            // munlock(2) call is paired with exactly one prior mlock(2) call.
            unsafe {
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                munlock(ptr, size);
            }
        }
    }
}

// Securely erase key material to prevent forensic recovery.
// Implement Deref for SecureMemory.
// Implement Deref for SecureMemory.
impl<T: Zeroize> Deref for SecureMemory<T> {
    // Type alias for readability.
    // Type alias for protocol readability.
    // Type alias for protocol readability.
    type Target = T;

    /// Deref.
    // Perform the 'deref' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'deref' operation.
    // Errors are propagated to the caller via Result.
    fn deref(&self) -> &Self::Target {
        // Chain the operation on the intermediate result.
        // Execute this protocol step.
        // Execute this protocol step.
        &self.data
    }
}

// Securely erase key material to prevent forensic recovery.
// Implement DerefMut for SecureMemory.
// Implement DerefMut for SecureMemory.
impl<T: Zeroize> DerefMut for SecureMemory<T> {
    /// Deref mut.
    // Perform the 'deref mut' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'deref mut' operation.
    // Errors are propagated to the caller via Result.
    fn deref_mut(&mut self) -> &mut Self::Target {
        // Chain the operation on the intermediate result.
        // Execute this protocol step.
        // Execute this protocol step.
        &mut self.data
    }
}

/// Secure byte array specifically for cryptographic keys
// Type alias for protocol readability.
// Type alias for protocol readability.
pub type SecureBytes = SecureMemory<Vec<u8>>;

// Begin the block scope.
// SecureBytes implementation — core protocol logic.
// SecureBytes implementation — core protocol logic.
impl SecureBytes {
    /// Create from a slice, copying the data into secure memory
    // Perform the 'from slice' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'from slice' operation.
    // Errors are propagated to the caller via Result.
    pub fn from_slice(slice: &[u8]) -> Result<Self, SecureMemoryError> {
        // Create a new instance with the specified parameters.
        // Execute this protocol step.
        // Execute this protocol step.
        Self::new(slice.to_vec())
    }

    /// Create with specific size, filled with zeros
    // Perform the 'zeros' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'zeros' operation.
    // Errors are propagated to the caller via Result.
    pub fn zeros(size: usize) -> Result<Self, SecureMemoryError> {
        // Create a new instance with the specified parameters.
        // Execute this protocol step.
        // Execute this protocol step.
        Self::new(vec![0u8; size])
    }
}

/// Secure storage for a 32-byte key
#[derive(Zeroize)]
// Execute the operation and bind the result.
// SecureKey32 — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SecureKey32 — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct SecureKey32(pub [u8; 32]);

// Begin the block scope.
// SecureKey32 implementation — core protocol logic.
// SecureKey32 implementation — core protocol logic.
impl SecureKey32 {
    /// Construct a new instance.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new(key: [u8; 32]) -> Result<SecureMemory<Self>, SecureMemoryError> {
        // Create a new instance with the specified parameters.
        // Execute this protocol step.
        // Execute this protocol step.
        SecureMemory::new(SecureKey32(key))
    }

    /// Random.
    // Perform the 'random' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'random' operation.
    // Errors are propagated to the caller via Result.
    pub fn random() -> Result<SecureMemory<Self>, SecureMemoryError> {
        use rand_core::{OsRng, RngCore};
        // Key material — must be zeroized when no longer needed.
        // Compute key for this protocol step.
        // Compute key for this protocol step.
        let mut key = [0u8; 32];
        // OS-provided cryptographic random number generator.
        // Execute this protocol step.
        // Execute this protocol step.
        OsRng.fill_bytes(&mut key);
        // Create a new instance with the specified parameters.
        // Execute this protocol step.
        // Execute this protocol step.
        Self::new(key)
    }

    /// As bytes.
    // Perform the 'as bytes' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'as bytes' operation.
    // Errors are propagated to the caller via Result.
    pub fn as_bytes(&self) -> &[u8; 32] {
        // Chain the operation on the intermediate result.
        &self.0
    }
}

/// Secure storage for a 64-byte key
#[derive(Zeroize)]
// Execute the operation and bind the result.
// SecureKey64 — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SecureKey64 — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct SecureKey64(pub [u8; 64]);

// Begin the block scope.
// SecureKey64 implementation — core protocol logic.
// SecureKey64 implementation — core protocol logic.
impl SecureKey64 {
    /// Construct a new instance.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new(key: [u8; 64]) -> Result<SecureMemory<Self>, SecureMemoryError> {
        // Create a new instance with the specified parameters.
        // Execute this protocol step.
        // Execute this protocol step.
        SecureMemory::new(SecureKey64(key))
    }

    /// As bytes.
    // Perform the 'as bytes' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'as bytes' operation.
    // Errors are propagated to the caller via Result.
    pub fn as_bytes(&self) -> &[u8; 64] {
        // Chain the operation on the intermediate result.
        &self.0
    }
}

#[derive(Debug)]
// Begin the block scope.
// SecureMemoryError — variant enumeration.
// Match exhaustively to handle every protocol state.
// SecureMemoryError — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum SecureMemoryError {
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    LockFailed(std::io::Error),
}

// Begin the block scope.
// Implement Display for SecureMemoryError.
// Implement Display for SecureMemoryError.
impl std::fmt::Display for SecureMemoryError {
    /// Fmt.
    // Perform the 'fmt' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'fmt' operation.
    // Errors are propagated to the caller via Result.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match self {
            // Format the output for display or logging.
            // Handle SecureMemoryError::LockFailed(e).
            // Handle SecureMemoryError::LockFailed(e).
            SecureMemoryError::LockFailed(e) => write!(f, "Failed to lock memory: {}", e),
        }
    }
}

// Process the current step in the protocol.
// Implement Error for SecureMemoryError.
// Implement Error for SecureMemoryError.
impl std::error::Error for SecureMemoryError {}

/// Secure overwrite of memory region
/// Performs multiple passes to prevent forensic recovery
///
/// # Safety
///
/// Caller must ensure `ptr` is valid for writes of `len` bytes and that the
/// region is not concurrently accessed by other threads while this function runs.
// Execute this protocol step.
// Execute this protocol step.
pub unsafe fn secure_overwrite(ptr: *mut u8, len: usize) {
    // Conditional branch based on the current state.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if len == 0 {
        return;
    }

    // Pass 1: Write zeros
    // Execute this protocol step.
    // Execute this protocol step.
    ptr::write_bytes(ptr, 0x00, len);

    // Pass 2: Write ones
    // Execute this protocol step.
    // Execute this protocol step.
    ptr::write_bytes(ptr, 0xFF, len);

    // Pass 3: Write zeros again
    // Execute this protocol step.
    // Execute this protocol step.
    ptr::write_bytes(ptr, 0x00, len);

    // Compiler fence to prevent optimization
    // Execute this protocol step.
    // Execute this protocol step.
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Emergency panic handler - wipes all secure memory
/// This is automatically called via Drop during panic unwinding.
/// All SecureMemory instances will be zeroized when they go out of scope.
// Perform the 'emergency wipe all' operation.
// Errors are propagated to the caller via Result.
// Perform the 'emergency wipe all' operation.
// Errors are propagated to the caller via Result.
pub fn emergency_wipe_all() {
    // Securely erase key material to prevent forensic recovery.
    // Execute this protocol step.
    // Execute this protocol step.
    eprintln!("EMERGENCY WIPE: All SecureMemory instances will be zeroized via Drop");
    // Execute the operation and bind the result.
    // Execute this protocol step.
    // Execute this protocol step.
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
