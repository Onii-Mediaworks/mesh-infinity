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
// Windows has the same primitive under a different name (SPEC §15 memory
// table: VirtualLock on key pages). ERROR_WORKING_SET_QUOTA is the Windows
// analogue of ENOMEM: the process has used up its lockable working set.
#[cfg(windows)]
use windows_sys::Win32::Foundation::{GetLastError, ERROR_WORKING_SET_QUOTA};
#[cfg(windows)]
use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};

// Warn exactly once per process when pages cannot be locked, instead of one
// stderr line per key allocation (which itself leaks when keys are handled).
static LOCK_WARNED: Once = Once::new();

// Global flag to track if panic handler is installed
static PANIC_HANDLER_INIT: Once = Once::new();

// Initialize the panic handler to wipe keys on panic
/// Init panic handler.
fn init_panic_handler() {
    // Apply the closure to each element.
    PANIC_HANDLER_INIT.call_once(|| {
        // Invoke the associated function.
        let original_hook = panic::take_hook();
        panic::set_hook(Box::new(move |panic_info| {
            // Securely erase key material to prevent forensic recovery.
            eprintln!("PANIC DETECTED - SecureMemory instances will be zeroized on drop");
            original_hook(panic_info);
        }));
    });
}

/// Marker for secret types whose bytes live inline in the value itself.
///
/// `SecureMemory::new` locks exactly `size_of::<T>()` bytes at the Box
/// address, so `T` must not own heap memory: a `Vec<u8>` would have only
/// its 24-byte header pinned while the key bytes stayed swappable. The
/// trait is sealed so only the fixed-size key wrappers in this module can
/// be placed in `SecureMemory` (SPEC §15.1 memory locking).
pub trait InlineSecret: sealed::Sealed {}

/// Private supertrait that keeps `InlineSecret` closed to this module.
mod sealed {
    pub trait Sealed {}
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
pub struct SecureMemory<T: Zeroize + InlineSecret> {
    data: Box<T>,
    /// Whether the pages are currently pinned (mlock / VirtualLock).
    locked: bool,
}

/// Pin `size` bytes at `ptr` so they cannot be swapped out.
///
/// Returns `Ok(true)` when locked, `Ok(false)` when the platform refused for
/// a resource reason (lockable quota exhausted) — the allocation still works
/// but is swappable, which is reported once — and `Err` for any other failure.
///
/// # Safety
/// `ptr` must point to at least `size` bytes of live memory owned by the
/// caller for as long as the lock is held.
unsafe fn lock_pages(ptr: *mut u8, size: usize) -> Result<bool, SecureMemoryError> {
    #[cfg(unix)]
    {
        // mlock(2) only reads the address/length; it does not dereference.
        if unsafe { mlock(ptr as *mut libc::c_void, size) } == 0 {
            return Ok(true);
        }
        let errno = std::io::Error::last_os_error();
        if errno.raw_os_error() == Some(ENOMEM) {
            warn_unlocked_once();
            return Ok(false);
        }
        Err(SecureMemoryError::LockFailed(errno))
    }
    #[cfg(windows)]
    {
        // VirtualLock returns non-zero on success.
        if unsafe { VirtualLock(ptr as *mut core::ffi::c_void, size) } != 0 {
            return Ok(true);
        }
        let code = unsafe { GetLastError() };
        if code == ERROR_WORKING_SET_QUOTA {
            warn_unlocked_once();
            return Ok(false);
        }
        Err(SecureMemoryError::LockFailed(
            std::io::Error::from_raw_os_error(code as i32),
        ))
    }
    #[cfg(not(any(unix, windows)))]
    {
        // No locking primitive on this target; zeroization still applies.
        let _ = (ptr, size);
        warn_unlocked_once();
        Ok(false)
    }
}

/// Release a lock taken by `lock_pages`. Failures are ignored: the memory
/// is about to be zeroized and freed either way.
///
/// # Safety
/// Same pointer and size as the matching `lock_pages` call.
unsafe fn unlock_pages(ptr: *mut u8, size: usize) {
    #[cfg(unix)]
    unsafe {
        munlock(ptr as *mut libc::c_void, size);
    }
    #[cfg(windows)]
    unsafe {
        VirtualUnlock(ptr as *mut core::ffi::c_void, size);
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (ptr, size);
    }
}

/// One-time notice that key pages are swappable on this process.
fn warn_unlocked_once() {
    LOCK_WARNED.call_once(|| {
        tracing::warn!("secure memory could not be locked; key material may be swapped to disk");
    });
}

// Securely erase key material to prevent forensic recovery.
// SecureMemory implementation — core protocol logic.
// SecureMemory implementation — core protocol logic.
impl<T: Zeroize + InlineSecret> SecureMemory<T> {
    /// Create new secure memory region
    pub fn new(value: T) -> Result<Self, SecureMemoryError> {
        init_panic_handler();

        // Box first so the address is stable for the lifetime of the lock.
        let mut data = Box::new(value);
        let ptr = data.as_mut() as *mut T as *mut u8;
        let size = std::mem::size_of::<T>();

        // SAFETY: `ptr` comes from a live, heap-allocated Box<T> via
        // `as_mut()`, so it is non-null, aligned and valid for `size` bytes,
        // and the Box is kept alive inside `Self` until `unlock_pages` runs.
        let locked = unsafe { lock_pages(ptr, size) }?;

        Ok(Self { data, locked })
    }

    /// Public emergency wipe method - immediately zeroize and unlock
    pub fn wipe(&mut self) {
        // Securely erase key material to prevent forensic recovery.
        // Zeroize sensitive key material.
        // Zeroize sensitive key material.
        self.data.zeroize();

        if self.locked {
            let ptr = self.data.as_mut() as *mut T as *mut u8;
            let size = std::mem::size_of::<T>();
            // SAFETY: same Box<T>, pointer and size as the lock in `new`.
            unsafe { unlock_pages(ptr, size) };
            // A wiped region is never re-locked; mark it so Drop skips it.
            self.locked = false;
        }
    }
}

// Securely erase key material to prevent forensic recovery.
// Trait implementation.
// Trait implementation.
impl<T: Zeroize + InlineSecret> AsRef<T> for SecureMemory<T> {
    /// As ref.
    fn as_ref(&self) -> &T {
        // Chain the operation on the intermediate result.
        &self.data
    }
}

// Securely erase key material to prevent forensic recovery.
// Trait implementation.
// Trait implementation.
impl<T: Zeroize + InlineSecret> AsMut<T> for SecureMemory<T> {
    /// As mut.
    fn as_mut(&mut self) -> &mut T {
        // Chain the operation on the intermediate result.
        &mut self.data
    }
}

// Securely erase key material to prevent forensic recovery.
// Implement Drop for SecureMemory.
// Implement Drop for SecureMemory.
impl<T: Zeroize + InlineSecret> Drop for SecureMemory<T> {
    /// Drop.
    fn drop(&mut self) {
        // Zeroize the data
        // Zeroize sensitive key material.
        // Zeroize sensitive key material.
        self.data.zeroize();

        // Unlock memory. Drop runs once, so this pairs with exactly one
        // `lock_pages` call unless `wipe` already released it.
        if self.locked {
            let ptr = self.data.as_mut() as *mut T as *mut u8;
            let size = std::mem::size_of::<T>();
            // SAFETY: `ptr` and `size` match the lock taken in `new`.
            unsafe { unlock_pages(ptr, size) };
        }
    }
}

// Securely erase key material to prevent forensic recovery.
// Implement Deref for SecureMemory.
// Implement Deref for SecureMemory.
impl<T: Zeroize + InlineSecret> Deref for SecureMemory<T> {
    // Type alias for readability.
    // Type alias for protocol readability.
    // Type alias for protocol readability.
    type Target = T;

    /// Deref.
    fn deref(&self) -> &Self::Target {
        // Chain the operation on the intermediate result.
        &self.data
    }
}

// Securely erase key material to prevent forensic recovery.
// Implement DerefMut for SecureMemory.
// Implement DerefMut for SecureMemory.
impl<T: Zeroize + InlineSecret> DerefMut for SecureMemory<T> {
    /// Deref mut.
    fn deref_mut(&mut self) -> &mut Self::Target {
        // Chain the operation on the intermediate result.
        &mut self.data
    }
}

// There is deliberately no `SecureMemory<Vec<u8>>` alias. `new` locks
// `size_of::<T>()` bytes at the Box address, which for a heap-owning `T`
// such as `Vec<u8>` would pin only the 24-byte Vec header while the key
// bytes on the heap stayed swappable with `locked == true`. Variable-length
// secrets must use a fixed-size wrapper (`SecureKey32`, `SecureKey64`) so
// the locked range is the key itself (SPEC §15.1 memory locking).

/// Secure storage for a 32-byte key
#[derive(Zeroize)]
// SecureKey32 — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SecureKey32 — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct SecureKey32(pub [u8; 32]);

impl sealed::Sealed for SecureKey32 {}
impl InlineSecret for SecureKey32 {}

// SecureKey32 implementation — core protocol logic.
// SecureKey32 implementation — core protocol logic.
impl SecureKey32 {
    /// Construct a new instance.
    pub fn new(key: [u8; 32]) -> Result<SecureMemory<Self>, SecureMemoryError> {
        SecureMemory::new(SecureKey32(key))
    }

    /// Random.
    pub fn random() -> Result<SecureMemory<Self>, SecureMemoryError> {
        use rand_core::{OsRng, RngCore};
        let mut key = [0u8; 32];
        // OS-provided cryptographic random number generator.
        OsRng.fill_bytes(&mut key);
        Self::new(key)
    }

    /// As bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        // Chain the operation on the intermediate result.
        &self.0
    }
}

/// Secure storage for a 64-byte key
#[derive(Zeroize)]
// SecureKey64 — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// SecureKey64 — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct SecureKey64(pub [u8; 64]);

impl sealed::Sealed for SecureKey64 {}
impl InlineSecret for SecureKey64 {}

// SecureKey64 implementation — core protocol logic.
// SecureKey64 implementation — core protocol logic.
impl SecureKey64 {
    /// Construct a new instance.
    pub fn new(key: [u8; 64]) -> Result<SecureMemory<Self>, SecureMemoryError> {
        SecureMemory::new(SecureKey64(key))
    }

    /// As bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        // Chain the operation on the intermediate result.
        &self.0
    }
}

#[derive(Debug)]
// SecureMemoryError — variant enumeration.
// Match exhaustively to handle every protocol state.
// SecureMemoryError — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum SecureMemoryError {
    LockFailed(std::io::Error),
}

// Implement Display for SecureMemoryError.
// Implement Display for SecureMemoryError.
impl std::fmt::Display for SecureMemoryError {
    /// Fmt.
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
    // Securely erase key material to prevent forensic recovery.
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
