//! Platform keystore integration for identity key material.
//!
//! # What is a keystore and why does it exist?
//!
//! The keystore is the operating system's secure vault for cryptographic keys.
//! Every major platform offers one:
//!
//! | Platform | Keystore name |
//! |---|---|
//! | Android | Android Keystore (hardware-backed on most devices) |
//! | macOS / iOS | Keychain |
//! | Windows | Credential Manager |
//! | Linux (desktop) | Secret Service (e.g. GNOME Keyring, KWallet) |
//!
//! The keystore solves a fundamental chicken-and-egg problem:
//! *you need a key to protect your key*.  If you simply store your secret key
//! in a file, an attacker with read access to the filesystem can steal it.
//! The keystore breaks this cycle by storing the key inside a dedicated,
//! access-controlled subsystem — often backed by hardware (a Trusted Execution
//! Environment, or a dedicated security chip) — that is physically separate
//! from the main application storage.
//!
//! ANALOGY: Think of a keystore like a safety deposit box at a bank.  Your
//! house key (identity encryption key) is stored in the box.  To get it out
//! you have to physically go to the bank (the OS keystore API) and prove who
//! you are (app identity, device unlock state).  Someone who breaks into your
//! house only finds a locked box, not the contents.
//!
//! # Wrapping vs. storing
//!
//! Some keystores (notably Android Keystore) do not let you *export* the
//! actual hardware-backed key at all.  Instead you ask the hardware to
//! *wrap* (encrypt) another key using a hardware-protected master key.
//! The wrapped blob is safe to store on disk because it can only be unwrapped
//! by asking the same hardware again — the hardware never exposes its own
//! master key, even to the OS.
//!
//! ANALOGY FOR WRAPPING: Imagine a locksmith who can put your house key inside
//! a tiny steel box, seal it with a special lock, and give you the steel box.
//! The steel box is safe to leave on your desk — nobody can open it without
//! the locksmith's special key.  And the locksmith never gives out that
//! special key; they only agree to open the box for you in person.  The Android
//! Keystore hardware plays the role of the locksmith.
//!
//! Other platforms (macOS Keychain, Windows Credential Manager, Linux Secret
//! Service) allow storing arbitrary secret bytes directly; they handle access
//! control at the OS level.
//!
//! # Android vs. everything else
//!
//! Because Android Keystore uses a wrap/unwrap model (hardware-backed
//! AES encryption) and is accessed through Java/Kotlin APIs, the Android path
//! in this file uses JNI (Java Native Interface) to call into Kotlin code.
//! All other platforms use the `keyring` crate, which provides a uniform Rust
//! API over the native keystore of each non-Android OS.
//!
//! # What is JNI?
//!
//! JNI (Java Native Interface) is a standard mechanism that allows "native"
//! code (C, C++, Rust — compiled to machine code) to call Java/Kotlin methods
//! that run on the Java Virtual Machine (JVM), and vice versa.
//!
//! On Android, the Java Virtual Machine is called ART (Android Runtime).  It
//! starts automatically when the app launches.  Most Android system APIs
//! (including the Keystore) are only available as Java objects — there is no
//! C API for the Keystore.  So to call them from Rust, we must:
//!   1. Find the already-running JVM in the process.
//!   2. Attach our Rust thread to the JVM (so it can call Java methods).
//!   3. Look up the Java class we want to call.
//!   4. Convert Rust types (byte slices) into Java types (byte arrays).
//!   5. Call the Java method and convert the result back to Rust types.
//!   6. Check for any Java exceptions that were thrown.
//!
//! This file implements all six steps for the three keystore operations:
//! wrap, unwrap, and delete.
//!
//! # Why `#[cfg(target_os = "android")]`?
//!
//! Rust's `#[cfg(...)]` attribute is a "conditional compilation" gate.
//! Code inside `#[cfg(target_os = "android")]` only exists in the binary
//! when the build target is Android.  When building for macOS, Windows, or
//! Linux, the compiler completely ignores that code — it is as if it was
//! never written.  This means:
//!
//! * We do not link against the JNI library on non-Android platforms.
//! * We do not accidentally call Android-specific functions on desktop.
//! * The non-Android code path is clean and platform-appropriate.
//!
//! The inverse, `#[cfg(not(target_os = "android"))]`, applies to everything
//! that should NOT be compiled for Android (the `keyring`-based path).

use crate::core::error::{MeshInfinityError, Result};

// ============================================================================
// Android implementation — JNI bridge to Android Keystore
// ============================================================================
//
// This entire module is compiled ONLY when the build target is Android
// (`target_os = "android"`).  On all other platforms, the compiler ignores
// everything inside `mod android { ... }`.
//
// HOW THIS MODULE FITS INTO THE LARGER SYSTEM:
//   persistence.rs (caller)
//       calls keystore::wrap_key_bytes / unwrap_key_bytes / delete_key_alias
//           which call android::wrap_key / unwrap_key / delete_key
//               which call with_env(...)
//                   which calls get_vm() to find the JVM
//                   then attaches the thread
//                   then calls call_static_wrap / call_static_delete
//                       which use JNI to call KeystoreBridge.wrapKey / .unwrapKey / .deleteKey

#[cfg(target_os = "android")]
mod android {
    use super::{MeshInfinityError, Result};

    // JNI (Java Native Interface) types.
    // JNI is the standard bridge that allows C/Rust code (the "native" side)
    // to call Java/Kotlin methods (the "managed" side) and vice versa.
    // Without JNI, Rust code running inside an Android app cannot access any
    // Android API — including the Keystore — because those APIs are only
    // available as Java objects.
    //
    // `JByteArray` — a JNI handle representing a Java `byte[]` object.
    //                We use this when reading back the return value from
    //                wrapKey / unwrapKey (both return a Java byte array).
    // `JClass`     — a JNI handle representing a Java class object.
    //                We need this to find the static method we want to call.
    // `JValue`     — a tagged union representing any Java value type
    //                (boolean, int, long, float, double, or Object reference).
    //                We use `JValue::Object` to wrap our byte array argument.
    use jni::objects::{JByteArray, JClass, JValue};
    use jni::strings::{JNIString, MethodSignature};

    // Low-level JNI system types (from the C-level JNI header translated to Rust).
    //
    // `jsize`              — JNI's integer type for array lengths and counts.
    //                        It is typically a 32-bit signed integer.
    // `JavaVM as SysJavaVM`— the raw C-level struct representing a JVM instance.
    //                        We rename it to `SysJavaVM` to distinguish it from
    //                        the Rust-level `JavaVM` wrapper imported below.
    // `JNI_GetCreatedJavaVMs` — a C function mandated by the JNI specification.
    //                        It fills a provided array with pointers to any JVMs
    //                        currently alive in the process.  On Android there is
    //                        always exactly one: the ART runtime that the system
    //                        started when the app launched.
    use jni::sys::{jsize, JavaVM as SysJavaVM, JNI_GetCreatedJavaVMs};

    // Higher-level Rust wrappers from the `jni` crate.
    //
    // `JNIEnv` — a per-thread JNI "environment" handle.  Almost every JNI
    //            function takes a `JNIEnv` pointer.  It encapsulates thread-
    //            local JNI state (pending exceptions, local reference frames, etc.).
    //            You cannot share a `JNIEnv` across threads; each thread must
    //            obtain its own.
    // `JavaVM`  — the Rust-level wrapper around the raw JVM pointer
    //             (`SysJavaVM`).  It provides methods like `attach_current_thread()`.
    // In jni 0.22, `JNIEnv` was split into `EnvUnowned` (FFI-safe raw pointer,
    // used as function parameters) and `Env` (the full API with find_class,
    // call_static_method, etc.).  We import `JavaVM` for attach, and use
    // `jni::Env` (fully qualified) for the environment type in helpers below.
    use jni::JavaVM;

    // The fully-qualified Java class name of our Kotlin bridge class.
    //
    // Android uses forward-slash path separators in class names, not dots.
    // In Java/Kotlin source code you would write:
    //   com.oniimediaworks.meshinfinity.KeystoreBridge
    // In JNI, it becomes:
    //   com/oniimediaworks/meshinfinity/KeystoreBridge
    //
    // This class must be compiled into the APK (it lives in the
    // `android/app/src/main/kotlin/...` directory of the Flutter project).
    // It must expose three static methods:
    //   static byte[] wrapKey(byte[] input)    — encrypt a key with the hardware key
    //   static byte[] unwrapKey(byte[] input)  — decrypt a previously wrapped blob
    //   static boolean deleteKey()             — delete the hardware key entry
    const KEYSTORE_CLASS: &str = "com/oniimediaworks/meshinfinity/KeystoreBridge";

    // ------------------------------------------------------------------------
    // get_vm() — locate the already-running Java Virtual Machine
    // ------------------------------------------------------------------------
    //
    // When Android launches our app, the Java runtime (ART, Android Runtime)
    // is already running because the Flutter framework and the app itself are
    // JVM-based.  We do not start a JVM ourselves; we just find the one that
    // is already there.
    //
    // ANALOGY: This is like finding a running elevator in a building.  You
    // did not install the elevator; it was there when you arrived.  You just
    // need to find the button panel (the JVM pointer) to use it.
    //
    // `JNI_GetCreatedJavaVMs` is a C-level function defined by the JNI
    // specification.  It fills a caller-provided array with pointers to any
    // JVMs that are currently alive in this process.  On Android there is
    // always exactly one.
    //
    // We return a `ManuallyDrop<JavaVM>` rather than a plain `JavaVM` because
    // `JavaVM`'s `Drop` implementation would call `DestroyJavaVM()` — which
    // would shut down the entire Java runtime and crash the app!  By wrapping
    // in `ManuallyDrop` we tell Rust "do NOT run the destructor when this
    // goes out of scope".  We only *borrow* the JVM; we do not own it.
    //
    // WHY IS DESTROYING THE JVM BAD?
    //   Flutter uses the JVM for its rendering engine, event handling, and
    //   platform channel communication.  Calling `DestroyJavaVM()` would
    //   immediately crash the Flutter UI and the entire app process.
    //   `ManuallyDrop<T>` is Rust's way of saying "skip the destructor for
    //   this value" — it is a zero-cost abstraction that prevents the
    //   accidental `drop` from firing.
    fn get_vm() -> Result<std::mem::ManuallyDrop<JavaVM>> {
        // Allocate a null pointer that will receive the JVM address.
        // `*mut SysJavaVM` is a mutable raw pointer to a C-level JVM struct.
        // We start it as null (no JVM found yet) and pass its address to
        // `JNI_GetCreatedJavaVMs` which will fill it in.
        let mut vm: *mut SysJavaVM = std::ptr::null_mut();
        // `count` will be set to the number of JVMs found.
        // We expect exactly 1 (the Android runtime's JVM).
        let mut count: jsize = 0;

        // Call the C-level JNI function.
        //
        // Arguments:
        //   &mut vm  — pointer to our output buffer (receives the JVM pointer).
        //   1        — maximum number of JVMs to return (we only need one).
        //   &mut count — receives the actual number of JVMs found.
        //
        // Return value: JNI_OK (0) on success, a negative error code on failure.
        //
        // This is `unsafe` because:
        //   1. It calls into C code (no Rust safety guarantees).
        //   2. It writes to a raw pointer (`&mut vm`), which Rust cannot verify.
        //   3. We must ensure the output buffer (`vm`) has enough capacity for
        //      the count we request (1) — which it does, since it is a single pointer.
        let status = unsafe { JNI_GetCreatedJavaVMs(&mut vm, 1, &mut count) };

        // A non-zero status, zero count, or null pointer all mean "no JVM found".
        // This should never happen on Android (the JVM is always running),
        // but we handle it defensively in case of extremely early-startup calls.
        if status != 0 || count < 1 || vm.is_null() {
            return Err(MeshInfinityError::CryptoError(
                "Android JVM not available for keystore operations".to_string(),
            ));
        }

        // Wrap the raw C pointer in the Rust `JavaVM` type.
        //
        // `JavaVM::from_raw` is also `unsafe` because we are asserting that
        // `vm` is a valid JVM pointer — which we have just verified above.
        // (The JNI spec guarantees `JNI_GetCreatedJavaVMs` only writes valid
        // non-null pointers when it reports count >= 1.)
        // In jni 0.22, `JavaVM::from_raw` is infallible — it returns `JavaVM`
        // directly rather than `Result<JavaVM>`.  We just assert validity via `unsafe`.
        let java_vm = unsafe { JavaVM::from_raw(vm) };

        // Return the JVM wrapped in ManuallyDrop to prevent accidental shutdown.
        // The caller will use this only briefly to attach the current thread.
        Ok(std::mem::ManuallyDrop::new(java_vm))
    }

    // ------------------------------------------------------------------------
    // with_env() — attach the current Rust thread to the JVM
    // ------------------------------------------------------------------------
    //
    // JNI calls must be made from a thread that is "attached" to the JVM.
    //
    // "Attached" means the JVM is aware of this thread and has set up a local
    // reference frame for it.  Without attachment, calling any JNI method
    // would invoke undefined behaviour (likely a crash).
    //
    // The main Android thread is always attached, but Rust spawns its own
    // OS threads for async work, timers, etc.  Those threads start unattached.
    //
    // `attach_current_thread()` attaches THIS thread if it is not already
    // attached, and returns an `AttachGuard` — a RAII guard that automatically
    // DETACHES the thread when it is dropped (goes out of scope).  This
    // "attach on entry, detach on exit" pattern ensures we never leak attached
    // threads, which would waste JVM resources.
    //
    // WHAT DOES "ATTACH" ACTUALLY DO?
    //   It tells the JVM "this OS thread is now part of the JVM".  The JVM
    //   sets up a thread-local reference frame so Java objects created on
    //   this thread are tracked by the garbage collector.  The `JNIEnv`
    //   pointer returned is a handle to this thread's JNI state.
    //
    // The `with_env` helper abstracts this pattern: find the JVM, attach
    // the thread, pass a `JNIEnv` to the closure `f`, then clean up automatically.
    //
    // The type signature `impl FnOnce(&mut jni::Env) -> Result<T>` means:
    //   - `f` is a closure (anonymous function) that can only be called once.
    //   - It receives a mutable reference to a `jni::Env` (the full-API env).
    //   - It returns a `Result<T>` (success or error).
    //   - `<T>` is a generic type parameter — the return type can be anything.
    //
    // In jni 0.22, `attach_current_thread` changed to a callback-based API:
    // instead of returning an `AttachGuard`, it takes a `FnOnce(&mut Env) -> Result<T,E>`
    // and calls it while the thread is attached, detaching automatically afterward.
    // We route the callback's Result out via a local variable to bridge the types.
    fn with_env<T>(f: impl FnOnce(&mut jni::Env) -> Result<T>) -> Result<T> {
        // Find the already-running JVM.
        let vm = get_vm()?;
        // Wrap `f` in Option so we can `take()` it inside the closure without
        // moving it into the closure (which would prevent us from reading the result).
        let mut opt_f = Some(f);
        // Where we store the result that `f` produces.
        let mut retval: Result<T> = Err(MeshInfinityError::CryptoError(
            "JNI attach_current_thread did not invoke callback".into(),
        ));
        // jni 0.22 callback-based attach: the closure receives `&mut jni::Env`,
        // which has all the JNI methods (find_class, call_static_method, etc.).
        // The outer Result uses `jni::errors::Error` as its error type so that
        // any failure during attach itself is propagated correctly.
        let attach_result: std::result::Result<(), jni::errors::Error> =
            vm.attach_current_thread(|env| {
                if let Some(cb) = opt_f.take() {
                    retval = cb(env);
                }
                Ok(())
            });
        // Translate any attach-level JNI error into our own error type.
        attach_result.map_err(|e| {
            MeshInfinityError::CryptoError(format!("JNI attach failed: {}", e))
        })?;
        retval
    }

    // ------------------------------------------------------------------------
    // call_static_wrap() — generic JNI call for wrapKey / unwrapKey
    // ------------------------------------------------------------------------
    //
    // Both `wrapKey` and `unwrapKey` have the same Java method signature:
    //   static byte[] methodName(byte[] input)
    //
    // This helper performs the whole dance:
    //   1. Find the Kotlin class by name.
    //   2. Convert the Rust `&[u8]` slice into a Java `byte[]`.
    //   3. Call the static method with that array as the argument.
    //   4. Check for any Java exception that was thrown.
    //   5. Convert the returned Java `byte[]` back into a Rust `Vec<u8>`.
    //
    // WHY A GENERIC HELPER?
    //   `wrapKey` and `unwrapKey` differ only in the method name — everything
    //   else (argument type, return type, class name, exception handling) is
    //   identical.  Sharing this helper avoids duplicating ~30 lines of boilerplate.
    //
    // UNDERSTANDING JNI METHOD DESCRIPTORS:
    //   JNI uses a compact string notation to describe method signatures.
    //   The descriptor `"([B)[B"` breaks down as:
    //     `(`   — start of argument list
    //     `[B`  — one argument: a Java `byte[]` (array `[` of byte `B`)
    //     `)`   — end of argument list
    //     `[B`  — return type: a Java `byte[]`
    //
    //   Other common type codes:
    //     V — void            Z — boolean     B — byte
    //     C — char            S — short       I — int
    //     J — long            F — float       D — double
    //     L<classname>; — an object of class <classname>
    //     [<type> — an array of <type>
    fn call_static_wrap(env: &mut jni::Env, method: &str, input: &[u8]) -> Result<Vec<u8>> {
        // Step 1: find the class.  JNI needs the class object before it can
        // call any methods on it.
        //
        // `find_class` searches the class loader for a class with the given
        // fully-qualified JNI name.  It returns an error if the class is not
        // found — this would happen if the APK was built without including
        // KeystoreBridge.kt, or if the class name constant above is wrong.
        let class: JClass = env
            .find_class(JNIString::from(KEYSTORE_CLASS))
            .map_err(|e| MeshInfinityError::CryptoError(format!("JNI class lookup failed: {}", e)))?;

        // Step 2: convert &[u8] → Java byte[].
        // JNI cannot pass Rust slices directly; they must be converted into
        // Java's `byte[]` type first.
        //
        // `byte_array_from_slice` allocates a new Java byte array in the JVM's
        // heap, copies the Rust slice into it, and returns a `JByteArray`
        // handle (a local reference managed by the JVM GC).
        let input_array = env
            .byte_array_from_slice(input)
            .map_err(|e| MeshInfinityError::CryptoError(format!("JNI byte array failed: {}", e)))?;

        // Step 3: call the static method.
        //
        // `call_static_method` performs a Java static method call.  Arguments:
        //   `class`   — the class object from step 1.
        //   `method`  — the method name ("wrapKey" or "unwrapKey").
        //   `"([B)[B"`— the JNI descriptor (see above): takes byte[], returns byte[].
        //   `&[...]`  — the argument list, as a slice of `JValue` variants.
        //
        // `JValue::Object(&*input_array)` packages the Java byte[] as a JNI
        // argument value.  The `*` dereferences from JByteArray to the raw
        // JNI object handle; `&` then re-borrows it as an object reference.
        //
        // The call returns a `JValueOwned` (an owned JNI value variant).
        let output = env
            .call_static_method(
                class,
                JNIString::from(method),
                MethodSignature::from("([B)[B"),   // descriptor: (byte[]) -> byte[]
                &[JValue::Object(&*input_array)],  // one argument: the input byte[]
            )
            .map_err(|e| MeshInfinityError::CryptoError(format!("JNI call failed: {}", e)))?
            // `.l()` extracts the return value as a generic Java object reference.
            // (The alternative `.b()` would be for a primitive `byte`, but our
            // method returns an object — `byte[]` is an object in Java, not
            // a primitive, even though its elements are primitive bytes.)
            .l()
            .map_err(|e| MeshInfinityError::CryptoError(format!("JNI return failed: {}", e)))?;

        // Step 4: check for Java exceptions.
        //
        // In JNI, Java exceptions do NOT automatically propagate to Rust.
        // If the Kotlin code throws an exception (e.g. because the Android
        // Keystore hardware is temporarily unavailable, the device is locked,
        // or there is an internal Keystore error), the JNI call "succeeds"
        // at the C level but leaves a "pending exception" on the JVM thread.
        // We MUST check for this and clear it before making any more JNI calls.
        //
        // `exception_check` — returns true if an exception is pending on this thread.
        // `exception_describe` — prints the exception class and stack trace to
        //                        Android logcat (visible in Android Studio or `adb logcat`).
        //                        This is only for debugging; it does not clear the exception.
        // `exception_clear` — resets the pending exception flag so future JNI
        //                     calls on this thread will not fail due to the old exception.
        //
        // In jni 0.22, `exception_check()` returns `bool` directly (no Result).
        if env.exception_check() {
            let _ = env.exception_describe();
            let _ = env.exception_clear();
            return Err(MeshInfinityError::CryptoError(
                "Android keystore raised exception".to_string(),
            ));
        }

        // Step 5: convert the returned Java byte[] back to a Rust Vec<u8>.
        //
        // Reinterpret the generic JObject as a typed JByteArray.
        // In jni 0.22, there is no From<JObject> for JPrimitiveArray, so we use
        // the unsafe from_raw conversion to reinterpret the raw JNI pointer.
        // Safety: the Kotlin method is declared to return byte[], so the object
        // reference is guaranteed to be a valid Java byte array.
        let output_array: JByteArray = unsafe { JByteArray::from_raw(output.into_raw()) };
        let bytes = env
            .convert_byte_array(output_array)
            .map_err(|e| MeshInfinityError::CryptoError(format!("JNI read bytes failed: {}", e)))?;
        Ok(bytes)
    }

    // ------------------------------------------------------------------------
    // call_static_delete() — JNI call for deleteKey
    // ------------------------------------------------------------------------
    //
    // `deleteKey` has a different signature from wrapKey/unwrapKey:
    //   static boolean deleteKey()
    //
    // It takes no arguments and returns a boolean (true = success, false = failure).
    //
    // The JNI descriptor `"()Z"` breaks down as:
    //   `(` `)` — empty argument list (no parameters)
    //   `Z`     — return type: Java `boolean`
    //
    // We separate this from `call_static_wrap` because the argument list and
    // return type are fundamentally different — sharing would require more
    // complex generic machinery than the clarity savings would justify.
    fn call_static_delete(env: &mut jni::Env) -> Result<()> {
        let class: JClass = env
            .find_class(JNIString::from(KEYSTORE_CLASS))
            .map_err(|e| MeshInfinityError::CryptoError(format!("JNI class lookup failed: {}", e)))?;

        // Call the static `deleteKey()` method with no arguments.
        // The empty slice `&[]` means "no arguments".
        let result = env
            .call_static_method(class, JNIString::from("deleteKey"), MethodSignature::from("()Z"), &[])
            .map_err(|e| MeshInfinityError::CryptoError(format!("JNI call failed: {}", e)))?
            // `.z()` extracts the return value as a Java `boolean`.
            // This is a primitive type extractor — it returns `bool` directly.
            .z()
            .map_err(|e| MeshInfinityError::CryptoError(format!("JNI return failed: {}", e)))?;

        // Check for exceptions thrown by the Kotlin side.
        // Same pattern as in `call_static_wrap` — see the comments there for
        // a full explanation of why this check is necessary.
        // In jni 0.22, `exception_check()` returns `bool` directly (no Result).
        if env.exception_check() {
            let _ = env.exception_describe();
            let _ = env.exception_clear();
            return Err(MeshInfinityError::CryptoError(
                "Android keystore raised exception".to_string(),
            ));
        }

        // The Kotlin method returns `false` if deletion failed.
        // Possible reasons:
        //   * The key alias did not exist (it was already deleted).
        //   * The Keystore hardware or service was temporarily unavailable.
        //   * The app lacks the right permissions to delete this key alias.
        //
        // We treat `false` as an error here because a failed deletion during
        // an identity-destroy sequence could leave lingering key material,
        // which is a security concern.
        if !result {
            return Err(MeshInfinityError::CryptoError(
                "Android keystore delete returned false".to_string(),
            ));
        }
        Ok(())
    }

    // ------------------------------------------------------------------------
    // Public API for the Android keystore path
    // ------------------------------------------------------------------------
    //
    // "Wrapping" a key means:
    //   Taking our 32-byte raw encryption key and asking the Android hardware
    //   to encrypt it using a hardware-backed AES key that never leaves the
    //   secure element.  The result (the "wrapped" blob) is safe to store on
    //   disk — an attacker who copies the file cannot decrypt it without also
    //   having the hardware (i.e. the physical device with its unique,
    //   non-extractable hardware key).
    //
    //   Under the hood, the Android Keystore performs AES-256-GCM encryption
    //   of our 32-byte key using a hardware-generated key stored in the Trusted
    //   Execution Environment (TEE) or, on modern phones, a dedicated Secure
    //   Element (SE) chip.  The hardware key never appears in RAM even during
    //   the wrap/unwrap operation.
    //
    // "Unwrapping" a key means:
    //   Asking the hardware to decrypt the wrapped blob back to the original
    //   32-byte key.  The hardware only does this if the device is unlocked
    //   and the app has the right permissions.
    //
    //   The Android Keystore can be configured (via the Kotlin bridge) to
    //   require device unlock ("user authentication") before allowing unwrap
    //   operations.  This means a locked, stolen device cannot be used to
    //   read identity keys even if the attacker has root shell access.

    /// Encrypt (`wrap`) `bytes` using the Android hardware-backed Keystore.
    ///
    /// Returns the wrapped blob, which is safe to store on disk.
    ///
    /// Internally this calls `KeystoreBridge.wrapKey(bytes)` over JNI.
    /// The hardware AES key used for wrapping is generated and held by the
    /// Android Keystore; it is never returned to this process.
    pub fn wrap_key(bytes: &[u8]) -> Result<Vec<u8>> {
        // `with_env` handles finding the JVM and attaching the current thread.
        // The closure receives a `JNIEnv` and calls the Kotlin `wrapKey` method.
        with_env(|env| call_static_wrap(env, "wrapKey", bytes))
    }

    /// Decrypt (`unwrap`) a previously wrapped key blob.
    ///
    /// Returns the original raw key bytes.
    ///
    /// The hardware will refuse to unwrap if:
    ///   * The device is locked (if the key requires authentication).
    ///   * The hardware key entry was deleted (see `delete_key`).
    ///   * The blob was wrapped by a different hardware key (different device
    ///     or factory-reset device).
    pub fn unwrap_key(bytes: &[u8]) -> Result<Vec<u8>> {
        with_env(|env| call_static_wrap(env, "unwrapKey", bytes))
    }

    /// Delete the hardware-backed Keystore key entry.
    ///
    /// After this, any wrapped blobs stored on disk become permanently
    /// unreadable — the hardware key that could unwrap them no longer exists.
    ///
    /// This is the Android equivalent of "shredding the locksmith's special key":
    /// once it is gone, the steel box (wrapped key file) can never be opened,
    /// even by the original owner.  This is intentional — it is used for the
    /// emergency identity destroy sequence.
    pub fn delete_key() -> Result<()> {
        // `call_static_delete` is a function, not a closure.
        // Passing it directly as `with_env(call_static_delete)` is equivalent
        // to `with_env(|env| call_static_delete(env))` — Rust allows passing
        // function pointers where closures are expected, as long as the
        // signature matches.
        with_env(call_static_delete)
    }
}

// ============================================================================
// Android-specific public wrappers
// ============================================================================
//
// These re-export the inner `android` module's functions at the crate level
// so that `persistence.rs` can call `keystore::wrap_key_bytes(...)` without
// needing to know about the internal module structure.
//
// WHY THE EXTRA LEVEL OF INDIRECTION?
//   The `android` module is private (no `pub mod`), so its contents are only
//   accessible within this file.  These three `pub fn` wrappers expose the
//   Android functionality to the rest of the crate.  They are thin pass-throughs
//   with no logic of their own.
//
// The `#[cfg(target_os = "android")]` attribute ensures these definitions only
// exist in Android builds — on other platforms these symbols simply do not exist.
// Callers in `persistence.rs` also guard their calls with the same `#[cfg]`,
// so there is no risk of accidentally calling these on non-Android platforms.

/// Wrap (hardware-encrypt) raw key bytes using the Android Keystore.
///
/// The returned blob can be stored on disk; only this physical device's
/// hardware can decrypt it.
///
/// Callers: `persistence::IdentityStore::store_key_bytes` (Android path).
#[cfg(target_os = "android")]
pub fn wrap_key_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
    android::wrap_key(bytes)
}

/// Unwrap (hardware-decrypt) a previously wrapped key blob.
///
/// The hardware will refuse to unwrap if the device is locked or if the
/// Keystore entry has been deleted.
///
/// Callers: `persistence::IdentityStore::load_key_bytes` (Android path).
#[cfg(target_os = "android")]
pub fn unwrap_key_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
    android::unwrap_key(bytes)
}

/// Delete the hardware-backed Keystore key alias.
///
/// Once deleted, all wrapped blobs on disk become permanently unreadable.
/// This is a destructive, irreversible operation — used only in the
/// emergency "destroy identity" killswitch.
///
/// Callers: `persistence::IdentityStore::destroy_keyfile` (Android path).
#[cfg(target_os = "android")]
pub fn delete_key_alias() -> Result<()> {
    android::delete_key()
}

// ============================================================================
// Non-Android implementation — platform keyring via the `keyring` crate
// ============================================================================
//
// On macOS, iOS, Windows, and Linux (desktop), the `keyring` crate provides a
// uniform Rust API over each platform's native secret storage.  Under the hood:
//
//   • macOS / iOS  → uses the Security framework (Keychain Services).
//                    Entries are stored per-user, per-app in the macOS Keychain.
//                    On iOS, entries can be marked iCloud-synced or device-only.
//
//   • Windows      → uses the Windows Credential Manager (DPAPI-backed).
//                    DPAPI (Data Protection API) ties the key to the Windows
//                    user account — only the logged-in user can read it.
//
//   • Linux        → uses the Secret Service D-Bus API.
//                    This is a standard interface implemented by GNOME Keyring,
//                    KWallet, and other desktop secret-storage daemons.
//                    Entries are stored per-user in the running secret-service
//                    daemon's encrypted database.
//
// IMPORTANT LINUX CAVEAT:
//   On headless Linux systems (servers, CI runners, containers without a
//   desktop environment), there is no Secret Service daemon running.
//   `keyring` calls will fail on such systems.  `persistence.rs` handles this
//   gracefully by falling back to a 0600-restricted plain file.
//
// We store the raw 32-byte encryption key as a binary secret.  The keyring
// entries are identified by a "service" and "user" pair, both hardcoded below.
//
// HOW THE KEYRING API WORKS:
//   1. Create an `Entry` handle with a service name and user name.
//      This is just a key in the keyring's "namespace" — no I/O happens yet.
//   2. Call `set_secret(bytes)` to store bytes in the keyring.
//      The OS keyring encrypts the bytes and stores them securely.
//   3. Call `get_secret()` to retrieve the stored bytes.
//      The OS keyring decrypts and returns the bytes (subject to access control).
//   4. Call `delete_credential()` to remove the entry from the keyring.

/// The "service" name used to identify this app's keyring entries.
///
/// Think of this as the application namespace — it prevents our entry from
/// colliding with entries from other apps that also use the keyring.
///
/// On macOS this becomes the "service" field in the Keychain item.
/// On Linux it becomes the "service" attribute in the Secret Service item.
/// On Windows it is part of the credential target name.
///
/// Using a distinctive name ("mesh-infinity") rather than a generic one
/// ("identity-key") ensures that if another application happens to use the
/// same user/key pair, its entry is in a completely different namespace.
#[cfg(not(target_os = "android"))]
const KEYRING_SERVICE: &str = "mesh-infinity";

/// The "user" / "account" name for our specific keyring entry within the service.
///
/// We only store one secret (the identity encryption key), so this is a fixed
/// constant rather than something derived per-user.
///
/// If in the future we needed to store multiple secrets (e.g. one per
/// identity, or one for the key and one for something else), we would use
/// different `KEYRING_USER` values to keep them separate.
#[cfg(not(target_os = "android"))]
const KEYRING_USER: &str = "identity-key";

/// Store `key` bytes in the platform keystore.
///
/// On success, the bytes are held by the OS keyring and can be retrieved
/// by any process running as the same user, subject to OS access controls.
///
/// On failure (e.g. headless Linux without a Secret Service daemon), returns
/// an error.  The caller should fall back to writing a 0600-restricted file.
///
/// # Why not validate `key.len() == 32` here?
///
/// This function is a thin storage layer — it does not know or care about
/// what the bytes represent.  Length validation belongs in the caller
/// (`persistence.rs`) which knows the semantic meaning of the bytes.
/// Keeping this function generic makes it easier to reuse or change.
#[cfg(not(target_os = "android"))]
pub fn store_key(key: &[u8]) -> Result<()> {
    // Create a handle to our specific keyring entry (identified by service + user).
    // `keyring::Entry::new` does NOT read or write anything yet; it just
    // creates a reference object that knows where to find (or create) the entry.
    // This is analogous to constructing a file path object before opening a file.
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .map_err(|e| MeshInfinityError::CryptoError(format!("keyring init: {e}")))?;

    // Write the key bytes as the secret for this entry.
    //
    // `set_secret(key)` sends the bytes to the OS keyring daemon/API.
    // The OS encrypts the bytes and stores them associated with this
    // service+user pair.  If an entry already exists with this service+user,
    // it is overwritten — this is the correct behaviour for a key rotation.
    //
    // The OS takes care of all access control.  On macOS, the Keychain
    // will only allow our app (by bundle ID) to read back this entry.
    // On Linux, any process running as this Unix user can read it.
    entry
        .set_secret(key)
        .map_err(|e| MeshInfinityError::CryptoError(format!("keyring store: {e}")))
}

/// Load the key bytes from the platform keystore.
///
/// Returns an error if the keystore is unavailable or the entry does not
/// exist yet (i.e. the identity has not been saved before on this device).
///
/// The caller (`persistence.rs`) interprets a `load_key` error as "no key in
/// keystore" and falls back to the plain file, so this function does NOT
/// need to distinguish "entry not found" from "keystore unavailable" —
/// both are handled the same way.
#[cfg(not(target_os = "android"))]
pub fn load_key() -> Result<Vec<u8>> {
    // Create the entry handle (no I/O yet).
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .map_err(|e| MeshInfinityError::CryptoError(format!("keyring init: {e}")))?;
    // Retrieve the secret bytes from the OS keyring.
    // On macOS, this may show a Keychain access prompt if the app is not
    // already authorized (though this is typically pre-authorized at install
    // time for the app's own keychain entries).
    entry
        .get_secret()
        .map_err(|e| MeshInfinityError::CryptoError(format!("keyring load: {e}")))
}

/// Return `true` if the platform keystore currently holds an identity key entry.
///
/// Used by `IdentityStore::key_exists()` in `persistence.rs` to decide
/// whether to try loading from the keystore or to generate a new key.
///
/// Returns `false` (rather than an error) if the keystore is unreachable, so
/// this function is safe to call unconditionally even on headless Linux.
///
/// # Why return `bool` instead of `Result<bool>`?
///
/// This is a "probe" function used in conditional checks like
/// `if keystore::key_in_keystore() { ... }`.  Making it return `bool`
/// rather than `Result` means the caller does not need to handle an error —
/// "keystore unreachable" and "entry not found" are both treated as `false`,
/// which is the safe fallback behaviour (generate a new key or look in the
/// fallback file).
#[cfg(not(target_os = "android"))]
pub fn key_in_keystore() -> bool {
    // Attempt to create a keyring handle AND read the secret.
    //
    // This uses Rust's "option chaining" idiom:
    //   1. `keyring::Entry::new(...).ok()` — converts the Result to an Option:
    //      Some(entry) if the Entry was created, None on error.
    //   2. `.and_then(|e| e.get_secret().ok())` — if we have an entry, try to
    //      read it.  `get_secret().ok()` converts the Result to an Option.
    //      If the entry does not exist or the keyring is unavailable, returns None.
    //   3. `.is_some()` — true only if both steps succeeded (we have a valid entry
    //      with a readable secret).
    //
    // The entire chain returns `false` (not `true`) for any failure, which is
    // the safe default: "assume the key is not in the keystore".
    keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .ok()
        .and_then(|e| e.get_secret().ok())
        .is_some()
}

/// Remove the identity key entry from the platform keystore.
///
/// # Why this is the critical first step of the destroy sequence
///
/// The identity data file (`identity.dat`) on disk is just encrypted bytes.
/// Without the keystore entry that holds the encryption key, those bytes are
/// mathematically unreadable — not "hard to read", but *permanently* unreadable
/// with current cryptographic knowledge.
///
/// So to destroy an identity, we delete the key first.  Even if a backup of
/// `identity.dat` exists somewhere (cloud backup, old SD card, etc.), that
/// backup is now permanently locked.  The data has been effectively destroyed
/// without needing to find and delete every copy of `identity.dat` — which
/// might be impossible.
///
/// We ignore "entry not found" errors deliberately: if this function is called
/// a second time (e.g. because the first attempt partially succeeded before
/// a crash), we do not want it to fail — the outcome is the same either way.
///
/// # Idempotency
///
/// This function is designed to be called multiple times safely.
/// The first call deletes the entry (if it exists); subsequent calls
/// are no-ops that still return `Ok(())`.  This is important for
/// reliability: the destroy sequence can be retried on failure without
/// worrying about double-delete errors.
#[cfg(not(target_os = "android"))]
pub fn delete_key() -> Result<()> {
    if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER) {
        // `delete_credential` asks the OS keyring to remove this entry.
        // It returns an error if:
        //   a) The entry is not found (already deleted — idempotent destroy).
        //   b) The keystore daemon is unavailable (headless Linux — the key
        //      was never in the keystore to begin with, so nothing to delete).
        //   c) The OS denied the deletion (unusual, but possible with strict ACLs).
        //
        // We ignore ALL errors here (`let _ = ...`) because:
        //   * If the entry is gone, that is exactly the outcome we wanted.
        //   * If the keystore is unavailable, the key was never there anyway.
        //   * The critical destruction is handled by `persistence.rs` which
        //     also overwrites and deletes the fallback plain key file.
        let _ = entry.delete_credential();
    }
    Ok(())
}
