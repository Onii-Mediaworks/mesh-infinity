## Resolution Status: RESOLVED

# 107 FFI Functions Not Marked `unsafe` — Build-Blocking Clippy Errors
**Date:** 2026-03-29
**Auditor:** claude-sonnet-4-6
**Status:** UNRESOLVED
**Severity:** High

## Issue

`cargo clippy` produces 107 errors of type `clippy::not_unsafe_ptr_arg_deref`, all in
`backend/ffi/lib.rs`. Every public `extern "C"` function that dereferences a raw
`*const c_char` or `*mut MeshContext` pointer is flagged because the function is not
marked `unsafe`. The build DOES NOT COMPILE under clippy.

This violates Standard 1: "warnings and errors need to be treated as valid and fixed."

The functions themselves have correct null checks and SAFETY comments, but the function
signature must be `unsafe extern "C"` to properly communicate the raw-pointer contract
to Clippy, to the compiler, and to Dart FFI callers. Not marking them unsafe creates a
false API contract.

Example errors (representative):
- `lib.rs:4832` — `mesh_init` dereferences `data_dir: *const c_char`
- `lib.rs:4858` — `mesh_destroy` calls `Box::from_raw(ctx)`
- `lib.rs:4872` — `mi_get_last_error` dereferences `ctx: *mut MeshContext`
- ...and 104 more throughout the file

## Resolution
*(fill in when resolved)*

Change all 107 affected `pub extern "C" fn` declarations to `pub unsafe extern "C" fn`.
Update Dart FFI `@Native` declarations to match (Dart requires `unsafe` awareness at
the annotation layer for functions that dereference raw pointers). This is a mechanical
change; no logic changes are required.
