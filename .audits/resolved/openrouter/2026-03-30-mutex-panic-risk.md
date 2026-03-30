## Resolution Status: RESOLVED

# MED-1: Mutex Unwrap Panic Risk in Spawned Threads
**Date:** 2026-03-30
**Auditor:** claude
**Status:** UNRESOLVED
**Severity:** High

## Issue
The codebase uses `.lock().unwrap()` in background threads across multiple transport modules (cjdns, WiFi Direct, CAN bus, KCP, Yggdrasil, etc.). If a thread panics while holding a Mutex, the mutex becomes poisoned, causing subsequent `.lock().unwrap()` calls from other threads to panic, leading to cascading failures and potential denial of service.

Specific unsafe usages include:
- `backend/transport/wireguard.rs:181-182` where `self.recv_high.lock().unwrap()` and `self.recv_seen.lock().unwrap()` are used without handling poison.
- `backend/transport/tor.rs:363` where `self.circuit_stats.lock().unwrap()` is used without handling poison.
- `backend/transport/kcp.rs:446` where `self.inbound.lock().unwrap()` is used in `drain_inbound()`.

These patterns can cause cascading panics across threads, compromising availability.

## Resolution
Replace all instances of `.lock().unwrap()` in background threads with `.lock().unwrap_or_else(|e| e.into_inner())` to gracefully handle poisoned mutexes. This aligns with the pattern used in the FFI layer and prevents cascading failures.

Potential automated refactoring can be performed using IDE tools to replace the pattern safely.