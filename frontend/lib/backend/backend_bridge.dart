// =============================================================================
// backend_bridge.dart
//
// This file is the ONLY place in the Flutter app that directly talks to the
// compiled Rust library.  Everything else in the UI goes through this file.
//
// WHAT IS FFI?
// FFI stands for "Foreign Function Interface".  It is the mechanism that lets
// code written in one programming language call functions written in a
// different language.  Here, Dart (the language Flutter uses) calls functions
// that were written in Rust and compiled into a shared library (.so / .dylib /
// .dll depending on platform).  The Rust code does all the heavy work:
// cryptography, networking, peer discovery, persistence.  Dart just calls into
// it when the UI needs data or wants to trigger an action.
//
// The overall flow is:
//   1.  At startup, we open the compiled Rust shared library with
//       DynamicLibrary.open().
//   2.  We look up each Rust function by its exported C-compatible symbol name
//       (e.g. "mesh_init", "mi_rooms_json").
//   3.  We call those functions, passing Dart values converted to C types, and
//       receive C values back that we convert back to Dart types.
//
// WHY JSON?
// Passing complex structured data across the FFI boundary is tricky because
// Dart and Rust have incompatible memory layouts for anything beyond simple
// numbers.  The pragmatic solution used here is: the Rust side serialises its
// data structures to a JSON string and returns a pointer to that string.  The
// Dart side receives the pointer, reads the string, and parses it back into
// Dart objects.  This keeps the FFI surface small and simple at the cost of a
// tiny serialisation overhead.
// =============================================================================

import 'dart:convert';  // jsonDecode / jsonEncode — parse/build JSON strings
import 'dart:ffi';      // Core FFI types: DynamicLibrary, Pointer, Struct, etc.
import 'dart:io';       // Platform.isAndroid / isIOS etc. — detect the OS at runtime

import 'package:ffi/ffi.dart';         // Extra FFI helpers: Utf8, calloc
import 'package:flutter/foundation.dart'; // debugPrint — prints only in debug builds

import 'models/file_transfer_models.dart';
import 'models/message_models.dart';
import 'models/peer_models.dart';
import 'models/room_models.dart';
import 'models/settings_models.dart';

// =============================================================================
// BackendBridge
//
// The main public class that the rest of the Flutter app talks to.
// It wraps all FFI calls in safe, typed Dart methods so that no other file
// ever has to think about pointers, native strings, or memory management.
//
// Typical usage:
//   final bridge = BackendBridge.open(allowMissing: true);
//   final rooms = bridge.fetchRooms();
// =============================================================================

class BackendBridge {
  // ---------------------------------------------------------------------------
  // Private constructor — use the factory `BackendBridge.open()` instead.
  // Having a private constructor with named parameters ensures that we can
  // never accidentally create an "empty" BackendBridge without going through
  // the factory which loads the library and initialises the Rust context.
  // ---------------------------------------------------------------------------
  BackendBridge._(this._bindings, this._context, this._initError);

  // ---------------------------------------------------------------------------
  // Factory constructor: open the library and initialise the Rust context.
  //
  // A "factory constructor" in Dart is a constructor that returns an instance
  // but can perform arbitrary logic first (unlike a regular constructor which
  // must always create a new object of the exact type).
  //
  // Parameters:
  //   nodeMode     — integer passed to Rust to configure the operating mode
  //                  (e.g. relay node vs. leaf node).
  //   allowMissing — if true, a failure to load the library or initialise the
  //                  context returns a BackendBridge with isAvailable==false
  //                  rather than throwing.  Useful on desktop dev machines
  //                  where the .so may not be built yet.
  //   configPath   — optional path to the mesh config directory; if null the
  //                  Rust side uses its default path.
  // ---------------------------------------------------------------------------
  factory BackendBridge.open({
    int nodeMode = 0,
    required bool allowMissing,
    String? configPath,
  }) {
    try {
      // Step 1: load the Rust shared library from disk into memory.
      final bindings = _BackendBindings(_openLibrary());

      // Step 2: call mesh_init() inside Rust to create the context object.
      // The context is an opaque blob of Rust state — we get a pointer back.
      final context = _initContext(bindings, nodeMode, configPath: configPath);

      if (context == nullptr) {
        // nullptr means Rust returned a null pointer — initialisation failed.
        // Read the human-readable error that Rust stored in thread-local storage.
        final error = _readLastError(bindings) ?? 'mesh_init returned null';
        debugPrint('BackendBridge: mesh_init failed: $error');
        if (allowMissing) {
          // Return a bridge that knows it is unavailable; callers check isAvailable.
          return BackendBridge._(bindings, context, error);
        }
        throw StateError(error);
      }

      // Success — the backend is live and _context holds a valid Rust object.
      return BackendBridge._(bindings, context, null);
    } catch (error, stack) {
      // This catches exceptions thrown by _openLibrary() if the .so file is
      // missing or the symbols don't match.
      final message = 'BackendBridge: failed to load backend library: $error';
      debugPrint(message);
      debugPrint(stack.toString());
      if (allowMissing) {
        // Return a no-op bridge; UI features will gracefully show empty data.
        return BackendBridge._(null, nullptr, message);
      }
      throw StateError(message);
    }
  }

  // ---------------------------------------------------------------------------
  // Private fields
  // ---------------------------------------------------------------------------

  // _bindings holds every resolved Rust function, ready to call.
  // It is nullable because on an allowMissing failure we may not have a library.
  final _BackendBindings? _bindings;

  // _context is the Rust "context" — think of it as an opaque handle to all
  // the internal Rust state (peer tables, message queues, network sockets...).
  //
  // WHAT IS Pointer<Void>?
  // In C/FFI, "void*" is a pointer to memory of unknown type — it is just an
  // address.  Dart represents this as Pointer<Void>.  We never dereference
  // it on the Dart side; we just pass it back to Rust so Rust can find its
  // own objects.  This pattern is called an "opaque handle".
  final Pointer<Void> _context;

  // Human-readable error message captured during initialisation, if any.
  final String? _initError;

  // ---------------------------------------------------------------------------
  // Public status accessors
  // ---------------------------------------------------------------------------

  /// True if the Rust library loaded successfully and mesh_init returned a
  /// valid (non-null) context.  All other methods return empty/false/null
  /// immediately when this is false, so callers don't need to guard every call.
  bool get isAvailable => _bindings != null && _context != nullptr;

  /// The error string captured at construction time, or null if all is well.
  String? get initError => _initError;

  /// Raw integer address of the Rust context pointer.
  ///
  /// WHY EXPOSE AN INTEGER?
  /// Dart Isolates (background threads — see event_bus.dart) cannot share
  /// Dart objects between them.  But they CAN share plain integers.  So we
  /// expose the raw memory address of the context pointer as an int.  The
  /// background isolate then reconstructs a `Pointer<Void>` from that integer
  /// and uses it to call Rust functions on its own DynamicLibrary handle.
  ///
  /// This is safe here because:
  ///   - The Rust context lives for the lifetime of the app.
  ///   - Rust's internal locking ensures concurrent calls are safe.
  int get contextAddress => _context.address;

  // ---------------------------------------------------------------------------
  // Error introspection
  // ---------------------------------------------------------------------------

  /// Ask Rust for the last error string it stored in thread-local storage.
  /// Returns null if the backend is not available or if there is no error.
  String? getLastError() {
    if (!isAvailable) return null;
    return _readString(_bindings!.lastErrorMessage());
  }

  // ---------------------------------------------------------------------------
  // Rooms
  //
  // A "room" is a named conversation channel.  It can be a private chat between
  // two peers or a group channel.
  // ---------------------------------------------------------------------------

  /// Fetch all rooms the local node is a member of.
  /// Returns a list of RoomSummary objects parsed from the JSON that Rust
  /// produces.  Returns an empty list if the backend is unavailable.
  List<RoomSummary> fetchRooms() {
    if (!isAvailable) return const [];
    // Call mi_rooms_json() in Rust; it allocates and returns a JSON string.
    final json = _readString(_bindings!.roomsJson(_context));
    if (json == null) return const [];
    // jsonDecode turns the JSON string into a Dart List of Maps.
    final decoded = jsonDecode(json) as List<dynamic>;
    // Map each raw Map into a typed RoomSummary object.
    return decoded
        .map((e) => RoomSummary.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  /// Returns the ID of the currently active (selected) room, or null.
  String? activeRoomId() {
    if (!isAvailable) return null;
    return _readString(_bindings!.activeRoomId(_context));
  }

  /// Create a new room with the given display name.
  /// Returns the new room's ID string, or throws/returns null on failure.
  String? createRoom(String name) {
    if (!isAvailable) return null;
    // Convert the Dart String to a null-terminated UTF-8 byte array in
    // native (non-GC) memory.  Rust expects C strings in this format.
    final namePtr = name.toNativeUtf8();
    try {
      final roomId = _readString(_bindings!.createRoom(_context, namePtr));
      if (roomId == null) throw StateError(getLastError() ?? 'Failed to create room');
      return roomId;
    } finally {
      // IMPORTANT: we must always free the native string we allocated above.
      // calloc.free() releases the memory back to the system.
      // The `finally` block ensures this happens even if an exception is thrown.
      calloc.free(namePtr);
    }
  }

  /// Mark a room as the currently selected/active room.
  /// Returns true on success (Rust returns 0 for success, like C errno).
  bool selectRoom(String roomId) {
    if (!isAvailable || roomId.isEmpty) return false;
    final ptr = roomId.toNativeUtf8();
    final result = _bindings!.selectRoom(_context, ptr);
    calloc.free(ptr); // Always free the native string after the call.
    return result == 0; // 0 = success in C convention.
  }

  /// Permanently delete a room and all its messages.
  /// Returns true if Rust reported success.
  bool deleteRoom(String roomId) {
    if (!isAvailable) return false;
    final ptr = roomId.toNativeUtf8();
    final result = _bindings!.deleteRoom(_context, ptr);
    calloc.free(ptr);
    return result == 0;
  }

  // ---------------------------------------------------------------------------
  // Messages
  // ---------------------------------------------------------------------------

  /// Fetch the message history for a specific room.
  /// Pass null for roomId to get messages for the currently active room.
  List<MessageModel> fetchMessages(String? roomId) {
    if (!isAvailable) return const [];
    // When roomId is null, we pass nullptr (the C null pointer) to Rust,
    // which interprets it as "use the active room".
    final roomPtr = roomId == null ? nullptr : roomId.toNativeUtf8();
    final json = _readString(_bindings!.messagesJson(_context, roomPtr));
    // Only free if we actually allocated (i.e. roomId was not null).
    if (roomPtr != nullptr) calloc.free(roomPtr);
    if (json == null) return const [];
    final decoded = jsonDecode(json) as List<dynamic>;
    return decoded
        .map((e) => MessageModel.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  /// Send a plain-text message to a room.
  /// Pass null for roomId to send to the currently active room.
  /// Returns true if Rust accepted the message.
  bool sendMessage(String? roomId, String text) {
    if (!isAvailable) return false;
    final roomPtr = roomId == null ? nullptr : roomId.toNativeUtf8();
    final textPtr = text.toNativeUtf8();
    final result = _bindings!.sendTextMessage(_context, roomPtr, textPtr);
    // Free both pointers.  Order doesn't matter here.
    if (roomPtr != nullptr) calloc.free(roomPtr);
    calloc.free(textPtr);
    return result == 0;
  }

  /// Delete a specific message by its ID.
  bool deleteMessage(String messageId) {
    if (!isAvailable) return false;
    final ptr = messageId.toNativeUtf8();
    final result = _bindings!.deleteMessage(_context, ptr);
    calloc.free(ptr);
    return result == 0;
  }

  // ---------------------------------------------------------------------------
  // Peers
  //
  // A "peer" is another node on the mesh network — another device running
  // Mesh Infinity.  Peers are identified by their cryptographic public-key
  // derived ID.
  // ---------------------------------------------------------------------------

  /// Fetch the current list of known peers and their online/trust status.
  List<PeerModel> fetchPeers() {
    if (!isAvailable) return const [];
    final json = _readString(_bindings!.peerListJson(_context));
    if (json == null) return const [];
    final decoded = jsonDecode(json) as List<dynamic>;
    return decoded
        .map((e) => PeerModel.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  /// Initiate pairing with a peer using a pairing code (typically scanned
  /// from a QR code displayed on the other device).
  bool pairPeer(String code) {
    if (!isAvailable) return false;
    final ptr = code.toNativeUtf8();
    final result = _bindings!.pairPeer(_context, ptr);
    calloc.free(ptr);
    return result == 0;
  }

  /// Record a trust attestation — one peer (endorser) vouches for another
  /// (target) at a specific trust level using a verification method code.
  ///
  /// This feeds the web-of-trust system in the Rust backend.
  bool trustAttest({
    required String endorserPeerId,
    required String targetPeerId,
    required int trustLevel,
    required int verificationMethod,
  }) {
    if (!isAvailable) return false;
    final endorserPtr = endorserPeerId.toNativeUtf8();
    final targetPtr = targetPeerId.toNativeUtf8();
    final result = _bindings!.trustAttest(
      _context, endorserPtr, targetPtr, trustLevel, verificationMethod,
    );
    calloc.free(endorserPtr);
    calloc.free(targetPtr);
    return result == 0;
  }

  /// Ask the Rust trust engine whether a given peer is trusted, optionally
  /// providing known markers (e.g. shared contacts) that help the engine
  /// calculate transitive trust.  Returns a decoded Map on success, null if
  /// the backend is unavailable or the call fails.
  Map<String, dynamic>? trustVerify({
    required String targetPeerId,
    List<Map<String, dynamic>> markers = const [],
  }) {
    if (!isAvailable) return null;
    final targetPtr = targetPeerId.toNativeUtf8();
    // The markers list is passed as a JSON string — simpler than a custom struct.
    final markersPtr = jsonEncode(markers).toNativeUtf8();
    final json = _readString(_bindings!.trustVerifyJson(_context, targetPtr, markersPtr));
    calloc.free(targetPtr);
    calloc.free(markersPtr);
    if (json == null) return null;
    final decoded = jsonDecode(json);
    return decoded is Map ? Map<String, dynamic>.from(decoded) : null;
  }

  // ---------------------------------------------------------------------------
  // File Transfers
  // ---------------------------------------------------------------------------

  /// Get the current list of in-progress or recently completed file transfers.
  List<FileTransferModel> fetchFileTransfers() {
    if (!isAvailable) return const [];
    final json = _readString(_bindings!.fileTransfersJson(_context));
    if (json == null) return const [];
    final decoded = jsonDecode(json) as List<dynamic>;
    return decoded
        .map((e) => FileTransferModel.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  /// Start a new file transfer (send or receive).
  ///
  /// direction — "send" or "receive"
  /// peerId    — the target/source peer, or null for the active peer
  /// filePath  — local filesystem path of the file to send (or destination path)
  ///
  /// Returns a Map describing the new transfer (including its ID), or null on
  /// failure.
  Map<String, dynamic>? startFileTransfer({
    required String direction,
    String? peerId,
    required String filePath,
  }) {
    if (!isAvailable) return null;
    final dirPtr = direction.toNativeUtf8();
    // Use the null-pointer shortcut when peerId is not provided.
    final peerPtr = peerId?.toNativeUtf8() ?? nullptr;
    final pathPtr = filePath.toNativeUtf8();
    final json = _readString(
      _bindings!.fileTransferStart(_context, dirPtr, peerPtr, pathPtr),
    );
    calloc.free(dirPtr);
    if (peerPtr != nullptr) calloc.free(peerPtr);
    calloc.free(pathPtr);
    if (json == null) return null;
    final decoded = jsonDecode(json);
    return decoded is Map ? Map<String, dynamic>.from(decoded) : null;
  }

  /// Cancel an in-progress file transfer by its transfer ID.
  bool cancelFileTransfer(String transferId) {
    if (!isAvailable) return false;
    final ptr = transferId.toNativeUtf8();
    final result = _bindings!.fileTransferCancel(_context, ptr);
    calloc.free(ptr);
    return result == 0;
  }

  /// Accept an incoming file transfer offer.
  ///
  /// [savePath] is where the file should be saved; pass empty string to use
  /// the default downloads location.  Returns true on success.
  bool acceptFileTransfer(String transferId, {String savePath = ''}) {
    if (!isAvailable) return false;
    final tPtr = transferId.toNativeUtf8();
    final pPtr = savePath.toNativeUtf8();
    try {
      return _bindings!.fileTransferAccept(_context, tPtr, pPtr) == 0;
    } finally {
      calloc.free(tPtr);
      calloc.free(pPtr);
    }
  }

  // ---------------------------------------------------------------------------
  // Settings & Identity
  // ---------------------------------------------------------------------------

  /// Fetch the current node settings (transport toggles, mode, etc.).
  SettingsModel? fetchSettings() {
    if (!isAvailable) return null;
    final json = _readString(_bindings!.settingsJson(_context));
    if (json == null) return null;
    final decoded = jsonDecode(json);
    if (decoded is! Map) return null;
    return SettingsModel.fromJson(Map<String, dynamic>.from(decoded));
  }

  /// Fetch the local node's cryptographic identity summary (peer ID, public
  /// key, display name).
  LocalIdentitySummary? fetchLocalIdentity() {
    if (!isAvailable) return null;
    final json = _readString(_bindings!.localIdentityJson(_context));
    if (json == null) return null;
    final decoded = jsonDecode(json);
    if (decoded is! Map) return null;
    return LocalIdentitySummary.fromJson(Map<String, dynamic>.from(decoded));
  }

  /// Returns true if the Rust backend has a saved identity (key pair) on disk.
  /// This is checked during startup to decide whether to show onboarding.
  bool hasIdentity() {
    if (!isAvailable) return false;
    // Rust returns 1 for true, 0 for false (standard C boolean convention).
    return _bindings!.hasIdentity(_context) == 1;
  }

  /// Create a new identity and persist it to disk.
  /// Call once during onboarding after the user chooses "Create New Identity".
  /// Returns true on success. On failure, call [lastError] for details.
  bool createIdentity({String? name}) {
    if (!isAvailable) return false;
    final namePtr = name != null ? name.toNativeUtf8() : nullptr;
    final result = _bindings!.createIdentity(_context, namePtr);
    if (namePtr != nullptr) calloc.free(namePtr);
    return result == 0;
  }

  /// Unlock an existing identity using the provided PIN.
  ///
  /// Pass null [pin] if no PIN was configured at creation time.
  /// Returns true on success. On failure (wrong PIN, missing identity),
  /// call [lastError] for the human-readable reason.
  bool unlockIdentity({String? pin}) {
    if (!isAvailable) return false;
    final pinPtr = pin != null ? pin.toNativeUtf8() : nullptr;
    final result = _bindings!.unlockIdentity(_context, pinPtr);
    if (pinPtr != nullptr) calloc.free(pinPtr);
    return result == 0;
  }

  /// Update the public profile fields and re-persist the identity.
  bool setPublicProfile({String? displayName, bool isPublic = false}) {
    if (!isAvailable) return false;
    // Bundle multiple fields as JSON rather than having separate FFI parameters.
    final ptr = jsonEncode(<String, dynamic>{
      'displayName': displayName ?? '',
      'isPublic': isPublic,
    }).toNativeUtf8();
    final result = _bindings!.setPublicProfile(_context, ptr);
    calloc.free(ptr);
    return result == 0;
  }

  /// Update the private profile fields and re-persist the identity.
  bool setPrivateProfile({String? displayName, String? bio}) {
    if (!isAvailable) return false;
    final ptr = jsonEncode(<String, dynamic>{
      'displayName': displayName ?? '',
      'bio': bio ?? '',
    }).toNativeUtf8();
    final result = _bindings!.setPrivateProfile(_context, ptr);
    calloc.free(ptr);
    return result == 0;
  }

  /// Create an encrypted backup of identity, trust data, network map, and
  /// settings.  Returns the JSON-serialised EncryptedBackup on success, or
  /// null on failure.
  /// [backupType]: 0 = full backup (identity + contacts + settings),
  /// 1 = identity-only (keys only, smaller payload).
  String? createBackup({required String passphrase, int backupType = 0}) {
    if (!isAvailable) return null;
    final passphrasePtr = passphrase.toNativeUtf8();
    final result = _readString(
        _bindings!.createBackup(_context, passphrasePtr, backupType));
    calloc.free(passphrasePtr);
    return result;
  }

  /// Restore an identity from an encrypted backup payload + passphrase.
  bool importIdentity({required String backupJson, required String passphrase}) {
    if (!isAvailable) return false;
    final backupPtr = backupJson.toNativeUtf8();
    final passphrasePtr = passphrase.toNativeUtf8();
    final result = _bindings!.importIdentity(_context, backupPtr, passphrasePtr);
    calloc.free(backupPtr);
    calloc.free(passphrasePtr);
    return result == 0;
  }

  /// Killswitch: overwrite the keyfile and remove all identity files,
  /// permanently destroying the on-disk identity.
  bool resetIdentity() {
    if (!isAvailable) return false;
    return _bindings!.resetIdentity(_context) == 0;
  }

  /// Get the full pairing payload JSON for QR code display and sharing.
  /// Includes our Ed25519 + X25519 public keys, a fresh one-time token,
  /// display name (signed), and transport hints.
  /// Returns null if the identity is not unlocked.
  String? getPairingPayload() {
    if (!isAvailable) return null;
    return _readString(_bindings!.getPairingPayload(_context));
  }

  /// Start the clearnet TCP listener on the configured port (default 7234).
  /// Call once after unlocking the identity so incoming connections can be
  /// accepted during the mi_poll_events cycle.
  bool startClearnetListener() {
    if (!isAvailable) return false;
    return _bindings!.startClearnetListener(_context) == 0;
  }

  /// Stop the clearnet TCP listener and close all open connections.
  bool stopClearnetListener() {
    if (!isAvailable) return false;
    return _bindings!.stopClearnetListener(_context) == 0;
  }

  /// Change the TCP port the clearnet listener will bind to.
  /// Takes effect on the next [startClearnetListener] call.
  bool setClearnetPort(int port) {
    if (!isAvailable) return false;
    return _bindings!.setClearnetPort(_context, port) == 0;
  }

  /// Update the threat context level (0=Normal, 1=Elevated, 2=Critical).
  /// Elevated/Critical automatically suppresses cloud push tiers.
  bool setThreatContext(int level) {
    if (!isAvailable) return false;
    return _bindings!.setThreatContext(_context, level) == 0;
  }

  /// Read the current threat context level (0=Normal, 1=Elevated, 2=Critical).
  int getThreatContext() {
    if (!isAvailable) return 0;
    return _bindings!.getThreatContext(_context);
  }

  /// Set the trust level for a peer identified by hex peer ID.
  /// [level]: 0=Unknown … 9=Absolute (see TrustLevel in the spec §8).
  bool setTrustLevel(String peerId, int level) {
    if (!isAvailable) return false;
    final peerPtr = peerId.toNativeUtf8();
    final result = _bindings!.setTrustLevel(_context, peerPtr, level);
    calloc.free(peerPtr);
    return result == 0;
  }

  /// Set the security mode for a conversation room.
  /// [mode]: 0=Standard, 1=HighSecurity, 2=MaxSecurity.
  bool setConversationSecurityMode(String roomId, int mode) {
    if (!isAvailable) return false;
    final roomPtr = roomId.toNativeUtf8();
    final result = _bindings!.setConversationSecurityMode(_context, roomPtr, mode);
    calloc.free(roomPtr);
    return result == 0;
  }

  /// Set the node operating mode (e.g. 0 = standard, 1 = relay-only, etc.).
  bool setNodeMode(int mode) {
    if (!isAvailable) return false;
    return _bindings!.setNodeMode(_context, mode) == 0;
  }

  /// Toggle a single named transport (e.g. "tor", "clearnet") on or off.
  bool toggleTransport(String transportName, bool enabled) {
    if (!isAvailable) return false;
    final ptr = transportName.toNativeUtf8();
    // Dart booleans become ints (1/0) at the FFI boundary — C has no bool type.
    final result = _bindings!.toggleTransportFlag(_context, ptr, enabled ? 1 : 0);
    calloc.free(ptr);
    return result != 0;
  }

  /// Set all transport flags in one call — more efficient than calling
  /// toggleTransport() six times separately.
  bool setTransportFlags({
    required bool enableTor,
    required bool enableClearnet,
    required bool meshDiscovery,
    required bool allowRelays,
    required bool enableI2p,
    required bool enableBluetooth,
  }) {
    if (!isAvailable) return false;
    return _bindings!.setTransportFlags(
      _context,
      enableTor ? 1 : 0,
      enableClearnet ? 1 : 0,
      meshDiscovery ? 1 : 0,
      allowRelays ? 1 : 0,
      enableI2p ? 1 : 0,
      enableBluetooth ? 1 : 0,
    ) == 0;
  }

  /// Set the VPN routing mode (§6.9).
  bool setVpnModeConfig(Map<String, dynamic> modeConfig) {
    if (!isAvailable) return false;
    final ptr = jsonEncode(modeConfig).toNativeUtf8();
    final result = _bindings!.setVpnMode(_context, ptr);
    calloc.free(ptr);
    return result == 0;
  }

  /// Set the exit node peer ID (§6.9.2). Pass empty string to clear.
  bool setExitNode(String peerIdHex) {
    if (!isAvailable) return false;
    final ptr = peerIdHex.toNativeUtf8();
    final result = _bindings!.setExitNode(_context, ptr);
    calloc.free(ptr);
    return result == 0;
  }

  /// Configure the clearnet (plain internet) routing rules.
  bool setClearnetRoute(Map<String, dynamic> routeConfig) {
    if (!isAvailable) return false;
    final ptr = jsonEncode(routeConfig).toNativeUtf8();
    final result = _bindings!.setClearnetRoute(_context, ptr);
    calloc.free(ptr);
    return result != 0;
  }

  /// Configure VPN routing (alias for [setVpnModeConfig]).
  bool setVpnRoute(Map<String, dynamic> routeConfig) {
    return setVpnModeConfig(routeConfig);
  }

  // ---------------------------------------------------------------------------
  // VPN / Exit Node
  //
  // These methods control the VPN subsystem described in spec section 13.
  // The Rust backend may not have full implementations yet — callers should
  // handle false returns gracefully.
  // ---------------------------------------------------------------------------

  /// Set the VPN mode (§6.9).
  ///
  /// [mode] is one of: "off", "mesh_only", "exit_node", "policy".
  /// [exitNodePeerId] is required when mode is "exit_node".
  bool setVpnMode(String mode, {String? exitNodePeerId}) {
    if (exitNodePeerId != null) setExitNode(exitNodePeerId);
    return setVpnModeConfig({'mode': mode});
  }

  /// Enable or disable the VPN kill switch (§6.9.4).
  bool setVpnKillSwitch(bool enabled) {
    return setVpnModeConfig({'killSwitch': enabled ? 'strict' : 'disabled'});
  }

  /// Fetch current VPN status from the backend.
  ///
  /// Returns a map with keys: mode, exitNodePeerId, connectionStatus,
  /// killSwitch, uptimeSeconds.  Returns null if the backend has no VPN
  /// state yet.
  ///
  /// Fetch current VPN status from the backend.
  ///
  /// Returns a map with keys: enabled, mode, state, killSwitch, exitPeerId,
  /// internetAllowed.  Returns null if the backend is not available.
  Map<String, dynamic>? getVpnStatus() {
    if (!isAvailable) return null;
    final json = _readString(_bindings!.getVpnStatus(_context));
    if (json == null) return null;
    final decoded = jsonDecode(json);
    if (decoded is! Map) return null;
    return Map<String, dynamic>.from(decoded);
  }

  /// Perform a standard emergency erase (§3.9.1).
  ///
  /// Destroys ALL three identity layers permanently. Non-reversible.
  /// Returns true if the erase was initiated.
  bool emergencyErase() {
    if (!isAvailable) return false;
    return _bindings!.emergencyErase(_context) == 0;
  }

  /// Perform a duress erase (§3.9.2).
  ///
  /// Preserves Layer 1 (mesh identity), destroys Layers 2 and 3.
  /// An observer sees a normal-looking fresh account with real mesh history.
  /// Returns true if the erase was initiated.
  bool duressErase() {
    if (!isAvailable) return false;
    return _bindings!.duressErase(_context) == 0;
  }

  // ---------------------------------------------------------------------------
  // SDR / RF Transport
  //
  // The SDR stack treats all radio as software-defined. Dedicated hardware
  // (LoRa chips, Meshtastic, HF transceivers) are hardware-backed profiles
  // implementing the same interface with limited configurability.
  // ---------------------------------------------------------------------------

  /// Configure the SDR transport.
  ///
  /// [profile] — one of: "balanced", "secure", "long_range", "long_range_hf", "evasive"
  /// [driver]  — one of: "lora", "hackrf", "limesdr", "pluto", "rtlsdr",
  ///             "hf_transceiver", "meshtastic", "simulated"
  /// [freqHz]  — primary frequency in Hz (ignored for profile-determined frequencies)
  /// [hopKeyHex] — 64-char hex hop key (required for "secure" and "evasive" profiles)
  bool configureSdr({
    String profile = 'balanced',
    String driver = 'simulated',
    int freqHz = 433175000,
    String? hopKeyHex,
  }) {
    if (!isAvailable) return false;
    final config = <String, dynamic>{
      'profile': profile,
      'driver': driver,
      'freq_hz': freqHz,
      if (hopKeyHex != null) 'hop_key_hex': hopKeyHex,
    };
    final ptr = jsonEncode(config).toNativeUtf8();
    final result = _bindings!.sdrConfigure(_context, ptr);
    calloc.free(ptr);
    return result == 0;
  }

  /// Get current SDR/RF status.
  ///
  /// Returns a map with keys: enabled, profile, driver, fhss, ale,
  /// primaryFreqHz, stats (txBytes, rxBytes, fhssHops, lossRatio, etc.).
  Map<String, dynamic>? getSdrStatus() {
    if (!isAvailable) return null;
    final json = _readString(_bindings!.sdrStatus(_context));
    if (json == null) return null;
    final decoded = jsonDecode(json);
    if (decoded is! Map) return null;
    return Map<String, dynamic>.from(decoded);
  }

  /// Get the current FHSS channel (if FHSS is active).
  ///
  /// Returns a map with keys: freq_hz, epoch, label, bandwidth_hz.
  /// Returns null if FHSS is not configured.
  Map<String, dynamic>? getSdrCurrentChannel() {
    if (!isAvailable) return null;
    final json = _readString(_bindings!.sdrCurrentChannel(_context));
    if (json == null) return null;
    final decoded = jsonDecode(json);
    if (decoded is! Map || decoded.containsKey('error')) return null;
    return Map<String, dynamic>.from(decoded);
  }

  /// List available SDR radio profiles.
  ///
  /// Returns a list of maps with keys: id, name, description, bandwidth_class,
  /// fhss, ale, approx_range_km.
  List<Map<String, dynamic>> listSdrProfiles() {
    if (!isAvailable) return const [];
    final json = _readString(_bindings!.sdrListProfiles(_context));
    if (json == null) return const [];
    final decoded = jsonDecode(json);
    if (decoded is! List) return const [];
    return decoded.map((e) => Map<String, dynamic>.from(e as Map)).toList();
  }

  /// List supported SDR hardware types.
  ///
  /// Returns a list of maps with keys: id, name, min_freq_mhz, max_freq_mhz,
  /// full_duplex, raw_iq.
  List<Map<String, dynamic>> listSdrHardware() {
    if (!isAvailable) return const [];
    final json = _readString(_bindings!.sdrListHardware(_context));
    if (json == null) return const [];
    final decoded = jsonDecode(json);
    if (decoded is! List) return const [];
    return decoded.map((e) => Map<String, dynamic>.from(e as Map)).toList();
  }

  // ---------------------------------------------------------------------------
  // Network / mDNS
  //
  // mDNS (Multicast DNS) lets devices on the same local network discover each
  // other without any central server.  It is the same technology that makes
  // "Bonjour" / ".local" hostnames work on macOS.
  // ---------------------------------------------------------------------------

  /// Start the mDNS discovery service on the given UDP port.
  /// Returns true if Rust started the service successfully.
  bool enableMdns({int port = 51820}) {
    if (!isAvailable) return false;
    return _bindings!.mdnsEnable(_context, port) == 0;
  }

  /// Stop the mDNS discovery service.
  bool disableMdns() {
    if (!isAvailable) return false;
    return _bindings!.mdnsDisable(_context) == 0;
  }

  /// Returns true if the mDNS service is currently running.
  bool isMdnsRunning() {
    if (!isAvailable) return false;
    return _bindings!.mdnsIsRunning(_context) == 1;
  }

  /// Return the list of peers discovered on the local network via mDNS.
  List<Map<String, dynamic>> getDiscoveredPeers() {
    if (!isAvailable) return const [];
    final json = _readString(_bindings!.mdnsGetDiscoveredPeers(_context));
    if (json == null) return const [];
    final decoded = jsonDecode(json);
    if (decoded is! List) return const [];
    return decoded.map((e) => Map<String, dynamic>.from(e as Map)).toList();
  }

  /// Fetch overall network statistics (bytes sent/received, peer count, etc.)
  /// as a raw Map.  The UI layer can format these however it likes.
  Map<String, dynamic>? getNetworkStats() {
    if (!isAvailable) return null;
    final json = _readString(_bindings!.getNetworkStats(_context));
    if (json == null) return null;
    final decoded = jsonDecode(json);
    return decoded is Map ? Map<String, dynamic>.from(decoded) : null;
  }

  /// Get routing table summary statistics (§6).
  Map<String, dynamic>? getRoutingTableStats() {
    if (!isAvailable) return null;
    final json = _readString(_bindings!.routingTableStats(_context));
    if (json == null) return null;
    final decoded = jsonDecode(json);
    return decoded is Map ? Map<String, dynamic>.from(decoded) : null;
  }

  /// Look up next-hop for a destination peer (§6).
  Map<String, dynamic>? routingLookup(String destPeerIdHex) {
    if (!isAvailable) return null;
    final ptr = destPeerIdHex.toNativeUtf8();
    try {
      final json = _readString(_bindings!.routingLookup(_context, ptr));
      if (json == null) return null;
      final decoded = jsonDecode(json);
      return decoded is Map ? Map<String, dynamic>.from(decoded) : null;
    } finally {
      calloc.free(ptr);
    }
  }

  // ---------------------------------------------------------------------------
  // Trusted Contexts (§4.8.3)
  //
  // Trusted contexts control which networks permit automatic peer discovery.
  // They do NOT affect routing or pathing — only mDNS/local discovery.
  // ---------------------------------------------------------------------------

  /// Toggle a trusted context on or off.
  ///
  /// [context] is one of: "tailscale", "zerotier", "lan", "mdns".
  /// [enabled] is the new state.
  ///
  /// Returns true if the backend accepted the change.
  bool setTrustedContext(String context, bool enabled) {
    if (!isAvailable) return false;
    // We reuse the transport flags mechanism — trusted contexts are
    // stored as transport-level flags in the backend.
    final flagName = 'trusted_ctx_$context';
    final flagPtr = flagName.toNativeUtf8();
    final result = _bindings!.toggleTransportFlag(
        _context, flagPtr, enabled ? 1 : 0);
    calloc.free(flagPtr);
    return result == 0;
  }

  /// Get the list of all peers from the contact store.
  ///
  /// Returns a list of JSON maps with peer info including:
  /// - "id": hex peer ID
  /// - "name": display name
  /// - "trustLevel": int 0-8
  /// - "status": "online" or "offline"
  /// - "pairingMethod": how they were paired (for trust metrics)
  List<Map<String, dynamic>> getPeerList() {
    if (!isAvailable) return const [];
    final json = _readString(_bindings!.peerListJson(_context));
    if (json == null) return const [];
    final decoded = jsonDecode(json);
    if (decoded is! List) return const [];
    return decoded
        .map((e) => Map<String, dynamic>.from(e as Map))
        .toList();
  }

  // ---------------------------------------------------------------------------
  // Services
  //
  // "Services" are optional pluggable capabilities that the Rust node can run
  // (e.g. a local proxy, a relay service).  The UI can list and configure them.
  // ---------------------------------------------------------------------------

  /// Fetch the list of available/running services.
  List<ServiceModel> fetchServices() {
    if (!isAvailable) return const [];
    final json = _readString(_bindings!.getServiceList(_context));
    if (json == null) return const [];
    final decoded = jsonDecode(json);
    if (decoded is! List) return const [];
    return decoded
        .map((e) => ServiceModel.fromJson(Map<String, dynamic>.from(e as Map)))
        .toList();
  }

  /// Apply a configuration map to a named service.
  bool configureService(String serviceId, Map<String, dynamic> config) {
    if (!isAvailable) return false;
    final idPtr = serviceId.toNativeUtf8();
    final cfgPtr = jsonEncode(config).toNativeUtf8();
    final result = _bindings!.configureService(_context, idPtr, cfgPtr);
    calloc.free(idPtr);
    calloc.free(cfgPtr);
    return result != 0;
  }

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // Messaging — extended actions
  // ---------------------------------------------------------------------------

  /// Send a reaction emoji to a message.
  bool sendReaction(String roomId, String messageId, String emoji) {
    if (!isAvailable) return false;
    final roomPtr = roomId.toNativeUtf8();
    final msgPtr = messageId.toNativeUtf8();
    final emojiPtr = emoji.toNativeUtf8();
    final result = _bindings!.sendReaction(_context, roomPtr, msgPtr, emojiPtr);
    calloc.free(roomPtr);
    calloc.free(msgPtr);
    calloc.free(emojiPtr);
    return result == 0;
  }

  /// Edit the text of a previously sent message.
  bool editMessage(String roomId, String messageId, String newText) {
    if (!isAvailable) return false;
    final roomPtr = roomId.toNativeUtf8();
    final msgPtr = messageId.toNativeUtf8();
    final textPtr = newText.toNativeUtf8();
    final result = _bindings!.editMessage(_context, roomPtr, msgPtr, textPtr);
    calloc.free(roomPtr);
    calloc.free(msgPtr);
    calloc.free(textPtr);
    return result == 0;
  }

  /// Delete a message for all participants in the room.
  bool deleteForEveryone(String roomId, String messageId) {
    if (!isAvailable) return false;
    final roomPtr = roomId.toNativeUtf8();
    final msgPtr = messageId.toNativeUtf8();
    final result = _bindings!.deleteForEveryone(_context, roomPtr, msgPtr);
    calloc.free(roomPtr);
    calloc.free(msgPtr);
    return result == 0;
  }

  /// Set the disappearing message timer for a room (0 to disable).
  bool setDisappearingTimer(String roomId, int durationSecs) {
    if (!isAvailable) return false;
    final roomPtr = roomId.toNativeUtf8();
    final result = _bindings!.setDisappearingTimer(_context, roomPtr, durationSecs);
    calloc.free(roomPtr);
    return result == 0;
  }

  /// Send a typing indicator to a room.
  bool sendTypingIndicator(String roomId, bool isTyping) {
    if (!isAvailable) return false;
    final roomPtr = roomId.toNativeUtf8();
    final result = _bindings!.sendTypingIndicator(
      _context, roomPtr, isTyping ? 1 : 0,
    );
    calloc.free(roomPtr);
    return result == 0;
  }

  /// Send a read receipt for a specific message.
  bool sendReadReceipt(String roomId, String messageId) {
    if (!isAvailable) return false;
    final roomPtr = roomId.toNativeUtf8();
    final msgPtr = messageId.toNativeUtf8();
    final result = _bindings!.sendReadReceipt(_context, roomPtr, msgPtr);
    calloc.free(roomPtr);
    calloc.free(msgPtr);
    return result == 0;
  }

  /// Reply to a specific message in a room.
  bool replyToMessage(String roomId, String parentId, String text) {
    if (!isAvailable) return false;
    final roomPtr = roomId.toNativeUtf8();
    final parentPtr = parentId.toNativeUtf8();
    final textPtr = text.toNativeUtf8();
    final result = _bindings!.replyToMessage(_context, roomPtr, parentPtr, textPtr);
    calloc.free(roomPtr);
    calloc.free(parentPtr);
    calloc.free(textPtr);
    return result == 0;
  }

  /// Forward a message from one room to another.
  bool forwardMessage(String fromRoomId, String messageId, String toRoomId) {
    if (!isAvailable) return false;
    final fromPtr = fromRoomId.toNativeUtf8();
    final msgPtr = messageId.toNativeUtf8();
    final toPtr = toRoomId.toNativeUtf8();
    final result = _bindings!.forwardMessage(_context, fromPtr, msgPtr, toPtr);
    calloc.free(fromPtr);
    calloc.free(msgPtr);
    calloc.free(toPtr);
    return result == 0;
  }

  /// Search messages across all rooms. Returns matching messages.
  List<MessageModel> searchMessages(String query) {
    if (!isAvailable) return const [];
    final queryPtr = query.toNativeUtf8();
    final json = _readString(_bindings!.searchMessages(_context, queryPtr));
    calloc.free(queryPtr);
    if (json == null) return const [];
    final decoded = jsonDecode(json) as List<dynamic>;
    return decoded
        .map((e) => MessageModel.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  /// Pin a message in a room.
  bool pinMessage(String roomId, String messageId) {
    if (!isAvailable) return false;
    final roomPtr = roomId.toNativeUtf8();
    final msgPtr = messageId.toNativeUtf8();
    final result = _bindings!.pinMessage(_context, roomPtr, msgPtr);
    calloc.free(roomPtr);
    calloc.free(msgPtr);
    return result == 0;
  }

  /// Unpin a message in a room.
  bool unpinMessage(String roomId, String messageId) {
    if (!isAvailable) return false;
    final roomPtr = roomId.toNativeUtf8();
    final msgPtr = messageId.toNativeUtf8();
    final result = _bindings!.unpinMessage(_context, roomPtr, msgPtr);
    calloc.free(roomPtr);
    calloc.free(msgPtr);
    return result == 0;
  }

  /// Prune all expired disappearing messages across all rooms.
  bool pruneExpiredMessages() {
    if (!isAvailable) return false;
    return _bindings!.pruneExpiredMessages(_context) == 0;
  }

  // ---------------------------------------------------------------------------
  // Message requests (§22.5.4)
  // ---------------------------------------------------------------------------

  /// Fetch all pending message requests (inbound conversations from peers
  /// below trust Level 6 that are awaiting user acceptance).
  ///
  /// Returns a list of [MessageRequest] objects decoded from JSON.
  /// Returns an empty list when the backend is unavailable (stub mode)
  /// or when there are no pending requests.
  ///
  /// Backend symbol (once implemented): `mi_message_requests_json(ctx)`
  /// Expected JSON: `[{ "id": "...", "peerId": "...", ... }, ...]`
  List<MessageRequest> fetchMessageRequests() {
    if (!isAvailable) return const [];
    final ptr = _bindings!.messageRequestsJson(_context);
    if (ptr == nullptr) return const [];
    try {
      final json = jsonDecode(ptr.toDartString()) as List<dynamic>;
      return json
          .whereType<Map<String, dynamic>>()
          .map(MessageRequest.fromJson)
          .toList();
    } catch (_) {
      return const [];
    }
  }

  /// Accept a message request by ID.
  ///
  /// Instructs Rust to promote the pending request into a full room in the
  /// main conversation list.  The first reply from the user serves as implicit
  /// confirmation — the sender receives no explicit accept signal.
  ///
  /// Returns true if the backend confirmed the acceptance.
  bool acceptMessageRequest(String requestId) {
    if (!isAvailable) return false;
    final idPtr = requestId.toNativeUtf8();
    try {
      return _bindings!.acceptMessageRequestFn(_context, idPtr) == 0;
    } finally {
      calloc.free(idPtr);
    }
  }

  /// Decline a message request by ID.
  ///
  /// Removes the request from the queue without notifying the sender.
  /// This is intentional — the sender must not be able to infer user activity
  /// from a decline signal.
  ///
  /// Returns true if the backend confirmed the removal.
  bool declineMessageRequest(String requestId) {
    if (!isAvailable) return false;
    final idPtr = requestId.toNativeUtf8();
    try {
      return _bindings!.declineMessageRequestFn(_context, idPtr) == 0;
    } finally {
      calloc.free(idPtr);
    }
  }

  // ---------------------------------------------------------------------------
  // Overlay networks (Tailscale / ZeroTier)
  // ---------------------------------------------------------------------------

  /// Authenticate with Tailscale using a pre-auth key.
  ///
  /// [authKey] is a Tailscale pre-authentication key from the admin console.
  /// [controlUrl] is the control plane URL — pass empty string for
  /// the default Tailscale SaaS (`https://controlplane.tailscale.com`), or
  /// a Headscale URL for self-hosted deployments.
  ///
  /// Returns true if Rust accepted the credentials.
  bool tailscaleAuthKey(String authKey, String controlUrl) {
    if (!isAvailable) return false;
    final keyPtr = authKey.toNativeUtf8();
    final urlPtr = controlUrl.toNativeUtf8();
    final result = _bindings!.tailscaleAuthKey(_context, keyPtr, urlPtr);
    calloc.free(keyPtr);
    calloc.free(urlPtr);
    return result == 0;
  }

  /// Begin a Tailscale OAuth flow (browser-based login).
  ///
  /// [controlUrl] is the control plane URL, same convention as
  /// [tailscaleAuthKey].  An empty string uses the default Tailscale SaaS.
  ///
  /// The backend emits a `TailscaleOAuthUrl` event with the URL to open.
  /// Returns true if Rust started the OAuth flow.
  bool tailscaleBeginOAuth(String controlUrl) {
    if (!isAvailable) return false;
    final urlPtr = controlUrl.toNativeUtf8();
    final result = _bindings!.tailscaleBeginOAuth(_context, urlPtr);
    calloc.free(urlPtr);
    return result == 0;
  }

  /// Connect to one or more ZeroTier networks.
  ///
  /// [apiKey] is a ZeroTier Central API token (empty for self-hosted without
  /// authentication).
  /// [controllerUrl] is the URL of the ZeroTier controller — pass empty string
  /// for `https://my.zerotier.com` (ZeroTier Central SaaS), or a self-hosted
  /// controller URL.
  /// [networkIds] is the list of 16-hex-digit ZeroTier network IDs to join.
  ///
  /// Returns true if Rust accepted the configuration.
  bool zerotierConnect(String apiKey, String controllerUrl, List<String> networkIds) {
    if (!isAvailable) return false;
    final keyPtr = apiKey.toNativeUtf8();
    final urlPtr = controllerUrl.toNativeUtf8();
    final idsPtr = jsonEncode(networkIds).toNativeUtf8();
    final result = _bindings!.zerotierConnect(_context, keyPtr, urlPtr, idsPtr);
    calloc.free(keyPtr);
    calloc.free(urlPtr);
    calloc.free(idsPtr);
    return result == 0;
  }

  // ---------------------------------------------------------------------------
  // LoSec — Low-Traffic Security Mode (§6.9.6)
  // ---------------------------------------------------------------------------

  /// Request LoSec (low-traffic security) mode negotiation with a peer.
  ///
  /// [sessionId] is a 64-char hex string (32 random bytes).
  /// [mode] is "standard" | "losec" | "direct".
  /// [hopCount] is 1 or 2 (only used for LoSec mode).
  /// [reason] is a human-readable string shown in the remote peer's dialog.
  /// [ambientBytesPerSec] is the current measured traffic volume.
  /// [activeTunnels] is the current active tunnel count.
  ///
  /// Returns a map with `accepted` (bool) and `rejection_reason` (String?),
  /// or null on failure.
  Map<String, dynamic>? loSecRequest({
    required String sessionId,
    String mode = 'losec',
    int hopCount = 2,
    String reason = '',
    int ambientBytesPerSec = 0,
    int activeTunnels = 0,
    String? peerId,
  }) {
    if (!isAvailable) return null;
    final requestJson = jsonEncode({
      'session_id': sessionId,
      'mode': mode,
      'hop_count': hopCount,
      'reason': reason,
      'ambient_bytes_per_sec': ambientBytesPerSec,
      'active_tunnels': activeTunnels,
      if (peerId != null) 'peer_id': peerId,
    });
    final ptr = requestJson.toNativeUtf8();
    final json = _readString(_bindings!.loSecRequest(_context, ptr));
    calloc.free(ptr);
    if (json == null) return null;
    final decoded = jsonDecode(json);
    return decoded is Map ? Map<String, dynamic>.from(decoded) : null;
  }

  /// Query the current ambient traffic level for LoSec eligibility.
  ///
  /// Returns a map with:
  /// - `available`: bool — true if ambient traffic is sufficient for LoSec
  /// - `active_tunnels`: int
  /// - `bytes_per_sec`: int
  Map<String, dynamic>? loSecAmbientStatus() {
    if (!isAvailable) return null;
    final json = _readString(_bindings!.loSecAmbientStatus(_context));
    if (json == null) return null;
    final decoded = jsonDecode(json);
    return decoded is Map ? Map<String, dynamic>.from(decoded) : null;
  }

  /// Fetch the current overlay network status.
  ///
  /// Returns a map with keys:
  /// - `tailscale`: `{connected, ip, node_name, controller}`
  /// - `zerotier`: `{connected, networks: [{id, name, ip}]}`
  /// - `exit_nodes`: list of available exit node peers
  /// - `anonymous_score`: integer 0-100 (§5.20)
  ///
  /// Returns null if the backend is unavailable.
  Map<String, dynamic>? getOverlayStatus() {
    if (!isAvailable) return null;
    final json = _readString(_bindings!.overlayStatus(_context));
    if (json == null) return null;
    final decoded = jsonDecode(json);
    return decoded is Map ? Map<String, dynamic>.from(decoded) : null;
  }

  // ---------------------------------------------------------------------------
  // Group Management (§8.7)
  // ---------------------------------------------------------------------------

  /// Create a new group owned by this identity.
  ///
  /// [name] is the group display name (max 64 bytes).
  /// [description] is optional.
  /// [networkType] is 0=Private, 1=Closed, 2=Open, 3=Public.
  ///
  /// Returns a map with `groupId`, `name`, `memberCount`, `roomId`,
  /// or null on failure.
  Map<String, dynamic>? createGroup({
    required String name,
    String description = '',
    int networkType = 0,
  }) {
    if (!isAvailable) return null;
    final namePtr = name.toNativeUtf8();
    final descPtr = description.toNativeUtf8();
    final json = _readString(
        _bindings!.createGroup(_context, namePtr, descPtr, networkType));
    calloc.free(namePtr);
    calloc.free(descPtr);
    if (json == null) return null;
    final decoded = jsonDecode(json);
    if (decoded is Map && decoded.containsKey('error')) return null;
    return decoded is Map ? Map<String, dynamic>.from(decoded) : null;
  }

  /// List all groups the user belongs to.
  List<Map<String, dynamic>> listGroups() {
    if (!isAvailable) return [];
    final json = _readString(_bindings!.listGroups(_context));
    if (json == null) return [];
    final decoded = jsonDecode(json);
    if (decoded is List) {
      return decoded.whereType<Map>()
          .map((e) => Map<String, dynamic>.from(e))
          .toList();
    }
    return [];
  }

  /// Get the member list for a group.
  List<Map<String, dynamic>> getGroupMembers(String groupId) {
    if (!isAvailable) return [];
    final ptr = groupId.toNativeUtf8();
    final json = _readString(_bindings!.groupMembers(_context, ptr));
    calloc.free(ptr);
    if (json == null) return [];
    final decoded = jsonDecode(json);
    if (decoded is List) {
      return decoded.whereType<Map>()
          .map((e) => Map<String, dynamic>.from(e))
          .toList();
    }
    return [];
  }

  /// Leave a group. Returns true on success.
  bool leaveGroup(String groupId) {
    if (!isAvailable) return false;
    final ptr = groupId.toNativeUtf8();
    final result = _bindings!.leaveGroup(_context, ptr);
    calloc.free(ptr);
    return result == 0;
  }

  /// Invite a peer (by peer-ID hex) into a group. Returns true on success.
  bool inviteToGroup(String groupId, String peerId) {
    if (!isAvailable) return false;
    final gPtr = groupId.toNativeUtf8();
    final pPtr = peerId.toNativeUtf8();
    final result = _bindings!.groupInvitePeer(_context, gPtr, pPtr);
    calloc.free(gPtr);
    calloc.free(pPtr);
    return result == 0;
  }

  /// Send a text message to a group. Returns true on success.
  bool groupSendMessage(String groupId, String text) {
    if (!isAvailable) return false;
    final gidPtr = groupId.toNativeUtf8();
    final textPtr = text.toNativeUtf8();
    final result = _bindings!.groupSendMessage(_context, gidPtr, textPtr);
    calloc.free(gidPtr);
    calloc.free(textPtr);
    return result == 0;
  }

  // ---------------------------------------------------------------------------
  // Calls (§10.1.6)
  // ---------------------------------------------------------------------------

  /// Initiate an outgoing call to [peerIdHex]. [isVideo] enables the video
  /// track. Returns `{"ok":true,"callId":"<hex>"}` on success.
  Map<String, dynamic>? callOffer(String peerIdHex, {bool isVideo = false}) {
    if (!isAvailable) return null;
    final ptr = peerIdHex.toNativeUtf8();
    final result = _readString(
      _bindings!.callOffer(_context, ptr, isVideo ? 1 : 0),
    );
    calloc.free(ptr);
    if (result == null) return null;
    try {
      return jsonDecode(result) as Map<String, dynamic>;
    } catch (_) {
      return null;
    }
  }

  /// Accept (accept=true) or reject (accept=false) an incoming call.
  bool callAnswer(String callIdHex, {required bool accept}) {
    if (!isAvailable) return false;
    final ptr = callIdHex.toNativeUtf8();
    final result = _bindings!.callAnswer(_context, ptr, accept ? 1 : 0);
    calloc.free(ptr);
    return result == 1;
  }

  /// End an active call. Returns true if there was an active call to end.
  bool callHangup(String callIdHex) {
    if (!isAvailable) return false;
    final ptr = callIdHex.toNativeUtf8();
    final result = _bindings!.callHangup(_context, ptr);
    calloc.free(ptr);
    return result == 1;
  }

  /// Returns the current call status as a map, or null if unavailable.
  Map<String, dynamic>? callStatus() {
    if (!isAvailable) return null;
    final result = _readString(_bindings!.callStatus(_context));
    if (result == null) return null;
    try {
      return jsonDecode(result) as Map<String, dynamic>;
    } catch (_) {
      return null;
    }
  }

  // ---------------------------------------------------------------------------
  // §14 — Notification configuration
  // ---------------------------------------------------------------------------

  /// Get the current notification configuration from the backend.
  Map<String, dynamic>? getNotificationConfig() {
    if (!isAvailable) return null;
    final result = _readString(_bindings!.getNotificationConfig(_context));
    if (result == null) return null;
    try {
      return jsonDecode(result) as Map<String, dynamic>;
    } catch (_) {
      return null;
    }
  }

  /// Save notification configuration to the backend.
  bool setNotificationConfig(Map<String, dynamic> config) {
    if (!isAvailable) return false;
    final jsonStr = jsonEncode(config);
    final ptr = jsonStr.toNativeUtf8();
    try {
      return _bindings!.setNotificationConfig(_context, ptr) == 0;
    } finally {
      malloc.free(ptr);
    }
  }

  // ---------------------------------------------------------------------------
  // WireGuard handshake (§5.2)
  // ---------------------------------------------------------------------------

  /// Initiate a WireGuard handshake with [peerIdHex].
  ///
  /// Returns a map with `init_hex` (the 80-byte handshake init message to
  /// send to the peer) or `error` on failure.
  Map<String, dynamic>? wgInitiateHandshake(String peerIdHex) {
    if (!isAvailable) return null;
    final ptr = peerIdHex.toNativeUtf8();
    final json = _readString(_bindings!.wgInitiateHandshake(_context, ptr));
    calloc.free(ptr);
    if (json == null) return null;
    try { return jsonDecode(json) as Map<String, dynamic>; } catch (_) { return null; }
  }

  /// Respond to an incoming WireGuard handshake from [peerIdHex].
  ///
  /// [initHex] is the 80-byte handshake init message (hex-encoded).
  /// Returns a map with `response_hex` and `session_established: true` or
  /// `error` on failure.
  Map<String, dynamic>? wgRespondToHandshake(String peerIdHex, String initHex) {
    if (!isAvailable) return null;
    final peerPtr = peerIdHex.toNativeUtf8();
    final initPtr = initHex.toNativeUtf8();
    final json = _readString(_bindings!.wgRespondToHandshake(_context, peerPtr, initPtr));
    calloc.free(peerPtr);
    calloc.free(initPtr);
    if (json == null) return null;
    try { return jsonDecode(json) as Map<String, dynamic>; } catch (_) { return null; }
  }

  /// Complete an initiator-side WireGuard handshake after receiving the
  /// responder's reply.
  ///
  /// [peerIdHex] is the responder's peer ID.
  /// [responseHex] is the 32-byte ephemeral public key from the responder.
  /// Returns a map with `session_established: true` or `error` on failure.
  Map<String, dynamic>? wgCompleteHandshake(String peerIdHex, String responseHex) {
    if (!isAvailable) return null;
    final peerPtr = peerIdHex.toNativeUtf8();
    final respPtr = responseHex.toNativeUtf8();
    final json = _readString(_bindings!.wgCompleteHandshake(_context, peerPtr, respPtr));
    calloc.free(peerPtr);
    calloc.free(respPtr);
    if (json == null) return null;
    try { return jsonDecode(json) as Map<String, dynamic>; } catch (_) { return null; }
  }

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  /// Shut down the Rust backend cleanly.
  ///
  /// This calls mesh_destroy() which flushes any pending writes, closes
  /// network sockets, and frees all Rust-side memory.  Must be called when
  /// the app is closing to avoid resource leaks.
  void dispose() {
    if (isAvailable) _bindings!.meshDestroy(_context);
  }

  // ---------------------------------------------------------------------------
  // Garden — posts and discovery (§22.6)
  // ---------------------------------------------------------------------------

  /// Fetch posts for a garden. Returns a list of post maps, or empty list.
  List<Map<String, dynamic>> fetchGardenPosts(String gardenId) {
    if (!isAvailable) return const [];
    final ptr = gardenId.toNativeUtf8();
    final json = _readString(_bindings!.gardenPosts(_context, ptr));
    calloc.free(ptr);
    if (json == null) return const [];
    final decoded = jsonDecode(json);
    if (decoded is! List) return const [];
    return decoded.cast<Map<String, dynamic>>();
  }

  /// Discover gardens advertised on the local mesh.
  List<Map<String, dynamic>> discoverGardens() {
    if (!isAvailable) return const [];
    final json = _readString(_bindings!.gardenDiscover(_context));
    if (json == null) return const [];
    final decoded = jsonDecode(json);
    if (decoded is! List) return const [];
    return decoded.cast<Map<String, dynamic>>();
  }

  /// Publish a post to a garden. Returns true on success.
  bool postToGarden(String gardenId, String content) {
    if (!isAvailable) return false;
    final ptr = jsonEncode({'gardenId': gardenId, 'content': content})
        .toNativeUtf8();
    final result = _bindings!.gardenPost(_context, ptr);
    calloc.free(ptr);
    return result == 0;
  }

  // ---------------------------------------------------------------------------
  // Files — distributed storage (§22.7)
  // ---------------------------------------------------------------------------

  /// Fetch distributed storage usage stats.
  Map<String, dynamic>? fetchStorageStats() {
    if (!isAvailable) return null;
    final json = _readString(_bindings!.storageStats(_context));
    if (json == null) return null;
    final decoded = jsonDecode(json);
    if (decoded is! Map) return null;
    return Map<String, dynamic>.from(decoded);
  }

  /// Fetch the list of files this node has published. Returns empty list.
  List<Map<String, dynamic>> fetchPublishedFiles() {
    if (!isAvailable) return const [];
    final json = _readString(_bindings!.publishedFiles(_context));
    if (json == null) return const [];
    final decoded = jsonDecode(json);
    if (decoded is! List) return const [];
    return decoded.cast<Map<String, dynamic>>();
  }

  /// Publish a local file to distributed storage. Returns true on success.
  bool publishFile(String path) {
    if (!isAvailable) return false;
    final ptr = path.toNativeUtf8();
    final result = _bindings!.publishFile(_context, ptr);
    calloc.free(ptr);
    return result == 0;
  }

  /// Unpublish a previously published file by its ID. Returns true on success.
  bool unpublishFile(String fileId) {
    if (!isAvailable) return false;
    final ptr = fileId.toNativeUtf8();
    final result = _bindings!.unpublishFile(_context, ptr);
    calloc.free(ptr);
    return result == 0;
  }

  // ---------------------------------------------------------------------------
  // Services — mesh discovery and hosting config (§22.54)
  // ---------------------------------------------------------------------------

  /// Discover services hosted by peers on the local mesh.
  List<Map<String, dynamic>> discoverMeshServices() {
    if (!isAvailable) return const [];
    final json = _readString(_bindings!.meshServicesDiscover(_context));
    if (json == null) return const [];
    final decoded = jsonDecode(json);
    if (decoded is! List) return const [];
    return decoded.cast<Map<String, dynamic>>();
  }

  /// Fetch this node's service hosting configuration.
  Map<String, dynamic>? fetchHostingConfig() {
    if (!isAvailable) return null;
    final json = _readString(_bindings!.hostingConfig(_context));
    if (json == null) return null;
    final decoded = jsonDecode(json);
    if (decoded is! Map) return null;
    return Map<String, dynamic>.from(decoded);
  }

  /// Enable or disable a named hosted service. Returns true on success.
  bool setHostedService(String serviceId, {required bool enabled}) {
    if (!isAvailable) return false;
    final ptr = serviceId.toNativeUtf8();
    final result = _bindings!.hostingSet(_context, ptr, enabled ? 1 : 0);
    calloc.free(ptr);
    return result == 0;
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /// Read a string from a Rust-allocated `Pointer<Utf8>` and immediately free
  /// that memory via mi_string_free().
  ///
  /// WHY MUST WE FREE THE STRING?
  /// The Rust library allocates a new string on the heap each time it returns
  /// one.  Dart's garbage collector does NOT manage Rust heap memory — they are
  /// completely separate.  If we don't call mi_string_free(), the memory leaks
  /// permanently until the process exits.
  ///
  /// IMPORTANT: After calling _readString() the pointer is invalid — Rust has
  /// freed it.  Do not use `ptr` again after passing it here.
  String? _readString(Pointer<Utf8> ptr) {
    if (ptr == nullptr) return null;
    // toDartString() copies the bytes into a Dart-managed String.
    final value = ptr.toDartString();
    // Now tell Rust to free its allocation.
    _bindings?.stringFree(ptr);
    return value;
  }

  /// Static variant of _readString() used before we have a full BackendBridge
  /// instance (e.g. when reading the error that caused initialisation to fail).
  static String? _readLastError(_BackendBindings bindings) {
    final ptr = bindings.lastErrorMessage();
    if (ptr == nullptr) return null;
    final value = ptr.toDartString();
    bindings.stringFree(ptr);
    return value;
  }
}

// =============================================================================
// Initialization helpers (module-level private functions)
// =============================================================================

/// Build the FfiMeshConfig struct, call mesh_init(), and return the opaque
/// context pointer.
///
/// This function runs once at startup.  It reads optional configuration from
/// environment variables so that the binary can be tested without recompiling.
Pointer<Void> _initContext(
  _BackendBindings bindings,
  int nodeMode, {
  String? configPath,
}) {
  // Prefer an explicitly passed configPath; fall back to the environment variable.
  // M15: env-var overrides are only honoured in debug builds. In release builds
  // they are silently ignored so that MDM/shell env cannot redirect config paths.
  final envConfigPath = kDebugMode
      ? Platform.environment['MESH_CONFIG_PATH']?.trim()
      : null;
  final resolvedPath = (configPath != null && configPath.isNotEmpty)
      ? configPath
      : (envConfigPath != null && envConfigPath.isNotEmpty)
          ? envConfigPath
          : null;

  // Allow overriding the WireGuard UDP port at runtime for testing (debug only).
  final wireguardPort = kDebugMode
      ? int.tryParse((Platform.environment['MESH_WIREGUARD_PORT'] ?? '').trim())
      : null;

  // Convert the optional config path string into a native C pointer.
  // If no path is given, use the null pointer (Rust interprets this as "default").
  final configPathPtr = resolvedPath != null
      ? resolvedPath.toNativeUtf8()
      : nullptr;

  // Allocate a FfiMeshConfig struct in NATIVE (non-GC) memory.
  //
  // WHY calloc?
  // `calloc` allocates memory outside of Dart's garbage-collected heap, in the
  // same memory space that C/Rust code can access.  Dart's normal `new` keyword
  // allocates inside the Dart heap, which Rust cannot safely touch.
  // calloc also zero-initialises the memory, which is important for structs.
  //
  // `calloc<FfiMeshConfig>()` is equivalent to:
  //   FfiMeshConfig* config = calloc(1, sizeof(FfiMeshConfig));
  // in C.
  final config = calloc<FfiMeshConfig>();

  // Fill each field of the struct via the `.ref` accessor, which lets us
  // write Dart-side field assignments that map directly to the C struct layout.
  config.ref
    ..configPath = configPathPtr
    ..logLevel = 2          // 2 = INFO level in Rust's log crate convention
    ..enableTor = 1         // Start with Tor enabled by default
    ..enableClearnet = 0    // Clearnet disabled by default (privacy-first posture)
    ..meshDiscovery = 1     // Enable local-network peer discovery
    ..allowRelays = 1       // Allow peers to act as relay nodes
    ..enableI2p = 0         // I2P disabled until more mature
    ..enableBluetooth = 0   // Bluetooth transport off by default
    ..enableRf = 0          // RF (radio) transport off by default
    ..wireguardPort =
        (wireguardPort != null && wireguardPort > 0 && wireguardPort <= 65535)
        ? wireguardPort
        : 0                 // 0 means "let Rust pick a free port"
    ..maxPeers = 0          // 0 means "no limit" in Rust
    ..maxConnections = 0
    ..nodeMode = nodeMode;

  // Pass the filled struct to Rust.  Rust copies what it needs internally.
  final context = bindings.meshInit(config);

  // Free both the struct and the configPath string — Rust already copied them.
  calloc.free(config);
  if (configPathPtr != nullptr) calloc.free(configPathPtr);

  return context;
}

/// Detect the current platform and open the Rust shared library by its
/// platform-specific filename.
///
/// WHY DIFFERENT NAMES PER PLATFORM?
///   - Linux / Android: libXXX.so   (Executable and Linkable Format shared object)
///   - macOS / iOS:     libXXX.dylib (Mach-O dynamic library)
///   - Windows:         XXX.dll      (Portable Executable dynamic-link library)
///   - iOS (device):    DynamicLibrary.process() — on iOS, static linking is
///                      required; all symbols end up in the main process binary.
///
/// DynamicLibrary.open() loads the file, resolves its symbols, and returns a
/// handle we can call lookupFunction() on.
DynamicLibrary _openLibrary() {
  if (Platform.isAndroid) return DynamicLibrary.open('libmesh_infinity.so');
  if (Platform.isIOS) return DynamicLibrary.process();
  if (Platform.isMacOS) return DynamicLibrary.process(); // statically linked
  if (Platform.isWindows) return DynamicLibrary.open('mesh_infinity.dll');
  // Default to Linux .so for any other platform (e.g. desktop Linux, CI).
  return DynamicLibrary.open('libmesh_infinity.so');
}

// =============================================================================
// _BackendBindings
//
// This private class holds a resolved callable function for every exported
// Rust symbol we use.
//
// HOW DOES lookupFunction WORK?
// lib.lookupFunction<NativeType, DartType>('symbol_name') does two things:
//   1. Searches the loaded library for the exported symbol named 'symbol_name'.
//      This is equivalent to dlsym() in C.
//   2. Creates a Dart function wrapper around the native function pointer,
//      using the type parameters to know how to marshal arguments and return
//      values between Dart and C types.
//
// WHY TWO TYPE PARAMETERS (NativeType AND DartType)?
// Dart FFI needs to know the function signature TWICE:
//   - NativeType: how the function looks in C/Rust (uses C types like Int32,
//     Uint8, Pointer<Void>, Void, etc.)
//   - DartType: how we want to call it in Dart (uses Dart types like int, void,
//     Pointer<Void>, etc.)
//
// The FFI layer handles the conversion between the two automatically.
// For example, Rust's `u8` becomes `Uint8` in the Native signature and `int`
// in the Dart signature — Dart has no separate 8-bit integer type.
// =============================================================================

class _BackendBindings {
  /// Look up all Rust function symbols at construction time.
  /// If any symbol is missing, this throws immediately — fail fast.
  _BackendBindings(this._lib)
    : meshInit = _lib.lookupFunction<MeshInitNative, MeshInitDart>('mesh_init'),
      meshDestroy =
          _lib.lookupFunction<MeshDestroyNative, MeshDestroyDart>('mesh_destroy'),
      roomsJson =
          _lib.lookupFunction<RoomsJsonNative, RoomsJsonDart>('mi_rooms_json'),
      messagesJson = _lib
          .lookupFunction<MessagesJsonNative, MessagesJsonDart>('mi_messages_json'),
      peerListJson = _lib
          .lookupFunction<PeerListJsonNative, PeerListJsonDart>('mi_get_peer_list'),
      fileTransfersJson = _lib
          .lookupFunction<FileTransfersJsonNative, FileTransfersJsonDart>(
            'mi_file_transfers_json',
          ),
      activeRoomId = _lib
          .lookupFunction<ActiveRoomIdNative, ActiveRoomIdDart>('mi_active_room_id'),
      createRoom =
          _lib.lookupFunction<CreateRoomNative, CreateRoomDart>('mi_create_room'),
      selectRoom =
          _lib.lookupFunction<SelectRoomNative, SelectRoomDart>('mi_select_room'),
      deleteRoom =
          _lib.lookupFunction<DeleteRoomNative, DeleteRoomDart>('mi_delete_room'),
      sendTextMessage = _lib
          .lookupFunction<SendTextMessageNative, SendTextMessageDart>(
            'mi_send_text_message',
          ),
      deleteMessage = _lib
          .lookupFunction<DeleteMessageNative, DeleteMessageDart>('mi_delete_message'),
      setNodeMode =
          _lib.lookupFunction<SetNodeModeNative, SetNodeModeDart>('mi_set_node_mode'),
      settingsJson = _lib
          .lookupFunction<SettingsJsonNative, SettingsJsonDart>('mi_settings_json'),
      setTransportFlags = _lib
          .lookupFunction<SetTransportFlagsNative, SetTransportFlagsDart>(
            'mi_set_transport_flags',
          ),
      pairPeer =
          _lib.lookupFunction<PairPeerNative, PairPeerDart>('mi_pair_peer'),
      localIdentityJson = _lib
          .lookupFunction<LocalIdentityJsonNative, LocalIdentityJsonDart>(
            'mi_local_identity_json',
          ),
      trustAttest =
          _lib.lookupFunction<TrustAttestNative, TrustAttestDart>('mi_trust_attest'),
      trustVerifyJson = _lib
          .lookupFunction<TrustVerifyJsonNative, TrustVerifyJsonDart>(
            'mi_trust_verify_json',
          ),
      hasIdentity =
          _lib.lookupFunction<HasIdentityNative, HasIdentityDart>('mi_has_identity'),
      lastErrorMessage = _lib
          .lookupFunction<LastErrorMessageNative, LastErrorMessageDart>(
            'mi_last_error_message',
          ),
      stringFree =
          _lib.lookupFunction<StringFreeNative, StringFreeDart>('mi_string_free'),
      mdnsEnable =
          _lib.lookupFunction<MdnsEnableNative, MdnsEnableDart>('mi_mdns_enable'),
      mdnsDisable =
          _lib.lookupFunction<MdnsDisableNative, MdnsDisableDart>('mi_mdns_disable'),
      mdnsIsRunning = _lib
          .lookupFunction<MdnsIsRunningNative, MdnsIsRunningDart>('mi_mdns_is_running'),
      mdnsGetDiscoveredPeers = _lib
          .lookupFunction<MdnsGetDiscoveredPeersNative, MdnsGetDiscoveredPeersDart>(
            'mi_mdns_get_discovered_peers',
          ),
      getNetworkStats = _lib
          .lookupFunction<GetNetworkStatsNative, GetNetworkStatsDart>(
            'mi_get_network_stats',
          ),
      routingTableStats = _lib
          .lookupFunction<RoutingTableStatsNative, RoutingTableStatsDart>(
            'mi_routing_table_stats',
          ),
      routingLookup = _lib
          .lookupFunction<RoutingLookupNative, RoutingLookupDart>(
            'mi_routing_lookup',
          ),
      fileTransferStart = _lib
          .lookupFunction<FileTransferStartNative, FileTransferStartDart>(
            'mi_file_transfer_start',
          ),
      fileTransferCancel = _lib
          .lookupFunction<FileTransferCancelNative, FileTransferCancelDart>(
            'mi_file_transfer_cancel',
          ),
      fileTransferAccept = _lib
          .lookupFunction<FileTransferAcceptNative, FileTransferAcceptDart>(
            'mi_file_transfer_accept',
          ),
      getServiceList = _lib
          .lookupFunction<GetServiceListNative, GetServiceListDart>(
            'mi_get_service_list',
          ),
      configureService = _lib
          .lookupFunction<ConfigureServiceNative, ConfigureServiceDart>(
            'mi_configure_service',
          ),
      toggleTransportFlag = _lib
          .lookupFunction<ToggleTransportFlagNative, ToggleTransportFlagDart>(
            'mi_toggle_transport_flag',
          ),
      setVpnMode =
          _lib.lookupFunction<SetVpnModeNative, SetVpnModeDart>('mi_set_vpn_mode'),
      setExitNode =
          _lib.lookupFunction<SetExitNodeNative, SetExitNodeDart>('mi_set_exit_node'),
      setClearnetRoute = _lib
          .lookupFunction<SetClearnetRouteNative, SetClearnetRouteDart>(
            'mi_set_clearnet_route',
          ),
      createIdentity = _lib
          .lookupFunction<CreateIdentityNative, CreateIdentityDart>(
            'mi_create_identity',
          ),
      unlockIdentity = _lib
          .lookupFunction<UnlockIdentityNative, UnlockIdentityDart>(
            'mi_unlock_identity',
          ),
      setPublicProfile = _lib
          .lookupFunction<SetPublicProfileNative, SetPublicProfileDart>(
            'mi_set_public_profile',
          ),
      setPrivateProfile = _lib
          .lookupFunction<SetPrivateProfileNative, SetPrivateProfileDart>(
            'mi_set_private_profile',
          ),
      createBackup = _lib
          .lookupFunction<CreateBackupNative, CreateBackupDart>(
            'mi_create_backup',
          ),
      importIdentity = _lib
          .lookupFunction<ImportIdentityNative, ImportIdentityDart>(
            'mi_import_identity',
          ),
      resetIdentity = _lib
          .lookupFunction<ResetIdentityNative, ResetIdentityDart>(
            'mi_reset_identity',
          ),
      sendReaction = _lib
          .lookupFunction<SendReactionNative, SendReactionDart>(
            'mi_send_reaction',
          ),
      editMessage = _lib
          .lookupFunction<EditMessageNative, EditMessageDart>(
            'mi_edit_message',
          ),
      deleteForEveryone = _lib
          .lookupFunction<DeleteForEveryoneNative, DeleteForEveryoneDart>(
            'mi_delete_for_everyone',
          ),
      setDisappearingTimer = _lib
          .lookupFunction<SetDisappearingTimerNative, SetDisappearingTimerDart>(
            'mi_set_disappearing_timer',
          ),
      sendTypingIndicator = _lib
          .lookupFunction<SendTypingIndicatorNative, SendTypingIndicatorDart>(
            'mi_send_typing_indicator',
          ),
      sendReadReceipt = _lib
          .lookupFunction<SendReadReceiptNative, SendReadReceiptDart>(
            'mi_send_read_receipt',
          ),
      replyToMessage = _lib
          .lookupFunction<ReplyToMessageNative, ReplyToMessageDart>(
            'mi_reply_to_message',
          ),
      forwardMessage = _lib
          .lookupFunction<ForwardMessageNative, ForwardMessageDart>(
            'mi_forward_message',
          ),
      searchMessages = _lib
          .lookupFunction<SearchMessagesNative, SearchMessagesDart>(
            'mi_search_messages',
          ),
      pinMessage = _lib
          .lookupFunction<PinMessageNative, PinMessageDart>(
            'mi_pin_message',
          ),
      unpinMessage = _lib
          .lookupFunction<UnpinMessageNative, UnpinMessageDart>(
            'mi_unpin_message',
          ),
      pruneExpiredMessages = _lib
          .lookupFunction<PruneExpiredMessagesNative, PruneExpiredMessagesDart>(
            'mi_prune_expired_messages',
          ),
      getVpnStatus =
          _lib.lookupFunction<GetVpnStatusNative, GetVpnStatusDart>('mi_get_vpn_status'),
      emergencyErase = _lib
          .lookupFunction<EmergencyEraseNative, EmergencyEraseDart>(
            'mi_emergency_erase',
          ),
      duressErase = _lib
          .lookupFunction<DuressEraseNative, DuressEraseDart>(
            'mi_duress_erase',
          ),
      sdrConfigure = _lib
          .lookupFunction<SdrConfigureNative, SdrConfigureDart>(
            'mi_sdr_configure',
          ),
      sdrStatus = _lib
          .lookupFunction<SdrStatusNative, SdrStatusDart>(
            'mi_sdr_status',
          ),
      sdrCurrentChannel = _lib
          .lookupFunction<SdrCurrentChannelNative, SdrCurrentChannelDart>(
            'mi_sdr_current_channel',
          ),
      sdrListProfiles = _lib
          .lookupFunction<SdrListProfilesNative, SdrListProfilesDart>(
            'mi_sdr_list_profiles',
          ),
      sdrListHardware = _lib
          .lookupFunction<SdrListHardwareNative, SdrListHardwareDart>(
            'mi_sdr_list_hardware',
          ),
      tailscaleAuthKey = _lib
          .lookupFunction<TailscaleAuthKeyNative, TailscaleAuthKeyDart>(
            'mi_tailscale_auth_key',
          ),
      tailscaleBeginOAuth = _lib
          .lookupFunction<TailscaleBeginOAuthNative, TailscaleBeginOAuthDart>(
            'mi_tailscale_begin_oauth',
          ),
      zerotierConnect = _lib
          .lookupFunction<ZeroTierConnectNative, ZeroTierConnectDart>(
            'mi_zerotier_connect',
          ),
      overlayStatus = _lib
          .lookupFunction<OverlayStatusNative, OverlayStatusDart>(
            'mi_overlay_status',
          ),
      loSecRequest = _lib
          .lookupFunction<LoSecRequestNative, LoSecRequestDart>(
            'mi_losec_request',
          ),
      loSecAmbientStatus = _lib
          .lookupFunction<LoSecAmbientStatusNative, LoSecAmbientStatusDart>(
            'mi_losec_ambient_status',
          ),
      getPairingPayload = _lib
          .lookupFunction<GetPairingPayloadNative, GetPairingPayloadDart>(
            'mi_get_pairing_payload',
          ),
      startClearnetListener = _lib
          .lookupFunction<StartClearnetListenerNative, StartClearnetListenerDart>(
            'mi_start_clearnet_listener',
          ),
      stopClearnetListener = _lib
          .lookupFunction<StopClearnetListenerNative, StopClearnetListenerDart>(
            'mi_stop_clearnet_listener',
          ),
      setClearnetPort = _lib
          .lookupFunction<SetClearnetPortNative, SetClearnetPortDart>(
            'mi_set_clearnet_port',
          ),
      setThreatContext = _lib
          .lookupFunction<SetThreatContextNative, SetThreatContextDart>(
            'mi_set_threat_context',
          ),
      getThreatContext = _lib
          .lookupFunction<GetThreatContextNative, GetThreatContextDart>(
            'mi_get_threat_context',
          ),
      setTrustLevel = _lib
          .lookupFunction<SetTrustLevelNative, SetTrustLevelDart>(
            'mi_set_trust_level',
          ),
      setConversationSecurityMode = _lib
          .lookupFunction<SetConversationSecurityModeNative, SetConversationSecurityModeDart>(
            'mi_set_conversation_security_mode',
          ),
      createGroup = _lib
          .lookupFunction<CreateGroupNative, CreateGroupDart>(
            'mi_create_group',
          ),
      listGroups = _lib
          .lookupFunction<ListGroupsNative, ListGroupsDart>(
            'mi_list_groups',
          ),
      groupMembers = _lib
          .lookupFunction<GroupMembersNative, GroupMembersDart>(
            'mi_group_members',
          ),
      leaveGroup = _lib
          .lookupFunction<LeaveGroupNative, LeaveGroupDart>(
            'mi_leave_group',
          ),
      groupSendMessage = _lib
          .lookupFunction<GroupSendMessageNative, GroupSendMessageDart>(
            'mi_group_send_message',
          ),
      groupInvitePeer = _lib
          .lookupFunction<GroupInvitePeerNative, GroupInvitePeerDart>(
            'mi_group_invite_peer',
          ),
      callOffer = _lib
          .lookupFunction<CallOfferNative, CallOfferDart>(
            'mi_call_offer',
          ),
      callAnswer = _lib
          .lookupFunction<CallAnswerNative, CallAnswerDart>(
            'mi_call_answer',
          ),
      callHangup = _lib
          .lookupFunction<CallHangupNative, CallHangupDart>(
            'mi_call_hangup',
          ),
      callStatus = _lib
          .lookupFunction<CallStatusNative, CallStatusDart>(
            'mi_call_status',
          ),
      getNotificationConfig = _lib
          .lookupFunction<GetNotificationConfigNative, GetNotificationConfigDart>(
            'mi_get_notification_config',
          ),
      setNotificationConfig = _lib
          .lookupFunction<SetNotificationConfigNative, SetNotificationConfigDart>(
            'mi_set_notification_config',
          ),
      wgInitiateHandshake = _lib
          .lookupFunction<WgInitiateHandshakeNative, WgInitiateHandshakeDart>(
            'mi_wg_initiate_handshake',
          ),
      wgRespondToHandshake = _lib
          .lookupFunction<WgRespondToHandshakeNative, WgRespondToHandshakeDart>(
            'mi_wg_respond_to_handshake',
          ),
      wgCompleteHandshake = _lib
          .lookupFunction<WgCompleteHandshakeNative, WgCompleteHandshakeDart>(
            'mi_wg_complete_handshake',
          ),
      gardenPosts = _lib
          .lookupFunction<GardenPostsNative, GardenPostsDart>(
            'mi_garden_posts',
          ),
      gardenDiscover = _lib
          .lookupFunction<GardenDiscoverNative, GardenDiscoverDart>(
            'mi_garden_discover',
          ),
      gardenPost = _lib
          .lookupFunction<GardenPostNative, GardenPostDart>(
            'mi_garden_post',
          ),
      storageStats = _lib
          .lookupFunction<StorageStatsNative, StorageStatsDart>(
            'mi_storage_stats',
          ),
      publishedFiles = _lib
          .lookupFunction<PublishedFilesNative, PublishedFilesDart>(
            'mi_published_files',
          ),
      publishFile = _lib
          .lookupFunction<PublishFileNative, PublishFileDart>(
            'mi_publish_file',
          ),
      unpublishFile = _lib
          .lookupFunction<UnpublishFileNative, UnpublishFileDart>(
            'mi_unpublish_file',
          ),
      meshServicesDiscover = _lib
          .lookupFunction<MeshServicesDiscoverNative, MeshServicesDiscoverDart>(
            'mi_mesh_services_discover',
          ),
      hostingConfig = _lib
          .lookupFunction<HostingConfigNative, HostingConfigDart>(
            'mi_hosting_config',
          ),
      hostingSet = _lib
          .lookupFunction<HostingSetNative, HostingSetDart>(
            'mi_hosting_set',
          ),
      messageRequestsJson = _lib
          .lookupFunction<MessageRequestsJsonNative, MessageRequestsJsonDart>(
            'mi_message_requests_json',
          ),
      acceptMessageRequestFn = _lib
          .lookupFunction<AcceptMessageRequestNative, AcceptMessageRequestDart>(
            'mi_accept_message_request',
          ),
      declineMessageRequestFn = _lib
          .lookupFunction<DeclineMessageRequestNative, DeclineMessageRequestDart>(
            'mi_decline_message_request',
          );

  // Keep a reference to the library so it is not garbage-collected while
  // any of our function pointers are still alive.
  // ignore: unused_field
  final DynamicLibrary _lib;

  // Each field below is a Dart function that directly invokes a Rust symbol.
  // Calling `meshInit(configPtr)` here is exactly like calling
  // `mesh_init(configPtr)` from C.
  final MeshInitDart meshInit;
  final MeshDestroyDart meshDestroy;
  final RoomsJsonDart roomsJson;
  final MessagesJsonDart messagesJson;
  final PeerListJsonDart peerListJson;
  final FileTransfersJsonDart fileTransfersJson;
  final ActiveRoomIdDart activeRoomId;
  final CreateRoomDart createRoom;
  final SelectRoomDart selectRoom;
  final DeleteRoomDart deleteRoom;
  final SendTextMessageDart sendTextMessage;
  final DeleteMessageDart deleteMessage;
  final SetNodeModeDart setNodeMode;
  final SettingsJsonDart settingsJson;
  final SetTransportFlagsDart setTransportFlags;
  final PairPeerDart pairPeer;
  final LocalIdentityJsonDart localIdentityJson;
  final TrustAttestDart trustAttest;
  final TrustVerifyJsonDart trustVerifyJson;
  final HasIdentityDart hasIdentity;
  final LastErrorMessageDart lastErrorMessage;
  final StringFreeDart stringFree;
  final MdnsEnableDart mdnsEnable;
  final MdnsDisableDart mdnsDisable;
  final MdnsIsRunningDart mdnsIsRunning;
  final MdnsGetDiscoveredPeersDart mdnsGetDiscoveredPeers;
  final GetNetworkStatsDart getNetworkStats;
  final RoutingTableStatsDart routingTableStats;
  final RoutingLookupDart routingLookup;
  final FileTransferStartDart fileTransferStart;
  final FileTransferCancelDart fileTransferCancel;
  final FileTransferAcceptDart fileTransferAccept;
  final GetServiceListDart getServiceList;
  final ConfigureServiceDart configureService;
  final ToggleTransportFlagDart toggleTransportFlag;
  final SetVpnModeDart setVpnMode;
  final SetExitNodeDart setExitNode;
  final SetClearnetRouteDart setClearnetRoute;
  final CreateIdentityDart createIdentity;
  final UnlockIdentityDart unlockIdentity;
  final SetPublicProfileDart setPublicProfile;
  final SetPrivateProfileDart setPrivateProfile;
  final CreateBackupDart createBackup;
  final ImportIdentityDart importIdentity;
  final ResetIdentityDart resetIdentity;
  final SendReactionDart sendReaction;
  final EditMessageDart editMessage;
  final DeleteForEveryoneDart deleteForEveryone;
  final SetDisappearingTimerDart setDisappearingTimer;
  final SendTypingIndicatorDart sendTypingIndicator;
  final SendReadReceiptDart sendReadReceipt;
  final ReplyToMessageDart replyToMessage;
  final ForwardMessageDart forwardMessage;
  final SearchMessagesDart searchMessages;
  final PinMessageDart pinMessage;
  final UnpinMessageDart unpinMessage;
  final PruneExpiredMessagesDart pruneExpiredMessages;
  final GetVpnStatusDart getVpnStatus;
  final EmergencyEraseDart emergencyErase;
  final DuressEraseDart duressErase;
  final SdrConfigureDart sdrConfigure;
  final SdrStatusDart sdrStatus;
  final SdrCurrentChannelDart sdrCurrentChannel;
  final SdrListProfilesDart sdrListProfiles;
  final SdrListHardwareDart sdrListHardware;
  final TailscaleAuthKeyDart tailscaleAuthKey;
  final TailscaleBeginOAuthDart tailscaleBeginOAuth;
  final ZeroTierConnectDart zerotierConnect;
  final OverlayStatusDart overlayStatus;
  final LoSecRequestDart loSecRequest;
  final LoSecAmbientStatusDart loSecAmbientStatus;
  final GetPairingPayloadDart getPairingPayload;
  final StartClearnetListenerDart startClearnetListener;
  final StopClearnetListenerDart stopClearnetListener;
  final SetClearnetPortDart setClearnetPort;
  final SetThreatContextDart setThreatContext;
  final GetThreatContextDart getThreatContext;
  final SetTrustLevelDart setTrustLevel;
  final SetConversationSecurityModeDart setConversationSecurityMode;
  final CreateGroupDart createGroup;
  final ListGroupsDart listGroups;
  final GroupMembersDart groupMembers;
  final LeaveGroupDart leaveGroup;
  final GroupSendMessageDart groupSendMessage;
  final GroupInvitePeerDart groupInvitePeer;
  final CallOfferDart callOffer;
  final CallAnswerDart callAnswer;
  final CallHangupDart callHangup;
  final CallStatusDart callStatus;
  final GetNotificationConfigDart getNotificationConfig;
  final SetNotificationConfigDart setNotificationConfig;
  final WgInitiateHandshakeDart wgInitiateHandshake;
  final WgRespondToHandshakeDart wgRespondToHandshake;
  final WgCompleteHandshakeDart wgCompleteHandshake;
  // Garden
  final GardenPostsDart gardenPosts;
  final GardenDiscoverDart gardenDiscover;
  final GardenPostDart gardenPost;
  // Storage
  final StorageStatsDart storageStats;
  final PublishedFilesDart publishedFiles;
  final PublishFileDart publishFile;
  final UnpublishFileDart unpublishFile;
  // Services hosting + discovery
  final MeshServicesDiscoverDart meshServicesDiscover;
  final HostingConfigDart hostingConfig;
  final HostingSetDart hostingSet;
  // Message requests (§10.1.1)
  final MessageRequestsJsonDart messageRequestsJson;
  final AcceptMessageRequestDart acceptMessageRequestFn;
  final DeclineMessageRequestDart declineMessageRequestFn;
}

// =============================================================================
// FFI Struct: FfiMeshConfig
//
// WHAT IS A STRUCT IN FFI CONTEXT?
// A Dart FFI `Struct` is a Dart class whose memory layout exactly mirrors a
// C struct.  When we write `calloc<FfiMeshConfig>()`, Dart allocates a block
// of native memory with the same byte layout as the corresponding C struct
// defined on the Rust side.  Rust can then read the fields directly from that
// memory without any copying or conversion.
//
// The annotations like @Uint8() and @Uint16() tell the FFI layer how many
// bytes each field occupies and how they are encoded.  They MUST match the
// types in the Rust #[repr(C)] struct exactly, or the fields will be read
// from the wrong byte offsets (a very hard-to-debug class of bug).
//
// Rust side (for reference, in backend/ffi/lib.rs):
//   #[repr(C)]
//   pub struct FfiMeshConfig {
//       pub config_path: *const c_char,
//       pub log_level: u8,
//       pub enable_tor: u8,
//       ...
//   }
// =============================================================================

base class FfiMeshConfig extends Struct {
  /// Pointer to a null-terminated UTF-8 string holding the config directory
  /// path.  May be null (nullptr) to use the Rust-side default.
  external Pointer<Utf8> configPath;

  /// Logging verbosity: 0=off, 1=error, 2=info, 3=debug, 4=trace.
  @Uint8()
  external int logLevel;

  /// 1 = route traffic through the Tor anonymity network, 0 = disabled.
  @Uint8()
  external int enableTor;

  /// 1 = allow direct clearnet (plain internet) connections, 0 = disabled.
  @Uint8()
  external int enableClearnet;

  /// 1 = enable local-network peer discovery (mDNS / UDP broadcast), 0 = off.
  @Uint8()
  external int meshDiscovery;

  /// 1 = allow this node to act as a relay / TURN-style server for other peers.
  @Uint8()
  external int allowRelays;

  /// 1 = route traffic through the I2P garlic routing network, 0 = disabled.
  @Uint8()
  external int enableI2p;

  /// 1 = enable Bluetooth low-energy peer discovery and data transport.
  @Uint8()
  external int enableBluetooth;

  /// 1 = enable software-defined radio (RF) transport (LoRa, etc.).
  @Uint8()
  external int enableRf;

  /// UDP port for the WireGuard VPN tunnel.  0 = let Rust pick a free port.
  /// Must fit in a 16-bit unsigned integer (0–65535).
  @Uint16()
  external int wireguardPort;

  /// Maximum number of peers to maintain connections to.  0 = unlimited.
  @Uint32()
  external int maxPeers;

  /// Maximum number of simultaneous network connections.  0 = unlimited.
  @Uint32()
  external int maxConnections;

  /// Node operating mode integer (e.g. 0=standard leaf, 1=relay, 2=gateway).
  @Uint8()
  external int nodeMode;
}

// =============================================================================
// FFI Typedefs
//
// Every Rust function we call needs TWO type definitions:
//
//   typedef XxxNative = <return> Function(<args using C types>);
//   typedef XxxDart   = <return> Function(<args using Dart types>);
//
// The "Native" typedef describes the function as it exists in C/Rust.
// The "Dart"   typedef describes how we call it from Dart code.
//
// C types → Dart types mapping used here:
//   Void          → void        (no return value)
//   Int32         → int         (32-bit signed integer)
//   Uint8         → int         (8-bit unsigned, Dart has no u8 type)
//   Uint16        → int         (16-bit unsigned)
//   Uint32        → int         (32-bit unsigned)
//   Pointer<Void> → Pointer<Void> (same — it's just an address)
//   Pointer<Utf8> → Pointer<Utf8> (same — pointer to C string bytes)
//
// IMPORTANT: these must EXACTLY match the extern "C" function signatures
// exported by the Rust library.  A mismatch causes undefined behaviour
// (crashes, corrupted data) and is not caught at compile time.
// =============================================================================

// mesh_init(config: *const FfiMeshConfig) -> *mut MeshContext
// Creates the Rust context; returns a pointer to it (or null on failure).
typedef MeshInitNative = Pointer<Void> Function(Pointer<FfiMeshConfig>);
typedef MeshInitDart = Pointer<Void> Function(Pointer<FfiMeshConfig>);

// mesh_destroy(ctx: *mut MeshContext)
// Cleanly shuts down and frees the Rust context.
typedef MeshDestroyNative = Void Function(Pointer<Void>);
typedef MeshDestroyDart = void Function(Pointer<Void>);

// mi_rooms_json(ctx: *mut MeshContext) -> *mut c_char
// Returns a JSON array string of all rooms.  Caller must free via mi_string_free.
typedef RoomsJsonNative = Pointer<Utf8> Function(Pointer<Void>);
typedef RoomsJsonDart = Pointer<Utf8> Function(Pointer<Void>);

// mi_messages_json(ctx, room_id: *const c_char) -> *mut c_char
// Returns a JSON array of messages for the given room (null room_id = active room).
typedef MessagesJsonNative = Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>);
typedef MessagesJsonDart = Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>);

// mi_get_peer_list(ctx) -> *mut c_char
typedef PeerListJsonNative = Pointer<Utf8> Function(Pointer<Void>);
typedef PeerListJsonDart = Pointer<Utf8> Function(Pointer<Void>);

// mi_file_transfers_json(ctx) -> *mut c_char
typedef FileTransfersJsonNative = Pointer<Utf8> Function(Pointer<Void>);
typedef FileTransfersJsonDart = Pointer<Utf8> Function(Pointer<Void>);

// mi_active_room_id(ctx) -> *mut c_char  (may be null if no room selected)
typedef ActiveRoomIdNative = Pointer<Utf8> Function(Pointer<Void>);
typedef ActiveRoomIdDart = Pointer<Utf8> Function(Pointer<Void>);

// mi_create_room(ctx, name: *const c_char) -> *mut c_char (new room ID)
typedef CreateRoomNative = Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>);
typedef CreateRoomDart = Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>);

// mi_select_room(ctx, room_id: *const c_char) -> i32  (0=ok)
typedef SelectRoomNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef SelectRoomDart = int Function(Pointer<Void>, Pointer<Utf8>);

// mi_delete_room(ctx, room_id: *const c_char) -> i32  (0=ok)
typedef DeleteRoomNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef DeleteRoomDart = int Function(Pointer<Void>, Pointer<Utf8>);

// mi_send_text_message(ctx, room_id: *const c_char, text: *const c_char) -> i32
typedef SendTextMessageNative =
    Int32 Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);
typedef SendTextMessageDart =
    int Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);

// mi_delete_message(ctx, message_id: *const c_char) -> i32
typedef DeleteMessageNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef DeleteMessageDart = int Function(Pointer<Void>, Pointer<Utf8>);

// mi_set_node_mode(ctx, mode: u8) -> i32
typedef SetNodeModeNative = Int32 Function(Pointer<Void>, Uint8);
typedef SetNodeModeDart = int Function(Pointer<Void>, int);

// mi_settings_json(ctx) -> *mut c_char
typedef SettingsJsonNative = Pointer<Utf8> Function(Pointer<Void>);
typedef SettingsJsonDart = Pointer<Utf8> Function(Pointer<Void>);

// mi_set_transport_flags(ctx, tor, clearnet, discovery, relays, i2p, bt) -> i32
typedef SetTransportFlagsNative =
    Int32 Function(Pointer<Void>, Uint8, Uint8, Uint8, Uint8, Uint8, Uint8);
typedef SetTransportFlagsDart =
    int Function(Pointer<Void>, int, int, int, int, int, int);

// mi_pair_peer(ctx, pairing_code: *const c_char) -> i32
typedef PairPeerNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef PairPeerDart = int Function(Pointer<Void>, Pointer<Utf8>);

// mi_local_identity_json(ctx) -> *mut c_char
typedef LocalIdentityJsonNative = Pointer<Utf8> Function(Pointer<Void>);
typedef LocalIdentityJsonDart = Pointer<Utf8> Function(Pointer<Void>);

// mi_trust_attest(ctx, endorser_id, target_id, trust_level: i32, method: u8) -> i32
typedef TrustAttestNative =
    Int32 Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, Int32, Uint8);
typedef TrustAttestDart =
    int Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, int, int);

// mi_trust_verify_json(ctx, target_id, markers_json) -> *mut c_char
typedef TrustVerifyJsonNative =
    Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);
typedef TrustVerifyJsonDart =
    Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);

// mi_has_identity(ctx) -> u8  (1=yes, 0=no)
typedef HasIdentityNative = Uint8 Function(Pointer<Void>);
typedef HasIdentityDart = int Function(Pointer<Void>);

// mi_last_error_message() -> *mut c_char  (no ctx — reads thread-local storage)
typedef LastErrorMessageNative = Pointer<Utf8> Function();
typedef LastErrorMessageDart = Pointer<Utf8> Function();

// mi_string_free(ptr: *mut c_char)
// Frees a string that was allocated by the Rust library.
// NEVER pass a pointer obtained from Dart here — only pass Rust-allocated ones.
typedef StringFreeNative = Void Function(Pointer<Utf8>);
typedef StringFreeDart = void Function(Pointer<Utf8>);

// mi_mdns_enable(ctx, port: u16) -> i32
typedef MdnsEnableNative = Int32 Function(Pointer<Void>, Uint16);
typedef MdnsEnableDart = int Function(Pointer<Void>, int);

// mi_mdns_disable(ctx) -> i32
typedef MdnsDisableNative = Int32 Function(Pointer<Void>);
typedef MdnsDisableDart = int Function(Pointer<Void>);

// mi_mdns_is_running(ctx) -> i32  (1=running, 0=stopped)
typedef MdnsIsRunningNative = Int32 Function(Pointer<Void>);
typedef MdnsIsRunningDart = int Function(Pointer<Void>);

// mi_mdns_get_discovered_peers(ctx) -> *mut c_char  (JSON array)
typedef MdnsGetDiscoveredPeersNative = Pointer<Utf8> Function(Pointer<Void>);
typedef MdnsGetDiscoveredPeersDart = Pointer<Utf8> Function(Pointer<Void>);

// mi_routing_table_stats(ctx) -> *const c_char (JSON)
typedef RoutingTableStatsNative = Pointer<Utf8> Function(Pointer<Void>);
typedef RoutingTableStatsDart   = Pointer<Utf8> Function(Pointer<Void>);

// mi_routing_lookup(ctx, dest_peer_id_hex) -> *const c_char (JSON)
typedef RoutingLookupNative = Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>);
typedef RoutingLookupDart   = Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>);

// mi_get_network_stats(ctx) -> *mut c_char  (JSON object)
typedef GetNetworkStatsNative = Pointer<Utf8> Function(Pointer<Void>);
typedef GetNetworkStatsDart = Pointer<Utf8> Function(Pointer<Void>);

// mi_file_transfer_start(ctx, direction, peer_id, file_path) -> *mut c_char
typedef FileTransferStartNative =
    Pointer<Utf8> Function(
      Pointer<Void>,
      Pointer<Utf8>,
      Pointer<Utf8>,
      Pointer<Utf8>,
    );
typedef FileTransferStartDart =
    Pointer<Utf8> Function(
      Pointer<Void>,
      Pointer<Utf8>,
      Pointer<Utf8>,
      Pointer<Utf8>,
    );

// mi_file_transfer_cancel(ctx, transfer_id: *const c_char) -> i32
typedef FileTransferCancelNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef FileTransferCancelDart = int Function(Pointer<Void>, Pointer<Utf8>);

// mi_file_transfer_accept(ctx, transfer_id, save_path) -> i32
typedef FileTransferAcceptNative = Int32 Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);
typedef FileTransferAcceptDart = int Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);

// mi_get_service_list(ctx) -> *mut c_char  (JSON array)
typedef GetServiceListNative = Pointer<Utf8> Function(Pointer<Void>);
typedef GetServiceListDart = Pointer<Utf8> Function(Pointer<Void>);

// mi_configure_service(ctx, service_id, config_json) -> i32
typedef ConfigureServiceNative =
    Int32 Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);
typedef ConfigureServiceDart =
    int Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);

// mi_toggle_transport_flag(ctx, transport_name, enabled: i32) -> i32
typedef ToggleTransportFlagNative =
    Int32 Function(Pointer<Void>, Pointer<Utf8>, Int32);
typedef ToggleTransportFlagDart =
    int Function(Pointer<Void>, Pointer<Utf8>, int);

// mi_set_vpn_mode(ctx, mode_json: *const c_char) -> i32
typedef SetVpnModeNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef SetVpnModeDart = int Function(Pointer<Void>, Pointer<Utf8>);

// mi_set_exit_node(ctx, peer_id_hex: *const c_char) -> i32
typedef SetExitNodeNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef SetExitNodeDart = int Function(Pointer<Void>, Pointer<Utf8>);

// mi_set_clearnet_route(ctx, route_config_json: *const c_char) -> i32
typedef SetClearnetRouteNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef SetClearnetRouteDart = int Function(Pointer<Void>, Pointer<Utf8>);

// mi_create_identity(ctx, name: *const c_char) -> i32  (name may be nullptr)
typedef CreateIdentityNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef CreateIdentityDart = int Function(Pointer<Void>, Pointer<Utf8>);

// mi_unlock_identity(ctx, pin: *const c_char) -> i32  (pin may be nullptr for no-PIN)
typedef UnlockIdentityNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef UnlockIdentityDart = int Function(Pointer<Void>, Pointer<Utf8>);

// mi_set_public_profile(ctx, profile_json: *const c_char) -> i32
typedef SetPublicProfileNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef SetPublicProfileDart = int Function(Pointer<Void>, Pointer<Utf8>);

// mi_set_private_profile(ctx, profile_json: *const c_char) -> i32
typedef SetPrivateProfileNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef SetPrivateProfileDart = int Function(Pointer<Void>, Pointer<Utf8>);

// mi_create_backup(ctx, passphrase, backup_type) -> *const c_char  (JSON EncryptedBackup)
// backup_type: 0=full, 1=identity_only
typedef CreateBackupNative =
    Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>, Uint8);
typedef CreateBackupDart =
    Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>, int);

// mi_import_identity(ctx, backup_json, passphrase) -> i32
typedef ImportIdentityNative =
    Int32 Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);
typedef ImportIdentityDart =
    int Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);

// mi_reset_identity(ctx) -> i32  (0=ok; this is irreversible!)
typedef ResetIdentityNative = Int32 Function(Pointer<Void>);
typedef ResetIdentityDart = int Function(Pointer<Void>);

// mi_send_reaction(ctx, room_id, message_id, emoji) -> i32
typedef SendReactionNative =
    Int32 Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>);
typedef SendReactionDart =
    int Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>);

// mi_edit_message(ctx, room_id, message_id, new_text) -> i32
typedef EditMessageNative =
    Int32 Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>);
typedef EditMessageDart =
    int Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>);

// mi_delete_for_everyone(ctx, room_id, message_id) -> i32
typedef DeleteForEveryoneNative =
    Int32 Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);
typedef DeleteForEveryoneDart =
    int Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);

// mi_set_disappearing_timer(ctx, room_id, duration_secs: i32) -> i32
typedef SetDisappearingTimerNative =
    Int32 Function(Pointer<Void>, Pointer<Utf8>, Int32);
typedef SetDisappearingTimerDart =
    int Function(Pointer<Void>, Pointer<Utf8>, int);

// mi_send_typing_indicator(ctx, room_id, is_typing: i32) -> i32
typedef SendTypingIndicatorNative =
    Int32 Function(Pointer<Void>, Pointer<Utf8>, Int32);
typedef SendTypingIndicatorDart =
    int Function(Pointer<Void>, Pointer<Utf8>, int);

// mi_send_read_receipt(ctx, room_id, message_id) -> i32
typedef SendReadReceiptNative =
    Int32 Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);
typedef SendReadReceiptDart =
    int Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);

// mi_reply_to_message(ctx, room_id, parent_id, text) -> i32
typedef ReplyToMessageNative =
    Int32 Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>);
typedef ReplyToMessageDart =
    int Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>);

// mi_forward_message(ctx, from_room_id, message_id, to_room_id) -> i32
typedef ForwardMessageNative =
    Int32 Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>);
typedef ForwardMessageDart =
    int Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>);

// mi_search_messages(ctx, query) -> *const c_char  (JSON array)
typedef SearchMessagesNative =
    Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>);
typedef SearchMessagesDart =
    Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>);

// mi_pin_message(ctx, room_id, message_id) -> i32
typedef PinMessageNative =
    Int32 Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);
typedef PinMessageDart =
    int Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);

// mi_unpin_message(ctx, room_id, message_id) -> i32
typedef UnpinMessageNative =
    Int32 Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);
typedef UnpinMessageDart =
    int Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);

// mi_prune_expired_messages(ctx) -> i32
typedef PruneExpiredMessagesNative = Int32 Function(Pointer<Void>);
typedef PruneExpiredMessagesDart = int Function(Pointer<Void>);

// mi_get_vpn_status(ctx) -> *const c_char  (JSON VPN state)
typedef GetVpnStatusNative = Pointer<Utf8> Function(Pointer<Void>);
typedef GetVpnStatusDart = Pointer<Utf8> Function(Pointer<Void>);

// mi_emergency_erase(ctx) -> i32  (standard killswitch — destroys all layers)
typedef EmergencyEraseNative = Int32 Function(Pointer<Void>);
typedef EmergencyEraseDart = int Function(Pointer<Void>);

// mi_duress_erase(ctx) -> i32  (duress killswitch — preserves Layer 1)
typedef DuressEraseNative = Int32 Function(Pointer<Void>);
typedef DuressEraseDart = int Function(Pointer<Void>);

// mi_sdr_configure(ctx, config_json) -> i32
typedef SdrConfigureNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef SdrConfigureDart = int Function(Pointer<Void>, Pointer<Utf8>);

// mi_sdr_status(ctx) -> *const c_char  (JSON SDR state)
typedef SdrStatusNative = Pointer<Utf8> Function(Pointer<Void>);
typedef SdrStatusDart = Pointer<Utf8> Function(Pointer<Void>);

// mi_sdr_current_channel(ctx) -> *const c_char  (JSON current FHSS channel)
typedef SdrCurrentChannelNative = Pointer<Utf8> Function(Pointer<Void>);
typedef SdrCurrentChannelDart = Pointer<Utf8> Function(Pointer<Void>);

// mi_sdr_list_profiles(ctx) -> *const c_char  (JSON array of profiles)
typedef SdrListProfilesNative = Pointer<Utf8> Function(Pointer<Void>);
typedef SdrListProfilesDart = Pointer<Utf8> Function(Pointer<Void>);

// mi_sdr_list_hardware(ctx) -> *const c_char  (JSON array of hardware types)
typedef SdrListHardwareNative = Pointer<Utf8> Function(Pointer<Void>);
typedef SdrListHardwareDart = Pointer<Utf8> Function(Pointer<Void>);

// mi_tailscale_auth_key(ctx, auth_key, control_url) -> i32
typedef TailscaleAuthKeyNative = Int32 Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);
typedef TailscaleAuthKeyDart = int Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);

// mi_tailscale_begin_oauth(ctx, control_url) -> i32
typedef TailscaleBeginOAuthNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef TailscaleBeginOAuthDart = int Function(Pointer<Void>, Pointer<Utf8>);

// mi_zerotier_connect(ctx, api_key, controller_url, network_ids_json) -> i32
typedef ZeroTierConnectNative = Int32 Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>);
typedef ZeroTierConnectDart = int Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>);

// mi_overlay_status(ctx) -> *const c_char  (JSON overlay state)
typedef OverlayStatusNative = Pointer<Utf8> Function(Pointer<Void>);
typedef OverlayStatusDart = Pointer<Utf8> Function(Pointer<Void>);

// mi_losec_request(ctx, request_json) -> *const c_char  (JSON accepted/rejection)
typedef LoSecRequestNative = Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>);
typedef LoSecRequestDart = Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>);

// mi_losec_ambient_status(ctx) -> *const c_char  (JSON ambient traffic info)
typedef LoSecAmbientStatusNative = Pointer<Utf8> Function(Pointer<Void>);
typedef LoSecAmbientStatusDart = Pointer<Utf8> Function(Pointer<Void>);

// mi_get_pairing_payload(ctx) -> *const c_char  (JSON PairingPayload with keys + token)
typedef GetPairingPayloadNative = Pointer<Utf8> Function(Pointer<Void>);
typedef GetPairingPayloadDart = Pointer<Utf8> Function(Pointer<Void>);

// mi_start_clearnet_listener(ctx) -> i32  (0=ok, -1=fail)
typedef StartClearnetListenerNative = Int32 Function(Pointer<Void>);
typedef StartClearnetListenerDart = int Function(Pointer<Void>);

// mi_stop_clearnet_listener(ctx) -> i32
typedef StopClearnetListenerNative = Int32 Function(Pointer<Void>);
typedef StopClearnetListenerDart = int Function(Pointer<Void>);

// mi_set_clearnet_port(ctx, port: u16) -> i32
typedef SetClearnetPortNative = Int32 Function(Pointer<Void>, Uint16);
typedef SetClearnetPortDart = int Function(Pointer<Void>, int);

// mi_set_threat_context(ctx, level: u8) -> i32
typedef SetThreatContextNative = Int32 Function(Pointer<Void>, Uint8);
typedef SetThreatContextDart = int Function(Pointer<Void>, int);

// mi_get_threat_context(ctx) -> u8
typedef GetThreatContextNative = Uint8 Function(Pointer<Void>);
typedef GetThreatContextDart = int Function(Pointer<Void>);

// mi_set_trust_level(ctx, peer_id: *const c_char, level: u8) -> i32
typedef SetTrustLevelNative = Int32 Function(Pointer<Void>, Pointer<Utf8>, Uint8);
typedef SetTrustLevelDart = int Function(Pointer<Void>, Pointer<Utf8>, int);

// mi_set_conversation_security_mode(ctx, room_id: *const c_char, mode: u8) -> i32
typedef SetConversationSecurityModeNative =
    Int32 Function(Pointer<Void>, Pointer<Utf8>, Uint8);
typedef SetConversationSecurityModeDart =
    int Function(Pointer<Void>, Pointer<Utf8>, int);

// mi_create_group(ctx, name, description, network_type) -> *const c_char (JSON)
typedef CreateGroupNative =
    Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, Int32);
typedef CreateGroupDart =
    Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, int);

// mi_list_groups(ctx) -> *const c_char (JSON array)
typedef ListGroupsNative = Pointer<Utf8> Function(Pointer<Void>);
typedef ListGroupsDart = Pointer<Utf8> Function(Pointer<Void>);

// mi_group_members(ctx, group_id) -> *const c_char (JSON array)
typedef GroupMembersNative = Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>);
typedef GroupMembersDart = Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>);

// mi_leave_group(ctx, group_id) -> i32
typedef LeaveGroupNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef LeaveGroupDart = int Function(Pointer<Void>, Pointer<Utf8>);

// mi_group_send_message(ctx, group_id, text) -> i32
typedef GroupSendMessageNative =
    Int32 Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);
typedef GroupSendMessageDart =
    int Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);

// mi_group_invite_peer(ctx, group_id, peer_id) -> i32
typedef GroupInvitePeerNative =
    Int32 Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);
typedef GroupInvitePeerDart =
    int Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);

// mi_call_offer(ctx, peer_id_hex, is_video) -> *const c_char (JSON ok/error)
typedef CallOfferNative = Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>, Int32);
typedef CallOfferDart = Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>, int);

// mi_call_answer(ctx, call_id_hex, accept) -> i32
typedef CallAnswerNative = Int32 Function(Pointer<Void>, Pointer<Utf8>, Int32);
typedef CallAnswerDart = int Function(Pointer<Void>, Pointer<Utf8>, int);

// mi_call_hangup(ctx, call_id_hex) -> i32
typedef CallHangupNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef CallHangupDart = int Function(Pointer<Void>, Pointer<Utf8>);

// mi_call_status(ctx) -> *const c_char (JSON)
typedef CallStatusNative = Pointer<Utf8> Function(Pointer<Void>);
typedef CallStatusDart = Pointer<Utf8> Function(Pointer<Void>);

// mi_get_notification_config(ctx) -> *const c_char (JSON)
typedef GetNotificationConfigNative = Pointer<Utf8> Function(Pointer<Void>);
typedef GetNotificationConfigDart = Pointer<Utf8> Function(Pointer<Void>);

// mi_set_notification_config(ctx, json) -> i32
typedef SetNotificationConfigNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef SetNotificationConfigDart = int Function(Pointer<Void>, Pointer<Utf8>);

// mi_wg_initiate_handshake(ctx, peer_id_hex) -> *const c_char  (JSON)
typedef WgInitiateHandshakeNative = Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>);
typedef WgInitiateHandshakeDart = Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>);

// mi_wg_respond_to_handshake(ctx, peer_id_hex, init_hex) -> *const c_char  (JSON)
typedef WgRespondToHandshakeNative =
    Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);
typedef WgRespondToHandshakeDart =
    Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);

// mi_wg_complete_handshake(ctx, peer_id_hex, response_hex) -> *const c_char  (JSON)
typedef WgCompleteHandshakeNative =
    Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);
typedef WgCompleteHandshakeDart =
    Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);

// mi_garden_posts(ctx, garden_id) -> *const c_char  (JSON array of posts)
typedef GardenPostsNative = Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>);
typedef GardenPostsDart   = Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>);

// mi_garden_discover(ctx) -> *const c_char  (JSON array of discoverable gardens)
typedef GardenDiscoverNative = Pointer<Utf8> Function(Pointer<Void>);
typedef GardenDiscoverDart   = Pointer<Utf8> Function(Pointer<Void>);

// mi_garden_post(ctx, post_json) -> i32  (0 = success)
typedef GardenPostNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef GardenPostDart   = int   Function(Pointer<Void>, Pointer<Utf8>);

// mi_storage_stats(ctx) -> *const c_char  (JSON object)
typedef StorageStatsNative = Pointer<Utf8> Function(Pointer<Void>);
typedef StorageStatsDart   = Pointer<Utf8> Function(Pointer<Void>);

// mi_published_files(ctx) -> *const c_char  (JSON array of published file records)
typedef PublishedFilesNative = Pointer<Utf8> Function(Pointer<Void>);
typedef PublishedFilesDart   = Pointer<Utf8> Function(Pointer<Void>);

// mi_publish_file(ctx, path) -> i32  (0 = success)
typedef PublishFileNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef PublishFileDart   = int   Function(Pointer<Void>, Pointer<Utf8>);

// mi_unpublish_file(ctx, file_id) -> i32  (0 = success)
typedef UnpublishFileNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef UnpublishFileDart   = int   Function(Pointer<Void>, Pointer<Utf8>);

// mi_mesh_services_discover(ctx) -> *const c_char  (JSON array of mesh services)
typedef MeshServicesDiscoverNative = Pointer<Utf8> Function(Pointer<Void>);
typedef MeshServicesDiscoverDart   = Pointer<Utf8> Function(Pointer<Void>);

// mi_hosting_config(ctx) -> *const c_char  (JSON object of hosting flags)
typedef HostingConfigNative = Pointer<Utf8> Function(Pointer<Void>);
typedef HostingConfigDart   = Pointer<Utf8> Function(Pointer<Void>);

// mi_hosting_set(ctx, service_id, enabled) -> i32  (0 = success)
typedef HostingSetNative = Int32 Function(Pointer<Void>, Pointer<Utf8>, Int32);
typedef HostingSetDart   = int   Function(Pointer<Void>, Pointer<Utf8>, int);

// mi_message_requests_json(ctx) -> *const c_char  (JSON array of pending requests)
typedef MessageRequestsJsonNative = Pointer<Utf8> Function(Pointer<Void>);
typedef MessageRequestsJsonDart   = Pointer<Utf8> Function(Pointer<Void>);

// mi_accept_message_request(ctx, request_id) -> i32  (0 = success)
typedef AcceptMessageRequestNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef AcceptMessageRequestDart   = int   Function(Pointer<Void>, Pointer<Utf8>);

// mi_decline_message_request(ctx, request_id) -> i32  (0 = success)
typedef DeclineMessageRequestNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef DeclineMessageRequestDart   = int   Function(Pointer<Void>, Pointer<Utf8>);
