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
  /// background isolate then reconstructs a Pointer<Void> from that integer
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

  /// Persist the current in-memory identity to disk.
  /// Call once during onboarding after the user chooses "Create New Identity".
  bool createIdentity({String? name}) {
    if (!isAvailable) return false;
    // Pass nullptr when no name is given — Rust will use a default.
    final namePtr = name != null ? name.toNativeUtf8() : nullptr;
    final result = _bindings!.createIdentity(_context, namePtr);
    if (namePtr != nullptr) calloc.free(namePtr);
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

  /// Configure the VPN routing rules (sent as a JSON blob to Rust).
  bool setVpnRoute(Map<String, dynamic> routeConfig) {
    if (!isAvailable) return false;
    final ptr = jsonEncode(routeConfig).toNativeUtf8();
    final result = _bindings!.setVpnRoute(_context, ptr);
    calloc.free(ptr);
    return result != 0;
  }

  /// Configure the clearnet (plain internet) routing rules.
  bool setClearnetRoute(Map<String, dynamic> routeConfig) {
    if (!isAvailable) return false;
    final ptr = jsonEncode(routeConfig).toNativeUtf8();
    final result = _bindings!.setClearnetRoute(_context, ptr);
    calloc.free(ptr);
    return result != 0;
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

  /// Shut down the Rust backend cleanly.
  ///
  /// This calls mesh_destroy() which flushes any pending writes, closes
  /// network sockets, and frees all Rust-side memory.  Must be called when
  /// the app is closing to avoid resource leaks.
  void dispose() {
    if (isAvailable) _bindings!.meshDestroy(_context);
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /// Read a string from a Rust-allocated Pointer<Utf8> and immediately free
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
  final envConfigPath = Platform.environment['MESH_CONFIG_PATH']?.trim();
  final resolvedPath = (configPath != null && configPath.isNotEmpty)
      ? configPath
      : (envConfigPath != null && envConfigPath.isNotEmpty)
          ? envConfigPath
          : null;

  // Allow overriding the WireGuard UDP port at runtime for testing.
  final wireguardPort = int.tryParse(
    (Platform.environment['MESH_WIREGUARD_PORT'] ?? '').trim(),
  );

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
    ..enableClearnet = 1    // And clearnet (plain TCP/UDP) enabled
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
  if (Platform.isMacOS) return DynamicLibrary.open('libmesh_infinity.dylib');
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
      fileTransferStart = _lib
          .lookupFunction<FileTransferStartNative, FileTransferStartDart>(
            'mi_file_transfer_start',
          ),
      fileTransferCancel = _lib
          .lookupFunction<FileTransferCancelNative, FileTransferCancelDart>(
            'mi_file_transfer_cancel',
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
      setVpnRoute =
          _lib.lookupFunction<SetVpnRouteNative, SetVpnRouteDart>('mi_set_vpn_route'),
      setClearnetRoute = _lib
          .lookupFunction<SetClearnetRouteNative, SetClearnetRouteDart>(
            'mi_set_clearnet_route',
          ),
      createIdentity = _lib
          .lookupFunction<CreateIdentityNative, CreateIdentityDart>(
            'mi_create_identity',
          ),
      setPublicProfile = _lib
          .lookupFunction<SetPublicProfileNative, SetPublicProfileDart>(
            'mi_set_public_profile',
          ),
      setPrivateProfile = _lib
          .lookupFunction<SetPrivateProfileNative, SetPrivateProfileDart>(
            'mi_set_private_profile',
          ),
      importIdentity = _lib
          .lookupFunction<ImportIdentityNative, ImportIdentityDart>(
            'mi_import_identity',
          ),
      resetIdentity = _lib
          .lookupFunction<ResetIdentityNative, ResetIdentityDart>(
            'mi_reset_identity',
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
  final FileTransferStartDart fileTransferStart;
  final FileTransferCancelDart fileTransferCancel;
  final GetServiceListDart getServiceList;
  final ConfigureServiceDart configureService;
  final ToggleTransportFlagDart toggleTransportFlag;
  final SetVpnRouteDart setVpnRoute;
  final SetClearnetRouteDart setClearnetRoute;
  final CreateIdentityDart createIdentity;
  final SetPublicProfileDart setPublicProfile;
  final SetPrivateProfileDart setPrivateProfile;
  final ImportIdentityDart importIdentity;
  final ResetIdentityDart resetIdentity;
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

// mi_set_vpn_route(ctx, route_config_json: *const c_char) -> i32
typedef SetVpnRouteNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef SetVpnRouteDart = int Function(Pointer<Void>, Pointer<Utf8>);

// mi_set_clearnet_route(ctx, route_config_json: *const c_char) -> i32
typedef SetClearnetRouteNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef SetClearnetRouteDart = int Function(Pointer<Void>, Pointer<Utf8>);

// mi_create_identity(ctx, name: *const c_char) -> i32  (name may be nullptr)
typedef CreateIdentityNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef CreateIdentityDart = int Function(Pointer<Void>, Pointer<Utf8>);

// mi_set_public_profile(ctx, profile_json: *const c_char) -> i32
typedef SetPublicProfileNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef SetPublicProfileDart = int Function(Pointer<Void>, Pointer<Utf8>);

// mi_set_private_profile(ctx, profile_json: *const c_char) -> i32
typedef SetPrivateProfileNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef SetPrivateProfileDart = int Function(Pointer<Void>, Pointer<Utf8>);

// mi_import_identity(ctx, backup_json, passphrase) -> i32
typedef ImportIdentityNative =
    Int32 Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);
typedef ImportIdentityDart =
    int Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);

// mi_reset_identity(ctx) -> i32  (0=ok; this is irreversible!)
typedef ResetIdentityNative = Int32 Function(Pointer<Void>);
typedef ResetIdentityDart = int Function(Pointer<Void>);
