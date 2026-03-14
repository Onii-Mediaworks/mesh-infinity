import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';

import 'models/file_transfer_models.dart';
import 'models/message_models.dart';
import 'models/peer_models.dart';
import 'models/room_models.dart';
import 'models/settings_models.dart';

class BackendBridge {
  BackendBridge._(this._bindings, this._context, this._initError);

  factory BackendBridge.open({
    int nodeMode = 0,
    required bool allowMissing,
    String? configPath,
  }) {
    try {
      final bindings = _BackendBindings(_openLibrary());
      final context = _initContext(bindings, nodeMode, configPath: configPath);
      if (context == nullptr) {
        final error = _readLastError(bindings) ?? 'mesh_init returned null';
        debugPrint('BackendBridge: mesh_init failed: $error');
        if (allowMissing) {
          return BackendBridge._(bindings, context, error);
        }
        throw StateError(error);
      }
      return BackendBridge._(bindings, context, null);
    } catch (error, stack) {
      final message = 'BackendBridge: failed to load backend library: $error';
      debugPrint(message);
      debugPrint(stack.toString());
      if (allowMissing) {
        return BackendBridge._(null, nullptr, message);
      }
      throw StateError(message);
    }
  }

  final _BackendBindings? _bindings;
  final Pointer<Void> _context;
  final String? _initError;

  bool get isAvailable => _bindings != null && _context != nullptr;
  String? get initError => _initError;

  /// Raw context pointer address — used by the background event-polling isolate.
  int get contextAddress => _context.address;

  String? getLastError() {
    if (!isAvailable) return null;
    return _readString(_bindings!.lastErrorMessage());
  }

  // ---------------------------------------------------------------------------
  // Rooms
  // ---------------------------------------------------------------------------

  List<RoomSummary> fetchRooms() {
    if (!isAvailable) return const [];
    final json = _readString(_bindings!.roomsJson(_context));
    if (json == null) return const [];
    final decoded = jsonDecode(json) as List<dynamic>;
    return decoded
        .map((e) => RoomSummary.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  String? activeRoomId() {
    if (!isAvailable) return null;
    return _readString(_bindings!.activeRoomId(_context));
  }

  String? createRoom(String name) {
    if (!isAvailable) return null;
    final namePtr = name.toNativeUtf8();
    try {
      final roomId = _readString(_bindings!.createRoom(_context, namePtr));
      if (roomId == null) throw StateError(getLastError() ?? 'Failed to create room');
      return roomId;
    } finally {
      calloc.free(namePtr);
    }
  }

  bool selectRoom(String roomId) {
    if (!isAvailable || roomId.isEmpty) return false;
    final ptr = roomId.toNativeUtf8();
    final result = _bindings!.selectRoom(_context, ptr);
    calloc.free(ptr);
    return result == 0;
  }

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

  List<MessageModel> fetchMessages(String? roomId) {
    if (!isAvailable) return const [];
    final roomPtr = roomId == null ? nullptr : roomId.toNativeUtf8();
    final json = _readString(_bindings!.messagesJson(_context, roomPtr));
    if (roomPtr != nullptr) calloc.free(roomPtr);
    if (json == null) return const [];
    final decoded = jsonDecode(json) as List<dynamic>;
    return decoded
        .map((e) => MessageModel.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  bool sendMessage(String? roomId, String text) {
    if (!isAvailable) return false;
    final roomPtr = roomId == null ? nullptr : roomId.toNativeUtf8();
    final textPtr = text.toNativeUtf8();
    final result = _bindings!.sendTextMessage(_context, roomPtr, textPtr);
    if (roomPtr != nullptr) calloc.free(roomPtr);
    calloc.free(textPtr);
    return result == 0;
  }

  bool deleteMessage(String messageId) {
    if (!isAvailable) return false;
    final ptr = messageId.toNativeUtf8();
    final result = _bindings!.deleteMessage(_context, ptr);
    calloc.free(ptr);
    return result == 0;
  }

  // ---------------------------------------------------------------------------
  // Peers
  // ---------------------------------------------------------------------------

  List<PeerModel> fetchPeers() {
    if (!isAvailable) return const [];
    final json = _readString(_bindings!.peerListJson(_context));
    if (json == null) return const [];
    final decoded = jsonDecode(json) as List<dynamic>;
    return decoded
        .map((e) => PeerModel.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  bool pairPeer(String code) {
    if (!isAvailable) return false;
    final ptr = code.toNativeUtf8();
    final result = _bindings!.pairPeer(_context, ptr);
    calloc.free(ptr);
    return result == 0;
  }

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

  Map<String, dynamic>? trustVerify({
    required String targetPeerId,
    List<Map<String, dynamic>> markers = const [],
  }) {
    if (!isAvailable) return null;
    final targetPtr = targetPeerId.toNativeUtf8();
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

  List<FileTransferModel> fetchFileTransfers() {
    if (!isAvailable) return const [];
    final json = _readString(_bindings!.fileTransfersJson(_context));
    if (json == null) return const [];
    final decoded = jsonDecode(json) as List<dynamic>;
    return decoded
        .map((e) => FileTransferModel.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  Map<String, dynamic>? startFileTransfer({
    required String direction,
    String? peerId,
    required String filePath,
  }) {
    if (!isAvailable) return null;
    final dirPtr = direction.toNativeUtf8();
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

  SettingsModel? fetchSettings() {
    if (!isAvailable) return null;
    final json = _readString(_bindings!.settingsJson(_context));
    if (json == null) return null;
    final decoded = jsonDecode(json);
    if (decoded is! Map) return null;
    return SettingsModel.fromJson(Map<String, dynamic>.from(decoded));
  }

  LocalIdentitySummary? fetchLocalIdentity() {
    if (!isAvailable) return null;
    final json = _readString(_bindings!.localIdentityJson(_context));
    if (json == null) return null;
    final decoded = jsonDecode(json);
    if (decoded is! Map) return null;
    return LocalIdentitySummary.fromJson(Map<String, dynamic>.from(decoded));
  }

  bool hasIdentity() {
    if (!isAvailable) return false;
    return _bindings!.hasIdentity(_context) == 1;
  }

  /// Persist the current in-memory identity to disk.
  /// Call once during onboarding after the user chooses "Create New Identity".
  bool createIdentity({String? name}) {
    if (!isAvailable) return false;
    final namePtr = name != null ? name.toNativeUtf8() : nullptr;
    final result = _bindings!.createIdentity(_context, namePtr);
    if (namePtr != nullptr) calloc.free(namePtr);
    return result == 0;
  }

  /// Update the public profile fields and re-persist the identity.
  bool setPublicProfile({String? displayName, bool isPublic = false}) {
    if (!isAvailable) return false;
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

  bool setNodeMode(int mode) {
    if (!isAvailable) return false;
    return _bindings!.setNodeMode(_context, mode) == 0;
  }

  bool toggleTransport(String transportName, bool enabled) {
    if (!isAvailable) return false;
    final ptr = transportName.toNativeUtf8();
    final result = _bindings!.toggleTransportFlag(_context, ptr, enabled ? 1 : 0);
    calloc.free(ptr);
    return result != 0;
  }

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

  bool setVpnRoute(Map<String, dynamic> routeConfig) {
    if (!isAvailable) return false;
    final ptr = jsonEncode(routeConfig).toNativeUtf8();
    final result = _bindings!.setVpnRoute(_context, ptr);
    calloc.free(ptr);
    return result != 0;
  }

  bool setClearnetRoute(Map<String, dynamic> routeConfig) {
    if (!isAvailable) return false;
    final ptr = jsonEncode(routeConfig).toNativeUtf8();
    final result = _bindings!.setClearnetRoute(_context, ptr);
    calloc.free(ptr);
    return result != 0;
  }

  // ---------------------------------------------------------------------------
  // Network / mDNS
  // ---------------------------------------------------------------------------

  bool enableMdns({int port = 51820}) {
    if (!isAvailable) return false;
    return _bindings!.mdnsEnable(_context, port) == 0;
  }

  bool disableMdns() {
    if (!isAvailable) return false;
    return _bindings!.mdnsDisable(_context) == 0;
  }

  bool isMdnsRunning() {
    if (!isAvailable) return false;
    return _bindings!.mdnsIsRunning(_context) == 1;
  }

  List<Map<String, dynamic>> getDiscoveredPeers() {
    if (!isAvailable) return const [];
    final json = _readString(_bindings!.mdnsGetDiscoveredPeers(_context));
    if (json == null) return const [];
    final decoded = jsonDecode(json);
    if (decoded is! List) return const [];
    return decoded.map((e) => Map<String, dynamic>.from(e as Map)).toList();
  }

  Map<String, dynamic>? getNetworkStats() {
    if (!isAvailable) return null;
    final json = _readString(_bindings!.getNetworkStats(_context));
    if (json == null) return null;
    final decoded = jsonDecode(json);
    return decoded is Map ? Map<String, dynamic>.from(decoded) : null;
  }

  // ---------------------------------------------------------------------------
  // Services
  // ---------------------------------------------------------------------------

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

  void dispose() {
    if (isAvailable) _bindings!.meshDestroy(_context);
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  String? _readString(Pointer<Utf8> ptr) {
    if (ptr == nullptr) return null;
    final value = ptr.toDartString();
    _bindings?.stringFree(ptr);
    return value;
  }

  static String? _readLastError(_BackendBindings bindings) {
    final ptr = bindings.lastErrorMessage();
    if (ptr == nullptr) return null;
    final value = ptr.toDartString();
    bindings.stringFree(ptr);
    return value;
  }
}

// ---------------------------------------------------------------------------
// Initialization helpers
// ---------------------------------------------------------------------------

Pointer<Void> _initContext(
  _BackendBindings bindings,
  int nodeMode, {
  String? configPath,
}) {
  final envConfigPath = Platform.environment['MESH_CONFIG_PATH']?.trim();
  final resolvedPath = (configPath != null && configPath.isNotEmpty)
      ? configPath
      : (envConfigPath != null && envConfigPath.isNotEmpty)
          ? envConfigPath
          : null;
  final wireguardPort = int.tryParse(
    (Platform.environment['MESH_WIREGUARD_PORT'] ?? '').trim(),
  );

  final configPathPtr = resolvedPath != null
      ? resolvedPath.toNativeUtf8()
      : nullptr;

  final config = calloc<FfiMeshConfig>();
  config.ref
    ..configPath = configPathPtr
    ..logLevel = 2
    ..enableTor = 1
    ..enableClearnet = 1
    ..meshDiscovery = 1
    ..allowRelays = 1
    ..enableI2p = 0
    ..enableBluetooth = 0
    ..enableRf = 0
    ..wireguardPort =
        (wireguardPort != null && wireguardPort > 0 && wireguardPort <= 65535)
        ? wireguardPort
        : 0
    ..maxPeers = 0
    ..maxConnections = 0
    ..nodeMode = nodeMode;
  final context = bindings.meshInit(config);
  calloc.free(config);
  if (configPathPtr != nullptr) calloc.free(configPathPtr);
  return context;
}

DynamicLibrary _openLibrary() {
  if (Platform.isAndroid) return DynamicLibrary.open('libmesh_infinity.so');
  if (Platform.isIOS) return DynamicLibrary.process();
  if (Platform.isMacOS) return DynamicLibrary.open('libmesh_infinity.dylib');
  if (Platform.isWindows) return DynamicLibrary.open('mesh_infinity.dll');
  return DynamicLibrary.open('libmesh_infinity.so');
}

// ---------------------------------------------------------------------------
// FFI bindings
// ---------------------------------------------------------------------------

class _BackendBindings {
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

  // ignore: unused_field
  final DynamicLibrary _lib;
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

// ---------------------------------------------------------------------------
// FFI struct
// ---------------------------------------------------------------------------

base class FfiMeshConfig extends Struct {
  external Pointer<Utf8> configPath;
  @Uint8()
  external int logLevel;
  @Uint8()
  external int enableTor;
  @Uint8()
  external int enableClearnet;
  @Uint8()
  external int meshDiscovery;
  @Uint8()
  external int allowRelays;
  @Uint8()
  external int enableI2p;
  @Uint8()
  external int enableBluetooth;
  @Uint8()
  external int enableRf;
  @Uint16()
  external int wireguardPort;
  @Uint32()
  external int maxPeers;
  @Uint32()
  external int maxConnections;
  @Uint8()
  external int nodeMode;
}

// ---------------------------------------------------------------------------
// FFI typedefs
// ---------------------------------------------------------------------------

typedef MeshInitNative = Pointer<Void> Function(Pointer<FfiMeshConfig>);
typedef MeshInitDart = Pointer<Void> Function(Pointer<FfiMeshConfig>);
typedef MeshDestroyNative = Void Function(Pointer<Void>);
typedef MeshDestroyDart = void Function(Pointer<Void>);
typedef RoomsJsonNative = Pointer<Utf8> Function(Pointer<Void>);
typedef RoomsJsonDart = Pointer<Utf8> Function(Pointer<Void>);
typedef MessagesJsonNative = Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>);
typedef MessagesJsonDart = Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>);
typedef PeerListJsonNative = Pointer<Utf8> Function(Pointer<Void>);
typedef PeerListJsonDart = Pointer<Utf8> Function(Pointer<Void>);
typedef FileTransfersJsonNative = Pointer<Utf8> Function(Pointer<Void>);
typedef FileTransfersJsonDart = Pointer<Utf8> Function(Pointer<Void>);
typedef ActiveRoomIdNative = Pointer<Utf8> Function(Pointer<Void>);
typedef ActiveRoomIdDart = Pointer<Utf8> Function(Pointer<Void>);
typedef CreateRoomNative = Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>);
typedef CreateRoomDart = Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>);
typedef SelectRoomNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef SelectRoomDart = int Function(Pointer<Void>, Pointer<Utf8>);
typedef DeleteRoomNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef DeleteRoomDart = int Function(Pointer<Void>, Pointer<Utf8>);
typedef SendTextMessageNative =
    Int32 Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);
typedef SendTextMessageDart =
    int Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);
typedef DeleteMessageNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef DeleteMessageDart = int Function(Pointer<Void>, Pointer<Utf8>);
typedef SetNodeModeNative = Int32 Function(Pointer<Void>, Uint8);
typedef SetNodeModeDart = int Function(Pointer<Void>, int);
typedef SettingsJsonNative = Pointer<Utf8> Function(Pointer<Void>);
typedef SettingsJsonDart = Pointer<Utf8> Function(Pointer<Void>);
typedef SetTransportFlagsNative =
    Int32 Function(Pointer<Void>, Uint8, Uint8, Uint8, Uint8, Uint8, Uint8);
typedef SetTransportFlagsDart =
    int Function(Pointer<Void>, int, int, int, int, int, int);
typedef PairPeerNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef PairPeerDart = int Function(Pointer<Void>, Pointer<Utf8>);
typedef LocalIdentityJsonNative = Pointer<Utf8> Function(Pointer<Void>);
typedef LocalIdentityJsonDart = Pointer<Utf8> Function(Pointer<Void>);
typedef TrustAttestNative =
    Int32 Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, Int32, Uint8);
typedef TrustAttestDart =
    int Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, int, int);
typedef TrustVerifyJsonNative =
    Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);
typedef TrustVerifyJsonDart =
    Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);
typedef HasIdentityNative = Uint8 Function(Pointer<Void>);
typedef HasIdentityDart = int Function(Pointer<Void>);
typedef LastErrorMessageNative = Pointer<Utf8> Function();
typedef LastErrorMessageDart = Pointer<Utf8> Function();
typedef StringFreeNative = Void Function(Pointer<Utf8>);
typedef StringFreeDart = void Function(Pointer<Utf8>);
typedef MdnsEnableNative = Int32 Function(Pointer<Void>, Uint16);
typedef MdnsEnableDart = int Function(Pointer<Void>, int);
typedef MdnsDisableNative = Int32 Function(Pointer<Void>);
typedef MdnsDisableDart = int Function(Pointer<Void>);
typedef MdnsIsRunningNative = Int32 Function(Pointer<Void>);
typedef MdnsIsRunningDart = int Function(Pointer<Void>);
typedef MdnsGetDiscoveredPeersNative = Pointer<Utf8> Function(Pointer<Void>);
typedef MdnsGetDiscoveredPeersDart = Pointer<Utf8> Function(Pointer<Void>);
typedef GetNetworkStatsNative = Pointer<Utf8> Function(Pointer<Void>);
typedef GetNetworkStatsDart = Pointer<Utf8> Function(Pointer<Void>);
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
typedef FileTransferCancelNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef FileTransferCancelDart = int Function(Pointer<Void>, Pointer<Utf8>);
typedef GetServiceListNative = Pointer<Utf8> Function(Pointer<Void>);
typedef GetServiceListDart = Pointer<Utf8> Function(Pointer<Void>);
typedef ConfigureServiceNative =
    Int32 Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);
typedef ConfigureServiceDart =
    int Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);
typedef ToggleTransportFlagNative =
    Int32 Function(Pointer<Void>, Pointer<Utf8>, Int32);
typedef ToggleTransportFlagDart =
    int Function(Pointer<Void>, Pointer<Utf8>, int);
typedef SetVpnRouteNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef SetVpnRouteDart = int Function(Pointer<Void>, Pointer<Utf8>);
typedef SetClearnetRouteNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef SetClearnetRouteDart = int Function(Pointer<Void>, Pointer<Utf8>);
typedef CreateIdentityNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef CreateIdentityDart = int Function(Pointer<Void>, Pointer<Utf8>);
typedef SetPublicProfileNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef SetPublicProfileDart = int Function(Pointer<Void>, Pointer<Utf8>);
typedef SetPrivateProfileNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef SetPrivateProfileDart = int Function(Pointer<Void>, Pointer<Utf8>);
typedef ImportIdentityNative =
    Int32 Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);
typedef ImportIdentityDart =
    int Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);
typedef ResetIdentityNative = Int32 Function(Pointer<Void>);
typedef ResetIdentityDart = int Function(Pointer<Void>);
