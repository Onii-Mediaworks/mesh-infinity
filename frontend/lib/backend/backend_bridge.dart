import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';

import '../models/thread_models.dart';
import 'backend_models.dart';

class BackendBridge {
  BackendBridge._(this._bindings, this._context, this._initError);

  factory BackendBridge.open({int nodeMode = 0, required bool allowMissing}) {
    try {
      final bindings = _BackendBindings(_openLibrary());
      final context = _initContext(bindings, nodeMode);
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

  String? getLastError() {
    if (!isAvailable) {
      return null;
    }
    return _readString(_bindings!.lastErrorMessage());
  }

  List<ThreadSummary> fetchThreads() {
    if (!isAvailable) {
      return const [];
    }
    final jsonString = _readString(_bindings!.roomsJson(_context));
    if (jsonString == null) {
      return const [];
    }
    final decoded = jsonDecode(jsonString) as List<dynamic>;
    return decoded
        .map(
          (item) => ThreadSummary(
            id: item['id'] as String? ?? '',
            title: item['title'] as String? ?? '',
            preview: item['preview'] as String? ?? '',
            lastSeen: item['lastSeen'] as String? ?? '',
            unreadCount: item['unreadCount'] as int? ?? 0,
          ),
        )
        .toList();
  }

  List<MessageItem> fetchMessages(String? roomId) {
    if (!isAvailable) {
      return const [];
    }
    final roomPtr = roomId == null ? nullptr : roomId.toNativeUtf8();
    final jsonString = _readString(_bindings!.messagesJson(_context, roomPtr));
    if (roomPtr != nullptr) {
      calloc.free(roomPtr);
    }
    if (jsonString == null) {
      return const [];
    }
    final decoded = jsonDecode(jsonString) as List<dynamic>;
    return decoded
        .map(
          (item) => MessageItem(
            id: item['id'] as String? ?? '',
            sender: item['sender'] as String? ?? '',
            text: item['text'] as String? ?? '',
            timestamp: item['timestamp'] as String? ?? '',
            isOutgoing: item['isOutgoing'] as bool? ?? false,
          ),
        )
        .toList();
  }

  List<Map<String, dynamic>> fetchPeers() {
    if (!isAvailable) {
      return const [];
    }
    final jsonString = _readString(_bindings!.peerListJson(_context));
    if (jsonString == null) {
      return const [];
    }
    final decoded = jsonDecode(jsonString) as List<dynamic>;
    return decoded
        .map((item) => Map<String, dynamic>.from(item as Map))
        .toList();
  }

  List<Map<String, dynamic>> fetchFileTransfers() {
    if (!isAvailable) {
      return const [];
    }
    final jsonString = _readString(_bindings!.fileTransfersJson(_context));
    if (jsonString == null) {
      return const [];
    }
    final decoded = jsonDecode(jsonString) as List<dynamic>;
    return decoded
        .map((item) => Map<String, dynamic>.from(item as Map))
        .toList();
  }

  String? activeRoomId() {
    if (!isAvailable) {
      return null;
    }
    final value = _readString(_bindings!.activeRoomId(_context));
    return value;
  }

  String? createRoom(String name) {
    if (!isAvailable) {
      return null;
    }
    final namePtr = name.toNativeUtf8();
    try {
      final roomPtr = _bindings!.createRoom(_context, namePtr);
      final roomId = _readString(roomPtr);
      if (roomId == null) {
        throw StateError(getLastError() ?? 'Failed to create room');
      }
      return roomId;
    } finally {
      calloc.free(namePtr);
    }
  }

  bool hasIdentity() {
    if (!isAvailable) {
      return false;
    }
    return _bindings!.hasIdentity(_context) == 1;
  }

  bool selectRoom(String roomId) {
    if (!isAvailable) {
      return false;
    }
    if (roomId.isEmpty) {
      return false;
    }
    final roomPtr = roomId.toNativeUtf8();
    final result = _bindings!.selectRoom(_context, roomPtr);
    calloc.free(roomPtr);
    return result == 0;
  }

  bool deleteRoom(String roomId) {
    if (!isAvailable) {
      return false;
    }
    final roomPtr = roomId.toNativeUtf8();
    final result = _bindings!.deleteRoom(_context, roomPtr);
    calloc.free(roomPtr);
    return result == 0;
  }

  bool sendMessage(String? roomId, String text) {
    if (!isAvailable) {
      return false;
    }
    final roomPtr = roomId == null ? nullptr : roomId.toNativeUtf8();
    final textPtr = text.toNativeUtf8();
    final result = _bindings!.sendTextMessage(_context, roomPtr, textPtr);
    if (roomPtr != nullptr) {
      calloc.free(roomPtr);
    }
    calloc.free(textPtr);
    return result == 0;
  }

  bool deleteMessage(String messageId) {
    if (!isAvailable) {
      return false;
    }
    final messagePtr = messageId.toNativeUtf8();
    final result = _bindings!.deleteMessage(_context, messagePtr);
    calloc.free(messagePtr);
    return result == 0;
  }

  bool setNodeMode(int mode) {
    if (!isAvailable) {
      return false;
    }
    final result = _bindings!.setNodeMode(_context, mode);
    return result == 0;
  }

  Map<String, dynamic>? fetchSettings() {
    if (!isAvailable) {
      return null;
    }
    final jsonString = _readString(_bindings!.settingsJson(_context));
    if (jsonString == null) {
      return null;
    }
    final decoded = jsonDecode(jsonString);
    if (decoded is Map<String, dynamic>) {
      return decoded;
    }
    if (decoded is Map) {
      return Map<String, dynamic>.from(decoded);
    }
    return null;
  }

  LocalIdentitySummary? fetchLocalIdentity() {
    if (!isAvailable) {
      return null;
    }
    final jsonString = _readString(_bindings!.localIdentityJson(_context));
    if (jsonString == null) {
      return null;
    }
    final decoded = jsonDecode(jsonString);
    if (decoded is Map<String, dynamic>) {
      return LocalIdentitySummary.fromJson(decoded);
    }
    if (decoded is Map) {
      return LocalIdentitySummary.fromJson(Map<String, dynamic>.from(decoded));
    }
    return null;
  }

  bool trustAttest({
    required String endorserPeerId,
    required String targetPeerId,
    required int trustLevel,
    required int verificationMethod,
  }) {
    if (!isAvailable) {
      return false;
    }
    final endorserPtr = endorserPeerId.toNativeUtf8();
    final targetPtr = targetPeerId.toNativeUtf8();
    final result = _bindings!.trustAttest(
      _context,
      endorserPtr,
      targetPtr,
      trustLevel,
      verificationMethod,
    );
    calloc.free(endorserPtr);
    calloc.free(targetPtr);
    return result == 0;
  }

  Map<String, dynamic>? trustVerify({
    required String targetPeerId,
    List<Map<String, dynamic>> markers = const [],
  }) {
    if (!isAvailable) {
      return null;
    }
    final targetPtr = targetPeerId.toNativeUtf8();
    final markersPtr = jsonEncode(markers).toNativeUtf8();
    final jsonString = _readString(
      _bindings!.trustVerifyJson(_context, targetPtr, markersPtr),
    );
    calloc.free(targetPtr);
    calloc.free(markersPtr);
    if (jsonString == null) {
      return null;
    }
    final decoded = jsonDecode(jsonString);
    if (decoded is Map<String, dynamic>) {
      return decoded;
    }
    if (decoded is Map) {
      return Map<String, dynamic>.from(decoded);
    }
    return null;
  }

  bool setTransportFlags({
    required bool enableTor,
    required bool enableClearnet,
    required bool meshDiscovery,
    required bool allowRelays,
    required bool enableI2p,
    required bool enableBluetooth,
  }) {
    if (!isAvailable) {
      return false;
    }
    final result = _bindings!.setTransportFlags(
      _context,
      enableTor ? 1 : 0,
      enableClearnet ? 1 : 0,
      meshDiscovery ? 1 : 0,
      allowRelays ? 1 : 0,
      enableI2p ? 1 : 0,
      enableBluetooth ? 1 : 0,
    );
    return result == 0;
  }

  bool pairPeer(String code) {
    if (!isAvailable) {
      return false;
    }
    final codePtr = code.toNativeUtf8();
    final result = _bindings!.pairPeer(_context, codePtr);
    calloc.free(codePtr);
    return result == 0;
  }

  bool pollEvents() {
    if (!isAvailable) {
      return false;
    }
    final jsonString = _readString(_bindings!.pollEvents(_context, 64));
    if (jsonString == null) {
      return false;
    }
    final decoded = jsonDecode(jsonString) as List<dynamic>;
    return decoded.isNotEmpty;
  }

  // mDNS Discovery methods

  bool enableMdns({int port = 51820}) {
    if (!isAvailable) {
      return false;
    }
    final result = _bindings!.mdnsEnable(_context, port);
    return result == 0;
  }

  bool disableMdns() {
    if (!isAvailable) {
      return false;
    }
    final result = _bindings!.mdnsDisable(_context);
    return result == 0;
  }

  bool isMdnsRunning() {
    if (!isAvailable) {
      return false;
    }
    final result = _bindings!.mdnsIsRunning(_context);
    return result == 1;
  }

  List<Map<String, dynamic>> getDiscoveredPeers() {
    if (!isAvailable) {
      return [];
    }
    final jsonString = _readString(_bindings!.mdnsGetDiscoveredPeers(_context));
    if (jsonString == null) {
      return [];
    }
    final decoded = jsonDecode(jsonString);
    if (decoded is List) {
      return decoded.cast<Map<String, dynamic>>();
    }
    return [];
  }

  Map<String, dynamic>? getNetworkStats() {
    if (!isAvailable) {
      return null;
    }
    final jsonString = _readString(_bindings!.getNetworkStats(_context));
    if (jsonString == null) {
      return null;
    }
    final decoded = jsonDecode(jsonString);
    if (decoded is Map<String, dynamic>) {
      return decoded;
    }
    if (decoded is Map) {
      return Map<String, dynamic>.from(decoded);
    }
    return null;
  }

  Map<String, dynamic>? startFileTransfer({
    required String direction,
    String? peerId,
    required String filePath,
  }) {
    if (!isAvailable) {
      return null;
    }
    final directionPtr = direction.toNativeUtf8();
    final peerIdPtr = peerId?.toNativeUtf8() ?? nullptr;
    final filePathPtr = filePath.toNativeUtf8();

    final jsonString = _readString(
      _bindings!.fileTransferStart(
        _context,
        directionPtr,
        peerIdPtr,
        filePathPtr,
      ),
    );

    calloc.free(directionPtr);
    if (peerIdPtr != nullptr) calloc.free(peerIdPtr);
    calloc.free(filePathPtr);

    if (jsonString == null) {
      return null;
    }
    final decoded = jsonDecode(jsonString);
    if (decoded is Map<String, dynamic>) {
      return decoded;
    }
    if (decoded is Map) {
      return Map<String, dynamic>.from(decoded);
    }
    return null;
  }

  bool cancelFileTransfer(String transferId) {
    if (!isAvailable) {
      return false;
    }
    final transferIdPtr = transferId.toNativeUtf8();
    final result = _bindings!.fileTransferCancel(_context, transferIdPtr);
    calloc.free(transferIdPtr);
    return result == 0;
  }

  Map<String, dynamic>? getFileTransferStatus(String transferId) {
    if (!isAvailable) {
      return null;
    }
    final transferIdPtr = transferId.toNativeUtf8();
    final jsonString = _readString(
      _bindings!.fileTransferStatus(_context, transferIdPtr),
    );
    calloc.free(transferIdPtr);

    if (jsonString == null) {
      return null;
    }
    final decoded = jsonDecode(jsonString);
    if (decoded is Map<String, dynamic>) {
      return decoded;
    }
    if (decoded is Map) {
      return Map<String, dynamic>.from(decoded);
    }
    return null;
  }

  List<Map<String, dynamic>> getServiceList() {
    if (!isAvailable) {
      return [];
    }
    final jsonString = _readString(_bindings!.getServiceList(_context));
    if (jsonString == null) {
      return [];
    }
    final decoded = jsonDecode(jsonString);
    if (decoded is List) {
      return decoded.map((e) {
        if (e is Map<String, dynamic>) {
          return e;
        }
        if (e is Map) {
          return Map<String, dynamic>.from(e);
        }
        return <String, dynamic>{};
      }).toList();
    }
    return [];
  }

  bool configureService(String serviceId, Map<String, dynamic> config) {
    if (!isAvailable) {
      return false;
    }
    final serviceIdPtr = serviceId.toNativeUtf8();
    final configJsonPtr = jsonEncode(config).toNativeUtf8();
    final result = _bindings!.configureService(
      _context,
      serviceIdPtr,
      configJsonPtr,
    );
    calloc.free(serviceIdPtr);
    calloc.free(configJsonPtr);
    return result != 0;
  }

  bool toggleTransport(String transportName, bool enabled) {
    if (!isAvailable) {
      return false;
    }
    final transportNamePtr = transportName.toNativeUtf8();
    final result = _bindings!.toggleTransportFlag(
      _context,
      transportNamePtr,
      enabled ? 1 : 0,
    );
    calloc.free(transportNamePtr);
    return result != 0;
  }

  bool setVpnRoute(Map<String, dynamic> routeConfig) {
    if (!isAvailable) {
      return false;
    }
    final routeConfigPtr = jsonEncode(routeConfig).toNativeUtf8();
    final result = _bindings!.setVpnRoute(_context, routeConfigPtr);
    calloc.free(routeConfigPtr);
    return result != 0;
  }

  bool setClearnetRoute(Map<String, dynamic> routeConfig) {
    if (!isAvailable) {
      return false;
    }
    final routeConfigPtr = jsonEncode(routeConfig).toNativeUtf8();
    final result = _bindings!.setClearnetRoute(_context, routeConfigPtr);
    calloc.free(routeConfigPtr);
    return result != 0;
  }

  void dispose() {
    if (isAvailable) {
      _bindings!.meshDestroy(_context);
    }
  }

  String? _readString(Pointer<Utf8> ptr) {
    if (ptr == nullptr) {
      return null;
    }
    final value = ptr.toDartString();
    _bindings?.stringFree(ptr);
    return value;
  }

  static String? _readLastError(_BackendBindings bindings) {
    final ptr = bindings.lastErrorMessage();
    if (ptr == nullptr) {
      return null;
    }
    final value = ptr.toDartString();
    bindings.stringFree(ptr);
    return value;
  }
}

Pointer<Void> _initContext(_BackendBindings bindings, int nodeMode) {
  final configPath = Platform.environment['MESH_CONFIG_PATH']?.trim();
  final wireguardPort = int.tryParse(
    (Platform.environment['MESH_WIREGUARD_PORT'] ?? '').trim(),
  );

  final configPathPtr = (configPath != null && configPath.isNotEmpty)
      ? configPath.toNativeUtf8()
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
    ..wireguardPort =
        (wireguardPort != null && wireguardPort > 0 && wireguardPort <= 65535)
        ? wireguardPort
        : 0
    ..maxPeers = 0
    ..maxConnections = 0
    ..nodeMode = nodeMode;
  final context = bindings.meshInit(config);
  calloc.free(config);
  if (configPathPtr != nullptr) {
    calloc.free(configPathPtr);
  }
  return context;
}

DynamicLibrary _openLibrary() {
  if (Platform.isAndroid) {
    return DynamicLibrary.open('libmesh_infinity.so');
  }
  if (Platform.isIOS) {
    return DynamicLibrary.process();
  }
  if (Platform.isMacOS) {
    return DynamicLibrary.open('libmesh_infinity.dylib');
  }
  if (Platform.isWindows) {
    return DynamicLibrary.open('mesh_infinity.dll');
  }
  return DynamicLibrary.open('libmesh_infinity.so');
}

class _BackendBindings {
  // ignore: unused_field
  _BackendBindings(this._lib)
    : meshInit = _lib.lookupFunction<MeshInitNative, MeshInitDart>('mesh_init'),
      meshDestroy = _lib.lookupFunction<MeshDestroyNative, MeshDestroyDart>(
        'mesh_destroy',
      ),
      roomsJson = _lib.lookupFunction<RoomsJsonNative, RoomsJsonDart>(
        'mi_rooms_json',
      ),
      messagesJson = _lib.lookupFunction<MessagesJsonNative, MessagesJsonDart>(
        'mi_messages_json',
      ),
      peersJson = _lib.lookupFunction<PeersJsonNative, PeersJsonDart>(
        'mi_peers_json',
      ),
      peerListJson = _lib.lookupFunction<PeerListJsonNative, PeerListJsonDart>(
        'mi_get_peer_list',
      ),
      fileTransfersJson = _lib
          .lookupFunction<FileTransfersJsonNative, FileTransfersJsonDart>(
            'mi_file_transfers_json',
          ),
      activeRoomId = _lib.lookupFunction<ActiveRoomIdNative, ActiveRoomIdDart>(
        'mi_active_room_id',
      ),
      createRoom = _lib.lookupFunction<CreateRoomNative, CreateRoomDart>(
        'mi_create_room',
      ),
      selectRoom = _lib.lookupFunction<SelectRoomNative, SelectRoomDart>(
        'mi_select_room',
      ),
      deleteRoom = _lib.lookupFunction<DeleteRoomNative, DeleteRoomDart>(
        'mi_delete_room',
      ),
      sendTextMessage = _lib
          .lookupFunction<SendTextMessageNative, SendTextMessageDart>(
            'mi_send_text_message',
          ),
      deleteMessage = _lib
          .lookupFunction<DeleteMessageNative, DeleteMessageDart>(
            'mi_delete_message',
          ),
      setNodeMode = _lib.lookupFunction<SetNodeModeNative, SetNodeModeDart>(
        'mi_set_node_mode',
      ),
      settingsJson = _lib.lookupFunction<SettingsJsonNative, SettingsJsonDart>(
        'mi_settings_json',
      ),
      setTransportFlags = _lib
          .lookupFunction<SetTransportFlagsNative, SetTransportFlagsDart>(
            'mi_set_transport_flags',
          ),
      pairPeer = _lib.lookupFunction<PairPeerNative, PairPeerDart>(
        'mi_pair_peer',
      ),
      pollEvents = _lib.lookupFunction<PollEventsNative, PollEventsDart>(
        'mi_poll_events',
      ),
      localIdentityJson = _lib
          .lookupFunction<LocalIdentityJsonNative, LocalIdentityJsonDart>(
            'mi_local_identity_json',
          ),
      trustAttest = _lib.lookupFunction<TrustAttestNative, TrustAttestDart>(
        'mi_trust_attest',
      ),
      trustVerifyJson = _lib
          .lookupFunction<TrustVerifyJsonNative, TrustVerifyJsonDart>(
            'mi_trust_verify_json',
          ),
      hasIdentity = _lib.lookupFunction<HasIdentityNative, HasIdentityDart>(
        'mi_has_identity',
      ),
      lastErrorMessage = _lib
          .lookupFunction<LastErrorMessageNative, LastErrorMessageDart>(
            'mi_last_error_message',
          ),
      stringFree = _lib.lookupFunction<StringFreeNative, StringFreeDart>(
        'mi_string_free',
      ),
      mdnsEnable = _lib.lookupFunction<MdnsEnableNative, MdnsEnableDart>(
        'mi_mdns_enable',
      ),
      mdnsDisable = _lib.lookupFunction<MdnsDisableNative, MdnsDisableDart>(
        'mi_mdns_disable',
      ),
      mdnsIsRunning = _lib
          .lookupFunction<MdnsIsRunningNative, MdnsIsRunningDart>(
            'mi_mdns_is_running',
          ),
      mdnsGetDiscoveredPeers = _lib
          .lookupFunction<
            MdnsGetDiscoveredPeersNative,
            MdnsGetDiscoveredPeersDart
          >('mi_mdns_get_discovered_peers'),
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
      fileTransferStatus = _lib
          .lookupFunction<FileTransferStatusNative, FileTransferStatusDart>(
            'mi_file_transfer_status',
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
      setVpnRoute = _lib.lookupFunction<SetVpnRouteNative, SetVpnRouteDart>(
        'mi_set_vpn_route',
      ),
      setClearnetRoute = _lib
          .lookupFunction<SetClearnetRouteNative, SetClearnetRouteDart>(
            'mi_set_clearnet_route',
          );

  // ignore: unused_field
  final DynamicLibrary _lib;
  final MeshInitDart meshInit;
  final MeshDestroyDart meshDestroy;
  final RoomsJsonDart roomsJson;
  final MessagesJsonDart messagesJson;
  final PeersJsonDart peersJson;
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
  final PollEventsDart pollEvents;
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
  final FileTransferStatusDart fileTransferStatus;
  final GetServiceListDart getServiceList;
  final ConfigureServiceDart configureService;
  final ToggleTransportFlagDart toggleTransportFlag;
  final SetVpnRouteDart setVpnRoute;
  final SetClearnetRouteDart setClearnetRoute;
}

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

  @Uint16()
  external int wireguardPort;

  @Uint32()
  external int maxPeers;

  @Uint32()
  external int maxConnections;

  @Uint8()
  external int nodeMode;
}

typedef MeshInitNative = Pointer<Void> Function(Pointer<FfiMeshConfig>);
typedef MeshInitDart = Pointer<Void> Function(Pointer<FfiMeshConfig>);
typedef MeshDestroyNative = Void Function(Pointer<Void>);
typedef MeshDestroyDart = void Function(Pointer<Void>);
typedef RoomsJsonNative = Pointer<Utf8> Function(Pointer<Void>);
typedef RoomsJsonDart = Pointer<Utf8> Function(Pointer<Void>);
typedef MessagesJsonNative =
    Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>);
typedef MessagesJsonDart = Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>);
typedef PeersJsonNative = Pointer<Utf8> Function(Pointer<Void>);
typedef PeersJsonDart = Pointer<Utf8> Function(Pointer<Void>);
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
typedef PollEventsNative = Pointer<Utf8> Function(Pointer<Void>, Uint32);
typedef PollEventsDart = Pointer<Utf8> Function(Pointer<Void>, int);
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

// mDNS Discovery
typedef MdnsEnableNative = Int32 Function(Pointer<Void>, Uint16);
typedef MdnsEnableDart = int Function(Pointer<Void>, int);
typedef MdnsDisableNative = Int32 Function(Pointer<Void>);
typedef MdnsDisableDart = int Function(Pointer<Void>);
typedef MdnsIsRunningNative = Int32 Function(Pointer<Void>);
typedef MdnsIsRunningDart = int Function(Pointer<Void>);
typedef MdnsGetDiscoveredPeersNative = Pointer<Utf8> Function(Pointer<Void>);

// Network Statistics
typedef GetNetworkStatsNative = Pointer<Utf8> Function(Pointer<Void>);
typedef GetNetworkStatsDart = Pointer<Utf8> Function(Pointer<Void>);

// File Transfer
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
typedef FileTransferStatusNative =
    Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>);
typedef FileTransferStatusDart =
    Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>);

// Service Management
typedef GetServiceListNative = Pointer<Utf8> Function(Pointer<Void>);
typedef GetServiceListDart = Pointer<Utf8> Function(Pointer<Void>);
typedef ConfigureServiceNative =
    Int32 Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);
typedef ConfigureServiceDart =
    int Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>);

// Transport Management
typedef ToggleTransportFlagNative =
    Int32 Function(Pointer<Void>, Pointer<Utf8>, Int32);
typedef ToggleTransportFlagDart =
    int Function(Pointer<Void>, Pointer<Utf8>, int);

// Route Configuration
typedef SetVpnRouteNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef SetVpnRouteDart = int Function(Pointer<Void>, Pointer<Utf8>);
typedef SetClearnetRouteNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef SetClearnetRouteDart = int Function(Pointer<Void>, Pointer<Utf8>);

typedef MdnsGetDiscoveredPeersDart = Pointer<Utf8> Function(Pointer<Void>);
