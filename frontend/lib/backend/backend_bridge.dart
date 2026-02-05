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
        .map((item) => ThreadSummary(
              id: item['id'] as String? ?? '',
              title: item['title'] as String? ?? '',
              preview: item['preview'] as String? ?? '',
              lastSeen: item['lastSeen'] as String? ?? '',
              unreadCount: item['unreadCount'] as int? ?? 0,
            ))
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
        .map((item) => MessageItem(
              id: item['id'] as String? ?? '',
              sender: item['sender'] as String? ?? '',
              text: item['text'] as String? ?? '',
              timestamp: item['timestamp'] as String? ?? '',
              isOutgoing: item['isOutgoing'] as bool? ?? false,
            ))
        .toList();
  }

  List<Map<String, dynamic>> fetchPeers() {
    if (!isAvailable) {
      return const [];
    }
    final jsonString = _readString(_bindings!.peersJson(_context));
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
    final roomPtr = _bindings!.createRoom(_context, namePtr);
    calloc.free(namePtr);
    return _readString(roomPtr);
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
  final config = calloc<FfiMeshConfig>();
  config.ref
    ..configPath = nullptr
    ..logLevel = 2
    ..enableTor = 1
    ..enableClearnet = 1
    ..meshDiscovery = 1
    ..allowRelays = 1
    ..enableI2p = 0
    ..enableBluetooth = 0
    ..wireguardPort = 0
    ..maxPeers = 0
    ..maxConnections = 0
    ..nodeMode = nodeMode;
  final context = bindings.meshInit(config);
  calloc.free(config);
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
        meshDestroy =
            _lib.lookupFunction<MeshDestroyNative, MeshDestroyDart>('mesh_destroy'),
        roomsJson = _lib.lookupFunction<RoomsJsonNative, RoomsJsonDart>('mi_rooms_json'),
        messagesJson = _lib.lookupFunction<MessagesJsonNative, MessagesJsonDart>('mi_messages_json'),
        peersJson = _lib.lookupFunction<PeersJsonNative, PeersJsonDart>('mi_peers_json'),
        fileTransfersJson =
            _lib.lookupFunction<FileTransfersJsonNative, FileTransfersJsonDart>(
          'mi_file_transfers_json',
        ),
        activeRoomId = _lib.lookupFunction<ActiveRoomIdNative, ActiveRoomIdDart>('mi_active_room_id'),
        createRoom = _lib.lookupFunction<CreateRoomNative, CreateRoomDart>('mi_create_room'),
        selectRoom = _lib.lookupFunction<SelectRoomNative, SelectRoomDart>('mi_select_room'),
        deleteRoom = _lib.lookupFunction<DeleteRoomNative, DeleteRoomDart>('mi_delete_room'),
        sendTextMessage = _lib.lookupFunction<SendTextMessageNative, SendTextMessageDart>(
          'mi_send_text_message',
        ),
        deleteMessage =
            _lib.lookupFunction<DeleteMessageNative, DeleteMessageDart>('mi_delete_message'),
        setNodeMode = _lib.lookupFunction<SetNodeModeNative, SetNodeModeDart>('mi_set_node_mode'),
        settingsJson =
            _lib.lookupFunction<SettingsJsonNative, SettingsJsonDart>('mi_settings_json'),
        setTransportFlags = _lib.lookupFunction<SetTransportFlagsNative, SetTransportFlagsDart>(
          'mi_set_transport_flags',
        ),
        pollEvents = _lib.lookupFunction<PollEventsNative, PollEventsDart>('mi_poll_events'),
        localIdentityJson =
            _lib.lookupFunction<LocalIdentityJsonNative, LocalIdentityJsonDart>(
          'mi_local_identity_json',
        ),
        trustAttest = _lib.lookupFunction<TrustAttestNative, TrustAttestDart>(
          'mi_trust_attest',
        ),
        trustVerifyJson =
            _lib.lookupFunction<TrustVerifyJsonNative, TrustVerifyJsonDart>(
          'mi_trust_verify_json',
        ),
        lastErrorMessage = _lib.lookupFunction<LastErrorMessageNative, LastErrorMessageDart>(
          'mi_last_error_message',
        ),
        stringFree = _lib.lookupFunction<StringFreeNative, StringFreeDart>('mi_string_free');

  // ignore: unused_field
  final DynamicLibrary _lib;
  final MeshInitDart meshInit;
  final MeshDestroyDart meshDestroy;
  final RoomsJsonDart roomsJson;
  final MessagesJsonDart messagesJson;
  final PeersJsonDart peersJson;
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
  final PollEventsDart pollEvents;
  final LocalIdentityJsonDart localIdentityJson;
  final TrustAttestDart trustAttest;
  final TrustVerifyJsonDart trustVerifyJson;
  final LastErrorMessageDart lastErrorMessage;
  final StringFreeDart stringFree;
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
typedef MessagesJsonNative = Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>);
typedef MessagesJsonDart = Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>);
typedef PeersJsonNative = Pointer<Utf8> Function(Pointer<Void>);
typedef PeersJsonDart = Pointer<Utf8> Function(Pointer<Void>);
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
typedef SendTextMessageNative = Int32 Function(
  Pointer<Void>,
  Pointer<Utf8>,
  Pointer<Utf8>,
);
typedef SendTextMessageDart = int Function(
  Pointer<Void>,
  Pointer<Utf8>,
  Pointer<Utf8>,
);
typedef DeleteMessageNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef DeleteMessageDart = int Function(Pointer<Void>, Pointer<Utf8>);
typedef SetNodeModeNative = Int32 Function(Pointer<Void>, Uint8);
typedef SetNodeModeDart = int Function(Pointer<Void>, int);
typedef SettingsJsonNative = Pointer<Utf8> Function(Pointer<Void>);
typedef SettingsJsonDart = Pointer<Utf8> Function(Pointer<Void>);
typedef SetTransportFlagsNative = Int32 Function(
  Pointer<Void>,
  Uint8,
  Uint8,
  Uint8,
  Uint8,
  Uint8,
  Uint8,
);
typedef SetTransportFlagsDart = int Function(
  Pointer<Void>,
  int,
  int,
  int,
  int,
  int,
  int,
);
typedef PollEventsNative = Pointer<Utf8> Function(Pointer<Void>, Uint32);
typedef PollEventsDart = Pointer<Utf8> Function(Pointer<Void>, int);
typedef LocalIdentityJsonNative = Pointer<Utf8> Function(Pointer<Void>);
typedef LocalIdentityJsonDart = Pointer<Utf8> Function(Pointer<Void>);
typedef TrustAttestNative = Int32 Function(
  Pointer<Void>,
  Pointer<Utf8>,
  Pointer<Utf8>,
  Int32,
  Uint8,
);
typedef TrustAttestDart = int Function(
  Pointer<Void>,
  Pointer<Utf8>,
  Pointer<Utf8>,
  int,
  int,
);
typedef TrustVerifyJsonNative = Pointer<Utf8> Function(
  Pointer<Void>,
  Pointer<Utf8>,
  Pointer<Utf8>,
);
typedef TrustVerifyJsonDart = Pointer<Utf8> Function(
  Pointer<Void>,
  Pointer<Utf8>,
  Pointer<Utf8>,
);
typedef LastErrorMessageNative = Pointer<Utf8> Function();
typedef LastErrorMessageDart = Pointer<Utf8> Function();
typedef StringFreeNative = Void Function(Pointer<Utf8>);
typedef StringFreeDart = void Function(Pointer<Utf8>);
