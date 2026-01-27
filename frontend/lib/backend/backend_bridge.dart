import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

import '../models/thread_models.dart';

class BackendBridge {
  BackendBridge._(this._bindings, this._context, this._useMocks);

  factory BackendBridge.open({int nodeMode = 0}) {
    try {
      final bindings = _BackendBindings(_openLibrary());
      final context = _initContext(bindings, nodeMode);
      if (context == nullptr) {
        return BackendBridge._(bindings, context, true);
      }
      return BackendBridge._(bindings, context, false);
    } catch (_) {
      return BackendBridge._(null, nullptr, true);
    }
  }

  final _BackendBindings? _bindings;
  final Pointer<Void> _context;
  final bool _useMocks;

  bool get isAvailable => !_useMocks && _bindings != null && _context != nullptr;

  List<ThreadSummary> fetchThreads() {
    if (!isAvailable) {
      return _mockThreads;
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
      return _mockMessages[roomId] ?? const [];
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

  String? activeRoomId() {
    if (!isAvailable) {
      return _mockThreads.isNotEmpty ? _mockThreads.first.id : null;
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
    final roomPtr = roomId.toNativeUtf8();
    final result = _bindings!.selectRoom(_context, roomPtr);
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

  bool setNodeMode(int mode) {
    if (!isAvailable) {
      return false;
    }
    final result = _bindings!.setNodeMode(_context, mode);
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
    return DynamicLibrary.open('libnet_infinity.so');
  }
  if (Platform.isIOS) {
    return DynamicLibrary.process();
  }
  if (Platform.isMacOS) {
    return DynamicLibrary.open('libnet_infinity.dylib');
  }
  if (Platform.isWindows) {
    return DynamicLibrary.open('net_infinity.dll');
  }
  return DynamicLibrary.open('libnet_infinity.so');
}

class _BackendBindings {
  _BackendBindings(this._lib)
      : meshInit = _lib.lookupFunction<MeshInitNative, MeshInitDart>('mesh_init'),
        meshDestroy =
            _lib.lookupFunction<MeshDestroyNative, MeshDestroyDart>('mesh_destroy'),
        roomsJson = _lib.lookupFunction<RoomsJsonNative, RoomsJsonDart>('ni_rooms_json'),
        messagesJson = _lib.lookupFunction<MessagesJsonNative, MessagesJsonDart>('ni_messages_json'),
        activeRoomId = _lib.lookupFunction<ActiveRoomIdNative, ActiveRoomIdDart>('ni_active_room_id'),
        createRoom = _lib.lookupFunction<CreateRoomNative, CreateRoomDart>('ni_create_room'),
        selectRoom = _lib.lookupFunction<SelectRoomNative, SelectRoomDart>('ni_select_room'),
        sendTextMessage = _lib.lookupFunction<SendTextMessageNative, SendTextMessageDart>(
          'ni_send_text_message',
        ),
        setNodeMode = _lib.lookupFunction<SetNodeModeNative, SetNodeModeDart>('ni_set_node_mode'),
        pollEvents = _lib.lookupFunction<PollEventsNative, PollEventsDart>('ni_poll_events'),
        stringFree = _lib.lookupFunction<StringFreeNative, StringFreeDart>('ni_string_free');

  final DynamicLibrary _lib;
  final MeshInitDart meshInit;
  final MeshDestroyDart meshDestroy;
  final RoomsJsonDart roomsJson;
  final MessagesJsonDart messagesJson;
  final ActiveRoomIdDart activeRoomId;
  final CreateRoomDart createRoom;
  final SelectRoomDart selectRoom;
  final SendTextMessageDart sendTextMessage;
  final SetNodeModeDart setNodeMode;
  final PollEventsDart pollEvents;
  final StringFreeDart stringFree;
}

class FfiMeshConfig extends Struct {
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
typedef ActiveRoomIdNative = Pointer<Utf8> Function(Pointer<Void>);
typedef ActiveRoomIdDart = Pointer<Utf8> Function(Pointer<Void>);
typedef CreateRoomNative = Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>);
typedef CreateRoomDart = Pointer<Utf8> Function(Pointer<Void>, Pointer<Utf8>);
typedef SelectRoomNative = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef SelectRoomDart = int Function(Pointer<Void>, Pointer<Utf8>);
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
typedef SetNodeModeNative = Int32 Function(Pointer<Void>, Uint8);
typedef SetNodeModeDart = int Function(Pointer<Void>, int);
typedef PollEventsNative = Pointer<Utf8> Function(Pointer<Void>, Uint32);
typedef PollEventsDart = Pointer<Utf8> Function(Pointer<Void>, int);
typedef StringFreeNative = Void Function(Pointer<Utf8>);
typedef StringFreeDart = void Function(Pointer<Utf8>);

final List<ThreadSummary> _mockThreads = const [
  ThreadSummary(
    id: 'thread-1',
    title: 'Signal Crew',
    preview: 'Nova: Signal-style UX...',
    lastSeen: '09:43',
    unreadCount: 2,
  ),
  ThreadSummary(
    id: 'thread-2',
    title: 'Mesh Operations',
    preview: 'Avery: trust graph update',
    lastSeen: 'Yesterday',
    unreadCount: 0,
  ),
  ThreadSummary(
    id: 'thread-3',
    title: 'Private Link',
    preview: 'Pairing code rotated',
    lastSeen: 'Mon',
    unreadCount: 1,
  ),
];

final Map<String, List<MessageItem>> _mockMessages = {
  'thread-1': [
    const MessageItem(
      id: 'm1',
      sender: 'Avery',
      text: 'The web-of-trust handshake is ready. Want to sync keys? We can do a QR pairing.',
      timestamp: '09:41',
      isOutgoing: false,
    ),
    const MessageItem(
      id: 'm2',
      sender: 'You',
      text: 'Yes. We can share bundles over the mesh; no servers.',
      timestamp: '09:42',
      isOutgoing: true,
    ),
    const MessageItem(
      id: 'm3',
      sender: 'Nova',
      text: 'Signal-style UX. Threads, safety number, and session state.',
      timestamp: '09:43',
      isOutgoing: false,
    ),
  ],
  'thread-2': [
    const MessageItem(
      id: 'm4',
      sender: 'Avery',
      text: 'Transport rotation complete. Relays disabled.',
      timestamp: 'Yesterday',
      isOutgoing: false,
    ),
  ],
  'thread-3': [
    const MessageItem(
      id: 'm5',
      sender: 'You',
      text: 'Safety number verified. Session stable.',
      timestamp: 'Mon',
      isOutgoing: true,
    ),
  ],
};
