import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';

import 'package:ffi/ffi.dart';

import 'event_models.dart';

class EventBus {
  EventBus._();
  static final EventBus instance = EventBus._();

  final StreamController<BackendEvent> _controller =
      StreamController<BackendEvent>.broadcast();

  Stream<BackendEvent> get stream => _controller.stream;

  Isolate? _isolate;
  ReceivePort? _receivePort;

  void start(int contextAddress) {
    _receivePort = ReceivePort();
    _receivePort!.listen(_onMessage);
    Isolate.spawn(
      _pollLoop,
      _PollMessage(
        sendPort: _receivePort!.sendPort,
        contextAddress: contextAddress,
      ),
      errorsAreFatal: false,
    ).then((isolate) => _isolate = isolate);
  }

  void stop() {
    _isolate?.kill(priority: Isolate.immediate);
    _isolate = null;
    _receivePort?.close();
    _receivePort = null;
  }

  void _onMessage(dynamic message) {
    if (message is! String) return;
    try {
      final decoded = jsonDecode(message);
      if (decoded is! List) return;
      for (final item in decoded) {
        if (item is! Map<String, dynamic>) continue;
        final event = BackendEvent.fromJson(item);
        if (event != null) _controller.add(event);
      }
    } catch (_) {}
  }

  static void _pollLoop(_PollMessage msg) {
    final lib = _loadLibrary();
    final pollEvents = lib.lookupFunction<
      Pointer<Utf8> Function(Pointer<Void>, Uint32),
      Pointer<Utf8> Function(Pointer<Void>, int)
    >('mi_poll_events');
    final stringFree = lib.lookupFunction<
      Void Function(Pointer<Utf8>),
      void Function(Pointer<Utf8>)
    >('mi_string_free');

    final ctx = Pointer<Void>.fromAddress(msg.contextAddress);

    while (true) {
      final ptr = pollEvents(ctx, 64);
      if (ptr != nullptr) {
        final json = ptr.toDartString();
        stringFree(ptr);
        if (json.length > 2) {
          msg.sendPort.send(json);
          continue;
        }
      }
      sleep(const Duration(milliseconds: 200));
    }
  }

  static DynamicLibrary _loadLibrary() {
    if (Platform.isAndroid) return DynamicLibrary.open('libmesh_infinity.so');
    if (Platform.isIOS) return DynamicLibrary.process();
    if (Platform.isMacOS) return DynamicLibrary.open('libmesh_infinity.dylib');
    if (Platform.isWindows) return DynamicLibrary.open('mesh_infinity.dll');
    return DynamicLibrary.open('libmesh_infinity.so');
  }
}

class _PollMessage {
  const _PollMessage({required this.sendPort, required this.contextAddress});
  final SendPort sendPort;
  final int contextAddress;
}
