import 'dart:io';

import 'package:flutter/foundation.dart';

// §17.8.1 Debug Logging
//
// Active only in Flutter profile builds (kProfileMode == true), which
// corresponds to Makefile "debug" targets.  Writes a rolling log to
// internal storage so testers can retrieve diagnostics without a connected
// debugger.  No-ops entirely in release builds.
//
// Usage:
//   await DebugLogger.init(appSupportPath);   // call once at startup
//   DebugLogger.log('some message');          // explicit log call
//
// debugPrint is also overridden so existing debugPrint calls throughout
// the codebase are automatically routed to the file.

class DebugLogger {
  static const _fileName = 'mesh_infinity_debug.log';
  static const _backupName = 'mesh_infinity_debug.log.1';
  static const _maxBytes = 5 * 1024 * 1024; // 5 MB

  static IOSink? _sink;
  static File? _file;

  /// Initialise the logger.  Must be called once before BackendBridge.open().
  /// Does nothing in release builds.
  static Future<void> init(String appSupportPath) async {
    if (!kProfileMode) return;

    _file = File('$appSupportPath/$_fileName');
    await _openSink();

    final banner =
        '=== Mesh Infinity profile build started ${DateTime.now().toIso8601String()} ===';
    _writeLine(banner);

    // Override debugPrint so all existing calls in the codebase go to the file.
    debugPrint = (String? message, {int? wrapWidth}) {
      final line = message ?? '';
      // Still print to the platform console for live `flutter logs` use.
      debugPrintSynchronously(line, wrapWidth: wrapWidth);
      _writeLine(line);
    };
  }

  /// Explicit log call.  Safe to call before init() — silently ignored.
  static void log(String message) => _writeLine(message);

  // ── internals ────────────────────────────────────────────────────────────

  static Future<void> _openSink() async {
    final file = _file;
    if (file == null) return;
    _sink = file.openWrite(mode: FileMode.append);
  }

  static void _writeLine(String message) {
    if (!kProfileMode) return;
    final sink = _sink;
    if (sink == null) return;
    sink.writeln('${DateTime.now().toIso8601String()} $message');
    _maybeRotate();
  }

  static void _maybeRotate() {
    final file = _file;
    if (file == null) return;
    // Check size without blocking — if the file doesn't exist yet, skip.
    int length;
    try {
      length = file.lengthSync();
    } catch (_) {
      return;
    }
    if (length < _maxBytes) return;

    // Rotate: close current sink, rename file to backup, reopen.
    final backup = File('${file.parent.path}/$_backupName');
    _sink?.close();
    _sink = null;
    try {
      if (backup.existsSync()) backup.deleteSync();
      file.renameSync(backup.path);
      _file = File(file.path); // renameSync moves the file; reset reference
    } catch (_) {
      // If rotation fails, just keep writing to wherever we are.
      _file = file;
    }
    _sink = _file!.openWrite(mode: FileMode.append);
  }
}
