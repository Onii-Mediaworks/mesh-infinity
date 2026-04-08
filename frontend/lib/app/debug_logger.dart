import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:path_provider/path_provider.dart';

// §17.8.1 Debug Logging
//
// Active only in Flutter profile builds (kProfileMode == true), which
// corresponds to Makefile "debug" targets.  Writes a rolling log to a
// platform-appropriate externally accessible location so testers can
// retrieve diagnostics without a connected debugger.
//
// We intentionally use *profile* builds rather than debug builds for field
// testing: profile builds have AOT-compiled Dart (realistic performance) but
// still include the Flutter service extension infrastructure that lets us
// measure frame times.  A pure debug build runs in JIT mode and would give
// misleading timing numbers.
//
// Platform log paths:
//   Android  — getExternalStorageDirectory() (app-specific external storage,
//              /storage/emulated/0/Android/data/<pkg>/files/); accessible via
//              USB file transfer and ADB.  Falls back to appSupportPath if
//              external storage is unavailable.
//   iOS      — getApplicationDocumentsDirectory(); visible in the Files app
//              and via Finder (UIFileSharingEnabled = YES in Info.plist).
//   Desktop  — appSupportPath passed from main.dart (app support directory).
//
// Usage:
//   await DebugLogger.init(appSupportPath);   // call once at startup
//   DebugLogger.log('some message');          // explicit log call
//
// debugPrint is also overridden so existing debugPrint calls throughout
// the codebase are automatically routed to the file.  This means no
// call-site changes are needed — any code that already calls debugPrint
// gets file logging for free.

class DebugLogger {
  // Name of the active log file on disk.  A plain text file so any text
  // editor or `adb pull` can read it without special tooling.
  static const _fileName = 'mesh_infinity_debug.log';

  // When the active log exceeds _maxBytes we rename it to this name (the
  // previous backup, if any, is deleted first) and start a fresh active file.
  // Keeping one generation of backup means we don't lose the tail of the
  // previous session when the app is restarted and the file is recreated.
  static const _backupName = 'mesh_infinity_debug.log.1';

  // Maximum size of the active log file before rotation is triggered.
  // 5 MB is enough for several minutes of dense logging while keeping the
  // file small enough to share over email or Slack without hitting
  // attachment size limits.
  static const _maxBytes = 5 * 1024 * 1024; // 5 MB

  // The IOSink is the write handle to the open log file.  IOSink buffers
  // writes internally and flushes them asynchronously, which keeps logging
  // from blocking the UI thread.  Nullable so we can detect the
  // uninitialised state and silently no-op early callers.
  static IOSink? _sink;

  // The File object pointing at the active log path.  We keep this around
  // so _maybeRotate can check the file size with lengthSync() and so we
  // know the parent directory when constructing the backup path.
  static File? _file;

  // ── public API ────────────────────────────────────────────────────────────

  /// Initialise the logger.  Must be called once at startup, before the
  /// BackendBridge is opened, so that any early bridge errors are captured.
  ///
  /// [appSupportPath] is the platform app-support directory, obtained in
  /// main.dart via path_provider.  It is passed in rather than looked up
  /// here to avoid duplicating the async lookup.
  ///
  /// Does nothing in release builds (kProfileMode is false there), so this
  /// is safe to leave in the call site unconditionally.
  static Future<void> init(String appSupportPath) async {
    // kProfileMode is a Flutter compile-time constant that is true only in
    // `flutter run --profile` / `flutter build --profile` output.  In
    // release builds the entire body of this function is dead-code-eliminated
    // by the compiler, so there is zero runtime overhead.
    if (!kProfileMode) return;

    // Ask the platform for the right directory, then make sure it exists.
    // create(recursive: true) is a no-op if the directory already exists,
    // so this is safe to call on every launch.
    final logDir = await _resolveLogDirectory(appSupportPath);
    await Directory(logDir).create(recursive: true);

    // Build the File handle.  openWrite is called separately in _openSink so
    // that the same open logic can be reused after a log rotation.
    _file = File('$logDir/$_fileName');
    await _openSink();

    // Write a clearly visible session-start marker.  The ISO 8601 timestamp
    // makes it easy to correlate log entries with crash reports or user-
    // reported "it broke at 3pm" style feedback.
    final banner =
        '=== Mesh Infinity profile build started ${DateTime.now().toIso8601String()} ===';
    _writeLine(banner);

    // Shadow the global debugPrint function pointer with our own closure.
    // Flutter's framework and all in-tree code call debugPrint rather than
    // print(), so replacing this one hook captures everything automatically.
    debugPrint = (String? message, {int? wrapWidth}) {
      final line = message ?? '';
      // Keep writing to the platform console so `flutter logs` / logcat still
      // work for developers with a connected device — the file is in addition
      // to the console, not instead of it.
      debugPrintSynchronously(line, wrapWidth: wrapWidth);
      _writeLine(line);
    };
  }

  /// Write [message] to the log.  Safe to call before [init] — if the logger
  /// has not been initialised yet (or is running in a release build) the call
  /// is silently ignored rather than throwing.
  static void log(String message) => _writeLine(message);

  // ── internals ────────────────────────────────────────────────────────────

  /// Returns the directory path where the log file should be written, chosen
  /// to be accessible to testers without developer tools where possible.
  static Future<String> _resolveLogDirectory(String appSupportPath) async {
    if (Platform.isAndroid) {
      // App-specific external storage is under
      // /storage/emulated/0/Android/data/<package>/files/.
      // It is readable over USB MTP file transfer and via `adb pull` without
      // requiring the broad MANAGE_EXTERNAL_STORAGE permission (added in
      // API 30 / Android 11).  getExternalStorageDirectory() can return null
      // on devices where external storage is emulated but currently
      // unavailable (e.g. during an OTA), so we fall back to the internal
      // app-support directory rather than crashing.
      final ext = await getExternalStorageDirectory();
      return ext?.path ?? appSupportPath;
    }

    if (Platform.isIOS) {
      // The Documents directory is exposed to the iOS Files app and to
      // macOS Finder when the device is connected via USB, provided
      // UIFileSharingEnabled = YES is set in the Runner's Info.plist.
      // This lets testers grab the log without needing Xcode or instruments.
      final docs = await getApplicationDocumentsDirectory();
      return docs.path;
    }

    // macOS, Linux, Windows: the app-support directory is a reasonable
    // location that is writable by the app and findable by a developer
    // who knows where to look (e.g. ~/Library/Application Support on macOS).
    return appSupportPath;
  }

  /// Opens (or reopens) the write handle to [_file] in append mode.
  ///
  /// Append mode (FileMode.append) means every launch adds to the existing
  /// file rather than truncating it, which preserves the end of the previous
  /// session.  The session-start banner written by [init] provides a clear
  /// delimiter between sessions within the same file.
  static Future<void> _openSink() async {
    final file = _file;
    // Guard: _file is set just before _openSink is called in init(), but
    // this null check keeps the function self-contained in case the call
    // order ever changes.
    if (file == null) return;
    _sink = file.openWrite(mode: FileMode.append);
  }

  /// Prepend a UTC ISO 8601 timestamp and append [message] to the log.
  ///
  /// Timestamps use [DateTime.now()] which is local time on most platforms
  /// but renders to ISO 8601 regardless, making logs unambiguous when shared
  /// across time zones.  After writing, we check whether rotation is needed.
  static void _writeLine(String message) {
    // Double-guard: also checked at the top of init(), but callers like log()
    // can be invoked before init() in release builds, so we gate here too to
    // make the no-op contract unconditional.
    if (!kProfileMode) return;

    final sink = _sink;
    // If init() was never called, or if rotation temporarily closed the sink,
    // drop the message rather than buffering or throwing.  A missing log line
    // is vastly preferable to a crash in a debug helper.
    if (sink == null) return;

    sink.writeln('${DateTime.now().toIso8601String()} $message');

    // Check file size after every write.  Doing it synchronously here means
    // there is a small stat() overhead on each log call, but rotation events
    // are rare (once per 5 MB) and the cost is negligible compared to the
    // disk write that just happened.
    _maybeRotate();
  }

  /// Rotates the log file if it has exceeded [_maxBytes].
  ///
  /// Rotation strategy: close the current sink → rename active log to the
  /// backup name (deleting any pre-existing backup first) → reopen a fresh
  /// active file.  This gives us at most two files on disk at any time,
  /// capping total log disk usage at roughly 2 × _maxBytes.
  ///
  /// All I/O errors are silently swallowed.  A failure here must never
  /// propagate to the caller — the logger is a diagnostic aid and must not
  /// destabilise the application it is debugging.
  static void _maybeRotate() {
    final file = _file;
    // Nothing to rotate if we never opened a file.
    if (file == null) return;

    // lengthSync() is a single stat(2) call — cheap, but we still guard the
    // try/catch because the file could have been deleted externally (e.g. by
    // the user clearing app storage) at any point.
    int length;
    try {
      length = file.lengthSync();
    } catch (_) {
      // If we cannot stat the file we cannot make a size decision.
      // Silently bail — the next write will try again.
      return;
    }

    // Still within the size budget; nothing to do.
    if (length < _maxBytes) return;

    // ── Perform rotation ──────────────────────────────────────────────────
    // Build the backup File handle before we close the current sink, so we
    // have the parent path available regardless of what happens next.
    final backup = File('${file.parent.path}/$_backupName');

    // Close the sink first.  We must not write to it after calling close();
    // the IOSink contract says further writes after close are undefined.
    _sink?.close();
    _sink = null;

    try {
      // Delete the previous backup if one exists so renameSync does not fail
      // on platforms that require the destination to be absent (e.g. Windows).
      if (backup.existsSync()) backup.deleteSync();

      // Atomically rename the active log to the backup slot.  After this
      // line the active path no longer exists on disk.
      file.renameSync(backup.path);

      // renameSync invalidates the internal path state of [file], so we must
      // create a fresh File object pointing at the original path before
      // opening a new sink — reusing [file] after rename is undefined behaviour
      // in dart:io on some platforms.
      _file = File(file.path);
    } catch (_) {
      // Rename or delete failed (permissions, full disk, etc.).  Recover by
      // keeping _file pointed at the original path so future writes still go
      // somewhere.  The log will grow beyond _maxBytes until the condition
      // resolves, which is acceptable — correctness over size limits.
      _file = file;
    }

    // Reopen in append mode against the (now fresh) active path.
    // Using the null-assertion (!) is safe here because we always assign
    // _file above, both in the try branch and the catch branch.
    _sink = _file!.openWrite(mode: FileMode.append);
  }
}
