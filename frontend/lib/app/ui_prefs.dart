import 'dart:convert';
import 'dart:io';

import 'package:path_provider/path_provider.dart';

import 'debug_logger.dart';

/// Per-device UI flags that the backend has no reason to know about
/// (SPEC §22.35.1 `gesture_hint_seen_<id>`).
///
/// The Rust backend exposes no generic key/value API, and these flags are
/// purely cosmetic and local to one device, so they live in a tiny JSON file
/// in the application-support directory next to the debug log.  Nothing here
/// is secret, never leaves the device and needs no cloud service.
///
/// The store is a singleton so any widget can read a flag synchronously after
/// [load] has completed; [instance] is replaceable so tests can run against a
/// temporary directory or pure memory.
class UiPrefs {
  /// A store persisted in [directory].  A null directory keeps the flags in
  /// memory only, which is how widget tests (and a platform with no writable
  /// support directory) run.
  UiPrefs({Directory? directory, this.use_platform_dir = false})
    : _directory = directory;

  /// The store the app uses.  Resolves the platform support directory lazily
  /// on the first [load].
  static UiPrefs instance = UiPrefs(use_platform_dir: true);

  /// File name inside the directory.
  static final String prefs_path = 'ui_prefs.json';

  /// True when [load] should ask path_provider for the directory.
  final bool use_platform_dir;

  Directory? _directory;
  final Map<String, bool> _flags = {};
  Future<void>? _loading;

  /// Reads the flag file once; later calls return the same future.
  Future<void> load() => _loading ??= _read();

  /// True when [key] has been set on this device.  Call after [load].
  bool flag(String key) => _flags[key] ?? false;

  /// Sets [key] and persists the file.  The in-memory value changes even if
  /// the write fails, so a read-only disk costs one repeat of a hint per
  /// launch instead of a repeat on every screen visit.
  Future<void> set_flag(String key) async {
    await load();
    if (_flags[key] == true) return;
    _flags[key] = true;
    await _write();
  }

  Future<File?> _file() async {
    if (_directory == null && use_platform_dir) {
      try {
        _directory = await getApplicationSupportDirectory();
      } on Exception catch (e) {
        // No platform channel (headless host): fall back to memory.
        DebugLogger.log('ui_prefs: no support directory ($e)');
      }
    }
    final dir = _directory;
    return dir == null ? null : File('${dir.path}/$prefs_path');
  }

  Future<void> _read() async {
    final file = await _file();
    if (file == null || !await file.exists()) return;
    try {
      final decoded = jsonDecode(await file.readAsString());
      if (decoded is Map<String, dynamic>) {
        for (final entry in decoded.entries) {
          if (entry.value == true) _flags[entry.key] = true;
        }
      }
    } on Exception catch (e) {
      // A corrupt file only loses cosmetic flags; start clean.
      DebugLogger.log('ui_prefs: unreadable $prefs_path ($e)');
    }
  }

  Future<void> _write() async {
    final file = await _file();
    if (file == null) return;
    try {
      // Write to a temp file and rename so a crash never leaves half a file.
      final tmp = File('${file.path}.tmp');
      await tmp.writeAsString(jsonEncode(_flags), flush: true);
      await tmp.rename(file.path);
    } on Exception catch (e) {
      DebugLogger.log('ui_prefs: write failed ($e)');
    }
  }
}
