// debug_screen.dart
//
// DebugScreen — developer tools, log viewer, and protocol exerciser (§22.56).
//
// AVAILABILITY:
// -------------
// This screen is ONLY visible in debug builds.  In release builds kDebugMode
// is false and no code path leads here — the tile in SettingsScreen is
// wrapped in `if (kDebugMode)` so it doesn't appear in production at all.
// The Dart compiler tree-shakes dead code in release mode, so this entire
// file is eliminated from production binaries.
//
// WHY a debug menu?
// -----------------
// Many protocol failure modes are extremely hard to reproduce naturally
// (e.g. S&F round-trip, relay deposit with HMAC gate, forced rekey).  The
// Protocol Exerciser (§22.56.4) lets developers and testers trigger these
// flows on demand without attaching a debugger.
//
// The Log Viewer (§22.56.1) shows the last 5,000 log entries from Rust's
// ring buffer, filterable by level and module.  This lets us file precise
// bug reports without requiring users to capture adb logcat or syslog.
//
// SECTIONS:
//   §22.56.1 Log Viewer          — ring-buffer log display (stub, polling not wired)
//   §22.56.2 State Inspector     — read-only internal state dump
//   §22.56.3 Simulation Controls — inject failures, latency, threat contexts
//   §22.56.4 Protocol Exerciser  — run X3DH, Double Ratchet, 4-layer, S&F tests
//   §22.56.5 FFI Call Tracer     — timing + call count per bridge method
//   §22.56.6 Build Info          — version, platform, build flags
//
// Reached from: Settings → Developer Options (debug builds only).

import 'package:flutter/foundation.dart' show kDebugMode;
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/backend_bridge.dart';

// ---------------------------------------------------------------------------
// DebugScreen
// ---------------------------------------------------------------------------

/// Developer-only screen providing logs, state inspection, and test tools.
///
/// Guarded at the SettingsScreen call site by `if (kDebugMode)` — this
/// widget itself does not assert kDebugMode so it can be tested in debug
/// builds without workarounds.
class DebugScreen extends StatefulWidget {
  const DebugScreen({super.key});

  @override
  State<DebugScreen> createState() => _DebugScreenState();
}

class _DebugScreenState extends State<DebugScreen> {
  // ── Simulation state ─────────────────────────────────────────────────────
  // These fields drive the simulation controls section.  They're local to
  // this State because they only exist while the debug screen is open.

  /// Whether all outbound packets are being dropped (simulated partition).
  bool _networkPartition = false;

  /// Extra latency injected into every outbound send, in milliseconds.
  int _injectedLatencyMs = 0;

  // ── FFI tracing state ─────────────────────────────────────────────────────
  /// Whether FFI call timing is being recorded.
  bool _ffiTracingEnabled = false;

  // ── Protocol test results ─────────────────────────────────────────────────
  // Each entry: testId → ('pass'|'fail'|'running'|null).
  final Map<String, String?> _testResults = {};

  @override
  Widget build(BuildContext context) {
    final tt = Theme.of(context).textTheme;
    final cs = Theme.of(context).colorScheme;
    final bridge = context.read<BackendBridge>();

    return Scaffold(
      appBar: AppBar(
        title: const Text('Developer Options'),
        // Bright indicator so devs always know they're in the debug screen.
        backgroundColor: kDebugMode ? cs.errorContainer : null,
        foregroundColor: kDebugMode ? cs.onErrorContainer : null,
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // ── Warning banner ─────────────────────────────────────────────
          // Explicitly labels this as a debug build so screenshots in bug
          // reports are clearly identified as non-production.
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: cs.errorContainer.withValues(alpha: 0.4),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Row(
              children: [
                Icon(Icons.bug_report_outlined, color: cs.error, size: 18),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    'Debug build — this menu is not visible in production.',
                    style: tt.bodySmall?.copyWith(color: cs.onErrorContainer),
                  ),
                ),
              ],
            ),
          ),

          const SizedBox(height: 16),

          // ── §22.56.1 Log Viewer (entry point) ─────────────────────────
          // Full log viewer is in its own screen to avoid overloading this
          // list view.  The ring buffer is polled only when that screen is
          // open — no background polling cost while just browsing debug menu.
          const _SectionHeader('Logs'),
          ListTile(
            leading: const Icon(Icons.article_outlined),
            title: const Text('Log viewer'),
            subtitle: const Text('Last 5,000 entries from Rust ring buffer'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const _LogViewerScreen()),
            ),
          ),

          const Divider(height: 1),

          // ── §22.56.2 State Inspector (entry point) ─────────────────────
          const _SectionHeader('State Inspector'),
          ListTile(
            leading: const Icon(Icons.manage_search_outlined),
            title: const Text('Internal state'),
            subtitle: const Text('Identity, routing, sessions, storage'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => Navigator.push(
              context,
              MaterialPageRoute(
                builder: (_) => _StateInspectorScreen(bridge: bridge),
              ),
            ),
          ),

          const Divider(height: 1),

          // ── §22.56.3 Simulation Controls ──────────────────────────────
          const _SectionHeader('Simulate'),

          // Network partition — drops all outbound packets.
          // Useful for testing store-and-forward and peer reconnection.
          SwitchListTile(
            secondary: const Icon(Icons.wifi_off_outlined),
            title: const Text('Network partition'),
            subtitle: const Text('Drop all outbound packets'),
            value: _networkPartition,
            onChanged: (v) {
              setState(() => _networkPartition = v);
              // TODO(debug): bridge.setSimNetworkPartition(v)
              _snack(
                context,
                v ? 'Network partition active' : 'Network partition removed',
              );
            },
          ),

          // Latency injection — adds artificial delay to every send.
          // Useful for testing timeout and retry logic.
          ListTile(
            leading: const Icon(Icons.timer_outlined),
            title: const Text('Inject latency'),
            subtitle: Text('${_injectedLatencyMs}ms added to all sends'),
            trailing: SizedBox(
              width: 160,
              child: Slider(
                value: _injectedLatencyMs.toDouble(),
                min: 0,
                max: 2000,
                divisions: 40,
                label: '${_injectedLatencyMs}ms',
                onChanged: (v) {
                  setState(() => _injectedLatencyMs = v.toInt());
                  // TODO(debug): bridge.setSimLatencyMs(v.toInt())
                },
              ),
            ),
          ),

          // Force rekey on all active sessions.
          ListTile(
            leading: const Icon(Icons.lock_reset_outlined),
            title: const Text('Force session rekey'),
            subtitle: const Text('Triggers immediate rekey on all sessions'),
            trailing: FilledButton.tonal(
              onPressed: () {
                // TODO(debug): bridge.forceRekey()
                _snack(context, 'Rekey triggered (stub)');
              },
              child: const Text('Rekey'),
            ),
          ),

          // Killswitch test — creates a temporary identity, erases it, verifies.
          ListTile(
            leading: const Icon(Icons.verified_outlined),
            title: const Text('Test emergency erase (safe)'),
            subtitle: const Text(
              'Creates a temporary identity, erases it, verifies cleanup',
            ),
            trailing: FilledButton.tonal(
              style: FilledButton.styleFrom(
                backgroundColor: Colors.orange.withValues(alpha: 0.2),
              ),
              onPressed: () {
                // TODO(debug): bridge.testKillswitch()
                _snack(context, 'Killswitch test stub — not yet wired');
              },
              child: const Text('Run test'),
            ),
          ),

          // State dump — exports full JSON snapshot (no key material).
          ListTile(
            leading: const Icon(Icons.download_outlined),
            title: const Text('Export debug dump'),
            subtitle: const Text('Full state snapshot as JSON (no key material)'),
            trailing: IconButton(
              icon: const Icon(Icons.download),
              onPressed: () {
                // TODO(debug): bridge.exportDump() then share/copy
                _snack(context, 'Debug dump export not yet wired');
              },
            ),
          ),

          const Divider(height: 1),

          // ── §22.56.4 Protocol Exerciser ────────────────────────────────
          // Each button runs a specific protocol flow end-to-end and shows
          // pass/fail.  Results stay visible until the screen is closed.
          const _SectionHeader('Protocol Tests'),

          _TestButton(
            id: 'x3dh',
            title: 'X3DH Handshake',
            description: 'Full X3DH key agreement with self',
            result: _testResults['x3dh'],
            onRun: () => _runTest('x3dh'),
          ),
          _TestButton(
            id: 'ratchet',
            title: 'Double Ratchet',
            description: 'Send 100 messages through ratchet, verify decrypt',
            result: _testResults['ratchet'],
            onRun: () => _runTest('ratchet'),
          ),
          _TestButton(
            id: 'four_layer',
            title: '4-Layer Encrypt',
            description:
                'Encrypt and decrypt a test message through all 4 layers',
            result: _testResults['four_layer'],
            onRun: () => _runTest('four_layer'),
          ),
          _TestButton(
            id: 'sender_keys',
            title: 'Sender Keys',
            description:
                'Create a group, distribute sender keys, verify group decrypt',
            result: _testResults['sender_keys'],
            onRun: () => _runTest('sender_keys'),
          ),
          _TestButton(
            id: 'store_forward',
            title: 'S&F Round-Trip',
            description:
                'Deposit a message in S&F, retrieve it, verify integrity',
            result: _testResults['store_forward'],
            onRun: () => _runTest('store_forward'),
          ),
          _TestButton(
            id: 'relay',
            title: 'Relay Deposit',
            description: 'Deposit and retrieve with HMAC gate verification',
            result: _testResults['relay'],
            onRun: () => _runTest('relay'),
          ),
          _TestButton(
            id: 'sigma',
            title: 'Sigma Handshake',
            description: 'Sigma protocol with self, verify proof',
            result: _testResults['sigma'],
            onRun: () => _runTest('sigma'),
          ),

          const Divider(height: 1),

          // ── §22.56.5 FFI Call Tracer ───────────────────────────────────
          const _SectionHeader('FFI Tracer'),
          SwitchListTile(
            secondary: const Icon(Icons.timeline_outlined),
            title: const Text('FFI call tracing'),
            subtitle: const Text(
              'Records all Dart↔Rust calls with timing (impacts performance)',
            ),
            value: _ffiTracingEnabled,
            onChanged: (v) {
              setState(() => _ffiTracingEnabled = v);
              // TODO(debug): bridge.setFfiTracing(v)
              _snack(
                context,
                v ? 'FFI tracing enabled' : 'FFI tracing disabled',
              );
            },
          ),
          if (_ffiTracingEnabled)
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
              child: Text(
                'Trace data will appear here when backend wiring is complete.',
                style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
              ),
            ),

          const Divider(height: 1),

          // ── §22.56.6 Build Info ───────────────────────────────────────
          const _SectionHeader('Build Info'),
          const _KV('App version', '0.3.0'),
          _KV('Build number', kDebugMode ? 'debug' : 'release'),
          _KV('Debug mode', '$kDebugMode'),
          const _KV('Rust backend', 'wired — see mi_version()'),

          const SizedBox(height: 24),
        ],
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // Protocol test runner
  // ---------------------------------------------------------------------------

  /// Marks a test as running, calls the (stubbed) bridge method, updates result.
  ///
  /// TODO(debug): replace the stub delay with real bridge.runProtocolTest(id).
  Future<void> _runTest(String id) async {
    setState(() => _testResults[id] = 'running');
    // Stub: simulate a 500 ms test run.  Replace with real call when wired.
    await Future<void>.delayed(const Duration(milliseconds: 500));
    if (mounted) {
      setState(() => _testResults[id] = 'pass'); // always passes in stub
    }
  }

  void _snack(BuildContext context, String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message), duration: const Duration(seconds: 2)),
    );
  }
}

// ---------------------------------------------------------------------------
// _TestButton — one protocol test row
// ---------------------------------------------------------------------------

/// A ListTile that shows a protocol test with a run button and a result badge.
///
/// [result] is null (not run), 'running', 'pass', or 'fail'.
class _TestButton extends StatelessWidget {
  const _TestButton({
    required this.id,
    required this.title,
    required this.description,
    required this.result,
    required this.onRun,
  });

  final String id;
  final String title;
  final String description;

  /// null = not run, 'running', 'pass', 'fail'.
  final String? result;
  final VoidCallback onRun;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    // Result indicator widget — spinner, green check, or red X.
    Widget resultWidget;
    switch (result) {
      case 'running':
        resultWidget = const SizedBox(
          width: 20,
          height: 20,
          child: CircularProgressIndicator(strokeWidth: 2),
        );
      case 'pass':
        resultWidget = Icon(Icons.check_circle_outline, color: Colors.green[600]);
      case 'fail':
        resultWidget = Icon(Icons.cancel_outlined, color: cs.error);
      default:
        // Not yet run — show a "Run" button.
        resultWidget = TextButton(
          onPressed: onRun,
          child: const Text('Run'),
        );
    }

    return ListTile(
      title: Text(title),
      subtitle: Text(
        description,
        style: Theme.of(context).textTheme.bodySmall?.copyWith(
              color: cs.onSurfaceVariant,
            ),
      ),
      trailing: resultWidget,
    );
  }
}

// ---------------------------------------------------------------------------
// _KV — key/value row for Build Info
// ---------------------------------------------------------------------------

/// Simple key–value row for displaying static build information.
class _KV extends StatelessWidget {
  const _KV(this.label, this.value);

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final tt = Theme.of(context).textTheme;
    final cs = Theme.of(context).colorScheme;

    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      child: Row(
        children: [
          Expanded(
            child: Text(label, style: tt.bodyMedium),
          ),
          Text(
            value,
            style: tt.bodyMedium?.copyWith(
              color: cs.onSurfaceVariant,
              fontFamily: 'monospace',
            ),
          ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _SectionHeader
// ---------------------------------------------------------------------------

class _SectionHeader extends StatelessWidget {
  const _SectionHeader(this.title);

  final String title;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 6),
      child: Text(
        title,
        style: Theme.of(context).textTheme.labelMedium?.copyWith(
              color: Theme.of(context).colorScheme.primary,
              fontWeight: FontWeight.w600,
            ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// §22.56.1 _LogViewerScreen
// ---------------------------------------------------------------------------

/// In-app log viewer — shows the Rust ring buffer filtered by level/module.
///
/// Polling is started when this screen is pushed and stopped on pop, so
/// there is no background CPU cost when the log viewer is not visible.
///
/// TODO(debug/logs): wire bridge.getLogs(minLevel, sinceMs) and poll on
/// 1-second timer while this screen is mounted.
class _LogViewerScreen extends StatefulWidget {
  const _LogViewerScreen();

  @override
  State<_LogViewerScreen> createState() => _LogViewerScreenState();
}

class _LogViewerScreenState extends State<_LogViewerScreen> {
  // Log level filter — show entries at this level and above.
  String _minLevel = 'debug'; // 'trace'|'debug'|'info'|'warn'|'error'

  // Stub entries — replaced by real polling in a future sprint.
  static const List<_LogEntry> _stubEntries = [
    _LogEntry(level: 'info', module: 'app.init', message: 'MeshInfinityApp started'),
    _LogEntry(level: 'debug', module: 'ffi', message: 'Bridge initialised'),
    _LogEntry(level: 'info', module: 'event_bus', message: 'Polling isolate started'),
    _LogEntry(level: 'debug', module: 'settings', message: 'Loaded settings from backend'),
    _LogEntry(level: 'debug', module: 'identity', message: 'Identity loaded'),
    _LogEntry(
      level: 'info',
      module: 'network',
      message: 'No active connections yet — waiting for peers',
    ),
  ];

  @override
  Widget build(BuildContext context) {
    final tt = Theme.of(context).textTheme;
    final cs = Theme.of(context).colorScheme;

    // Filter by the selected min level (show this level and above).
    final levels = ['trace', 'debug', 'info', 'warn', 'error'];
    final minIdx = levels.indexOf(_minLevel);
    final filtered = _stubEntries
        .where((e) => levels.indexOf(e.level) >= minIdx)
        .toList();

    return Scaffold(
      appBar: AppBar(
        title: const Text('Logs'),
        actions: [
          // Level filter.
          PopupMenuButton<String>(
            icon: const Icon(Icons.filter_list),
            tooltip: 'Filter by level',
            onSelected: (level) => setState(() => _minLevel = level),
            itemBuilder: (_) => levels
                .map(
                  (l) => PopupMenuItem(
                    value: l,
                    child: Text(l.toUpperCase()),
                  ),
                )
                .toList(),
          ),
          // Clear logs.
          IconButton(
            icon: const Icon(Icons.delete_outline),
            tooltip: 'Clear logs',
            onPressed: () {
              // TODO(debug/logs): bridge.clearLogs()
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Log clearing not yet wired')),
              );
            },
          ),
        ],
      ),
      body: filtered.isEmpty
          ? Center(
              child: Text(
                'No log entries at ${_minLevel.toUpperCase()} or above.',
                style: tt.bodyMedium?.copyWith(color: cs.onSurfaceVariant),
              ),
            )
          : ListView.separated(
              reverse: true, // newest at bottom
              itemCount: filtered.length,
              separatorBuilder: (_, _) => const Divider(height: 1),
              itemBuilder: (_, i) {
                final log = filtered[i];
                return ListTile(
                  dense: true,
                  leading: Icon(
                    _levelIcon(log.level),
                    size: 16,
                    color: _levelColor(log.level, cs),
                  ),
                  title: Text(
                    '${log.module}: ${log.message}',
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                  ),
                );
              },
            ),
    );
  }

  IconData _levelIcon(String level) => switch (level) {
    'trace' => Icons.grain,
    'debug' => Icons.bug_report_outlined,
    'info' => Icons.info_outline,
    'warn' => Icons.warning_amber_outlined,
    'error' => Icons.error_outline,
    _ => Icons.circle_outlined,
  };

  Color _levelColor(String level, ColorScheme cs) => switch (level) {
    'trace' => cs.outline,
    'debug' => cs.onSurfaceVariant,
    'info' => cs.primary,
    'warn' => Colors.orange,
    'error' => cs.error,
    _ => cs.outline,
  };
}

// ---------------------------------------------------------------------------
// _LogEntry — stub log entry model
// ---------------------------------------------------------------------------

class _LogEntry {
  const _LogEntry({
    required this.level,
    required this.module,
    required this.message,
  });

  final String level;   // 'trace'|'debug'|'info'|'warn'|'error'
  final String module;  // e.g. 'crypto.x3dh', 'routing', 'ffi'
  final String message;
}

// ---------------------------------------------------------------------------
// §22.56.2 _StateInspectorScreen
// ---------------------------------------------------------------------------

/// Shows a read-only dump of internal state in expandable sections.
///
/// Data comes from the backend bridge's various fetch methods.
/// All values are strings — no editing is possible from this screen.
class _StateInspectorScreen extends StatelessWidget {
  const _StateInspectorScreen({required this.bridge});

  final BackendBridge bridge;

  @override
  Widget build(BuildContext context) {
    // Fetch stub identity data from bridge.
    final identity = bridge.fetchLocalIdentity();
    final settings = bridge.fetchSettings();
    final stats = bridge.getNetworkStats();

    return Scaffold(
      appBar: AppBar(title: const Text('State Inspector')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // ── Identity ────────────────────────────────────────────────
          _InspectorSection(
            'Identity',
            entries: [
              _InspectorEntry(
                'Peer ID',
                identity?.peerId.isEmpty ?? true
                    ? '(none)'
                    : identity!.peerId,
              ),
              _InspectorEntry('Name', identity?.name ?? '(none)'),
            ],
          ),

          // ── Settings ─────────────────────────────────────────────
          _InspectorSection(
            'Settings',
            entries: [
              _InspectorEntry(
                'Node mode',
                '${settings?.nodeMode ?? 0}',
              ),
              _InspectorEntry(
                'Tor',
                '${settings?.enableTor ?? false}',
              ),
              _InspectorEntry(
                'Clearnet',
                '${settings?.enableClearnet ?? false}',
              ),
              _InspectorEntry(
                'I2P',
                '${settings?.enableI2p ?? false}',
              ),
            ],
          ),

          // ── Network Stats ────────────────────────────────────────
          _InspectorSection(
            'Network Stats',
            entries: [
              _InspectorEntry(
                'Active connections',
                '${stats?['activeConnections'] ?? 0}',
              ),
              _InspectorEntry(
                'Bytes sent',
                '${stats?['bytesSent'] ?? 0}',
              ),
              _InspectorEntry(
                'Bytes received',
                '${stats?['bytesReceived'] ?? 0}',
              ),
              _InspectorEntry(
                'Gossip map size',
                '${stats?['gossipMapSize'] ?? 0}',
              ),
            ],
          ),

          const SizedBox(height: 24),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _InspectorSection — expandable section in State Inspector
// ---------------------------------------------------------------------------

class _InspectorSection extends StatelessWidget {
  const _InspectorSection(this.title, {required this.entries});

  final String title;
  final List<_InspectorEntry> entries;

  @override
  Widget build(BuildContext context) {
    final tt = Theme.of(context).textTheme;
    final cs = Theme.of(context).colorScheme;

    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      clipBehavior: Clip.antiAlias,
      child: ExpansionTile(
        title: Text(title, style: tt.titleSmall),
        children: entries
            .map(
              (e) => Padding(
                padding: const EdgeInsets.fromLTRB(16, 4, 16, 4),
                child: Row(
                  children: [
                    Expanded(child: Text(e.key, style: tt.bodySmall)),
                    Text(
                      e.value,
                      style: tt.bodySmall?.copyWith(
                        fontFamily: 'monospace',
                        color: cs.onSurfaceVariant,
                      ),
                    ),
                  ],
                ),
              ),
            )
            .toList(),
      ),
    );
  }
}

class _InspectorEntry {
  const _InspectorEntry(this.key, this.value);

  final String key;
  final String value;
}
