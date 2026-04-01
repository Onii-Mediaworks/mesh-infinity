// app_connector_screen.dart
//
// AppConnectorScreen — route selected apps through the mesh (§22.9.4).
//
// WHAT APP CONNECTOR DOES:
// ------------------------
// When Mesh VPN mode is active (§13.15), App Connector intercepts network
// traffic from chosen apps and routes it through the mesh instead of the
// device's normal internet connection.  Two modes:
//
//   Allowlist — only the apps you explicitly select use the mesh.
//               Everything else uses the normal connection.  Good default
//               for most users: route Signal through the mesh, leave
//               streaming apps on direct internet.
//
//   Denylist  — all apps go through the mesh EXCEPT those you exclude.
//               Useful on a dedicated privacy device where most traffic
//               should be mesh-routed.
//
// WHY PER-APP ROUTING?
// --------------------
// A global VPN that captures all traffic would break apps that need the
// real internet (streaming, banking) or have certificate pinning.
// Per-app routing gives users surgical control: privacy where they need it,
// normal performance where they don't.
//
// BACKEND STATUS:
// ---------------
// VPN mode and per-app routing are not yet implemented in the backend.
// This screen shows the full UI with:
//   - VPN toggle wired to NetworkState.setVpnMode() (stub returns false).
//   - App list and picker shown as stubs — actual system app enumeration
//     is platform-specific and requires platform channels.
// When backend is ready: replace stub app list with real data from
// bridge.getInstalledApps() / bridge.getConnectorConfig().
//
// Reached from: Network → Status → "App Connector" tile.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../network_state.dart';

// ---------------------------------------------------------------------------
// ConnectorMode — allowlist vs denylist selection
// ---------------------------------------------------------------------------

/// Whether the app list is an allowlist (only these apps use mesh) or
/// a denylist (all apps use mesh except these).
enum ConnectorMode {
  /// Only selected apps route through the mesh.
  allowlist,

  /// All apps route through the mesh except excluded ones.
  denylist,
}

// ---------------------------------------------------------------------------
// ConnectorApp — one configured app entry (stub model)
// ---------------------------------------------------------------------------

/// Represents one app in the connector's allowlist or denylist.
///
/// [icon] is null in the stub — replaced with real app icon when the
/// platform channel for app enumeration is implemented.
class ConnectorApp {
  const ConnectorApp({
    required this.name,
    required this.packageName,
    this.icon,
  });

  final String name;

  /// Android package name or iOS bundle ID.
  final String packageName;

  /// App icon image provider.  Null until platform channels are wired.
  final ImageProvider? icon;
}

// ---------------------------------------------------------------------------
// AppConnectorScreen
// ---------------------------------------------------------------------------

/// Configures which apps route through the mesh network.
class AppConnectorScreen extends StatefulWidget {
  const AppConnectorScreen({super.key});

  @override
  State<AppConnectorScreen> createState() => _AppConnectorScreenState();
}

class _AppConnectorScreenState extends State<AppConnectorScreen> {
  /// Current selection mode — starts as allowlist (opt-in is safer default).
  ConnectorMode _mode = ConnectorMode.allowlist;

  /// The configured app list (allowlist or denylist depending on [_mode]).
  ///
  /// Stub: empty until platform channels enumerate installed apps.
  /// TODO(backend/connector): load from bridge.getConnectorConfig().
  final List<ConnectorApp> _configuredApps = [];

  @override
  Widget build(BuildContext context) {
    final net = context.watch<NetworkState>();
    final tt = Theme.of(context).textTheme;
    final cs = Theme.of(context).colorScheme;

    // VPN is "active" when the mode is anything other than "off".
    final vpnEnabled = net.isVpnActive;

    return Scaffold(
      appBar: AppBar(title: const Text('App Connector')),
      body: Column(
        children: [
          // ── VPN master toggle card ───────────────────────────────────
          // The toggle must be enabled before per-app configuration matters.
          // Shown at the top so users can see why the app list is grayed out.
          Padding(
            padding: const EdgeInsets.all(16),
            child: Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                'Mesh VPN mode',
                                style: tt.titleSmall,
                              ),
                              const SizedBox(height: 2),
                              Text(
                                'Routes selected apps through the mesh network.',
                                style: tt.bodySmall?.copyWith(
                                  color: cs.onSurfaceVariant,
                                ),
                              ),
                            ],
                          ),
                        ),
                        Switch(
                          value: vpnEnabled,
                          onChanged: (v) => v
                              ? _enableVpn(context, net)
                              : _confirmDisableVpn(context, net),
                        ),
                      ],
                    ),
                    // Active indicator — shown when VPN is running.
                    if (vpnEnabled) ...[
                      const SizedBox(height: 8),
                      Row(
                        children: [
                          Container(
                            width: 8,
                            height: 8,
                            decoration: const BoxDecoration(
                              color: Color(0xFF22C55E), // secGreen
                              shape: BoxShape.circle,
                            ),
                          ),
                          const SizedBox(width: 6),
                          Text(
                            'Active — routing ${_configuredApps.length} apps',
                            style: tt.bodySmall?.copyWith(
                              color: const Color(0xFF22C55E),
                            ),
                          ),
                        ],
                      ),
                    ],
                  ],
                ),
              ),
            ),
          ),

          // ── VPN off — full-screen empty state ────────────────────────
          // When VPN is off, there's nothing else to configure.  Show an
          // invitation to enable it rather than a disabled-looking form.
          if (!vpnEnabled) ...[
            Expanded(
              child: Center(
                child: Padding(
                  padding: const EdgeInsets.all(32),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(
                        Icons.vpn_key_outlined,
                        size: 56,
                        color: cs.outline,
                      ),
                      const SizedBox(height: 12),
                      Text('VPN mode is off', style: tt.titleMedium),
                      const SizedBox(height: 4),
                      Text(
                        "Enable Mesh VPN mode above to route other apps' "
                        'traffic through the mesh network.',
                        style: tt.bodyMedium?.copyWith(
                          color: cs.onSurfaceVariant,
                        ),
                        textAlign: TextAlign.center,
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ] else ...[
            // ── Mode selector ────────────────────────────────────────────
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('App selection mode', style: tt.labelMedium),
                  const SizedBox(height: 8),
                  SegmentedButton<ConnectorMode>(
                    segments: const [
                      ButtonSegment(
                        value: ConnectorMode.allowlist,
                        label: Text('Selected apps only'),
                        icon: Icon(Icons.checklist_outlined, size: 14),
                      ),
                      ButtonSegment(
                        value: ConnectorMode.denylist,
                        label: Text('All except excluded'),
                        icon: Icon(Icons.block_outlined, size: 14),
                      ),
                    ],
                    selected: {_mode},
                    onSelectionChanged: (s) =>
                        setState(() => _mode = s.first),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    _mode == ConnectorMode.allowlist
                        ? 'Only the apps you select will route through the mesh.'
                        : 'All apps will route through the mesh except those you exclude.',
                    style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
                  ),
                ],
              ),
            ),

            const SizedBox(height: 8),
            const Divider(height: 1),

            // ── App list header ──────────────────────────────────────────
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
              child: Row(
                children: [
                  Expanded(
                    child: Text(
                      _mode == ConnectorMode.allowlist
                          ? 'Apps routed through mesh'
                          : 'Excluded apps',
                      style: tt.titleSmall,
                    ),
                  ),
                  TextButton.icon(
                    onPressed: () => _openAppPicker(context),
                    icon: const Icon(Icons.add, size: 16),
                    label: const Text('Add'),
                  ),
                ],
              ),
            ),

            // ── App list or empty state ──────────────────────────────────
            Expanded(
              child: _configuredApps.isEmpty
                  ? Center(
                      child: Padding(
                        padding: const EdgeInsets.all(32),
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(Icons.apps_outlined, size: 40, color: cs.outline),
                            const SizedBox(height: 8),
                            Text(
                              _mode == ConnectorMode.allowlist
                                  ? 'No apps selected — tap Add'
                                  : 'No exclusions — all apps are routed',
                              style: tt.bodyMedium?.copyWith(
                                color: cs.onSurfaceVariant,
                              ),
                              textAlign: TextAlign.center,
                            ),
                          ],
                        ),
                      ),
                    )
                  : ListView.separated(
                      itemCount: _configuredApps.length,
                      separatorBuilder: (_, _) =>
                          const Divider(height: 1, indent: 72),
                      itemBuilder: (ctx, i) {
                        final app = _configuredApps[i];
                        return ListTile(
                          // App icon — placeholder until platform channel is wired.
                          leading: app.icon != null
                              ? ClipRRect(
                                  borderRadius: BorderRadius.circular(8),
                                  child: Image(
                                    image: app.icon!,
                                    width: 40,
                                    height: 40,
                                  ),
                                )
                              : const _AppIconPlaceholder(),
                          title: Text(app.name),
                          subtitle: Text(
                            app.packageName,
                            style: tt.bodySmall?.copyWith(
                              color: cs.onSurfaceVariant,
                              fontFamily: 'monospace',
                              fontSize: 11,
                            ),
                          ),
                          trailing: IconButton(
                            icon: Icon(
                              Icons.remove_circle_outline,
                              color: cs.error,
                            ),
                            tooltip: 'Remove',
                            onPressed: () => setState(
                              () => _configuredApps.removeWhere(
                                (a) => a.packageName == app.packageName,
                              ),
                            ),
                          ),
                        );
                      },
                    ),
            ),
          ],
        ],
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // VPN enable / disable
  // ---------------------------------------------------------------------------

  Future<void> _enableVpn(BuildContext context, NetworkState net) async {
    // TODO(backend/connector): request VPN permission on Android (VpnService API).
    await net.setVpnMode('mesh_only');
    if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Mesh VPN enabled — backend stub, no real routing yet.'),
        ),
      );
    }
  }

  Future<void> _confirmDisableVpn(
    BuildContext context,
    NetworkState net,
  ) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Disable Mesh VPN?'),
        content: const Text(
          'All apps will revert to their normal internet connections.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Disable'),
          ),
        ],
      ),
    );
    if (ok == true) await net.setVpnMode('off');
  }

  // ---------------------------------------------------------------------------
  // App picker (stub)
  // ---------------------------------------------------------------------------

  /// Opens the system app picker — stub until platform channels are wired.
  ///
  /// TODO(backend/connector): enumerate installed apps via platform channel
  /// and present them in a searchable bottom sheet.
  void _openAppPicker(BuildContext context) {
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('App picker requires platform channel — coming soon.'),
        duration: Duration(seconds: 3),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _AppIconPlaceholder — shown when no icon is available
// ---------------------------------------------------------------------------

/// Placeholder when app icon can't be loaded (platform channel not wired yet).
class _AppIconPlaceholder extends StatelessWidget {
  const _AppIconPlaceholder();

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 40,
      height: 40,
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Icon(
        Icons.apps_outlined,
        size: 24,
        color: Theme.of(context).colorScheme.onSurfaceVariant,
      ),
    );
  }
}
