// hosting_screen.dart
//
// HostingScreen — configure which services this device makes available to
// trusted mesh contacts.
//
// WHAT IS SERVICE HOSTING?
// ------------------------
// Any mesh node can advertise services to its trusted peers.  Services are
// grouped into three categories:
//   Remote Access — screen/desktop sharing and terminal (remoteDesktop, remoteShell)
//   Files & Data  — folder sharing and HTTP/gRPC API exposure (fileAccess, apiGateway)
//   Sharing       — clipboard sync, view-only screen share, printer sharing
//
// Each service is toggled independently via setHostedService() on the backend,
// which starts or stops the service listener and updates the local service
// advertisement broadcast so peers' discovery lists update automatically.
//
// OPTIMISTIC UPDATE:
// ------------------
// On a successful toggle, we update _config locally before waiting for a
// backend push event — this keeps the switch visually responsive even if the
// EventBus update takes a few milliseconds.  If the backend call fails, we
// show a snackbar and do NOT update _config, so the switch reverts to its
// previous position.
//
// Reached from: Services → Hosting tab.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../backend/backend_bridge.dart';
import '../../core/widgets/section_header.dart';
import '../../app/app_theme.dart';

/// Lets the user enable or disable each hosted service on this device.
///
/// Configuration is fetched from the backend on load and updated atomically
/// on each toggle.
class HostingScreen extends StatefulWidget {
  const HostingScreen({super.key});
  @override
  State<HostingScreen> createState() => _HostingScreenState();
}

class _HostingScreenState extends State<HostingScreen> {
  /// Current hosting configuration, keyed by service ID.
  /// Each value is a bool indicating whether the service is enabled.
  /// Starts as an empty map; populated by _load().
  Map<String, dynamic> _config = const {};

  /// True until the initial config fetch completes.
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  /// Fetches the current hosting configuration from the backend.
  ///
  /// fetchHostingConfig() may return null if the backend isn't ready yet;
  /// the null-coalescing `?? const {}` gives an empty map so the UI shows
  /// all services as disabled rather than crashing.
  Future<void> _load() async {
    final bridge = context.read<BackendBridge>();
    final cfg = bridge.fetchHostingConfig() ?? const {};
    // Guard: the user may have navigated away while the FFI call was in flight.
    if (mounted) setState(() { _config = cfg; _loading = false; });
  }

  /// Toggles [serviceId] to [enabled] and commits the change to the backend.
  ///
  /// Uses an optimistic local update: on success we update _config immediately
  /// so the switch animates without waiting for an EventBus push.  On failure
  /// we leave _config unchanged (the switch reverts) and show an error snackbar.
  Future<void> _toggle(String serviceId, bool enabled) async {
    final bridge = context.read<BackendBridge>();
    final ok = bridge.setHostedService(serviceId, enabled: enabled);
    if (ok) {
      // Optimistic update — mirror the new state locally.
      setState(() => _config = {..._config, serviceId: enabled});
    } else if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Failed to update service')),
      );
    }
  }

  /// Returns the current enabled state for [serviceId], defaulting to false
  /// when the service isn't in the config (e.g. first launch before any
  /// toggle has been persisted).
  bool _isEnabled(String serviceId) =>
      _config[serviceId] as bool? ?? false;

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator());

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // ── Remote Access group ──────────────────────────────────────────
        const SectionHeader('Remote Access'),
        _ServiceTile(
          icon: Icons.desktop_windows_outlined,
          title: 'Remote Desktop',
          subtitle: 'Stream your screen or individual apps to trusted contacts.',
          serviceId: 'remoteDesktop',
          enabled: _isEnabled('remoteDesktop'),
          onToggle: (v) => _toggle('remoteDesktop', v),
        ),
        _ServiceTile(
          icon: Icons.terminal_outlined,
          title: 'Remote Shell',
          subtitle: 'Secure terminal access from any mesh device.',
          serviceId: 'remoteShell',
          enabled: _isEnabled('remoteShell'),
          onToggle: (v) => _toggle('remoteShell', v),
        ),
        const SizedBox(height: 8),

        // ── Files & Data group ────────────────────────────────────────────
        const SectionHeader('Files & Data'),
        _ServiceTile(
          icon: Icons.folder_shared_outlined,
          title: 'File Access',
          subtitle: 'Share folders and drives with mesh contacts.',
          serviceId: 'fileAccess',
          enabled: _isEnabled('fileAccess'),
          onToggle: (v) => _toggle('fileAccess', v),
        ),
        _ServiceTile(
          icon: Icons.api_outlined,
          title: 'API Gateway',
          subtitle: 'Expose local HTTP, gRPC, or WebSocket services to the mesh.',
          serviceId: 'apiGateway',
          enabled: _isEnabled('apiGateway'),
          onToggle: (v) => _toggle('apiGateway', v),
        ),
        const SizedBox(height: 8),

        // ── Sharing group ─────────────────────────────────────────────────
        const SectionHeader('Sharing'),
        _ServiceTile(
          icon: Icons.content_copy_outlined,
          title: 'Clipboard Sync',
          subtitle: 'Keep clipboard in sync across your devices.',
          serviceId: 'clipboardSync',
          enabled: _isEnabled('clipboardSync'),
          onToggle: (v) => _toggle('clipboardSync', v),
        ),
        _ServiceTile(
          icon: Icons.monitor_outlined,
          title: 'Screen Share',
          subtitle: 'Share a view-only display with contacts.',
          serviceId: 'screenShare',
          enabled: _isEnabled('screenShare'),
          onToggle: (v) => _toggle('screenShare', v),
        ),
        _ServiceTile(
          icon: Icons.print_outlined,
          title: 'Print Services',
          subtitle: 'Share printers with mesh contacts.',
          serviceId: 'printService',
          enabled: _isEnabled('printService'),
          onToggle: (v) => _toggle('printService', v),
        ),
        const SizedBox(height: 24),
      ],
    );
  }
}

/// A card-style tile for a single hostable service with an enable/disable Switch.
///
/// The icon background tints to brand colour when [enabled] and reverts to
/// the surface-variant colour when disabled, giving a quick visual scan of
/// which services are currently active.
class _ServiceTile extends StatelessWidget {
  const _ServiceTile({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.serviceId,
    required this.enabled,
    required this.onToggle,
  });

  final IconData icon;
  final String title;
  final String subtitle;

  /// The backend key used to identify this service in the config map.
  final String serviceId;

  /// Current enabled state of this service.
  final bool enabled;

  /// Called when the user flips the switch; receives the new desired state.
  final ValueChanged<bool> onToggle;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;

    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: ListTile(
        contentPadding: const EdgeInsets.fromLTRB(16, 8, 8, 8),
        leading: Container(
          width: 40, height: 40,
          decoration: BoxDecoration(
            // Active services get a brand-tinted background; inactive services
            // use a neutral surface colour to clearly show they're off.
            color: enabled
                ? MeshTheme.brand.withValues(alpha: 0.12)
                : cs.surfaceContainerHighest,
            borderRadius: BorderRadius.circular(10),
          ),
          child: Icon(icon, size: 20,
            color: enabled ? MeshTheme.brand : cs.onSurfaceVariant),
        ),
        title: Text(title, style: theme.textTheme.titleSmall),
        subtitle: Text(subtitle,
          style: theme.textTheme.bodySmall
              ?.copyWith(color: cs.onSurfaceVariant)),
        // isThreeLine: true ensures the card has enough height for the
        // subtitle to wrap comfortably on narrow screens.
        isThreeLine: true,
        trailing: Switch(value: enabled, onChanged: onToggle),
      ),
    );
  }
}
