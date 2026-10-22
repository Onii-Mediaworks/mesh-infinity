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
// CONFIGURE BUTTONS (§22.54.4):
// ----------------------------
// Five services carry server-side settings defined in §20 (trust floors,
// adapters, shell grants, share roots, the upstream URL, printer queues).
// While such a service is enabled its tile shows a tune icon that pushes
// the matching §22.54.5–§22.54.9 screen.  Clipboard Sync and Screen Share
// have no settings and therefore no button.
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
import 'config/api_gateway_config_screen.dart';
import 'config/mnfp_shares_config_screen.dart';
import 'config/mnrdp_server_config_screen.dart';
import 'config/mnsp_server_config_screen.dart';
import 'config/print_service_config_screen.dart';

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
    if (mounted) {
      setState(() {
        _config = cfg;
        _loading = false;
      });
    }
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
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('Failed to update service')));
    }
  }

  /// Returns the current enabled state for [serviceId], defaulting to false
  /// when the service isn't in the config (e.g. first launch before any
  /// toggle has been persisted).
  bool _isEnabled(String serviceId) => _config[serviceId] as bool? ?? false;

  bool get _anyEnabled => _config.values.any((value) => value == true);

  /// Push one of the §22.54.5–§22.54.9 configuration screens.
  void _configure(Widget screen) {
    Navigator.of(
      context,
    ).push(MaterialPageRoute<void>(builder: (_) => screen));
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator());

    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _HostingExplainer(onHelpPressed: _showExplainerSheet),
          if (!_anyEnabled) ...[
            const SizedBox(height: 12),
            const _NoServicesBanner(),
          ],
          const SizedBox(height: 16),
          // ── Remote Access group ──────────────────────────────────────────
          const SectionHeader('Remote Access'),
          _ServiceTile(
            icon: Icons.desktop_windows_outlined,
            title: 'Remote Desktop',
            subtitle:
                'Stream your screen or individual apps to trusted contacts.',
            serviceId: 'remoteDesktop',
            enabled: _isEnabled('remoteDesktop'),
            onToggle: (v) => _toggle('remoteDesktop', v),
            onConfigure: () => _configure(const MnrdpServerConfigScreen()),
          ),
          _ServiceTile(
            icon: Icons.terminal_outlined,
            title: 'Remote Shell',
            subtitle: 'Secure terminal access from any mesh device.',
            serviceId: 'remoteShell',
            enabled: _isEnabled('remoteShell'),
            onToggle: (v) => _toggle('remoteShell', v),
            onConfigure: () => _configure(const MnspServerConfigScreen()),
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
            onConfigure: () => _configure(const MnfpSharesConfigScreen()),
          ),
          _ServiceTile(
            icon: Icons.api_outlined,
            title: 'API Gateway',
            subtitle:
                'Expose local HTTP, gRPC, or WebSocket services to the mesh.',
            serviceId: 'apiGateway',
            enabled: _isEnabled('apiGateway'),
            onToggle: (v) => _toggle('apiGateway', v),
            onConfigure: () => _configure(const ApiGatewayConfigScreen()),
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
            onConfigure: () => _configure(const PrintServiceConfigScreen()),
          ),
          const SizedBox(height: 24),
        ],
      ),
    );
  }

  void _showExplainerSheet() {
    showModalBottomSheet<void>(
      context: context,
      showDragHandle: true,
      builder: (sheetContext) {
        final theme = Theme.of(sheetContext);
        final colorScheme = theme.colorScheme;

        return SafeArea(
          child: Padding(
            padding: const EdgeInsets.fromLTRB(20, 8, 20, 24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Hosted services', style: theme.textTheme.titleLarge),
                const SizedBox(height: 12),
                Text(
                  'Hosted services let this device expose local tools to approved mesh peers. '
                  'Turn on only the protocols you actually need, and review trust levels before '
                  'sharing access.',
                  style: theme.textTheme.bodyMedium?.copyWith(
                    color: colorScheme.onSurfaceVariant,
                  ),
                ),
                const SizedBox(height: 16),
                const _ExplainerBullet(
                  icon: Icons.lock_outline,
                  text:
                      'Trust requirements still apply even when a service is enabled.',
                ),
                const _ExplainerBullet(
                  icon: Icons.public_off_outlined,
                  text: 'Disabling a service stops advertising it to peers.',
                ),
                const _ExplainerBullet(
                  icon: Icons.tune_outlined,
                  text:
                      'Turn a service on to reveal its settings: who can connect, what is shared, and which adapters run.',
                ),
              ],
            ),
          ),
        );
      },
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
    this.onConfigure,
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

  /// Opens the service's configuration screen (§22.54.4).  Null for the
  /// services that have no settings; the button is only drawn while the
  /// service is enabled, matching the §22.54.3 tile definition.
  final VoidCallback? onConfigure;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;

    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: ListTile(
        contentPadding: const EdgeInsets.fromLTRB(16, 8, 8, 8),
        leading: Container(
          width: 40,
          height: 40,
          decoration: BoxDecoration(
            // Active services get a brand-tinted background; inactive services
            // use a neutral surface colour to clearly show they're off.
            color: enabled
                ? MeshTheme.brand.withValues(alpha: 0.12)
                : cs.surfaceContainerHighest,
            borderRadius: BorderRadius.circular(10),
          ),
          child: Icon(
            icon,
            size: 20,
            // Enabled icon: brand foreground token (§22.1.1, CMR-019).
            color: enabled
                ? MeshColors.of(context).brand_fg
                : cs.onSurfaceVariant,
          ),
        ),
        title: Text(title, style: theme.textTheme.titleSmall),
        subtitle: Text(
          subtitle,
          style: theme.textTheme.bodySmall?.copyWith(
            color: cs.onSurfaceVariant,
          ),
        ),
        // isThreeLine: true ensures the card has enough height for the
        // subtitle to wrap comfortably on narrow screens.
        isThreeLine: true,
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (onConfigure != null && enabled)
              IconButton(
                icon: const Icon(Icons.tune_outlined, size: 18),
                onPressed: onConfigure,
                tooltip: 'Configure $title',
                // 48dp target (§22.34) even though the glyph is small.
                constraints: const BoxConstraints(minWidth: 48, minHeight: 48),
              ),
            Switch(value: enabled, onChanged: onToggle),
          ],
        ),
      ),
    );
  }
}

class _HostingExplainer extends StatelessWidget {
  const _HostingExplainer({required this.onHelpPressed});

  final VoidCallback onHelpPressed;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Container(
              width: 40,
              height: 40,
              decoration: BoxDecoration(
                color: MeshTheme.brand.withValues(alpha: 0.12),
                borderRadius: BorderRadius.circular(12),
              ),
              // Icon foreground: per-theme brand token (CMR-019).
              child: Icon(
                Icons.hub_outlined,
                color: MeshColors.of(context).brand_fg,
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Host services on this device',
                    style: theme.textTheme.titleMedium,
                  ),
                  const SizedBox(height: 4),
                  Text(
                    'Expose remote access, file, and sharing tools to trusted mesh peers.',
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: colorScheme.onSurfaceVariant,
                    ),
                  ),
                ],
              ),
            ),
            IconButton(
              onPressed: onHelpPressed,
              icon: const Icon(Icons.help_outline),
              tooltip: 'How hosting works',
            ),
          ],
        ),
      ),
    );
  }
}

class _NoServicesBanner extends StatelessWidget {
  const _NoServicesBanner();

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    // Warning amber, resolved per theme for contrast.
    final amber = MeshColors.of(context).sec_amber;

    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: amber.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(16),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(Icons.info_outline, color: amber),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              'No services are running. Enable a service below to start hosting.',
              style: theme.textTheme.bodyMedium?.copyWith(
                color: amber,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _ExplainerBullet extends StatelessWidget {
  const _ExplainerBullet({required this.icon, required this.text});

  final IconData icon;
  final String text;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Bullet icon foreground: per-theme brand token (CMR-019).
          Icon(icon, size: 18, color: MeshColors.of(context).brand_fg),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              text,
              style: theme.textTheme.bodySmall?.copyWith(
                color: colorScheme.onSurfaceVariant,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
