// browse_screen.dart
//
// BrowseScreen — discover mesh services advertised by this device and by
// reachable peers.
//
// WHAT ARE MESH SERVICES?
// -----------------------
// Any device on the mesh can advertise services — remote desktop, file access,
// print queues, API gateways, etc. Services are scoped by trust level: a
// service that requires trust ≥ 5 is only visible and usable by contacts with
// at least that trust level.
//
// This screen calls discoverMeshServices() on every load and on pull-to-
// refresh. Discovery is a snapshot — it does not live-update. The user must
// manually refresh to see changes after a peer comes online.
//
// CONNECT ACTIONS:
// ----------------
// The spec requires an explicit Connect affordance or an explicit unavailable
// state. The backend already exposes discovery metadata, but the app still
// lacks per-protocol launch surfaces for these hosted services. Until those
// handlers exist, the UI presents a clear unavailable action instead of a
// dead tap target.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../app/app_theme.dart';
import '../../backend/backend_bridge.dart';
import '../../core/widgets/empty_state.dart';
import 'service_details_sheet.dart';

/// Displays all mesh services currently discoverable by this device.
///
/// Performs a one-shot discovery on [initState] and supports pull-to-refresh.
/// Service data arrives as raw maps from the backend FFI layer.
class BrowseScreen extends StatefulWidget {
  const BrowseScreen({super.key});

  @override
  State<BrowseScreen> createState() => _BrowseScreenState();
}

class _BrowseScreenState extends State<BrowseScreen> {
  /// Snapshot of discovered services. Each map is the raw FFI result with
  /// string keys such as `id`, `name`, `type`, `description`, `hostName`,
  /// `hostPeerId`, `address`, and `trustRequired`.
  List<Map<String, dynamic>> _services = const [];

  /// True until the first discovery call completes.
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  /// Calls the backend to re-discover all reachable services, then rebuilds.
  Future<void> _load() async {
    final bridge = context.read<BackendBridge>();
    final services = bridge.discoverMeshServices();
    if (mounted) {
      setState(() {
        _services = services;
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator());

    if (_services.isEmpty) {
      return const EmptyState(
        icon: Icons.hub_outlined,
        title: 'No services found',
        body: 'Services offered by mesh peers will appear here.',
      );
    }

    return RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.all(16),
        itemCount: _services.length,
        itemBuilder: (context, index) =>
            _ServiceTile(service: _services[index]),
      ),
    );
  }
}

/// A card row representing one discovered mesh service.
///
/// The backend currently returns discovery maps rather than a dedicated Dart
/// model. This widget reads only the fields it needs and defaults safely when
/// a key is absent.
class _ServiceTile extends StatelessWidget {
  const _ServiceTile({required this.service});

  final Map<String, dynamic> service;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    final name = service['name'] as String? ?? 'Unknown';
    final type = service['type'] as String? ?? '';
    final description = service['description'] as String? ?? '';
    final hostName = service['hostName'] as String? ?? '';
    final address = service['address'] as String? ?? '';
    final trustRequired = (service['trustRequired'] as num?)?.toInt() ?? 0;
    final isLocal = service['hostPeerId'] == '' || hostName == 'This device';
    final canConnect = _supportsDirectConnect(type);

    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 12, 16, 12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Container(
                  width: 40,
                  height: 40,
                  decoration: BoxDecoration(
                    color: MeshTheme.brand.withValues(alpha: 0.12),
                    borderRadius: BorderRadius.circular(10),
                  ),
                  child: Icon(
                    _iconForType(type),
                    size: 20,
                    color: MeshTheme.brand,
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(name, style: theme.textTheme.titleSmall),
                      const SizedBox(height: 2),
                      Text(
                        isLocal
                            ? 'Hosted on this device'
                            : hostName.isNotEmpty
                            ? 'Hosted by $hostName'
                            : 'Hosted elsewhere on the mesh',
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: colorScheme.onSurfaceVariant,
                        ),
                      ),
                    ],
                  ),
                ),
                Icon(
                  isLocal ? Icons.smartphone_outlined : Icons.route_outlined,
                  color: colorScheme.onSurfaceVariant,
                ),
              ],
            ),
            if (description.trim().isNotEmpty) ...[
              const SizedBox(height: 10),
              Text(
                description.trim(),
                style: theme.textTheme.bodyMedium?.copyWith(
                  color: colorScheme.onSurfaceVariant,
                ),
              ),
            ],
            if (trustRequired > 0 || address.trim().isNotEmpty) ...[
              const SizedBox(height: 10),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  if (trustRequired > 0)
                    _FactChip(
                      icon: Icons.verified_user_outlined,
                      label: 'Trust $trustRequired+',
                      color: MeshTheme.secAmber,
                    ),
                  if (address.trim().isNotEmpty)
                    _FactChip(
                      icon: Icons.link_outlined,
                      label: address.trim(),
                      color: MeshTheme.brand,
                      monospace: true,
                    ),
                ],
              ),
            ],
            const SizedBox(height: 12),
            Row(
              children: [
                TextButton(
                  onPressed: () => show_service_details_sheet(
                    context: context,
                    icon: _iconForType(type),
                    name: name,
                    description: description,
                    address: address,
                    hostName: isLocal ? 'This device' : hostName,
                    minTrustLevel: trustRequired,
                    statusLabel: isLocal
                        ? 'Hosted locally on this node'
                        : 'Discovered through the mesh',
                    footer: Text(
                      canConnect
                          ? 'This service advertises a direct handler.'
                          : 'This device does not have a direct connector for this service yet.',
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ),
                  child: const Text('Details'),
                ),
                const Spacer(),
                if (canConnect)
                  FilledButton.tonalIcon(
                    onPressed: () => _showConnectUnavailable(context, name),
                    icon: const Icon(Icons.open_in_new_outlined),
                    label: const Text('Connect'),
                  )
                else
                  OutlinedButton.icon(
                    onPressed: () => _showConnectUnavailable(context, name),
                    icon: const Icon(Icons.info_outline),
                    label: const Text('Unavailable'),
                  ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  /// The discovery payload is ready before the app has route openers for these
  /// service families. Keep the availability check centralized so the future
  /// flip to a real launcher is a one-line change.
  bool _supportsDirectConnect(String type) {
    return switch (type) {
      'remoteDesktop' ||
      'remoteShell' ||
      'fileAccess' ||
      'apiGateway' ||
      'clipboardSync' ||
      'screenShare' ||
      'printService' => false,
      _ => false,
    };
  }

  void _showConnectUnavailable(BuildContext context, String name) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          'Direct opening for $name is not implemented on this device yet.',
        ),
      ),
    );
  }

  IconData _iconForType(String type) => switch (type) {
    'remoteDesktop' => Icons.desktop_windows_outlined,
    'remoteShell' => Icons.terminal_outlined,
    'fileAccess' => Icons.folder_shared_outlined,
    'apiGateway' => Icons.api_outlined,
    'clipboardSync' => Icons.content_copy_outlined,
    'screenShare' => Icons.monitor_outlined,
    'printService' => Icons.print_outlined,
    _ => Icons.miscellaneous_services_outlined,
  };
}

/// A compact metadata chip used in browse cards.
class _FactChip extends StatelessWidget {
  const _FactChip({
    required this.icon,
    required this.label,
    required this.color,
    this.monospace = false,
  });

  final IconData icon;
  final String label;
  final Color color;
  final bool monospace;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.10),
        borderRadius: BorderRadius.circular(999),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 14, color: color),
          const SizedBox(width: 6),
          Text(
            label,
            style: theme.textTheme.bodySmall?.copyWith(
              color: color,
              fontFamily: monospace ? 'monospace' : null,
            ),
          ),
        ],
      ),
    );
  }
}
