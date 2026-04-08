// browse_screen.dart
//
// BrowseScreen — discover mesh services advertised by this device and by
// reachable peers.
//
// WHAT ARE MESH SERVICES?
// -----------------------
// Any device on the mesh can advertise services — remote desktop, file access,
// print queues, API gateways, etc.  Services are scoped by trust level: a
// service that requires trust ≥ 5 is only visible and usable by contacts with
// at least that trust level.
//
// This screen calls discoverMeshServices() on every load and on pull-to-
// refresh. Discovery is a snapshot — it does not live-update. The user must
// manually refresh to see changes after a peer comes online.
//
// HOST DETECTION:
// ---------------
// A service whose hostPeerId is empty (or whose hostName is "This device") is
// a locally-hosted service — it runs on this device. All other services are
// remote. The UI distinguishes these with different trailing icons so users
// know whether they're browsing a local or remote resource.
//
// TRUST REQUIREMENT DISPLAY:
// --------------------------
// When trustRequired > 0 the tile shows an amber warning line so the user
// knows in advance they may not be able to access the service.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../backend/backend_bridge.dart';
import '../../core/widgets/empty_state.dart';
import '../../app/app_theme.dart';

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
  /// string keys: 'name', 'type', 'hostName', 'hostPeerId', 'trustRequired'.
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
    // Guard against the widget being disposed while the FFI call was in flight
    // (e.g. the user navigated away). Calling setState on an unmounted widget
    // throws in debug builds.
    if (mounted) setState(() { _services = services; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator());

    if (_services.isEmpty) {
      return const EmptyState(
        icon: Icons.search,
        title: 'No services found',
        body: 'Services from this device and any discovered peers will appear here.',
      );
    }

    return RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.all(16),
        itemCount: _services.length,
        itemBuilder: (context, i) => _ServiceTile(service: _services[i]),
      ),
    );
  }
}

/// A single card row representing one discovered mesh service.
///
/// Extracts fields from the raw [service] map with safe defaults so a missing
/// field never crashes the UI — the backend may return partial data for newly
/// discovered services that haven't fully announced yet.
class _ServiceTile extends StatelessWidget {
  const _ServiceTile({required this.service});

  /// Raw FFI map for this service.
  final Map<String, dynamic> service;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;

    // Extract fields with safe defaults. The backend guarantees these keys
    // exist on fully-announced services but may omit them during partial
    // discovery (e.g. if the peer's profile hasn't synced yet).
    final name      = service['name']      as String? ?? 'Unknown';
    final type      = service['type']      as String? ?? '';
    final hostName  = service['hostName']  as String? ?? '';

    // trustRequired is an int sent as a JSON number — use num? then convert to
    // avoid a cast crash if the backend ever sends it as a double.
    final trustReq  = (service['trustRequired'] as num?)?.toInt() ?? 0;

    // A service is "local" if it has no host peer ID (this device is the host)
    // or if the hostName is explicitly labelled "This device".
    final isLocal = service['hostPeerId'] == '' || hostName == 'This device';

    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: ListTile(
        contentPadding: const EdgeInsets.fromLTRB(16, 8, 8, 8),
        leading: Container(
          width: 40, height: 40,
          decoration: BoxDecoration(
            // Tinted icon background using the brand colour at low opacity —
            // gives visual consistency across service types.
            color: MeshTheme.brand.withValues(alpha: 0.12),
            borderRadius: BorderRadius.circular(10),
          ),
          child: Icon(_iconForType(type), size: 20, color: MeshTheme.brand),
        ),
        title: Text(name, style: theme.textTheme.titleSmall),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Host attribution: show "Hosted on this device" or "Hosted by
            // <name>" so the user knows where the service is running.
            // Falls back to the type string if no host name is available.
            Text(
              isLocal
                  ? 'Hosted on this device'
                  : hostName.isNotEmpty
                      ? 'Hosted by $hostName'
                      : type,
              style: theme.textTheme.bodySmall
                  ?.copyWith(color: cs.onSurfaceVariant),
            ),
            // Trust warning line: only shown when the service requires a
            // specific trust level, so the user knows access may be restricted.
            if (trustReq > 0)
              Text('Requires trust level $trustReq',
                style: theme.textTheme.bodySmall
                    ?.copyWith(color: MeshTheme.secAmber)),
          ],
        ),
        // isThreeLine expands the tile height when the trust line is present.
        isThreeLine: trustReq > 0,
        // Trailing icon distinguishes local services (this device) from remote
        // ones (route through the mesh to a peer).
        trailing: Icon(
          isLocal ? Icons.smartphone_outlined : Icons.route_outlined,
          color: cs.onSurfaceVariant,
        ),
      ),
    );
  }

  /// Maps a service type string to a representative icon.
  ///
  /// Falls back to [Icons.miscellaneous_services_outlined] for any type not
  /// explicitly handled — new service types added to the backend are
  /// automatically handled without crashing.
  IconData _iconForType(String type) => switch (type) {
    'remoteDesktop' => Icons.desktop_windows_outlined,
    'remoteShell'   => Icons.terminal_outlined,
    'fileAccess'    => Icons.folder_shared_outlined,
    'apiGateway'    => Icons.api_outlined,
    'clipboardSync' => Icons.content_copy_outlined,
    'screenShare'   => Icons.monitor_outlined,
    'printService'  => Icons.print_outlined,
    _               => Icons.miscellaneous_services_outlined,
  };
}
