// services_screen.dart
//
// ServicesScreen — list and manage mesh-hosted services.
//
// WHAT IS A HOSTED SERVICE?
// -------------------------
// Mesh Infinity allows a device to expose local network services (TCP, UDP,
// HTTP, or shared file access) over the mesh network.  A "hosted service"
// is a binding that maps an inbound mesh connection to a local socket.
//
// Examples:
//   - A local HTTP server (port 8080) shared with trusted contacts over the mesh.
//   - A TCP application (e.g. a game server) reachable via a mesh address.
//   - A UDP service (e.g. VoIP) tunnelled through the encrypted mesh channel.
//
// Each service has:
//   name          — human-readable label
//   address       — the mesh address/port where it is reachable
//   minTrustLevel — minimum trust level required to connect (§9.2)
//   enabled       — whether the service is currently accepting connections
//   path          — local service path / port binding
//
// This screen lists all registered services and lets the user:
//   - Toggle a service on or off without removing it.
//   - Tap a service to see its full configuration.
//   - Create a new service via the FAB.
//
// REACHED FROM: Settings → Hosted Services.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../settings_state.dart';
import '../../../backend/models/settings_models.dart';

/// Lists all registered hosted services with enable/disable toggles.
///
/// A pull-to-refresh gesture and a manual Refresh button both call
/// [SettingsState.loadAll] to re-fetch the service list from the backend.
class ServicesScreen extends StatelessWidget {
  const ServicesScreen({super.key});

  @override
  Widget build(BuildContext context) {
    // context.watch rebuilds this widget when SettingsState notifies — which
    // happens after loadAll() is called (pull-to-refresh or FAB create).
    final state = context.watch<SettingsState>();
    final services = state.services;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Hosted Services'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            tooltip: 'Refresh',
            // loadAll is declared as Future<void> Function() in SettingsState,
            // so it can be used directly as a VoidCallback here.
            onPressed: state.loadAll,
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: () => _showCreateServiceSheet(context),
        icon: const Icon(Icons.add),
        label: const Text('New Service'),
      ),
      body: services.isEmpty
          // Empty state: explain what services are and how to create one,
          // rather than showing a blank screen.
          ? Center(
              child: Padding(
                padding: const EdgeInsets.all(32),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(
                      Icons.cloud_off_outlined,
                      size: 64,
                      // Muted colour so the empty state doesn't look like an error.
                      color: Theme.of(context)
                          .colorScheme
                          .onSurface
                          .withAlpha(100),
                    ),
                    const SizedBox(height: 16),
                    Text(
                      'No hosted services',
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                    const SizedBox(height: 8),
                    Text(
                      'Host TCP/UDP services, HTTP servers, or file shares '
                      'over the mesh network. Tap + to create one.',
                      textAlign: TextAlign.center,
                      style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                            color: Theme.of(context)
                                .colorScheme
                                .onSurface
                                .withAlpha(150),
                          ),
                    ),
                  ],
                ),
              ),
            )
          // Non-empty: scrollable list with pull-to-refresh.
          // Bottom padding prevents the last tile from being hidden behind the FAB.
          : RefreshIndicator(
              onRefresh: state.loadAll,
              child: ListView.separated(
                padding: const EdgeInsets.only(bottom: 80),
                itemCount: services.length,
                separatorBuilder: (_, _) => const Divider(height: 1),
                itemBuilder: (context, index) {
                  final svc = services[index];
                  return _ServiceTile(service: svc);
                },
              ),
            ),
    );
  }

  /// Show the bottom sheet for creating a new service.
  void _showCreateServiceSheet(BuildContext context) {
    showModalBottomSheet<void>(
      context: context,
      // isScrollControlled allows the sheet to grow with the keyboard.
      isScrollControlled: true,
      builder: (_) => const _CreateServiceSheet(),
    );
  }
}

// ---------------------------------------------------------------------------
// _ServiceTile — one service row in the list
// ---------------------------------------------------------------------------

/// A list tile representing one [ServiceModel].
///
/// Shows an avatar icon, name, address/status summary, and an enable/disable
/// switch.  Tapping the tile opens a detail sheet showing all fields.
class _ServiceTile extends StatelessWidget {
  const _ServiceTile({required this.service});

  final ServiceModel service;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    // context.read rather than watch — we don't need this tile to rebuild
    // when SettingsState notifies; only the parent ListView rebuilds.
    final state = context.read<SettingsState>();

    return ListTile(
      // Circle avatar doubles as a visual status indicator:
      //   enabled  → primary container (brand-tinted green feel)
      //   disabled → surface variant (muted grey)
      leading: CircleAvatar(
        backgroundColor: service.enabled
            ? theme.colorScheme.primaryContainer
            : theme.colorScheme.surfaceContainerHighest,
        child: Icon(
          service.enabled ? Icons.cloud_done_outlined : Icons.cloud_off_outlined,
          color: service.enabled
              ? theme.colorScheme.onPrimaryContainer
              : theme.colorScheme.onSurfaceVariant,
        ),
      ),
      title: Text(service.name),
      // Subtitle: "Active • mesh-address:port" or "Inactive".
      // The bullet character (•) is U+2022 (universally supported, no font issues).
      subtitle: Text(
        '${service.enabled ? "Active" : "Inactive"}'
        '${service.address.isNotEmpty ? " \u2022 ${service.address}" : ""}',
      ),
      // The switch lets the user toggle the service without tapping through
      // to the detail sheet, which is the common action.
      trailing: Switch(
        value: service.enabled,
        onChanged: (v) {
          // configureService('new', ...) creates; configureService(existingId, ...)
          // updates.  Here we pass the service ID and a partial update map.
          state.configureService(
            service.id,
            {'enabled': v},
          );
        },
      ),
      onTap: () => _showServiceDetail(context, service),
    );
  }

  /// Show a bottom sheet with the full service configuration.
  ///
  /// Read-only for now — editing individual fields would need a separate
  /// edit form screen (future work).
  void _showServiceDetail(BuildContext context, ServiceModel service) {
    showModalBottomSheet<void>(
      context: context,
      builder: (ctx) => Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(service.name,
                style: Theme.of(ctx).textTheme.headlineSmall),
            const SizedBox(height: 12),
            _DetailRow(label: 'Path', value: service.path),
            _DetailRow(label: 'Address', value: service.address),
            // minTrustLevel maps to the §9.2 trust level system.
            // Level 0 = anyone; level 8 = inner circle only.
            _DetailRow(
                label: 'Trust', value: 'Level ${service.minTrustLevel}'),
            _DetailRow(
                label: 'Status',
                value: service.enabled ? 'Active' : 'Inactive'),
            const SizedBox(height: 16),
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _DetailRow — label/value pair in the service detail sheet
// ---------------------------------------------------------------------------

/// A single label/value row used in the service detail bottom sheet.
///
/// The label column has a fixed width (80px) so all values left-align.
class _DetailRow extends StatelessWidget {
  const _DetailRow({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          // Fixed-width label column prevents value text from jumping position
          // as different rows have different label lengths.
          SizedBox(
            width: 80,
            child: Text(
              label,
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    color: Theme.of(context)
                        .colorScheme
                        .onSurface
                        .withAlpha(150),
                  ),
            ),
          ),
          Expanded(
            child: Text(value, style: Theme.of(context).textTheme.bodyMedium),
          ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _CreateServiceSheet — bottom sheet form for adding a new service
// ---------------------------------------------------------------------------

/// Modal bottom sheet with a minimal form for defining a new hosted service.
///
/// The Create button is disabled when the service name is empty — a name is
/// the minimum required field.  All other fields have sensible defaults.
class _CreateServiceSheet extends StatefulWidget {
  const _CreateServiceSheet();

  @override
  State<_CreateServiceSheet> createState() => _CreateServiceSheetState();
}

class _CreateServiceSheetState extends State<_CreateServiceSheet> {
  final _nameController = TextEditingController();
  final _portController = TextEditingController();

  // Protocol default: TCP is the most common choice.
  String _protocol = 'tcp';

  // Access policy default: public means any authenticated mesh peer can connect.
  // Users should narrow this for sensitive services.
  String _accessPolicy = 'public';

  @override
  void dispose() {
    _nameController.dispose();
    _portController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      // viewInsets.bottom is the height of the on-screen keyboard.
      // Adding it as bottom padding keeps the form above the keyboard so
      // inputs are not obscured while the user is typing.
      padding: EdgeInsets.fromLTRB(
        24,
        24,
        24,
        24 + MediaQuery.of(context).viewInsets.bottom,
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text('Create Service',
              style: Theme.of(context).textTheme.headlineSmall),
          const SizedBox(height: 16),
          TextField(
            controller: _nameController,
            decoration: const InputDecoration(
              labelText: 'Service name',
              border: OutlineInputBorder(),
            ),
            // Listen for text changes so the Create button enables/disables
            // as soon as the name field becomes non-empty.
            onChanged: (_) => setState(() {}),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _portController,
            decoration: const InputDecoration(
              labelText: 'Local port',
              border: OutlineInputBorder(),
            ),
            keyboardType: TextInputType.number,
          ),
          const SizedBox(height: 12),
          // Protocol selector: TCP / UDP / HTTP.
          // The protocol determines how the mesh tunnel handles the connection.
          DropdownButtonFormField<String>(
            initialValue: _protocol,
            decoration: const InputDecoration(
              labelText: 'Protocol',
              border: OutlineInputBorder(),
            ),
            items: const [
              DropdownMenuItem(value: 'tcp', child: Text('TCP')),
              DropdownMenuItem(value: 'udp', child: Text('UDP')),
              DropdownMenuItem(value: 'http', child: Text('HTTP')),
            ],
            onChanged: (v) => setState(() => _protocol = v ?? 'tcp'),
          ),
          const SizedBox(height: 12),
          // Access policy: who on the mesh can reach this service.
          //   public        — any authenticated mesh peer
          //   trusted_only  — only peers with trust level ≥ 4
          //   group_only    — only members of a specific group/garden
          DropdownButtonFormField<String>(
            initialValue: _accessPolicy,
            decoration: const InputDecoration(
              labelText: 'Access policy',
              border: OutlineInputBorder(),
            ),
            items: const [
              DropdownMenuItem(value: 'public', child: Text('Public')),
              DropdownMenuItem(
                  value: 'trusted_only', child: Text('Trusted peers only')),
              DropdownMenuItem(
                  value: 'group_only', child: Text('Group members only')),
            ],
            onChanged: (v) =>
                setState(() => _accessPolicy = v ?? 'public'),
          ),
          const SizedBox(height: 16),
          FilledButton(
            // Disable Create until a name has been entered — all other
            // fields have defaults so they are optional.
            onPressed: _nameController.text.trim().isEmpty
                ? null
                : () {
                    final state = context.read<SettingsState>();
                    // The special ID 'new' tells the backend to generate a
                    // new service ID rather than updating an existing one.
                    state.configureService('new', {
                      'name': _nameController.text.trim(),
                      // Parse the port; default to 0 if blank (backend will reject
                      // 0 and return an error, handled by SettingsState).
                      'port': int.tryParse(_portController.text) ?? 0,
                      'protocol': _protocol,
                      'access_policy': _accessPolicy,
                      'enabled': true, // new services start enabled
                    });
                    Navigator.of(context).pop();
                  },
            child: const Text('Create'),
          ),
        ],
      ),
    );
  }
}
