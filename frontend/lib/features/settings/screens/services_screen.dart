import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../settings_state.dart';
import '../../../backend/models/settings_models.dart';

/// Screen for managing hosted services.
///
/// Shows all registered services with their status, and provides
/// controls to enable/disable, configure, and create new services.
class ServicesScreen extends StatelessWidget {
  const ServicesScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final state = context.watch<SettingsState>();
    final services = state.services;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Hosted Services'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            tooltip: 'Refresh',
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
          ? Center(
              child: Padding(
                padding: const EdgeInsets.all(32),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(
                      Icons.cloud_off_outlined,
                      size: 64,
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

  void _showCreateServiceSheet(BuildContext context) {
    showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      builder: (_) => const _CreateServiceSheet(),
    );
  }
}

class _ServiceTile extends StatelessWidget {
  const _ServiceTile({required this.service});

  final ServiceModel service;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final state = context.read<SettingsState>();

    return ListTile(
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
      subtitle: Text(
        '${service.enabled ? "Active" : "Inactive"}'
        '${service.address.isNotEmpty ? " \u2022 ${service.address}" : ""}',
      ),
      trailing: Switch(
        value: service.enabled,
        onChanged: (v) {
          state.configureService(
            service.id,
            {'enabled': v},
          );
        },
      ),
      onTap: () => _showServiceDetail(context, service),
    );
  }

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

class _CreateServiceSheet extends StatefulWidget {
  const _CreateServiceSheet();

  @override
  State<_CreateServiceSheet> createState() => _CreateServiceSheetState();
}

class _CreateServiceSheetState extends State<_CreateServiceSheet> {
  final _nameController = TextEditingController();
  final _portController = TextEditingController();
  String _protocol = 'tcp';
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
            onPressed: _nameController.text.trim().isEmpty
                ? null
                : () {
                    final state = context.read<SettingsState>();
                    state.configureService('new', {
                      'name': _nameController.text.trim(),
                      'port': int.tryParse(_portController.text) ?? 0,
                      'protocol': _protocol,
                      'access_policy': _accessPolicy,
                      'enabled': true,
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
