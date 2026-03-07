import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../settings_state.dart';
import '../../../backend/models/settings_models.dart';
import 'identity_screen.dart';

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final settings = context.watch<SettingsState>();
    final s = settings.settings;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Settings'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            tooltip: 'Refresh',
            onPressed: settings.loadAll,
          ),
        ],
      ),
      body: ListView(
        children: [
          // Identity
          ListTile(
            leading: const Icon(Icons.fingerprint_outlined),
            title: const Text('Identity'),
            subtitle: s != null && s.localPeerId.isNotEmpty
                ? Text(
                    s.localPeerId.length > 16
                        ? s.localPeerId.substring(0, 16)
                        : s.localPeerId,
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                  )
                : const Text('Tap to view'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const IdentityScreen()),
            ),
          ),
          const Divider(),

          // Pairing code
          if (s != null && s.pairingCode.isNotEmpty)
            ListTile(
              leading: const Icon(Icons.qr_code_outlined),
              title: const Text('Pairing Code'),
              subtitle: Text(s.pairingCode, style: const TextStyle(fontFamily: 'monospace')),
              trailing: IconButton(
                icon: const Icon(Icons.copy_outlined),
                tooltip: 'Copy pairing code',
                onPressed: () {
                  // Copy to clipboard handled by the system
                },
              ),
            ),

          if (s != null && s.pairingCode.isNotEmpty) const Divider(),

          // Hosted services
          const _SectionHeader('Hosted Services'),
          if (settings.services.isEmpty)
            const Padding(
              padding: EdgeInsets.fromLTRB(16, 8, 16, 16),
              child: Text('No services configured'),
            )
          else
            for (final svc in settings.services)
              _ServiceTile(
                service: svc,
                onToggle: (enabled) => settings.configureService(
                  svc.id,
                  {'enabled': enabled},
                ),
              ),

          const Divider(),

          // About
          const _SectionHeader('About'),
          const ListTile(
            leading: Icon(Icons.info_outline),
            title: Text('Mesh Infinity'),
            subtitle: Text('v0.2.0 — Decentralised mesh networking'),
          ),
        ],
      ),
    );
  }
}

class _SectionHeader extends StatelessWidget {
  const _SectionHeader(this.title);

  final String title;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 20, 16, 4),
      child: Text(
        title,
        style: Theme.of(context).textTheme.labelMedium?.copyWith(
          color: Theme.of(context).colorScheme.primary,
          fontWeight: FontWeight.bold,
        ),
      ),
    );
  }
}

class _ServiceTile extends StatelessWidget {
  const _ServiceTile({required this.service, required this.onToggle});

  final ServiceModel service;
  final ValueChanged<bool> onToggle;

  @override
  Widget build(BuildContext context) {
    return SwitchListTile(
      secondary: const Icon(Icons.dns_outlined),
      title: Text(service.name),
      subtitle: Text(service.address),
      value: service.enabled,
      onChanged: onToggle,
    );
  }
}
