import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../settings_state.dart';
import 'identity_screen.dart';
import 'profile_edit_screen.dart';
import 'backup_screen.dart';
import 'killswitch_screen.dart';
import 'services_screen.dart';
import 'notification_screen.dart';

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
          ListTile(
            leading: const Icon(Icons.edit_outlined),
            title: const Text('Edit Profile'),
            subtitle: const Text('Update public and private profile'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const ProfileEditScreen()),
            ),
          ),
          ListTile(
            leading: const Icon(Icons.backup_outlined),
            title: const Text('Backup & Restore'),
            subtitle: const Text('Export or import encrypted backup'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const BackupScreen()),
            ),
          ),
          const Divider(),

          // Pairing code — only shown when backend has configured one.
          if (s != null && (s.pairingCode?.isNotEmpty ?? false))
            ListTile(
              leading: const Icon(Icons.qr_code_outlined),
              title: const Text('Pairing Code'),
              subtitle: Text(s.pairingCode!, style: const TextStyle(fontFamily: 'monospace')),
              trailing: IconButton(
                icon: const Icon(Icons.copy_outlined),
                tooltip: 'Copy pairing code',
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: s.pairingCode!));
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Pairing code copied')),
                  );
                },
              ),
            ),

          if (s != null && (s.pairingCode?.isNotEmpty ?? false)) const Divider(),

          // Hosted services
          ListTile(
            leading: const Icon(Icons.cloud_outlined),
            title: const Text('Hosted Services'),
            subtitle: Text(
              settings.services.isEmpty
                  ? 'No services configured'
                  : '${settings.services.length} service(s)',
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const ServicesScreen()),
            ),
          ),

          ListTile(
            leading: const Icon(Icons.notifications_outlined),
            title: const Text('Notifications'),
            subtitle: const Text('Alerts, sounds, cloud wake signal'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const NotificationScreen()),
            ),
          ),

          const Divider(),

          // About
          const _SectionHeader('About'),
          const ListTile(
            leading: Icon(Icons.info_outline),
            title: Text('Mesh Infinity'),
            subtitle: Text('v0.3.0 — Decentralised mesh networking'),
          ),

          const Divider(),

          // Danger zone
          ListTile(
            leading: Icon(Icons.warning_amber_rounded,
                color: Theme.of(context).colorScheme.error),
            title: Text(
              'Emergency Data Destruction',
              style: TextStyle(color: Theme.of(context).colorScheme.error),
            ),
            subtitle: const Text('Permanently destroy all local data'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const KillswitchScreen()),
            ),
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


