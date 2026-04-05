import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/backend_bridge.dart';
import '../settings_state.dart';
import 'identity_masks_screen.dart';
import 'node_screen.dart';
import 'notification_screen.dart';
import 'security_screen.dart';

class PrivacyScreen extends StatelessWidget {
  const PrivacyScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final settings = context.watch<SettingsState>();
    final s = settings.settings;
    final notifications = context.read<BackendBridge>().getNotificationConfig();

    return Scaffold(
      appBar: AppBar(title: const Text('Privacy controls')),
      body: ListView(
        children: [
          const _SectionHeader('Discovery'),
          ListTile(
            leading: const Icon(Icons.radar_outlined),
            title: const Text('Local network discovery'),
            subtitle: Text(
              s?.meshDiscovery == true
                  ? 'On. This device can look for nearby peers on the local network.'
                  : 'Off. Nearby peer discovery on the local network is disabled.',
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _push(context, const NodeScreen()),
          ),
          ListTile(
            leading: const Icon(Icons.public_off_outlined),
            title: const Text('Direct internet reachability'),
            subtitle: Text(
              s?.enableClearnet == true
                  ? 'On. Direct internet transport is available when policy allows it.'
                  : 'Off. Direct internet transport is disabled.',
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _push(context, const NodeScreen()),
          ),
          ListTile(
            leading: const Icon(Icons.bluetooth_disabled_outlined),
            title: const Text('Bluetooth transport'),
            subtitle: Text(
              s?.enableBluetooth == true
                  ? 'On. Nearby Bluetooth transport is enabled.'
                  : 'Off. Nearby Bluetooth transport is disabled.',
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _push(context, const NodeScreen()),
          ),
          const Divider(height: 1),
          const _SectionHeader('Identity'),
          ListTile(
            leading: const Icon(Icons.masks_outlined),
            title: const Text('Identity masks'),
            subtitle: const Text(
              'Use separate identities when you do not want the same profile everywhere.',
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _push(context, const IdentityMasksScreen()),
          ),
          ListTile(
            leading: const Icon(Icons.shield_outlined),
            title: const Text('Threat context'),
            subtitle: const Text(
              'Raise the threat level to apply stricter transport and metadata rules.',
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _push(context, const SecurityScreen()),
          ),
          const Divider(height: 1),
          const _SectionHeader('Alerts'),
          ListTile(
            leading: const Icon(Icons.notifications_off_outlined),
            title: const Text('Notification previews'),
            subtitle: Text(
              notifications?['showPreviews'] == true
                  ? 'On. Notifications can show message content on this device.'
                  : 'Off. Notifications avoid showing message content.',
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _push(context, const NotificationScreen()),
          ),
          ListTile(
            leading: const Icon(Icons.cloud_off_outlined),
            title: const Text('Cloud wake signals'),
            subtitle: Text(
              notifications?['cloudPingEnabled'] == true
                  ? 'On. A third-party push service may see notification timing.'
                  : 'Off. Notifications rely on mesh-native delivery only.',
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _push(context, const NotificationScreen()),
          ),
          const SizedBox(height: 24),
        ],
      ),
    );
  }

  void _push(BuildContext context, Widget screen) {
    Navigator.push(context, MaterialPageRoute(builder: (_) => screen));
  }
}

class _SectionHeader extends StatelessWidget {
  const _SectionHeader(this.title);

  final String title;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 20, 16, 6),
      child: Text(
        title,
        style: Theme.of(context).textTheme.labelMedium?.copyWith(
          color: Theme.of(context).colorScheme.primary,
          fontWeight: FontWeight.w700,
          letterSpacing: 0.8,
        ),
      ),
    );
  }
}
