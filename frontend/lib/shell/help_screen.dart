import 'package:flutter/material.dart';

import '../features/contacts/screens/pair_contact_screen.dart';
import '../features/settings/screens/backup_screen.dart';
import '../features/settings/screens/known_limitations_screen.dart';
import '../features/settings/screens/notification_screen.dart';
import '../features/settings/screens/security_screen.dart';

class HelpScreen extends StatelessWidget {
  const HelpScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Help')),
      body: ListView(
        children: [
          const _SectionHeader('Start here'),
          const ListTile(
            leading: Icon(Icons.info_outline),
            title: Text('What this app is good at'),
            subtitle: Text(
              'Private messaging, mesh networking, and controlled routing without a central account.',
            ),
          ),
          ListTile(
            leading: const Icon(Icons.person_add_outlined),
            title: const Text('Pair a contact'),
            subtitle: const Text(
              'Scan or paste a pairing code to add someone you trust.',
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _push(context, const PairContactScreen()),
          ),
          ListTile(
            leading: const Icon(Icons.security_outlined),
            title: const Text('Review security settings'),
            subtitle: const Text(
              'PIN, emergency erase, and threat context all live here.',
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _push(context, const SecurityScreen()),
          ),
          ListTile(
            leading: const Icon(Icons.backup_outlined),
            title: const Text('Back up your data'),
            subtitle: const Text(
              'Create an encrypted backup before making high-risk changes.',
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _push(context, const BackupScreen()),
          ),
          const Divider(height: 1),
          const _SectionHeader('Understand tradeoffs'),
          ListTile(
            leading: const Icon(Icons.notifications_outlined),
            title: const Text('Notification privacy'),
            subtitle: const Text(
              'See what each notification mode reveals to third parties.',
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _push(context, const NotificationScreen()),
          ),
          ListTile(
            leading: const Icon(Icons.warning_amber_outlined),
            title: const Text('Known limitations'),
            subtitle: const Text(
              'Read the situations this app cannot safely protect you from.',
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _push(context, const KnownLimitationsScreen()),
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
