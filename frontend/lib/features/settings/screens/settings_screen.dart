import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../settings_state.dart';
import 'notification_screen.dart';
import 'ambient_screen.dart';
import 'security_screen.dart';
import 'appearance_screen.dart';
import 'node_screen.dart';
import 'backup_screen.dart';
import 'identity_screen.dart';
import 'killswitch_screen.dart';

// ---------------------------------------------------------------------------
// SettingsScreen
//
// Layout per UI/UX proposal iteration 6/9.
// Identity is now in the "You" section — only a link to the advanced
// cryptographic identity view remains here under Security.
//
// Sections:
//   Notifications   — push delivery + ambient badge indicators
//   Security        — threat level, kill switch, advanced identity
//   Privacy         — (stub, backend not yet implemented)
//   Appearance      — dark / light / system mode
//   Data            — backup and restore
//   Node            — node mode, clearnet port
//   About
//   Danger Zone
// ---------------------------------------------------------------------------

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final settings = context.watch<SettingsState>();
    final s = settings.settings;

    return ListView(
      children: [
        // ── Notifications ───────────────────────────────────────────────
        const _SectionHeader('Notifications'),
        _Tile(
          icon: Icons.notifications_outlined,
          title: 'Push notifications',
          subtitle: 'Alerts, sounds, and delivery tiers',
          onTap: () => _push(context, const NotificationScreen()),
        ),
        _Tile(
          icon: Icons.circle_outlined,
          title: 'Ambient indicators',
          subtitle: 'Low-priority dots on navigation items',
          onTap: () => _push(context, const AmbientScreen()),
        ),
        const Divider(height: 1),

        // ── Security ────────────────────────────────────────────────────
        const _SectionHeader('Security'),
        _Tile(
          icon: Icons.shield_outlined,
          title: 'Security & threat level',
          subtitle: 'Threat context, duress mode, kill switch',
          onTap: () => _push(context, const SecurityScreen()),
        ),
        _Tile(
          icon: Icons.fingerprint_outlined,
          title: 'Advanced identity',
          subtitle: 'Cryptographic keys and pairing payload',
          onTap: () => _push(context, const IdentityScreen()),
        ),
        const Divider(height: 1),

        // ── Privacy ─────────────────────────────────────────────────────
        const _SectionHeader('Privacy'),
        _Tile(
          icon: Icons.visibility_off_outlined,
          title: 'Privacy controls',
          subtitle: 'Metadata minimisation and disclosure rules',
          onTap: null, // TODO: backend privacy controls not yet implemented
          trailing: _ComingSoon(),
        ),
        const Divider(height: 1),

        // ── Appearance ──────────────────────────────────────────────────
        const _SectionHeader('Appearance'),
        _Tile(
          icon: Icons.brightness_6_outlined,
          title: 'Theme',
          subtitle: 'Light, dark, or system default',
          onTap: () => _push(context, const AppearanceScreen()),
        ),
        const Divider(height: 1),

        // ── Data ────────────────────────────────────────────────────────
        const _SectionHeader('Data'),
        _Tile(
          icon: Icons.backup_outlined,
          title: 'Backup & restore',
          subtitle: 'Export or import an encrypted backup',
          onTap: () => _push(context, const BackupScreen()),
        ),
        const Divider(height: 1),

        // ── Node ────────────────────────────────────────────────────────
        const _SectionHeader('Node'),
        _Tile(
          icon: Icons.dns_outlined,
          title: 'Node configuration',
          subtitle: s != null
              ? _nodeModeName(s.nodeMode)
              : 'Mode, ports, and relay settings',
          onTap: () => _push(context, const NodeScreen()),
        ),
        const Divider(height: 1),

        // ── About ───────────────────────────────────────────────────────
        const _SectionHeader('About'),
        const ListTile(
          leading: Icon(Icons.info_outline),
          title: Text('Mesh Infinity'),
          subtitle: Text('v0.3.0 — Decentralised private mesh networking'),
        ),
        const Divider(height: 1),

        // ── Danger Zone ─────────────────────────────────────────────────
        const _SectionHeader('Danger Zone'),
        ListTile(
          leading: Icon(
            Icons.warning_amber_rounded,
            color: Theme.of(context).colorScheme.error,
          ),
          title: Text(
            'Emergency data destruction',
            style: TextStyle(color: Theme.of(context).colorScheme.error),
          ),
          subtitle: const Text('Permanently destroy all local data'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => _push(context, const KillswitchScreen()),
        ),
        const SizedBox(height: 24),
      ],
    );
  }

  void _push(BuildContext context, Widget screen) {
    Navigator.push(context, MaterialPageRoute(builder: (_) => screen));
  }

  String _nodeModeName(int mode) => switch (mode) {
    0 => 'Leaf node',
    1 => 'Relay node',
    2 => 'Full node',
    _ => 'Unknown mode',
  };
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

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

class _Tile extends StatelessWidget {
  const _Tile({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.onTap,
    this.trailing,
  });

  final IconData icon;
  final String title;
  final String subtitle;
  final VoidCallback? onTap;
  final Widget? trailing;

  @override
  Widget build(BuildContext context) {
    return ListTile(
      leading: Icon(icon),
      title: Text(title),
      subtitle: Text(
        subtitle,
        style: Theme.of(context).textTheme.bodySmall?.copyWith(
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
      ),
      trailing: trailing ?? (onTap != null ? const Icon(Icons.chevron_right) : null),
      onTap: onTap,
    );
  }
}

class _ComingSoon extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(6),
      ),
      child: Text(
        'Coming soon',
        style: Theme.of(context).textTheme.labelSmall?.copyWith(
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
      ),
    );
  }
}
