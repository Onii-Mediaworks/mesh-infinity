// settings_screen.dart
//
// SettingsScreen — the top-level settings list (§22.10.1, §22.55).
//
// SECTIONS:
//   Notifications     — push delivery + ambient badge indicators
//   Identity          — masks, cryptographic keys, multi-device (§22.10.2, §22.10.7)
//   Security          — threat level, PIN, emergency erase, advanced (§22.10.x–§22.10.11)
//   Privacy           — discovery, exposure, and notification disclosure
//   Appearance        — dark / light / system theme
//   Data              — backup and restore
//   Node              — node mode, clearnet port
//   Mesh participation — bandwidth profile (§22.55.1)
//   Features          — tier unlock + TierDiscoveryScreen link (§22.55.2)
//   About             — version info
//   Developer Options — debug-build only (§22.56)
//   [Footer]          — "Explore features" button (§22.53)
//
// DESIGN NOTES:
// -------------
// The "Danger Zone" section from the old design is removed — emergency erase
// now lives under Security → Emergency erase, which is the correct home for
// it (§22.10.11).  Keeping danger-zone actions inside the Security section
// reduces the chance of accidental activation and groups related controls.
//
// The "Explore features" footer button (§22.55.2) is always shown, even when
// the user is on the highest tier, so new features added in future updates
// are always discoverable.

import 'package:flutter/foundation.dart' show kDebugMode;
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
import 'identity_masks_screen.dart';
import 'multi_device_screen.dart';
import 'tier_discovery_screen.dart';
import 'debug_screen.dart';
import 'privacy_screen.dart';

// ---------------------------------------------------------------------------
// SettingsScreen
// ---------------------------------------------------------------------------

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final settings = context.watch<SettingsState>();
    final s = settings.settings;

    return ListView(
      children: [
        // ── Notifications ──────────────────────────────────────────────
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

        // ── Identity ───────────────────────────────────────────────────
        // Root identity, masks, and multi-device.  Grouped here rather
        // than under Security because identity management is routine —
        // users visit it to share their peer ID, not to lock things down.
        const _SectionHeader('Identity'),
        _Tile(
          icon: Icons.masks_outlined,
          title: 'Identity & Masks',
          subtitle: 'Root peer ID and contextual identities',
          onTap: () => _push(context, const IdentityMasksScreen()),
        ),
        _Tile(
          icon: Icons.devices_outlined,
          title: 'My Devices',
          subtitle: settings.deviceCount > 1
              ? '${settings.deviceCount} devices sharing this identity'
              : 'This device only',
          onTap: () => _push(context, const MultiDeviceScreen()),
        ),
        _Tile(
          icon: Icons.fingerprint_outlined,
          title: 'Advanced identity',
          subtitle: 'Cryptographic keys and pairing payload',
          onTap: () => _push(context, const IdentityScreen()),
        ),
        const Divider(height: 1),

        // ── Security ───────────────────────────────────────────────────
        // SecurityScreen is the hub for threat level, PIN, emergency erase,
        // potential extremes, known limitations, and crypto identity.
        // A single entry here keeps the top-level list uncluttered.
        const _SectionHeader('Security'),
        _Tile(
          icon: Icons.shield_outlined,
          title: 'Security & threat level',
          subtitle: 'PIN, emergency erase, threat context',
          onTap: () => _push(context, const SecurityScreen()),
        ),
        const Divider(height: 1),

        // ── Privacy ───────────────────────────────────────────────────
        const _SectionHeader('Privacy'),
        _Tile(
          icon: Icons.visibility_off_outlined,
          title: 'Privacy controls',
          subtitle: 'Discovery, identity exposure, and notification disclosure',
          onTap: () => _push(context, const PrivacyScreen()),
        ),
        const Divider(height: 1),

        // ── Appearance ────────────────────────────────────────────────
        const _SectionHeader('Appearance'),
        _Tile(
          icon: Icons.brightness_6_outlined,
          title: 'Theme',
          subtitle: 'Light, dark, or system default',
          onTap: () => _push(context, const AppearanceScreen()),
        ),
        const Divider(height: 1),

        // ── Data ──────────────────────────────────────────────────────
        const _SectionHeader('Data'),
        _Tile(
          icon: Icons.backup_outlined,
          title: 'Backup & restore',
          subtitle: 'Export or import an encrypted backup',
          onTap: () => _push(context, const BackupScreen()),
        ),
        const Divider(height: 1),

        // ── Node ──────────────────────────────────────────────────────
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

        // ── Mesh participation (§22.55.1) ─────────────────────────────
        // The bandwidth profile controls how much of this device's network
        // capacity is donated to routing for other mesh nodes.  Most users
        // never need to change this; it's here for power users with metered
        // data or battery constraints.
        const _SectionHeader('Mesh participation'),
        _Tile(
          icon: Icons.hub_outlined,
          title: 'Bandwidth profile',
          subtitle: _bandwidthLabel(settings.bandwidthProfile),
          onTap: () => _openBandwidthSheet(context, settings),
        ),
        const Divider(height: 1),

        // ── Features (§22.55.2) ───────────────────────────────────────
        // Links to TierDiscoveryScreen where the user can explore and unlock
        // higher tiers (Network, Infinet, Services, Power).  The subtitle
        // shows their current tier so they know where they stand at a glance.
        const _SectionHeader('Features'),
        _Tile(
          icon: Icons.explore_outlined,
          title: 'Explore features',
          subtitle:
              'Tier ${settings.activeTier.index + 1}: '
              '${_tierName(settings.activeTier)}',
          onTap: () => _push(context, const TierDiscoveryScreen()),
        ),
        const Divider(height: 1),

        // ── About ─────────────────────────────────────────────────────
        const _SectionHeader('About'),
        const ListTile(
          leading: Icon(Icons.info_outline),
          title: Text('Mesh Infinity'),
          subtitle: Text('v0.3.0 — Decentralised private mesh networking'),
        ),
        const Divider(height: 1),

        // ── Developer Options (§22.56) ────────────────────────────────
        // Only shown in debug builds — tree-shaken in release.
        // kDebugMode is a compile-time constant so this branch is
        // eliminated by the Dart compiler in production.
        if (kDebugMode) ...[
          const _SectionHeader('Developer'),
          _Tile(
            icon: Icons.bug_report_outlined,
            title: 'Developer options',
            subtitle: 'Logs, state inspector, protocol tests',
            onTap: () => _push(context, const DebugScreen()),
          ),
          const Divider(height: 1),
        ],

        const SizedBox(height: 16),
      ],
    );
  }

  // ---------------------------------------------------------------------------
  // Navigation helpers
  // ---------------------------------------------------------------------------

  void _push(BuildContext context, Widget screen) {
    Navigator.push(context, MaterialPageRoute(builder: (_) => screen));
  }

  // ---------------------------------------------------------------------------
  // Bandwidth profile bottom sheet (§22.55.1)
  // ---------------------------------------------------------------------------

  /// Opens a bottom sheet with radio tiles for each bandwidth profile.
  ///
  /// The sheet is dismissable — the user can cancel without changing anything.
  void _openBandwidthSheet(BuildContext context, SettingsState settings) {
    showModalBottomSheet<void>(
      context: context,
      showDragHandle: true,
      builder: (ctx) => Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 4, 16, 8),
            child: Text(
              'Mesh participation',
              style: Theme.of(ctx).textTheme.titleMedium,
            ),
          ),
          RadioGroup<BandwidthProfile>(
            groupValue: settings.bandwidthProfile,
            onChanged: (v) async {
              if (v != null) {
                await settings.setBandwidthProfile(v);
                if (!ctx.mounted) return;
                Navigator.pop(ctx);
              }
            },
            child: Column(
              children: [
                for (final profile in BandwidthProfile.values)
                  RadioListTile<BandwidthProfile>(
                    value: profile,
                    title: Text(_bandwidthLabel(profile)),
                    subtitle: Text(_bandwidthDesc(profile)),
                  ),
              ],
            ),
          ),
          const SizedBox(height: 8),
        ],
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // Label helpers
  // ---------------------------------------------------------------------------

  String _nodeModeName(int mode) => switch (mode) {
    0 => 'Leaf node',
    1 => 'Relay node',
    2 => 'Full node',
    _ => 'Unknown mode',
  };

  static String _bandwidthLabel(BandwidthProfile p) => switch (p) {
    BandwidthProfile.minimal => 'Minimal',
    BandwidthProfile.standard => 'Standard',
    BandwidthProfile.generous => 'Generous',
  };

  static String _bandwidthDesc(BandwidthProfile p) => switch (p) {
    BandwidthProfile.minimal =>
      'Metered or battery-constrained. Only essential mesh functions.',
    BandwidthProfile.standard =>
      'Balanced. Helps route traffic for others. Recommended.',
    BandwidthProfile.generous =>
      'Always-on device with good connectivity. Maximum mesh contribution.',
  };

  static String _tierName(MeshTier t) =>
      const ['Social', 'Network', 'Infinet', 'Services', 'Power'][t.index];
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
  });

  final IconData icon;
  final String title;
  final String subtitle;
  final VoidCallback? onTap;

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
      trailing: onTap != null ? const Icon(Icons.chevron_right) : null,
      onTap: onTap,
    );
  }
}
