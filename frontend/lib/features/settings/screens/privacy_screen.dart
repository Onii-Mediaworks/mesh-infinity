// privacy_screen.dart
//
// PrivacyScreen — a unified privacy-control summary screen (§22.10).
//
// WHAT THIS SCREEN IS:
// --------------------
// Rather than scattering privacy-relevant settings across multiple sections
// (notifications, security, node), this screen acts as a curated index of
// the settings that directly affect what information other devices or third
// parties can learn about this user.
//
// Each tile reflects the current value of its underlying setting and links
// through to the screen where it can be changed.  Reading the PrivacyScreen
// gives a quick "privacy posture snapshot" at a glance.
//
// THREE GROUPS:
// -------------
// Discovery — controls what transport mechanisms can be used to find this
//             node (local LAN mDNS, clearnet IP, Bluetooth).  Disabling
//             these reduces reachability but also reduces the surface area
//             an adversary can probe.
//
// Identity  — contextual identities (masks) and threat context.  Masks let
//             the user present a different face in different contexts.
//             Threat context applies stricter transport and metadata rules.
//
// Alerts    — notification previews and cloud wake signals.  Both can reveal
//             metadata to third parties (preview = message content on-screen;
//             cloud ping = timing via APNs / FCM).
//
// REACHED FROM: Settings → Privacy controls.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/backend_bridge.dart';
import '../settings_state.dart';
import 'identity_masks_screen.dart';
import 'node_screen.dart';
import 'notification_screen.dart';
import 'security_screen.dart';

/// Privacy-control summary screen — a curated index of privacy-relevant settings.
///
/// Shows the current state of each setting and routes to the screen where it
/// can be changed.  Values are read from [SettingsState] and [BackendBridge]
/// on each build so they stay in sync after the user returns from a sub-screen.
class PrivacyScreen extends StatelessWidget {
  const PrivacyScreen({super.key});

  @override
  Widget build(BuildContext context) {
    // context.watch rebuilds PrivacyScreen when SettingsState notifies,
    // which happens after any settings save.  This keeps the subtitle text
    // current without requiring the user to leave and return.
    final settings = context.watch<SettingsState>();
    final s = settings.settings;

    // getNotificationConfig is a synchronous bridge call.  We read it here
    // (not from SettingsState) because notification config is not part of
    // SettingsModel — it is fetched from a separate backend module.
    // context.read is fine here because we don't need reactivity on the
    // bridge itself (the bridge is a stable singleton).
    final notifications = context.read<BackendBridge>().getNotificationConfig();

    return Scaffold(
      appBar: AppBar(title: const Text('Privacy controls')),
      body: ListView(
        children: [
          // ── Discovery ───────────────────────────────────────────────────────
          // These settings control how reachable this device is to other nodes.
          // Displaying the current state in the subtitle means the user can
          // see their discovery posture at a glance without tapping through.
          const _SectionHeader('Discovery'),
          ListTile(
            leading: const Icon(Icons.radar_outlined),
            title: const Text('Local network discovery'),
            subtitle: Text(
              // Ternary reflects the actual setting rather than a static label,
              // so the user always sees what is currently configured.
              s?.meshDiscovery == true
                  ? 'On. This device can look for nearby peers on the local network.'
                  : 'Off. Nearby peer discovery on the local network is disabled.',
            ),
            trailing: const Icon(Icons.chevron_right),
            // All discovery settings live on NodeScreen, which is the right
            // home for transport-level controls.
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

          // ── Identity ────────────────────────────────────────────────────────
          // Masks are contextual identities — the user can appear as different
          // personas to different contacts, preventing correlation.
          // Threat context raises the security posture globally.
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
            // Threat context lives under SecurityScreen, which is the right
            // home for operational security posture controls.
            onTap: () => _push(context, const SecurityScreen()),
          ),
          const Divider(height: 1),

          // ── Alerts ──────────────────────────────────────────────────────────
          // These settings control what metadata is leaked via notifications.
          //   showPreviews = true  → message text appears in OS notification centre
          //   cloudPingEnabled     → APNs / FCM / UnifiedPush can see message timing
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

  /// Push a new screen on the navigator stack.
  ///
  /// Helper to keep individual onTap handlers concise and consistent.
  void _push(BuildContext context, Widget screen) {
    Navigator.push(context, MaterialPageRoute(builder: (_) => screen));
  }
}

// ---------------------------------------------------------------------------
// _SectionHeader — coloured section label
// ---------------------------------------------------------------------------

/// Small all-caps section label matching the settings design language.
///
/// Used throughout the settings sub-screens for visual consistency.
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
