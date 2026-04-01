// multi_device_screen.dart
//
// MultiDeviceScreen — manage the set of devices sharing this identity (§22.10.7).
//
// WHAT THIS SCREEN SHOWS:
// -----------------------
// One Mesh Infinity identity can be installed on multiple devices — phone,
// tablet, laptop, etc.  This screen shows:
//   1. "This device" card — the current device with its platform icon and
//      a star if it's the primary device.
//   2. "Other devices" list — paired devices that share this identity, with
//      last-seen relative timestamps and a remove option.
//   3. AppBar "+" button — starts the pairing flow for a new device.
//
// BACKEND STATUS:
// ---------------
// Multi-device is not yet implemented in the backend.  The screen shows a
// static representation of "this device" and an empty "other devices" section.
// When the backend wires up (§8.4, §11.1), replace _thisDevice and
// _otherDevices with real data from `bridge.fetchDevices()`.
//
// DESIGN PHILOSOPHY (§22.22):
// ----------------------------
// Devices are shown with plain-language platform names (not UUIDs).
// The primary device star is subtle — not everyone needs multi-device, and
// the concept of "primary" shouldn't alarm users who only have one device.
//
// Reached from: Settings → Identity & Devices → My Devices.

import 'dart:io' show Platform;

import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter/material.dart';

// ---------------------------------------------------------------------------
// Data model (stub — replaced by backend model when ready)
// ---------------------------------------------------------------------------

/// Represents one device sharing this identity.
///
/// [id] is an opaque backend identifier.
/// [name] is a human-readable label the user assigns (or the platform default).
/// [platform] describes the OS/form factor for icon selection.
/// [isPrimary] — the primary device receives all messages when multiple devices
///   are online.  Only one device can be primary at a time (§11.1.2).
/// [lastSeenMs] is the Unix timestamp of the last heartbeat, or null if unknown.
class _DeviceModel {
  const _DeviceModel({
    required this.id,
    required this.name,
    required this.platform,
    required this.isPrimary,
    required this.lastSeenMs,
  });

  final String id;
  final String name;
  final String platform; // 'android' | 'ios' | 'macos' | 'linux' | 'windows' | 'web'
  final bool isPrimary;

  // null = local device (always live); non-null = Unix ms of last heartbeat.
  // Required (not optional) so callers must explicitly pass null for "this device",
  // preventing accidentally omitted timestamps when constructing real device data.
  final int? lastSeenMs;
}

// ---------------------------------------------------------------------------
// MultiDeviceScreen
// ---------------------------------------------------------------------------

/// Shows the paired device list and allows adding or removing devices.
class MultiDeviceScreen extends StatelessWidget {
  const MultiDeviceScreen({super.key});

  // ---------------------------------------------------------------------------
  // Platform detection
  // ---------------------------------------------------------------------------
  // Detects the current platform for displaying the correct icon on the
  // "This device" card.  Web is checked first because kIsWeb is true even
  // when Platform.* would throw on web.
  static String get _currentPlatform {
    if (kIsWeb) return 'web';
    if (Platform.isAndroid) return 'android';
    if (Platform.isIOS) return 'ios';
    if (Platform.isMacOS) return 'macos';
    if (Platform.isLinux) return 'linux';
    if (Platform.isWindows) return 'windows';
    return 'unknown';
  }

  // Stub "this device" — replaced by backend data when §11.1 is wired.
  // The name defaults to the platform; users can rename in a future update.
  static _DeviceModel get _thisDevice => _DeviceModel(
    id: 'local',
    name: _platformDisplayName(_currentPlatform),
    platform: _currentPlatform,
    isPrimary: true, // by default, this device is primary (only device)
    lastSeenMs: null, // local device is always live — no heartbeat timestamp
  );

  // Empty other-devices list — populated by backend in a future sprint.
  static const List<_DeviceModel> _otherDevices = [];

  @override
  Widget build(BuildContext context) {
    final tt = Theme.of(context).textTheme;
    final cs = Theme.of(context).colorScheme;

    return Scaffold(
      appBar: AppBar(
        title: const Text('My Devices'),
        actions: [
          // "+" button starts the device pairing flow (stub).
          IconButton(
            icon: const Icon(Icons.add),
            tooltip: 'Pair a new device',
            onPressed: () => _stubPairDevice(context),
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // ---------------------------------------------------------------------------
          // Explanation paragraph
          // ---------------------------------------------------------------------------
          // Brief plain-language description so users understand what "sharing an
          // identity across devices" means before they start adding devices.
          Text(
            'All devices listed here share your identity and can send and '
            'receive messages on your behalf.  The primary device is '
            'preferred when multiple devices are online simultaneously.',
            style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
          ),

          const SizedBox(height: 20),

          // ---------------------------------------------------------------------------
          // "This device" section
          // ---------------------------------------------------------------------------
          const _SectionLabel('This device'),
          _DeviceTile(
            device: _thisDevice,
            isThisDevice: true, // suppresses "remove" option
            onRemove: null,
          ),

          const SizedBox(height: 20),

          // ---------------------------------------------------------------------------
          // "Other devices" section
          // ---------------------------------------------------------------------------
          Row(
            children: [
              const Expanded(child: _SectionLabel('Other devices')),
              // Secondary pairing button in the section row — mirrors AppBar.
              TextButton.icon(
                onPressed: () => _stubPairDevice(context),
                icon: const Icon(Icons.add, size: 16),
                label: const Text('Pair device'),
              ),
            ],
          ),

          // Empty state — shown until the backend returns paired devices.
          // The empty state is intentionally simple; multi-device is optional.
          if (_otherDevices.isEmpty)
            _OtherDevicesEmptyState(onPair: () => _stubPairDevice(context))
          else
            for (final device in _otherDevices)
              _DeviceTile(
                device: device,
                isThisDevice: false,
                onRemove: () => _confirmRemove(context, device),
              ),

          const SizedBox(height: 24),
        ],
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /// Stub: shows a SnackBar until the pairing flow is implemented.
  ///
  /// When the backend wires device pairing (§11.1.1), navigate to a
  /// DevicePairingScreen instead.
  void _stubPairDevice(BuildContext context) {
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Device pairing coming in a future update.'),
        duration: Duration(seconds: 3),
      ),
    );
  }

  /// Shows a confirmation dialog before removing a paired device.
  ///
  /// Removing a device revokes its access to this identity — it cannot
  /// send or receive messages as you until it is re-paired (§11.1.3).
  void _confirmRemove(BuildContext context, _DeviceModel device) {
    final cs = Theme.of(context).colorScheme;

    showDialog<void>(
      context: context,
      builder: (_) => AlertDialog(
        title: Text('Remove "${device.name}"?'),
        content: Text(
          'This device will no longer be able to send or receive messages '
          'as you.  You can re-pair it later if needed.',
          style: Theme.of(context).textTheme.bodySmall,
        ),
        actions: [
          // Cancel — safe path.
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          // Remove — destructive, but reversible (re-pairing is always possible).
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: cs.error),
            onPressed: () {
              Navigator.pop(context);
              // TODO(backend/multi-device): call bridge.removeDevice(device.id).
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(
                  content: Text('Device removal not yet available.'),
                ),
              );
            },
            child: const Text('Remove'),
          ),
        ],
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // Platform display helpers
  // ---------------------------------------------------------------------------

  /// Returns the icon that best represents the device's platform.
  static IconData _platformIcon(String platform) => switch (platform) {
    'android' => Icons.phone_android_outlined,
    'ios' => Icons.phone_iphone_outlined,
    'macos' => Icons.laptop_mac_outlined,
    'windows' => Icons.laptop_windows_outlined,
    'linux' => Icons.computer_outlined,
    'web' => Icons.language_outlined,
    _ => Icons.devices_outlined,
  };

  /// Returns a human-readable platform name for the "This device" card.
  static String _platformDisplayName(String platform) => switch (platform) {
    'android' => 'Android',
    'ios' => 'iPhone',
    'macos' => 'Mac',
    'windows' => 'Windows PC',
    'linux' => 'Linux',
    'web' => 'Web browser',
    _ => 'This device',
  };
}

// ---------------------------------------------------------------------------
// _SectionLabel — muted label above each device group
// ---------------------------------------------------------------------------

/// Small, muted section label matching the style used throughout Settings.
class _SectionLabel extends StatelessWidget {
  const _SectionLabel(this.title);

  final String title;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Text(
        title,
        style: Theme.of(context).textTheme.labelMedium?.copyWith(
              color: Theme.of(context).colorScheme.primary,
              fontWeight: FontWeight.w600,
            ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _DeviceTile — one row in the device list
// ---------------------------------------------------------------------------

/// Renders one device as a ListTile inside a Card.
///
/// Shows the platform icon, device name, primary badge (star), last-seen
/// time (or "This device" for the local device), and an optional remove
/// button (hidden for the local device — you can't remove yourself).
class _DeviceTile extends StatelessWidget {
  const _DeviceTile({
    required this.device,
    required this.isThisDevice,
    required this.onRemove,
  });

  final _DeviceModel device;

  /// True for the "This device" card — suppresses the remove action.
  final bool isThisDevice;

  /// Callback for the remove button.  Null when [isThisDevice] is true.
  final VoidCallback? onRemove;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    // Relative last-seen string.
    // "This device" is always live; other devices show how long ago they
    // sent a heartbeat.
    final lastSeenText = isThisDevice ? 'Active now' : _relativeTime(device.lastSeenMs);

    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: ListTile(
        // Platform icon — gives a quick visual cue (phone vs laptop etc.).
        leading: Icon(
          MultiDeviceScreen._platformIcon(device.platform),
          color: isThisDevice ? cs.primary : cs.onSurfaceVariant,
        ),

        // Device name + optional "primary" star badge.
        title: Row(
          children: [
            Text(device.name),
            if (device.isPrimary) ...[
              const SizedBox(width: 6),
              // Star badge — indicates this is the primary device.
              // Subtle: icon-only, no extra label needed.
              Icon(Icons.star_rounded, size: 14, color: cs.primary),
            ],
          ],
        ),

        // Last-seen line — helps users identify stale devices.
        subtitle: Text(
          lastSeenText,
          style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
        ),

        // Remove button — only for other devices (hidden for "This device").
        // Using an icon button rather than a swipe gesture for clarity and
        // accessibility (§22.22 plain-language principle extends to actions).
        trailing: isThisDevice
            ? null
            : IconButton(
                icon: const Icon(Icons.remove_circle_outline),
                color: cs.error,
                tooltip: 'Remove this device',
                onPressed: onRemove,
              ),
      ),
    );
  }

  /// Returns a plain-language relative time string.
  ///
  /// Falls back to 'Never seen' if no heartbeat timestamp is recorded.
  String _relativeTime(int? ms) {
    if (ms == null) return 'Never seen';
    final now = DateTime.now().millisecondsSinceEpoch;
    final diff = now - ms;
    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return '${diff ~/ 60000}m ago';
    if (diff < 86400000) return '${diff ~/ 3600000}h ago';
    return '${diff ~/ 86400000}d ago';
  }
}

// ---------------------------------------------------------------------------
// _OtherDevicesEmptyState — shown when no other devices are paired
// ---------------------------------------------------------------------------

/// Empty state for the "Other devices" section.
///
/// Multi-device is optional — the empty state is friendly, not alarming.
/// Most users will only ever see this.
class _OtherDevicesEmptyState extends StatelessWidget {
  const _OtherDevicesEmptyState({required this.onPair});

  /// Called when the user taps "Pair a device" inside the empty state.
  final VoidCallback onPair;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          children: [
            Icon(Icons.devices_outlined, size: 40, color: cs.outline),
            const SizedBox(height: 12),
            Text('No other devices', style: tt.titleSmall),
            const SizedBox(height: 6),
            Text(
              'Pair another device to use your identity across phones, '
              'tablets, or computers.',
              style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 16),
            // Action button inside the card — mirrors the AppBar "+" button.
            FilledButton.tonal(
              onPressed: onPair,
              child: const Text('Pair a device'),
            ),
          ],
        ),
      ),
    );
  }
}
