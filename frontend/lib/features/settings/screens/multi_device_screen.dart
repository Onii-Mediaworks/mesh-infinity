// multi_device_screen.dart
//
// MultiDeviceScreen — manage additional devices linked to the same identity.
//
// MULTI-DEVICE IDENTITY MODEL:
// ----------------------------
// A user can link multiple physical devices to a single cryptographic identity.
// Linking copies the identity's public metadata and key material to the new
// device over an encrypted enrollment channel — private keys are wrapped and
// transferred, not transmitted in the clear.
//
// PRIMARY vs SECONDARY DEVICES:
// ------------------------------
// One device is designated "primary". Only the primary device can authorize
// the enrollment of new devices and can remove linked devices. Secondary
// devices can use the identity but cannot manage the device list.
//
// The "Link a new device" button is only shown when isPrimary is true,
// enforcing this constraint in the UI.
//
// ENROLLMENT PROTOCOL:
// --------------------
// The enrollment is a two-step challenge/response flow:
//   Step 1 (new device): The new device generates an enrollment request
//     (a JSON blob containing its ephemeral public key + device metadata)
//     and displays it for the primary device to copy.
//   Step 2 (primary device): The primary device pastes the request into this
//     dialog, calls completeDeviceEnrollment(), and gets back a link package
//     (the wrapped key material + channel setup data).  The user copies this
//     package back to the new device.
//   Step 3 (new device): The new device imports the link package to complete
//     the enrollment.
//
// DEVICE REMOVAL:
// ---------------
// Removing a device rotates the forward-secrecy ratchet for future sessions.
// The removed device retains any messages it already decrypted but cannot
// decrypt new messages sent after removal.
//
// LAST SEEN TIME:
// ---------------
// lastSeenMs is a Unix timestamp in milliseconds from the backend. Null means
// the device has never been seen (e.g. it was added but never connected).
//
// Reached from: Settings → My Devices.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../../../backend/backend_bridge.dart';

/// Shows all devices linked to this identity with add/remove controls.
///
/// Stateful because it owns the device list fetched from the backend.
/// The primary device can add and remove other devices; secondary devices
/// have a read-only view.
class MultiDeviceScreen extends StatefulWidget {
  const MultiDeviceScreen({super.key});

  @override
  State<MultiDeviceScreen> createState() => _MultiDeviceScreenState();
}

class _MultiDeviceScreenState extends State<MultiDeviceScreen> {
  /// Raw device list from the backend, one map per device.
  /// Keys: 'id', 'name', 'platform', 'peerId', 'isThisDevice', 'isPrimary',
  /// 'lastSeenMs'.
  List<Map<String, dynamic>> _devices = const [];

  /// True until the first backend fetch completes.
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  /// Fetches the device list from the backend and rebuilds.
  ///
  /// Also called after enrollment or removal to refresh the list.
  Future<void> _load() async {
    final devices = context.read<BackendBridge>().fetchDevices();
    // Guard: widget may have been disposed while the FFI call was in flight.
    if (!mounted) return;
    setState(() {
      _devices = devices;
      _loading = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    final tt = Theme.of(context).textTheme;
    final cs = Theme.of(context).colorScheme;

    // Separate "this device" from the rest for distinct section rendering.
    // orElse returns an empty map — callers guard with `.isNotEmpty`.
    final thisDevice = _devices.cast<Map<String, dynamic>>().firstWhere(
          (device) => device['isThisDevice'] == true,
          orElse: () => const <String, dynamic>{},
        );
    final otherDevices = _devices
        .where((device) => device['isThisDevice'] != true)
        .toList(growable: false);

    // isPrimary controls whether the "Link a new device" button is shown —
    // only the primary device can enroll additional devices.
    final isPrimary = thisDevice['isPrimary'] == true;

    return Scaffold(
      appBar: AppBar(title: const Text('My Devices')),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : RefreshIndicator(
              onRefresh: _load,
              child: ListView(
                padding: const EdgeInsets.all(16),
                children: [
                  // Explanation of how multi-device identity works.
                  Text(
                    'When you add a device, your identity keys are copied to it over an encrypted channel. '
                    'History stays on each device unless you share it manually. '
                    'Removing a device rotates keys for future sessions.',
                    style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
                  ),
                  const SizedBox(height: 12),

                  // "Link a new device" button — shown only on the primary device.
                  // Secondary devices cannot initiate enrollment.
                  if (isPrimary)
                    FilledButton.icon(
                      onPressed: () => _openPrimaryEnrollmentDialog(context),
                      icon: const Icon(Icons.add_link_outlined),
                      label: const Text('Link a new device'),
                    ),

                  const SizedBox(height: 20),

                  // ── This device ─────────────────────────────────────────
                  const _SectionLabel('This device'),
                  if (thisDevice.isNotEmpty)
                    _DeviceTile(
                      device: thisDevice,
                      isThisDevice: true,
                    ),

                  const SizedBox(height: 20),

                  // ── Other devices ───────────────────────────────────────
                  const _SectionLabel('Other devices'),
                  if (otherDevices.isEmpty)
                    const _OtherDevicesEmptyState()
                  else
                    for (final device in otherDevices)
                      _DeviceTile(
                        device: device,
                        isThisDevice: false,
                        // Only the primary device gets a remove button —
                        // secondary devices cannot deauth other devices.
                        canRemove: isPrimary,
                        onRemove: () => _confirmRemoveDevice(device),
                      ),

                  const SizedBox(height: 24),
                ],
              ),
            ),
    );
  }

  // ---------------------------------------------------------------------------
  // Enrollment dialog (primary device only)
  // ---------------------------------------------------------------------------

  /// Shows the two-step enrollment dialog where the primary device authorises
  /// a new device by processing its enrollment request.
  ///
  /// Step 1: User pastes the enrollment request from the new device.
  /// Step 2: Bridge generates a link package; user copies it back to the new device.
  Future<void> _openPrimaryEnrollmentDialog(BuildContext context) async {
    final requestCtrl = TextEditingController();
    final responseCtrl = TextEditingController();

    // ValueNotifier drives the conditional display of the link package output
    // field — it only appears after a successful completeDeviceEnrollment() call.
    final generatedPackage = ValueNotifier<String?>(null);

    await showDialog<void>(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Link a new device'),
        content: SizedBox(
          // Fixed width so the dialog doesn't stretch to full screen on
          // tablets/desktop where dialogs default to intrinsic width.
          width: 440,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              // Step 1: paste the enrollment request from the new device.
              TextField(
                controller: requestCtrl,
                minLines: 4,
                maxLines: 8,
                decoration: const InputDecoration(
                  labelText: 'Enrollment request from the new device',
                ),
              ),
              const SizedBox(height: 12),
              Align(
                alignment: Alignment.centerRight,
                child: FilledButton(
                  onPressed: () {
                    final bridge = context.read<BackendBridge>();
                    // Process the enrollment request and get back a link package.
                    // Returns null on failure (e.g. tampered request, expired nonce).
                    final package = bridge.completeDeviceEnrollment(
                      requestCtrl.text.trim(),
                    );
                    if (package == null || package.isEmpty) {
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(
                          content: Text(
                            bridge.getLastError() ??
                                'Could not complete the device link request.',
                          ),
                        ),
                      );
                      return;
                    }
                    // Show the link package output field and refresh the device
                    // list so the newly enrolled device appears immediately.
                    generatedPackage.value = package;
                    responseCtrl.text = package;
                    _load();
                  },
                  child: const Text('Create link package'),
                ),
              ),
              const SizedBox(height: 12),

              // Step 2: show the link package so the user can copy it to the
              // new device. Hidden until step 1 succeeds.
              ValueListenableBuilder<String?>(
                valueListenable: generatedPackage,
                builder: (context, package, _) {
                  // Nothing to show until a package has been generated.
                  if (package == null || package.isEmpty) {
                    return const SizedBox.shrink();
                  }
                  return Column(
                    children: [
                      // Read-only text area showing the link package JSON.
                      TextField(
                        controller: responseCtrl,
                        minLines: 4,
                        maxLines: 8,
                        decoration: const InputDecoration(
                          labelText: 'Link package for the new device',
                        ),
                      ),
                      const SizedBox(height: 8),
                      Align(
                        alignment: Alignment.centerRight,
                        child: TextButton.icon(
                          onPressed: () {
                            Clipboard.setData(ClipboardData(text: package));
                            ScaffoldMessenger.of(context).showSnackBar(
                              const SnackBar(
                                content: Text('Link package copied.'),
                              ),
                            );
                          },
                          icon: const Icon(Icons.copy_outlined),
                          label: const Text('Copy package'),
                        ),
                      ),
                    ],
                  );
                },
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Close'),
          ),
        ],
      ),
    );

    // Dispose controllers after the dialog closes to free text buffer memory.
    requestCtrl.dispose();
    responseCtrl.dispose();
    generatedPackage.dispose();
  }

  // ---------------------------------------------------------------------------
  // Device removal
  // ---------------------------------------------------------------------------

  /// Shows a confirmation dialog before removing [device] from the identity.
  ///
  /// Removal rotates the session ratchet — the removed device loses the ability
  /// to decrypt future messages but retains messages it already received.
  Future<void> _confirmRemoveDevice(Map<String, dynamic> device) async {
    final bridge = context.read<BackendBridge>();
    final name = device['name'] as String? ?? 'this device';
    final deviceId = device['id'] as String? ?? '';

    // Guard: a device without an ID can't be removed — skip silently.
    // This should not happen with well-formed backend data, but the map
    // type is dynamic so defensive checks are appropriate.
    if (deviceId.isEmpty) {
      return;
    }

    final confirmed = await showDialog<bool>(
          context: context,
          builder: (_) => AlertDialog(
            title: Text('Remove $name?'),
            content: const Text(
              'Removing a device rotates keys for future sessions. That device will no longer decrypt new messages.',
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context, false),
                child: const Text('Cancel'),
              ),
              FilledButton(
                onPressed: () => Navigator.pop(context, true),
                child: const Text('Remove device'),
              ),
            ],
          ),
        ) ??
        // Dialog dismissed by back-gesture — treat as Cancel.
        false;

    if (!confirmed || !mounted) {
      return;
    }

    final ok = bridge.removeDevice(deviceId);

    if (!mounted) {
      return;
    }

    if (!ok) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            bridge.getLastError() ?? 'Could not remove the selected device.',
          ),
        ),
      );
      return;
    }

    // Refresh the list so the removed device disappears immediately.
    await _load();
  }
}

// ---------------------------------------------------------------------------
// Section label widget
// ---------------------------------------------------------------------------

/// Small coloured section label, e.g. "This device" / "Other devices".
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
// Device tile widget
// ---------------------------------------------------------------------------

/// A single card row representing one linked device.
///
/// Shows platform icon, device name, primary indicator, last-seen time, and
/// (on the primary device only) a remove button for other devices.
class _DeviceTile extends StatelessWidget {
  const _DeviceTile({
    required this.device,
    required this.isThisDevice,
    this.canRemove = false,
    this.onRemove,
  });

  /// Raw device map from the backend.
  final Map<String, dynamic> device;

  /// True if this tile represents the current device — drives icon colour
  /// and subtitle text.
  final bool isThisDevice;

  /// Whether to show a remove button on this tile.
  ///
  /// Only true when the currently running device is the primary device and
  /// this tile is for a different device.
  final bool canRemove;

  /// Called when the remove button is tapped. Nullable because [canRemove]
  /// may be false, in which case no button is shown.
  final VoidCallback? onRemove;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    // Extract fields with safe defaults — the map is dynamically typed.
    final platform   = device['platform']   as String? ?? 'unknown';
    final name       = device['name']       as String? ?? 'Unnamed device';
    final isPrimary  = device['isPrimary']  == true;
    final peerId     = device['peerId']     as String? ?? '';

    // lastSeenMs is null for devices that have never connected.
    final lastSeenMs = (device['lastSeenMs'] as num?)?.toInt();

    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: ListTile(
        // Platform icon uses primary colour for "this device" so it stands out.
        leading: Icon(
          _platformIcon(platform),
          color: isThisDevice ? cs.primary : cs.onSurfaceVariant,
        ),
        title: Row(
          children: [
            Expanded(child: Text(name)),
            // Star icon marks the primary device — only one device in the list
            // should ever have isPrimary=true.
            if (isPrimary)
              Icon(Icons.star_rounded, size: 14, color: cs.primary),
          ],
        ),
        subtitle: Text(
          isThisDevice
              // This device: show "Active now" with a short peer ID if available.
              // Showing the ID lets the user confirm it matches the one they expect.
              ? peerId.isEmpty
                  ? 'Active now'
                  : 'Active now · ${_short(peerId)}'
              // Other devices: show relative last-seen time.
              : _relativeTime(lastSeenMs),
          style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
        ),
        // Remove button only on other devices when this device is primary.
        trailing: !isThisDevice && canRemove
            ? IconButton(
                onPressed: onRemove,
                tooltip: 'Remove device',
                icon: Icon(
                  Icons.remove_circle_outline,
                  color: cs.error,
                ),
              )
            : null,
      ),
    );
  }

  /// Converts a millisecond Unix timestamp to a human-readable relative time.
  ///
  /// Returns "Unavailable" when [ms] is null (device never connected).
  String _relativeTime(int? ms) {
    if (ms == null) return 'Unavailable';
    final now = DateTime.now().millisecondsSinceEpoch;
    final diff = now - ms;
    // Thresholds: < 1 min, < 1 h, < 24 h, else days.
    if (diff < 60000)    return 'Just now';
    if (diff < 3600000)  return '${diff ~/ 60000}m ago';
    if (diff < 86400000) return '${diff ~/ 3600000}h ago';
    return '${diff ~/ 86400000}d ago';
  }

  /// Truncates [value] to 16 chars followed by an ellipsis.
  ///
  /// Used for peer ID display in the subtitle where full IDs would overflow.
  String _short(String value) =>
      value.length > 16 ? '${value.substring(0, 16)}…' : value;
}

/// Maps a platform string returned by the backend to a representative icon.
///
/// Top-level function (not a method) because Dart class member functions
/// cannot be called in const initializers; this function is also used by
/// the [_DeviceTile] widget directly.
IconData _platformIcon(String platform) => switch (platform) {
      'android' => Icons.phone_android_outlined,
      'ios'     => Icons.phone_iphone_outlined,
      'macos'   => Icons.laptop_mac_outlined,
      'windows' => Icons.laptop_windows_outlined,
      'linux'   => Icons.computer_outlined,
      'web'     => Icons.language_outlined,
      // Unknown/future platforms — generic device icon.
      _         => Icons.devices_outlined,
    };

// ---------------------------------------------------------------------------
// Empty state widget
// ---------------------------------------------------------------------------

/// Shown in the "Other devices" section when no additional devices are linked.
class _OtherDevicesEmptyState extends StatelessWidget {
  const _OtherDevicesEmptyState();

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
            Text('No other devices visible', style: tt.titleSmall),
            const SizedBox(height: 6),
            Text(
              'Additional devices will appear here when the backend can verify them.',
              style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }
}
