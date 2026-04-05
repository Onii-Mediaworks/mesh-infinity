import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../../../backend/backend_bridge.dart';

class MultiDeviceScreen extends StatefulWidget {
  const MultiDeviceScreen({super.key});

  @override
  State<MultiDeviceScreen> createState() => _MultiDeviceScreenState();
}

class _MultiDeviceScreenState extends State<MultiDeviceScreen> {
  List<Map<String, dynamic>> _devices = const [];
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final devices = context.read<BackendBridge>().fetchDevices();
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
    final thisDevice = _devices.cast<Map<String, dynamic>>().firstWhere(
          (device) => device['isThisDevice'] == true,
          orElse: () => const <String, dynamic>{},
        );
    final otherDevices = _devices
        .where((device) => device['isThisDevice'] != true)
        .toList(growable: false);
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
                  Text(
                    'When you add a device, your identity keys are copied to it over an encrypted channel. '
                    'History stays on each device unless you share it manually. '
                    'Removing a device rotates keys for future sessions.',
                    style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
                  ),
                  const SizedBox(height: 12),
                  if (isPrimary)
                    FilledButton.icon(
                      onPressed: () => _openPrimaryEnrollmentDialog(context),
                      icon: const Icon(Icons.add_link_outlined),
                      label: const Text('Link a new device'),
                    ),
                  const SizedBox(height: 20),
                  const _SectionLabel('This device'),
                  if (thisDevice.isNotEmpty)
                    _DeviceTile(
                      device: thisDevice,
                      isThisDevice: true,
                    ),
                  const SizedBox(height: 20),
                  const _SectionLabel('Other devices'),
                  if (otherDevices.isEmpty)
                    const _OtherDevicesEmptyState()
                  else
                    for (final device in otherDevices)
                      _DeviceTile(
                        device: device,
                        isThisDevice: false,
                        canRemove: isPrimary,
                        onRemove: () => _confirmRemoveDevice(device),
                      ),
                  const SizedBox(height: 24),
                ],
              ),
            ),
    );
  }

  Future<void> _openPrimaryEnrollmentDialog(BuildContext context) async {
    final requestCtrl = TextEditingController();
    final responseCtrl = TextEditingController();
    final generatedPackage = ValueNotifier<String?>(null);
    await showDialog<void>(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Link a new device'),
        content: SizedBox(
          width: 440,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
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
                    generatedPackage.value = package;
                    responseCtrl.text = package;
                    _load();
                  },
                  child: const Text('Create link package'),
                ),
              ),
              const SizedBox(height: 12),
              ValueListenableBuilder<String?>(
                valueListenable: generatedPackage,
                builder: (context, package, _) {
                  if (package == null || package.isEmpty) {
                    return const SizedBox.shrink();
                  }
                  return Column(
                    children: [
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
    requestCtrl.dispose();
    responseCtrl.dispose();
    generatedPackage.dispose();
  }

  Future<void> _confirmRemoveDevice(Map<String, dynamic> device) async {
    final bridge = context.read<BackendBridge>();
    final name = device['name'] as String? ?? 'this device';
    final deviceId = device['id'] as String? ?? '';
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
    await _load();
  }

}

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

class _DeviceTile extends StatelessWidget {
  const _DeviceTile({
    required this.device,
    required this.isThisDevice,
    this.canRemove = false,
    this.onRemove,
  });

  final Map<String, dynamic> device;
  final bool isThisDevice;
  final bool canRemove;
  final VoidCallback? onRemove;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;
    final platform = device['platform'] as String? ?? 'unknown';
    final name = device['name'] as String? ?? 'Unnamed device';
    final isPrimary = device['isPrimary'] == true;
    final peerId = device['peerId'] as String? ?? '';
    final lastSeenMs = (device['lastSeenMs'] as num?)?.toInt();

    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: ListTile(
        leading: Icon(
          _platformIcon(platform),
          color: isThisDevice ? cs.primary : cs.onSurfaceVariant,
        ),
        title: Row(
          children: [
            Expanded(child: Text(name)),
            if (isPrimary)
              Icon(Icons.star_rounded, size: 14, color: cs.primary),
          ],
        ),
        subtitle: Text(
          isThisDevice
              ? peerId.isEmpty
                  ? 'Active now'
                  : 'Active now · ${_short(peerId)}'
              : _relativeTime(lastSeenMs),
          style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
        ),
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

  String _relativeTime(int? ms) {
    if (ms == null) return 'Unavailable';
    final now = DateTime.now().millisecondsSinceEpoch;
    final diff = now - ms;
    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return '${diff ~/ 60000}m ago';
    if (diff < 86400000) return '${diff ~/ 3600000}h ago';
    return '${diff ~/ 86400000}d ago';
  }

  String _short(String value) =>
      value.length > 16 ? '${value.substring(0, 16)}…' : value;
}

IconData _platformIcon(String platform) => switch (platform) {
      'android' => Icons.phone_android_outlined,
      'ios' => Icons.phone_iphone_outlined,
      'macos' => Icons.laptop_mac_outlined,
      'windows' => Icons.laptop_windows_outlined,
      'linux' => Icons.computer_outlined,
      'web' => Icons.language_outlined,
      _ => Icons.devices_outlined,
    };

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
