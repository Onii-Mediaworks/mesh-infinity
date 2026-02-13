import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../backend/backend_models.dart';
import '../../backend/file_transfer_models.dart';
import '../../backend/peer_models.dart';
import '../../core/state/mesh_state.dart';
import '../../models/thread_models.dart';
import 'menu_models.dart';

class GlobalMenu extends StatelessWidget {
  const GlobalMenu({
    super.key,
    this.showHeader = true,
    required this.selection,
    required this.pairingCode,
    required this.peerCount,
    required this.peers,
    required this.transfers,
    required this.threads,
    required this.activeThreadId,
    required this.onSelectThread,
    required this.settings,
    required this.onSelect,
    required this.onUpdateSettings,
    required this.onSelectNodeMode,
    required this.onAttestTrust,
    required this.onVerifyTrust,
    required this.lastVerifiedTrustLevel,
  });

  final bool showHeader;
  final GlobalMenuSelection selection;
  final String? pairingCode;
  final int peerCount;
  final List<PeerInfoModel> peers;
  final List<FileTransferItem> transfers;
  final List<ThreadSummary> threads;
  final String? activeThreadId;
  final ValueChanged<String> onSelectThread;
  final BackendSettings? settings;
  final ValueChanged<GlobalMenuSelection> onSelect;
  final ValueChanged<BackendSettings> onUpdateSettings;
  final ValueChanged<BackendNodeMode> onSelectNodeMode;
  final ValueChanged<TrustAttestationRequest> onAttestTrust;
  final ValueChanged<String> onVerifyTrust;
  final int? lastVerifiedTrustLevel;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (showHeader) ...[
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 18, 16, 0),
            child: Text(
              selection.title,
              style: Theme.of(
                context,
              ).textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.w600),
            ),
          ),
          if (selection.subtitle != null)
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: Text(
                selection.subtitle!,
                style: TextStyle(color: cs.onSurfaceVariant),
              ),
            ),
          const SizedBox(height: 8),
        ],
        Expanded(child: _buildSection(context)),
      ],
    );
  }

  Widget _buildSection(BuildContext context) {
    final subSection = selection.subSectionId;
    switch (selection.section) {
      case GlobalMenuSection.chat:
        if (subSection == 'chat-settings') {
          return const _ChatSettingsSection();
        }
        return _ChatSection(
          pairingCode: pairingCode,
          threads: threads,
          activeThreadId: activeThreadId,
          onSelectThread: onSelectThread,
        );
      case GlobalMenuSection.files:
        if (subSection == 'settings') {
          return _FilesSettingsSection(transfers: transfers);
        }
        if (subSection == 'history') {
          return _FilesHistorySection(transfers: transfers);
        }
        if (subSection == 'storage') {
          return const _StorageSection();
        }
        return _FilesSection(transfers: transfers);
      case GlobalMenuSection.networkOptions:
        if (subSection == 'transports') {
          return _TransportsSection(
            settings: settings,
            onUpdateSettings: onUpdateSettings,
          );
        }
        if (subSection == 'settings') {
          return _NetworkSettingsSection(
            settings: settings,
            onUpdateSettings: onUpdateSettings,
          );
        }
        if (subSection == 'routing') {
          return const _RoutingSection();
        }
        if (subSection == 'discovery') {
          return const _DiscoverySection();
        }
        return _NetworkSection(
          settings: settings,
          onUpdateSettings: onUpdateSettings,
        );
      case GlobalMenuSection.meshOptions:
        return _MeshSection(peers: peers, onSelect: onSelect);
      case GlobalMenuSection.trustCenter:
        return _TrustCenterSection(
          localPeerId: settings?.localPeerId,
          onAttestTrust: onAttestTrust,
          onVerifyTrust: onVerifyTrust,
          lastVerifiedTrustLevel: lastVerifiedTrustLevel,
        );
      case GlobalMenuSection.applicationSettings:
        if (subSection == 'identity') {
          return _IdentitySection(settings: settings);
        }
        if (subSection == 'preferences') {
          return _PreferencesSection(
            settings: settings,
            onSelectNodeMode: onSelectNodeMode,
          );
        }
        if (subSection == 'services') {
          return const _ServicesSection();
        }
        if (subSection == 'advanced') {
          return const _AdvancedSection();
        }
        if (subSection == 'about') {
          return const _AboutSection();
        }
        return _AppSettingsSection(
          settings: settings,
          onSelectNodeMode: onSelectNodeMode,
        );
    }
  }
}

// ---------------------------------------------------------------------------
// Chat section — pairing code + thread picker (fallback if shown standalone)
// ---------------------------------------------------------------------------
class _ChatSection extends StatelessWidget {
  const _ChatSection({
    required this.pairingCode,
    required this.threads,
    required this.activeThreadId,
    required this.onSelectThread,
  });

  final String? pairingCode;
  final List<ThreadSummary> threads;
  final String? activeThreadId;
  final ValueChanged<String> onSelectThread;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Pairing code',
                  style: Theme.of(
                    context,
                  ).textTheme.bodyLarge?.copyWith(fontWeight: FontWeight.w600),
                ),
                const SizedBox(height: 6),
                SelectableText(
                  pairingCode?.isNotEmpty == true
                      ? pairingCode!
                      : 'Unavailable',
                  style: TextStyle(
                    fontSize: 16,
                    fontFamily: 'monospace',
                    color: cs.onSurfaceVariant,
                  ),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 12),
        if (threads.isEmpty)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 32),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(
                  Icons.chat_bubble_outline,
                  size: 40,
                  color: cs.onSurfaceVariant,
                ),
                const SizedBox(height: 8),
                Text(
                  'No conversations yet',
                  style: TextStyle(color: cs.onSurfaceVariant),
                ),
              ],
            ),
          )
        else
          Card(
            child: Column(
              children: [
                for (int i = 0; i < threads.length; i++) ...[
                  if (i > 0) const Divider(height: 1),
                  ListTile(
                    title: Text(threads[i].title),
                    subtitle: Text(
                      threads[i].preview,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                    trailing: Text(
                      threads[i].lastSeen,
                      style: TextStyle(
                        fontSize: 11,
                        color: cs.onSurfaceVariant,
                      ),
                    ),
                    selected: threads[i].id == activeThreadId,
                    onTap: () => onSelectThread(threads[i].id),
                  ),
                ],
              ],
            ),
          ),
      ],
    );
  }
}

class _ChatSettingsSection extends StatelessWidget {
  const _ChatSettingsSection();

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final meshState = context.watch<MeshState>();
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: Column(
            children: [
              SwitchListTile(
                title: const Text('Auto-save media'),
                subtitle: Text(
                  'Stores media to local vault',
                  style: TextStyle(color: cs.onSurfaceVariant),
                ),
                value: meshState.autoSaveMedia,
                onChanged: meshState.setAutoSaveMedia,
              ),
              const Divider(height: 1),
              SwitchListTile(
                title: const Text('Read receipts'),
                subtitle: Text(
                  'Share read status with peers',
                  style: TextStyle(color: cs.onSurfaceVariant),
                ),
                value: meshState.readReceipts,
                onChanged: meshState.setReadReceipts,
              ),
            ],
          ),
        ),
        const SizedBox(height: 12),
        Card(
          child: ListTile(
            leading: const Icon(Icons.key_outlined),
            title: const Text('Re-key conversations'),
            subtitle: Text(
              'Rotate session keys for active chats',
              style: TextStyle(color: cs.onSurfaceVariant),
            ),
            onTap: () {},
          ),
        ),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// Files section — transfer cards with progress bars
// ---------------------------------------------------------------------------
class _FilesSection extends StatelessWidget {
  const _FilesSection({required this.transfers});

  final List<FileTransferItem> transfers;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final activeTransfers = transfers
        .where((t) => t.status == 'active' || t.status == 'pending')
        .toList();

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // File transfer controls
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Row(
                  children: [
                    Icon(Icons.file_present_outlined, color: cs.primary, size: 20),
                    const SizedBox(width: 8),
                    Text(
                      'File Transfer',
                      style: Theme.of(context).textTheme.titleMedium?.copyWith(
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 16),
                Row(
                  children: [
                    Expanded(
                      child: FilledButton.tonalIcon(
                        onPressed: null, // TODO: Implement file sending
                        icon: const Icon(Icons.upload_outlined),
                        label: const Text('Send File'),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: FilledButton.tonalIcon(
                        onPressed: null, // TODO: Implement file hosting
                        icon: const Icon(Icons.cloud_upload_outlined),
                        label: const Text('Host File'),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                Text(
                  'File transfer requires FFI integration',
                  style: TextStyle(
                    color: cs.onSurfaceVariant,
                    fontSize: 11,
                  ),
                  textAlign: TextAlign.center,
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 16),

        // Active transfers section
        if (activeTransfers.isNotEmpty) ...[
          Text(
            'Active Transfers',
            style: Theme.of(context).textTheme.titleMedium?.copyWith(
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 8),
          ...activeTransfers.map((t) => _TransferCard(transfer: t)),
          const SizedBox(height: 16),
        ],

        // Empty state or recent transfers
        if (transfers.isEmpty)
          Card(
            child: Padding(
              padding: const EdgeInsets.symmetric(vertical: 48, horizontal: 16),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(
                    Icons.folder_open_outlined,
                    size: 48,
                    color: cs.onSurfaceVariant,
                  ),
                  const SizedBox(height: 12),
                  Text(
                    'No transfers yet',
                    style: TextStyle(
                      color: cs.onSurfaceVariant,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    'Send or host files to get started',
                    style: TextStyle(
                      color: cs.onSurfaceVariant,
                      fontSize: 12,
                    ),
                  ),
                ],
              ),
            ),
          )
        else if (activeTransfers.isEmpty) ...[
          Text(
            'Recent Transfers',
            style: Theme.of(context).textTheme.titleMedium?.copyWith(
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 8),
          ...transfers.take(5).map((t) => _TransferCard(transfer: t)),
        ],
      ],
    );
  }
}

class _FilesHistorySection extends StatelessWidget {
  const _FilesHistorySection({required this.transfers});

  final List<FileTransferItem> transfers;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final history = transfers
        .where((t) => t.status != 'active' && t.status != 'pending')
        .toList();
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        if (history.isEmpty)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 48),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(Icons.history, size: 48, color: cs.onSurfaceVariant),
                const SizedBox(height: 12),
                Text(
                  'No completed transfers yet',
                  style: TextStyle(color: cs.onSurfaceVariant),
                ),
              ],
            ),
          )
        else
          ...history.map((t) => _TransferCard(transfer: t)),
      ],
    );
  }
}

class _FilesSettingsSection extends StatelessWidget {
  const _FilesSettingsSection({required this.transfers});

  final List<FileTransferItem> transfers;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final meshState = context.watch<MeshState>();
    final activeTransfers = transfers.where((t) => t.status == 'active').length;
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: Column(
            children: [
              SwitchListTile(
                title: const Text('Auto-accept trusted transfers'),
                subtitle: Text(
                  'Accept from trusted peers automatically',
                  style: TextStyle(color: cs.onSurfaceVariant),
                ),
                value: meshState.autoAcceptTransfers,
                onChanged: meshState.setAutoAcceptTransfers,
              ),
              const Divider(height: 1),
              SwitchListTile(
                title: const Text('Notify on completion'),
                subtitle: Text(
                  'Push alert when a transfer completes',
                  style: TextStyle(color: cs.onSurfaceVariant),
                ),
                value: meshState.notifyOnTransferComplete,
                onChanged: meshState.setNotifyOnTransferComplete,
              ),
            ],
          ),
        ),
        const SizedBox(height: 12),
        Card(
          child: ListTile(
            leading: const Icon(Icons.pause_circle_outline),
            title: const Text('Pause all active transfers'),
            subtitle: Text(
              '$activeTransfers active',
              style: TextStyle(color: cs.onSurfaceVariant),
            ),
            onTap: () {},
          ),
        ),
      ],
    );
  }
}

class _StorageSection extends StatelessWidget {
  const _StorageSection();

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Storage locations',
                  style: Theme.of(
                    context,
                  ).textTheme.bodyLarge?.copyWith(fontWeight: FontWeight.w600),
                ),
                const SizedBox(height: 8),
                Text(
                  'TODO: Wire to backend storage settings once available.',
                  style: TextStyle(color: cs.onSurfaceVariant),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 12),
        Card(
          child: ListTile(
            leading: const Icon(Icons.delete_outline),
            title: const Text('Clear cached files'),
            subtitle: Text(
              'TODO: hook to cache manager',
              style: TextStyle(color: cs.onSurfaceVariant),
            ),
            onTap: () {},
          ),
        ),
      ],
    );
  }
}

class _TransferCard extends StatelessWidget {
  const _TransferCard({required this.transfer});

  final FileTransferItem transfer;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final progress = transfer.sizeBytes > 0
        ? (transfer.transferredBytes / transfer.sizeBytes).clamp(0.0, 1.0)
        : 0.0;
    final isActive =
        transfer.status == 'active' || transfer.status == 'pending';

    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  transfer.direction == 'incoming'
                      ? Icons.download_outlined
                      : Icons.upload_outlined,
                  color: cs.primary,
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    transfer.name.isNotEmpty ? transfer.name : transfer.id,
                    style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                      fontWeight: FontWeight.w600,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                Text(
                  transfer.status,
                  style: TextStyle(
                    fontSize: 12,
                    color: isActive ? cs.primary : cs.onSurfaceVariant,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            LinearProgressIndicator(
              value: progress,
              backgroundColor: cs.surfaceContainerHighest,
            ),
            const SizedBox(height: 4),
            Text(
              '${_fmtBytes(transfer.transferredBytes)} / ${_fmtBytes(transfer.sizeBytes)}',
              style: Theme.of(
                context,
              ).textTheme.bodySmall?.copyWith(color: cs.onSurfaceVariant),
            ),
          ],
        ),
      ),
    );
  }

  static String _fmtBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
  }
}

// ---------------------------------------------------------------------------
// Network section — Overview page with navigation to subsections
// ---------------------------------------------------------------------------
class _NetworkSection extends StatelessWidget {
  const _NetworkSection({
    required this.settings,
    required this.onUpdateSettings,
  });

  final BackendSettings? settings;
  final ValueChanged<BackendSettings> onUpdateSettings;

  @override
  Widget build(BuildContext context) {
    if (settings == null) {
      return const Center(child: Text('Settings unavailable'));
    }

    return const Center(
      child: Padding(
        padding: EdgeInsets.all(24),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.hub_outlined, size: 64),
            SizedBox(height: 16),
            Text(
              'Network Options',
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.w600),
            ),
            SizedBox(height: 8),
            Text(
              'Use the tabs above to configure transports, routing, discovery, and network settings',
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Transports section (Network Backends) — Transport toggles and statistics
// ---------------------------------------------------------------------------
class _TransportsSection extends StatelessWidget {
  const _TransportsSection({
    required this.settings,
    required this.onUpdateSettings,
  });

  final BackendSettings? settings;
  final ValueChanged<BackendSettings> onUpdateSettings;

  /// Returns a new BackendSettings with only the specified fields overridden.
  BackendSettings _emit({
    bool? enableTor,
    bool? enableClearnet,
    bool? meshDiscovery,
    bool? allowRelays,
    bool? enableI2p,
    bool? enableBluetooth,
  }) {
    final s = settings!;
    return BackendSettings(
      nodeMode: s.nodeMode,
      enableTor: enableTor ?? s.enableTor,
      enableClearnet: enableClearnet ?? s.enableClearnet,
      meshDiscovery: meshDiscovery ?? s.meshDiscovery,
      allowRelays: allowRelays ?? s.allowRelays,
      enableI2p: enableI2p ?? s.enableI2p,
      enableBluetooth: enableBluetooth ?? s.enableBluetooth,
      pairingCode: s.pairingCode,
      localPeerId: s.localPeerId,
    );
  }

  @override
  Widget build(BuildContext context) {
    if (settings == null) {
      return const Center(child: Text('Settings unavailable'));
    }
    final cs = Theme.of(context).colorScheme;

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // Network Statistics Card
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Icon(Icons.analytics_outlined, color: cs.primary, size: 20),
                    const SizedBox(width: 8),
                    Text(
                      'Network Statistics',
                      style: Theme.of(context).textTheme.titleMedium?.copyWith(
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 16),
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceAround,
                  children: [
                    _StatItem(
                      icon: Icons.arrow_upward,
                      label: 'Sent',
                      value: '0 KB',
                      color: cs.primary,
                    ),
                    _StatItem(
                      icon: Icons.arrow_downward,
                      label: 'Received',
                      value: '0 KB',
                      color: cs.secondary,
                    ),
                    _StatItem(
                      icon: Icons.link,
                      label: 'Active',
                      value: '0',
                      color: cs.tertiary,
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                Text(
                  'Statistics require FFI integration',
                  style: TextStyle(
                    color: cs.onSurfaceVariant,
                    fontSize: 11,
                  ),
                  textAlign: TextAlign.center,
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 16),

        // Transport Toggles
        Text(
          'Transport Backends',
          style: Theme.of(context).textTheme.titleMedium?.copyWith(
            fontWeight: FontWeight.w600,
          ),
        ),
        const SizedBox(height: 8),
        Card(
          child: Column(
            children: [
              SwitchListTile(
                title: const Text('Tor transport'),
                subtitle: Text(
                  'Anonymous routing via Tor network',
                  style: TextStyle(color: cs.onSurfaceVariant, fontSize: 12),
                ),
                value: settings!.enableTor,
                onChanged: (v) => onUpdateSettings(_emit(enableTor: v)),
              ),
              const Divider(height: 1),
              SwitchListTile(
                title: const Text('Clearnet transport'),
                subtitle: Text(
                  'Direct internet connectivity',
                  style: TextStyle(color: cs.onSurfaceVariant, fontSize: 12),
                ),
                value: settings!.enableClearnet,
                onChanged: (v) => onUpdateSettings(_emit(enableClearnet: v)),
              ),
              const Divider(height: 1),
              SwitchListTile(
                title: const Text('I2P transport'),
                subtitle: Text(
                  'Anonymous routing via I2P network',
                  style: TextStyle(color: cs.onSurfaceVariant, fontSize: 12),
                ),
                value: settings!.enableI2p,
                onChanged: (v) => onUpdateSettings(_emit(enableI2p: v)),
              ),
              const Divider(height: 1),
              SwitchListTile(
                title: const Text('Bluetooth transport'),
                subtitle: Text(
                  'Local peer-to-peer via Bluetooth',
                  style: TextStyle(color: cs.onSurfaceVariant, fontSize: 12),
                ),
                value: settings!.enableBluetooth,
                onChanged: (v) => onUpdateSettings(_emit(enableBluetooth: v)),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),

        // Mesh Options
        Text(
          'Mesh Options',
          style: Theme.of(context).textTheme.titleMedium?.copyWith(
            fontWeight: FontWeight.w600,
          ),
        ),
        const SizedBox(height: 8),
        Card(
          child: Column(
            children: [
              SwitchListTile(
                title: const Text('Mesh discovery'),
                subtitle: Text(
                  'Auto-discover peers on local network',
                  style: TextStyle(color: cs.onSurfaceVariant, fontSize: 12),
                ),
                value: settings!.meshDiscovery,
                onChanged: (v) => onUpdateSettings(_emit(meshDiscovery: v)),
              ),
              const Divider(height: 1),
              SwitchListTile(
                title: const Text('Allow relays'),
                subtitle: Text(
                  'Route traffic through relay nodes',
                  style: TextStyle(color: cs.onSurfaceVariant, fontSize: 12),
                ),
                value: settings!.allowRelays,
                onChanged: (v) => onUpdateSettings(_emit(allowRelays: v)),
              ),
            ],
          ),
        ),
      ],
    );
  }
}

// Helper widget for network statistics items
class _StatItem extends StatelessWidget {
  const _StatItem({
    required this.icon,
    required this.label,
    required this.value,
    required this.color,
  });

  final IconData icon;
  final String label;
  final String value;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Icon(icon, color: color, size: 24),
        const SizedBox(height: 4),
        Text(
          value,
          style: TextStyle(
            fontWeight: FontWeight.w600,
            fontSize: 16,
            color: color,
          ),
        ),
        Text(
          label,
          style: TextStyle(
            fontSize: 11,
            color: Theme.of(context).colorScheme.onSurfaceVariant,
          ),
        ),
      ],
    );
  }
}

class _NetworkSettingsSection extends StatelessWidget {
  const _NetworkSettingsSection({
    required this.settings,
    required this.onUpdateSettings,
  });

  final BackendSettings? settings;
  final ValueChanged<BackendSettings> onUpdateSettings;

  @override
  Widget build(BuildContext context) {
    if (settings == null) {
      return const Center(child: Text('Settings unavailable'));
    }
    final cs = Theme.of(context).colorScheme;
    final meshState = context.watch<MeshState>();
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: Column(
            children: [
              SwitchListTile(
                title: const Text('Enable relays'),
                subtitle: Text(
                  'Allow relay usage for routing',
                  style: TextStyle(color: cs.onSurfaceVariant),
                ),
                value: settings!.allowRelays,
                onChanged: (v) => onUpdateSettings(
                  BackendSettings(
                    nodeMode: settings!.nodeMode,
                    enableTor: settings!.enableTor,
                    enableClearnet: settings!.enableClearnet,
                    meshDiscovery: settings!.meshDiscovery,
                    allowRelays: v,
                    enableI2p: settings!.enableI2p,
                    enableBluetooth: settings!.enableBluetooth,
                    pairingCode: settings!.pairingCode,
                    localPeerId: settings!.localPeerId,
                  ),
                ),
              ),
              const Divider(height: 1),
              SwitchListTile(
                title: const Text('Prefer low-latency routes'),
                subtitle: Text(
                  'Bias routing toward low latency',
                  style: TextStyle(color: cs.onSurfaceVariant),
                ),
                value: meshState.preferLowLatencyRoutes,
                onChanged: meshState.setPreferLowLatencyRoutes,
              ),
            ],
          ),
        ),
      ],
    );
  }
}

class _RoutingSection extends StatefulWidget {
  const _RoutingSection();

  @override
  State<_RoutingSection> createState() => _RoutingSectionState();
}

class _RoutingSectionState extends State<_RoutingSection> {
  String _routingMode = 'mesh'; // mesh, vpn, clearnet
  String? _selectedExitNode;
  final List<Map<String, String>> _exitNodes = [
    {'id': 'auto', 'name': 'Automatic (Best performance)'},
    {'id': 'node-1', 'name': 'Exit Node 1 (US West)'},
    {'id': 'node-2', 'name': 'Exit Node 2 (EU Central)'},
  ];

  void _applyVpnRoute() {
    final meshState = Provider.of<MeshState>(context, listen: false);
    final config = {
      'mode': 'vpn',
      'exitNode': _selectedExitNode ?? 'auto',
      'killSwitch': true,
    };
    final success = meshState.backendBridge.setVpnRoute(config);
    if (success) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('VPN route configured')),
      );
    } else {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Failed to configure VPN route')),
      );
    }
  }

  void _applyClearnetRoute() {
    final meshState = Provider.of<MeshState>(context, listen: false);
    final config = {
      'mode': 'clearnet',
      'bypassMesh': true,
    };
    final success = meshState.backendBridge.setClearnetRoute(config);
    if (success) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Clearnet route configured')),
      );
    } else {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Failed to configure clearnet route')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // Info Card
        Card(
          color: cs.primaryContainer,
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Row(
              children: [
                Icon(Icons.alt_route_outlined, color: cs.primary),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Routing Configuration',
                        style: Theme.of(context).textTheme.titleMedium?.copyWith(
                          color: cs.primary,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        'Control how traffic is routed through the mesh network',
                        style: TextStyle(color: cs.onPrimaryContainer, fontSize: 13),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 16),

        // Routing Mode Selection
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Routing Mode',
                  style: Theme.of(context).textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(height: 12),
                RadioListTile<String>(
                  value: 'mesh',
                  groupValue: _routingMode,
                  onChanged: (value) {
                    setState(() => _routingMode = value!);
                  },
                  title: const Text('Mesh routing'),
                  subtitle: Text(
                    'Route through mesh peers (default)',
                    style: TextStyle(color: cs.onSurfaceVariant, fontSize: 13),
                  ),
                ),
                RadioListTile<String>(
                  value: 'vpn',
                  groupValue: _routingMode,
                  onChanged: (value) {
                    setState(() => _routingMode = value!);
                  },
                  title: const Text('VPN mode'),
                  subtitle: Text(
                    'Route through exit nodes with encryption',
                    style: TextStyle(color: cs.onSurfaceVariant, fontSize: 13),
                  ),
                ),
                RadioListTile<String>(
                  value: 'clearnet',
                  groupValue: _routingMode,
                  onChanged: (value) {
                    setState(() => _routingMode = value!);
                  },
                  title: const Text('Direct clearnet'),
                  subtitle: Text(
                    'Bypass mesh for direct internet access',
                    style: TextStyle(color: cs.onSurfaceVariant, fontSize: 13),
                  ),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 16),

        // VPN Configuration (shown when VPN mode selected)
        if (_routingMode == 'vpn') ...[
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Exit Node Selection',
                    style: Theme.of(context).textTheme.titleMedium?.copyWith(
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 12),
                  DropdownButtonFormField<String>(
                    value: _selectedExitNode ?? 'auto',
                    decoration: const InputDecoration(
                      labelText: 'Exit node',
                      border: OutlineInputBorder(),
                    ),
                    items: _exitNodes.map((node) {
                      return DropdownMenuItem(
                        value: node['id'],
                        child: Text(node['name']!),
                      );
                    }).toList(),
                    onChanged: (value) {
                      setState(() => _selectedExitNode = value);
                    },
                  ),
                  const SizedBox(height: 16),
                  Row(
                    children: [
                      Icon(Icons.info_outline, size: 16, color: cs.onSurfaceVariant),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          'Exit nodes route your traffic securely through the mesh',
                          style: TextStyle(color: cs.onSurfaceVariant, fontSize: 12),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 16),
                  FilledButton.icon(
                    onPressed: _applyVpnRoute,
                    icon: const Icon(Icons.check),
                    label: const Text('Apply VPN Route'),
                  ),
                ],
              ),
            ),
          ),
        ],

        // Clearnet Configuration (shown when clearnet mode selected)
        if (_routingMode == 'clearnet') ...[
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Direct Internet Access',
                    style: Theme.of(context).textTheme.titleMedium?.copyWith(
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 12),
                  Row(
                    children: [
                      Icon(Icons.warning_amber_rounded, size: 16, color: cs.error),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          'This bypasses the mesh network entirely. Your traffic will not be encrypted by the mesh.',
                          style: TextStyle(color: cs.error, fontSize: 12),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 16),
                  FilledButton.tonalIcon(
                    onPressed: _applyClearnetRoute,
                    icon: const Icon(Icons.check),
                    label: const Text('Apply Clearnet Route'),
                  ),
                ],
              ),
            ),
          ),
        ],

        // Current Status
        const SizedBox(height: 16),
        Card(
          child: ListTile(
            leading: Icon(
              _routingMode == 'vpn' ? Icons.vpn_lock :
              _routingMode == 'clearnet' ? Icons.public :
              Icons.hub_outlined,
              color: cs.primary,
            ),
            title: const Text('Current routing mode'),
            subtitle: Text(
              _routingMode == 'vpn' ? 'VPN mode active' :
              _routingMode == 'clearnet' ? 'Direct clearnet' :
              'Mesh routing',
            ),
          ),
        ),
      ],
    );
  }
}

class _DiscoverySection extends StatelessWidget {
  const _DiscoverySection();

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    // TODO: Wire to backend bridge for mDNS control
    // backend.enableMdns(port: 51820) / backend.disableMdns()
    // backend.isMdnsRunning() / backend.getDiscoveredPeers()

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // mDNS Info Card
        Card(
          color: cs.primaryContainer,
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Icon(Icons.router_outlined, color: cs.primary),
                    const SizedBox(width: 12),
                    Text(
                      'mDNS Discovery',
                      style: Theme.of(context).textTheme.titleMedium?.copyWith(
                        color: cs.primary,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 12),
                Text(
                  'Local network peer discovery is ready.\n\n'
                  'The backend now includes:\n'
                  '• mDNS/Bonjour broadcasting\n'
                  '• Automatic peer discovery on LAN\n'
                  '• WireGuard mesh networking\n\n'
                  'UI wiring is in progress. Use the backend bridge methods:\n'
                  '- enableMdns(port: 51820)\n'
                  '- disableMdns()\n'
                  '- isMdnsRunning()\n'
                  '- getDiscoveredPeers()',
                  style: TextStyle(color: cs.onPrimaryContainer, height: 1.5),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 12),
        Card(
          child: ListTile(
            leading: const Icon(Icons.check_circle_outline),
            title: const Text('Backend Ready'),
            subtitle: Text(
              'mDNS service implemented and compiled',
              style: TextStyle(color: cs.onSurfaceVariant),
            ),
          ),
        ),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// Mesh / peers section — trust-center banner + peer cards with status dots
// ---------------------------------------------------------------------------
class _MeshSection extends StatelessWidget {
  const _MeshSection({required this.peers, required this.onSelect});

  final List<PeerInfoModel> peers;
  final ValueChanged<GlobalMenuSelection> onSelect;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    // Divide peers into trusted and discovered categories
    final trustedPeers = peers.where((p) => p.trustLevel >= 2).toList();
    final discoveredPeers = peers.where((p) => p.trustLevel < 2).toList();

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // Trust Center banner — navigates into the trustCenter sub-section
        Card(
          color: cs.primaryContainer,
          child: InkWell(
            borderRadius: BorderRadius.circular(12),
            onTap: () => onSelect(
              const GlobalMenuSelection(
                section: GlobalMenuSection.trustCenter,
                title: 'Trust Center',
                subtitle: 'Attestations and verification',
              ),
            ),
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Row(
                children: [
                  Icon(Icons.shield_outlined, color: cs.primary, size: 28),
                  const SizedBox(width: 12),
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Trust Center',
                        style: TextStyle(
                          color: cs.primary,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      Text(
                        'Attest and verify peers',
                        style: TextStyle(
                          color: cs.onPrimaryContainer,
                          fontSize: 13,
                        ),
                      ),
                    ],
                  ),
                  const Spacer(),
                  Icon(Icons.chevron_right, color: cs.primary),
                ],
              ),
            ),
          ),
        ),
        const SizedBox(height: 24),

        // Trusted Peers section
        Text(
          'Trusted Peers',
          style: Theme.of(context).textTheme.titleMedium?.copyWith(
            fontWeight: FontWeight.w600,
          ),
        ),
        const SizedBox(height: 8),
        if (trustedPeers.isEmpty)
          Card(
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(
                    Icons.verified_user_outlined,
                    size: 32,
                    color: cs.onSurfaceVariant,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'No trusted peers yet',
                    style: TextStyle(color: cs.onSurfaceVariant),
                  ),
                ],
              ),
            ),
          )
        else
          Card(
            child: Column(
              children: [
                for (int i = 0; i < trustedPeers.length; i++) ...[
                  if (i > 0) const Divider(height: 1),
                  _PeerTile(peer: trustedPeers[i]),
                ],
              ],
            ),
          ),
        const SizedBox(height: 24),

        // Discovered/Added Peers section
        Text(
          'Discovered & Added Peers',
          style: Theme.of(context).textTheme.titleMedium?.copyWith(
            fontWeight: FontWeight.w600,
          ),
        ),
        const SizedBox(height: 8),
        if (discoveredPeers.isEmpty)
          Card(
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(
                    Icons.people_outline,
                    size: 32,
                    color: cs.onSurfaceVariant,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'No discovered peers',
                    style: TextStyle(color: cs.onSurfaceVariant),
                  ),
                ],
              ),
            ),
          )
        else
          Card(
            child: Column(
              children: [
                for (int i = 0; i < discoveredPeers.length; i++) ...[
                  if (i > 0) const Divider(height: 1),
                  _PeerTile(peer: discoveredPeers[i]),
                ],
              ],
            ),
          ),
      ],
    );
  }
}

class _PeerTile extends StatelessWidget {
  const _PeerTile({required this.peer});

  final PeerInfoModel peer;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final connected = peer.status == 'connected';

    return ListTile(
      leading: Stack(
        alignment: Alignment.bottomRight,
        children: [
          CircleAvatar(
            radius: 20,
            backgroundColor: cs.surfaceContainerHighest,
            child: Icon(Icons.person_outlined, color: cs.onSurfaceVariant),
          ),
          // Online / offline dot
          Container(
            width: 10,
            height: 10,
            decoration: BoxDecoration(
              color: connected ? const Color(0xFF4CAF50) : cs.onSurfaceVariant,
              shape: BoxShape.circle,
              border: Border.all(color: cs.surface, width: 2),
            ),
          ),
        ],
      ),
      title: Text(peer.name.isNotEmpty ? peer.name : peer.id),
      subtitle: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SizedBox(height: 4),
          Row(
            children: [
              // Connection status
              Icon(
                connected ? Icons.link : Icons.link_off,
                size: 14,
                color: cs.onSurfaceVariant,
              ),
              const SizedBox(width: 4),
              Text(
                peer.status,
                style: TextStyle(
                  color: cs.onSurfaceVariant,
                  fontSize: 12,
                ),
              ),
              const SizedBox(width: 12),
              // Trust-level badge
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                  color: peer.trustLevel >= 2
                      ? cs.primaryContainer
                      : cs.surfaceContainerHighest,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Text(
                  _trustLabel(peer.trustLevel),
                  style: TextStyle(
                    fontSize: 11,
                    fontWeight: FontWeight.w600,
                    color: peer.trustLevel >= 2 ? cs.primary : cs.onSurfaceVariant,
                  ),
                ),
              ),
            ],
          ),
          // Peer ID (truncated)
          if (peer.id.isNotEmpty && peer.name.isNotEmpty) ...[
            const SizedBox(height: 4),
            Text(
              'ID: ${peer.id.length > 16 ? "${peer.id.substring(0, 16)}..." : peer.id}',
              style: TextStyle(
                color: cs.onSurfaceVariant,
                fontSize: 11,
                fontFamily: 'monospace',
              ),
            ),
          ],
        ],
      ),
      trailing: Icon(Icons.chevron_right, color: cs.onSurfaceVariant),
      onTap: () {
        // TODO: Navigate to detailed peer profile view
        // This will show full peer ID, available transports, connection metrics,
        // trust attestations, etc.
      },
    );
  }

  static String _trustLabel(int level) {
    switch (level) {
      case 3:
        return 'High';
      case 2:
        return 'Trusted';
      case 1:
        return 'Caution';
      default:
        return 'None';
    }
  }
}

// ---------------------------------------------------------------------------
// Application settings — node mode chips + local peer ID in cards
// ---------------------------------------------------------------------------
class _AppSettingsSection extends StatelessWidget {
  const _AppSettingsSection({
    required this.settings,
    required this.onSelectNodeMode,
  });

  final BackendSettings? settings;
  final ValueChanged<BackendNodeMode> onSelectNodeMode;

  @override
  Widget build(BuildContext context) {
    if (settings == null) {
      return const Center(child: Text('Settings unavailable'));
    }
    final cs = Theme.of(context).colorScheme;
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Node mode',
                  style: Theme.of(
                    context,
                  ).textTheme.bodyLarge?.copyWith(fontWeight: FontWeight.w600),
                ),
                const SizedBox(height: 12),
                Wrap(
                  spacing: 8,
                  children: BackendNodeMode.values
                      .map(
                        (mode) => ChoiceChip(
                          label: Text(mode.label),
                          selected: settings!.nodeMode == mode,
                          onSelected: (_) => onSelectNodeMode(mode),
                        ),
                      )
                      .toList(),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 12),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Local peer ID',
                  style: Theme.of(
                    context,
                  ).textTheme.bodyLarge?.copyWith(fontWeight: FontWeight.w600),
                ),
                const SizedBox(height: 6),
                SelectableText(
                  settings!.localPeerId,
                  style: TextStyle(
                    color: cs.onSurfaceVariant,
                    fontFamily: 'monospace',
                  ),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }
}

class _PreferencesSection extends StatelessWidget {
  const _PreferencesSection({
    required this.settings,
    required this.onSelectNodeMode,
  });

  final BackendSettings? settings;
  final ValueChanged<BackendNodeMode> onSelectNodeMode;

  @override
  Widget build(BuildContext context) {
    if (settings == null) {
      return const Center(child: Text('Settings unavailable'));
    }
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Appearance',
                  style: Theme.of(
                    context,
                  ).textTheme.bodyLarge?.copyWith(fontWeight: FontWeight.w600),
                ),
                const SizedBox(height: 8),
                const _ThemeModeSelector(),
              ],
            ),
          ),
        ),
        const SizedBox(height: 12),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Node mode',
                  style: Theme.of(
                    context,
                  ).textTheme.bodyLarge?.copyWith(fontWeight: FontWeight.w600),
                ),
                const SizedBox(height: 12),
                Wrap(
                  spacing: 8,
                  children: BackendNodeMode.values
                      .map(
                        (mode) => ChoiceChip(
                          label: Text(mode.label),
                          selected: settings!.nodeMode == mode,
                          onSelected: (_) => onSelectNodeMode(mode),
                        ),
                      )
                      .toList(),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }
}

class _ThemeModeSelector extends StatelessWidget {
  const _ThemeModeSelector();

  @override
  Widget build(BuildContext context) {
    final meshState = context.watch<MeshState>();
    final themeMode = meshState.themeMode;
    return Wrap(
      spacing: 8,
      children: ThemeMode.values.map((mode) {
        final label = switch (mode) {
          ThemeMode.system => 'System',
          ThemeMode.light => 'Light',
          ThemeMode.dark => 'Dark',
        };
        return ChoiceChip(
          label: Text(label),
          selected: themeMode == mode,
          onSelected: (_) => meshState.setThemeMode(mode),
        );
      }).toList(),
    );
  }
}

class _IdentitySection extends StatelessWidget {
  const _IdentitySection({required this.settings});

  final BackendSettings? settings;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Local peer ID',
                  style: Theme.of(
                    context,
                  ).textTheme.bodyLarge?.copyWith(fontWeight: FontWeight.w600),
                ),
                const SizedBox(height: 6),
                SelectableText(
                  settings?.localPeerId.isNotEmpty == true
                      ? settings!.localPeerId
                      : 'Unavailable',
                  style: TextStyle(
                    color: cs.onSurfaceVariant,
                    fontFamily: 'monospace',
                  ),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 12),
        Card(
          child: ListTile(
            leading: const Icon(Icons.qr_code_2_outlined),
            title: const Text('Show pairing code'),
            subtitle: Text(
              'TODO: display pairing QR',
              style: TextStyle(color: cs.onSurfaceVariant),
            ),
            onTap: () {},
          ),
        ),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// Services section — Configure hosted services
// ---------------------------------------------------------------------------
class _ServicesSection extends StatelessWidget {
  const _ServicesSection();

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // Info card
        Card(
          color: cs.primaryContainer,
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Row(
              children: [
                Icon(Icons.cloud_outlined, color: cs.primary, size: 24),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Hosted Services',
                        style: TextStyle(
                          color: cs.primary,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        'Configure services hosted on this node',
                        style: TextStyle(
                          color: cs.onPrimaryContainer,
                          fontSize: 13,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 16),

        // Service configuration (placeholder)
        Text(
          'Active Services',
          style: Theme.of(context).textTheme.titleMedium?.copyWith(
            fontWeight: FontWeight.w600,
          ),
        ),
        const SizedBox(height: 8),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              children: [
                Icon(
                  Icons.cloud_off_outlined,
                  size: 40,
                  color: cs.onSurfaceVariant,
                ),
                const SizedBox(height: 12),
                Text(
                  'No services configured',
                  style: TextStyle(
                    color: cs.onSurfaceVariant,
                    fontWeight: FontWeight.w500,
                  ),
                ),
                const SizedBox(height: 8),
                Text(
                  'Service configuration requires FFI integration',
                  style: TextStyle(
                    color: cs.onSurfaceVariant,
                    fontSize: 12,
                  ),
                  textAlign: TextAlign.center,
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 16),

        // Add service button (disabled until FFI ready)
        FilledButton.icon(
          onPressed: null, // TODO: Enable when FFI ready
          icon: const Icon(Icons.add),
          label: const Text('Add Service'),
        ),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// Advanced section — Statistics visibility and diagnostics
// ---------------------------------------------------------------------------
class _AdvancedSection extends StatelessWidget {
  const _AdvancedSection();

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final meshState = context.watch<MeshState>();

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // Statistics visibility toggle
        Card(
          child: Column(
            children: [
              SwitchListTile(
                title: const Text('Show advanced statistics'),
                subtitle: Text(
                  'Display node health, packet loss, latency, and bandwidth',
                  style: TextStyle(color: cs.onSurfaceVariant, fontSize: 12),
                ),
                value: meshState.showAdvancedStats,
                onChanged: (value) => meshState.setShowAdvancedStats(value),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),

        // Diagnostic information
        if (meshState.showAdvancedStats) ...[
          Text(
            'Diagnostics',
            style: Theme.of(context).textTheme.titleMedium?.copyWith(
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 8),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  _DiagnosticRow(
                    label: 'Node Health',
                    value: 'Healthy',
                    color: cs.primary,
                  ),
                  const SizedBox(height: 12),
                  _DiagnosticRow(
                    label: 'Packet Loss',
                    value: '0.0%',
                    color: cs.secondary,
                  ),
                  const SizedBox(height: 12),
                  _DiagnosticRow(
                    label: 'Average Latency',
                    value: '0 ms',
                    color: cs.tertiary,
                  ),
                  const SizedBox(height: 12),
                  _DiagnosticRow(
                    label: 'Bandwidth Usage',
                    value: '0 KB/s',
                    color: cs.primary,
                  ),
                  const SizedBox(height: 12),
                  const Divider(),
                  const SizedBox(height: 8),
                  Text(
                    'Real-time statistics require FFI integration',
                    style: TextStyle(
                      color: cs.onSurfaceVariant,
                      fontSize: 11,
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ],
    );
  }
}

// Helper widget for diagnostic rows
class _DiagnosticRow extends StatelessWidget {
  const _DiagnosticRow({
    required this.label,
    required this.value,
    required this.color,
  });

  final String label;
  final String value;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(
          label,
          style: TextStyle(
            color: Theme.of(context).colorScheme.onSurfaceVariant,
          ),
        ),
        Text(
          value,
          style: TextStyle(
            fontWeight: FontWeight.w600,
            color: color,
          ),
        ),
      ],
    );
  }
}

class _AboutSection extends StatelessWidget {
  const _AboutSection();

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: ListTile(
            leading: const Icon(Icons.info_outline),
            title: const Text('Mesh Infinity'),
            subtitle: Text(
              'TODO: display version from package info',
              style: TextStyle(color: cs.onSurfaceVariant),
            ),
          ),
        ),
        const SizedBox(height: 12),
        Card(
          child: ListTile(
            leading: const Icon(Icons.description_outlined),
            title: const Text('Licenses'),
            subtitle: Text(
              'TODO: open license page',
              style: TextStyle(color: cs.onSurfaceVariant),
            ),
            onTap: () {},
          ),
        ),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// Trust attestation request — public so signal_shell can reference the type
// ---------------------------------------------------------------------------
class TrustAttestationRequest {
  const TrustAttestationRequest({
    required this.peerId,
    required this.trustLevel,
    required this.verificationMethod,
  });

  final String peerId;
  final int trustLevel;
  final int verificationMethod;
}

// ---------------------------------------------------------------------------
// Trust center — attest / verify UI with card layout
// ---------------------------------------------------------------------------
class _TrustCenterSection extends StatefulWidget {
  const _TrustCenterSection({
    required this.localPeerId,
    required this.onAttestTrust,
    required this.onVerifyTrust,
    required this.lastVerifiedTrustLevel,
  });

  final String? localPeerId;
  final ValueChanged<TrustAttestationRequest> onAttestTrust;
  final ValueChanged<String> onVerifyTrust;
  final int? lastVerifiedTrustLevel;

  @override
  State<_TrustCenterSection> createState() => _TrustCenterSectionState();
}

class _TrustCenterSectionState extends State<_TrustCenterSection> {
  final TextEditingController _peerController = TextEditingController();
  int _trustLevel = 2;
  int _verificationMethod = 2;

  @override
  void dispose() {
    _peerController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // Local identity card
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Local peer',
                  style: Theme.of(
                    context,
                  ).textTheme.bodyLarge?.copyWith(fontWeight: FontWeight.w600),
                ),
                const SizedBox(height: 4),
                SelectableText(
                  widget.localPeerId?.isNotEmpty == true
                      ? widget.localPeerId!
                      : 'Unavailable',
                  style: TextStyle(
                    color: cs.onSurfaceVariant,
                    fontFamily: 'monospace',
                    fontSize: 13,
                  ),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 12),
        // Target + controls card
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Target peer ID',
                  style: Theme.of(
                    context,
                  ).textTheme.bodyLarge?.copyWith(fontWeight: FontWeight.w600),
                ),
                const SizedBox(height: 8),
                TextField(
                  controller: _peerController,
                  decoration: const InputDecoration(
                    hintText: 'Enter peer ID or pairing code',
                    border: OutlineInputBorder(),
                  ),
                ),
                const SizedBox(height: 16),
                Text(
                  'Trust level',
                  style: Theme.of(
                    context,
                  ).textTheme.bodyMedium?.copyWith(fontWeight: FontWeight.w600),
                ),
                const SizedBox(height: 8),
                Wrap(
                  spacing: 8,
                  children: [
                    _trustChip('Caution', 1),
                    _trustChip('Trusted', 2),
                    _trustChip('Highly trusted', 3),
                  ],
                ),
                const SizedBox(height: 16),
                Text(
                  'Verification method',
                  style: Theme.of(
                    context,
                  ).textTheme.bodyMedium?.copyWith(fontWeight: FontWeight.w600),
                ),
                const SizedBox(height: 8),
                Wrap(
                  spacing: 8,
                  children: [
                    _methodChip('In person', 1),
                    _methodChip('Shared secret', 2),
                    _methodChip('Trusted intro', 3),
                    _methodChip('PKI', 4),
                  ],
                ),
                const SizedBox(height: 16),
                Row(
                  children: [
                    Expanded(
                      child: FilledButton(
                        onPressed: _handleAttest,
                        child: const Text('Attest trust'),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: OutlinedButton(
                        onPressed: _handleVerify,
                        child: const Text('Verify trust'),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
        // Result banner
        if (widget.lastVerifiedTrustLevel != null) ...[
          const SizedBox(height: 12),
          Card(
            color: cs.primaryContainer,
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Text(
                'Last verified: ${_trustLabel(widget.lastVerifiedTrustLevel!)}',
                style: TextStyle(
                  color: cs.onPrimaryContainer,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
          ),
        ],
      ],
    );
  }

  Widget _trustChip(String label, int level) {
    return ChoiceChip(
      label: Text(label),
      selected: _trustLevel == level,
      onSelected: (_) => setState(() => _trustLevel = level),
    );
  }

  Widget _methodChip(String label, int method) {
    return ChoiceChip(
      label: Text(label),
      selected: _verificationMethod == method,
      onSelected: (_) => setState(() => _verificationMethod = method),
    );
  }

  void _handleAttest() {
    final target = _peerController.text.trim();
    if (target.isEmpty) return;
    widget.onAttestTrust(
      TrustAttestationRequest(
        peerId: target,
        trustLevel: _trustLevel,
        verificationMethod: _verificationMethod,
      ),
    );
  }

  void _handleVerify() {
    final target = _peerController.text.trim();
    if (target.isEmpty) return;
    widget.onVerifyTrust(target);
  }

  static String _trustLabel(int level) {
    switch (level) {
      case 3:
        return 'Highly trusted';
      case 2:
        return 'Trusted';
      case 1:
        return 'Caution';
      default:
        return 'Untrusted';
    }
  }
}
