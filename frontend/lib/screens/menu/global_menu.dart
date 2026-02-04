import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../backend/backend_models.dart';
import '../../backend/file_transfer_models.dart';
import '../../backend/peer_models.dart';
import '../../models/thread_models.dart';
import '../../state/app_state.dart';
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
              style: Theme.of(context).textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.w600),
            ),
          ),
          if (selection.subtitle != null)
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: Text(selection.subtitle!, style: TextStyle(color: cs.onSurfaceVariant)),
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
        if (subSection == 'settings') {
          return _NetworkSettingsSection(settings: settings, onUpdateSettings: onUpdateSettings);
        }
        if (subSection == 'routing') {
          return const _RoutingSection();
        }
        if (subSection == 'discovery') {
          return const _DiscoverySection();
        }
        return _NetworkSection(settings: settings, onUpdateSettings: onUpdateSettings);
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
          return _PreferencesSection(settings: settings, onSelectNodeMode: onSelectNodeMode);
        }
        if (subSection == 'about') {
          return const _AboutSection();
        }
        return _AppSettingsSection(settings: settings, onSelectNodeMode: onSelectNodeMode);
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
                Text('Pairing code',
                    style: Theme.of(context).textTheme.bodyLarge?.copyWith(fontWeight: FontWeight.w600)),
                const SizedBox(height: 6),
                SelectableText(
                  pairingCode?.isNotEmpty == true ? pairingCode! : 'Unavailable',
                  style: TextStyle(fontSize: 16, fontFamily: 'monospace', color: cs.onSurfaceVariant),
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
                Icon(Icons.chat_bubble_outline, size: 40, color: cs.onSurfaceVariant),
                const SizedBox(height: 8),
                Text('No conversations yet', style: TextStyle(color: cs.onSurfaceVariant)),
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
                    subtitle: Text(threads[i].preview, maxLines: 1, overflow: TextOverflow.ellipsis),
                    trailing: Text(threads[i].lastSeen,
                        style: TextStyle(fontSize: 11, color: cs.onSurfaceVariant)),
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
    final appState = context.watch<AppState>();
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: Column(
            children: [
              SwitchListTile(
                title: const Text('Auto-save media'),
                subtitle: Text('Stores media to local vault', style: TextStyle(color: cs.onSurfaceVariant)),
                value: appState.autoSaveMedia,
                onChanged: appState.setAutoSaveMedia,
              ),
              const Divider(height: 1),
              SwitchListTile(
                title: const Text('Read receipts'),
                subtitle: Text('Share read status with peers', style: TextStyle(color: cs.onSurfaceVariant)),
                value: appState.readReceipts,
                onChanged: appState.setReadReceipts,
              ),
            ],
          ),
        ),
        const SizedBox(height: 12),
        Card(
          child: ListTile(
            leading: const Icon(Icons.key_outlined),
            title: const Text('Re-key conversations'),
            subtitle: Text('Rotate session keys for active chats', style: TextStyle(color: cs.onSurfaceVariant)),
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
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        if (transfers.isEmpty)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 48),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(Icons.folder_open_outlined, size: 48, color: cs.onSurfaceVariant),
                const SizedBox(height: 12),
                Text('No transfers yet', style: TextStyle(color: cs.onSurfaceVariant)),
              ],
            ),
          )
        else
          ...transfers.map((t) => _TransferCard(transfer: t)),
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
    final history = transfers.where((t) => t.status != 'active' && t.status != 'pending').toList();
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
                Text('No completed transfers yet', style: TextStyle(color: cs.onSurfaceVariant)),
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
    final appState = context.watch<AppState>();
    final activeTransfers = transfers.where((t) => t.status == 'active').length;
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: Column(
            children: [
              SwitchListTile(
                title: const Text('Auto-accept trusted transfers'),
                subtitle: Text('Accept from trusted peers automatically', style: TextStyle(color: cs.onSurfaceVariant)),
                value: appState.autoAcceptTransfers,
                onChanged: appState.setAutoAcceptTransfers,
              ),
              const Divider(height: 1),
              SwitchListTile(
                title: const Text('Notify on completion'),
                subtitle: Text('Push alert when a transfer completes', style: TextStyle(color: cs.onSurfaceVariant)),
                value: appState.notifyOnTransferComplete,
                onChanged: appState.setNotifyOnTransferComplete,
              ),
            ],
          ),
        ),
        const SizedBox(height: 12),
        Card(
          child: ListTile(
            leading: const Icon(Icons.pause_circle_outline),
            title: const Text('Pause all active transfers'),
            subtitle: Text('$activeTransfers active', style: TextStyle(color: cs.onSurfaceVariant)),
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
                Text('Storage locations',
                    style: Theme.of(context).textTheme.bodyLarge?.copyWith(fontWeight: FontWeight.w600)),
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
            subtitle: Text('TODO: hook to cache manager', style: TextStyle(color: cs.onSurfaceVariant)),
            onTap: () {},
          ),
        ),
      ],
    );
  }
}

class _TransferCard extends StatelessWidget {
  const _TransferCard({super.key, required this.transfer});

  final FileTransferItem transfer;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final progress = transfer.sizeBytes > 0
        ? (transfer.transferredBytes / transfer.sizeBytes).clamp(0.0, 1.0)
        : 0.0;
    final isActive = transfer.status == 'active' || transfer.status == 'pending';

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
                  transfer.direction == 'incoming' ? Icons.download_outlined : Icons.upload_outlined,
                  color: cs.primary,
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    transfer.name.isNotEmpty ? transfer.name : transfer.id,
                    style: Theme.of(context).textTheme.bodyLarge?.copyWith(fontWeight: FontWeight.w600),
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
              style: Theme.of(context).textTheme.bodySmall?.copyWith(color: cs.onSurfaceVariant),
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
// Network section — single _emit() helper eliminates 6× settings copy-paste
// ---------------------------------------------------------------------------
class _NetworkSection extends StatelessWidget {
  const _NetworkSection({required this.settings, required this.onUpdateSettings});

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
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: Column(
            children: [
              SwitchListTile(
                title: const Text('Tor transport'),
                value: settings!.enableTor,
                onChanged: (v) => onUpdateSettings(_emit(enableTor: v)),
              ),
              const Divider(height: 1),
              SwitchListTile(
                title: const Text('Clearnet transport'),
                value: settings!.enableClearnet,
                onChanged: (v) => onUpdateSettings(_emit(enableClearnet: v)),
              ),
              const Divider(height: 1),
              SwitchListTile(
                title: const Text('Mesh discovery'),
                value: settings!.meshDiscovery,
                onChanged: (v) => onUpdateSettings(_emit(meshDiscovery: v)),
              ),
              const Divider(height: 1),
              SwitchListTile(
                title: const Text('Allow relays'),
                value: settings!.allowRelays,
                onChanged: (v) => onUpdateSettings(_emit(allowRelays: v)),
              ),
              const Divider(height: 1),
              SwitchListTile(
                title: const Text('I2P transport'),
                value: settings!.enableI2p,
                onChanged: (v) => onUpdateSettings(_emit(enableI2p: v)),
              ),
              const Divider(height: 1),
              SwitchListTile(
                title: const Text('Bluetooth transport'),
                value: settings!.enableBluetooth,
                onChanged: (v) => onUpdateSettings(_emit(enableBluetooth: v)),
              ),
            ],
          ),
        ),
      ],
    );
  }
}

class _NetworkSettingsSection extends StatelessWidget {
  const _NetworkSettingsSection({required this.settings, required this.onUpdateSettings});

  final BackendSettings? settings;
  final ValueChanged<BackendSettings> onUpdateSettings;

  @override
  Widget build(BuildContext context) {
    if (settings == null) {
      return const Center(child: Text('Settings unavailable'));
    }
    final cs = Theme.of(context).colorScheme;
    final appState = context.watch<AppState>();
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: Column(
            children: [
              SwitchListTile(
                title: const Text('Enable relays'),
                subtitle: Text('Allow relay usage for routing', style: TextStyle(color: cs.onSurfaceVariant)),
                value: settings!.allowRelays,
                onChanged: (v) => onUpdateSettings(BackendSettings(
                  nodeMode: settings!.nodeMode,
                  enableTor: settings!.enableTor,
                  enableClearnet: settings!.enableClearnet,
                  meshDiscovery: settings!.meshDiscovery,
                  allowRelays: v,
                  enableI2p: settings!.enableI2p,
                  enableBluetooth: settings!.enableBluetooth,
                  pairingCode: settings!.pairingCode,
                  localPeerId: settings!.localPeerId,
                )),
              ),
              const Divider(height: 1),
              SwitchListTile(
                title: const Text('Prefer low-latency routes'),
                subtitle: Text('Bias routing toward low latency', style: TextStyle(color: cs.onSurfaceVariant)),
                value: appState.preferLowLatencyRoutes,
                onChanged: appState.setPreferLowLatencyRoutes,
              ),
            ],
          ),
        ),
      ],
    );
  }
}

class _RoutingSection extends StatelessWidget {
  const _RoutingSection();

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
                Text('Exit nodes',
                    style: Theme.of(context).textTheme.bodyLarge?.copyWith(fontWeight: FontWeight.w600)),
                const SizedBox(height: 6),
                Text('TODO: Load exit node list from backend.', style: TextStyle(color: cs.onSurfaceVariant)),
              ],
            ),
          ),
        ),
        const SizedBox(height: 12),
        Card(
          child: ListTile(
            leading: const Icon(Icons.vpn_lock_outlined),
            title: const Text('VPN routing mode'),
            subtitle: Text('TODO: Wire to policy engine', style: TextStyle(color: cs.onSurfaceVariant)),
            onTap: () {},
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
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Discovery health',
                    style: Theme.of(context).textTheme.bodyLarge?.copyWith(fontWeight: FontWeight.w600)),
                const SizedBox(height: 6),
                Text('TODO: Display discovery status from backend.', style: TextStyle(color: cs.onSurfaceVariant)),
              ],
            ),
          ),
        ),
        const SizedBox(height: 12),
        Card(
          child: ListTile(
            leading: const Icon(Icons.refresh_outlined),
            title: const Text('Refresh discovery'),
            subtitle: Text('TODO: trigger discovery cycle', style: TextStyle(color: cs.onSurfaceVariant)),
            onTap: () {},
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
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // Trust Center banner — navigates into the trustCenter sub-section
        Card(
          color: cs.primaryContainer,
          child: InkWell(
            borderRadius: BorderRadius.circular(12),
            onTap: () => onSelect(const GlobalMenuSelection(
              section: GlobalMenuSection.trustCenter,
              title: 'Trust Center',
              subtitle: 'Attestations and verification',
            )),
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Row(
                children: [
                  Icon(Icons.shield_outlined, color: cs.primary, size: 28),
                  const SizedBox(width: 12),
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('Trust Center', style: TextStyle(color: cs.primary, fontWeight: FontWeight.w600)),
                      Text('Attest and verify peers',
                          style: TextStyle(color: cs.onPrimaryContainer, fontSize: 13)),
                    ],
                  ),
                  const Spacer(),
                  Icon(Icons.chevron_right, color: cs.primary),
                ],
              ),
            ),
          ),
        ),
        const SizedBox(height: 16),
        // Peer list
        if (peers.isEmpty)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 32),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(Icons.people_outlined, size: 40, color: cs.onSurfaceVariant),
                const SizedBox(height: 8),
                Text('No peers connected yet', style: TextStyle(color: cs.onSurfaceVariant)),
              ],
            ),
          )
        else
          Card(
            child: Column(
              children: [
                for (int i = 0; i < peers.length; i++) ...[
                  if (i > 0) const Divider(height: 1),
                  _PeerTile(peer: peers[i]),
                ],
              ],
            ),
          ),
      ],
    );
  }
}

class _PeerTile extends StatelessWidget {
  const _PeerTile({super.key, required this.peer});

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
      subtitle: Row(
        children: [
          Text(peer.status, style: TextStyle(color: cs.onSurfaceVariant)),
          const SizedBox(width: 8),
          // Trust-level badge
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
            decoration: BoxDecoration(
              color: peer.trustLevel >= 2 ? cs.primaryContainer : cs.surfaceContainerHighest,
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
  const _AppSettingsSection({required this.settings, required this.onSelectNodeMode});

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
                Text('Node mode',
                    style: Theme.of(context).textTheme.bodyLarge?.copyWith(fontWeight: FontWeight.w600)),
                const SizedBox(height: 12),
                Wrap(
                  spacing: 8,
                  children: BackendNodeMode.values
                      .map((mode) => ChoiceChip(
                            label: Text(mode.label),
                            selected: settings!.nodeMode == mode,
                            onSelected: (_) => onSelectNodeMode(mode),
                          ))
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
                Text('Local peer ID',
                    style: Theme.of(context).textTheme.bodyLarge?.copyWith(fontWeight: FontWeight.w600)),
                const SizedBox(height: 6),
                SelectableText(
                  settings!.localPeerId,
                  style: TextStyle(color: cs.onSurfaceVariant, fontFamily: 'monospace'),
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
  const _PreferencesSection({required this.settings, required this.onSelectNodeMode});

  final BackendSettings? settings;
  final ValueChanged<BackendNodeMode> onSelectNodeMode;

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
                Text('Appearance',
                    style: Theme.of(context).textTheme.bodyLarge?.copyWith(fontWeight: FontWeight.w600)),
                const SizedBox(height: 8),
                const _ThemeModeSelector(),
              ],
            ),
          ),
        ),
        const SizedBox(height: 12),
        _AppSettingsSection(settings: settings, onSelectNodeMode: onSelectNodeMode),
      ],
    );
  }
}

class _ThemeModeSelector extends StatelessWidget {
  const _ThemeModeSelector();

  @override
  Widget build(BuildContext context) {
    final appState = context.watch<AppState>();
    final themeMode = appState.themeMode;
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
          onSelected: (_) => appState.setThemeMode(mode),
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
                Text('Local peer ID',
                    style: Theme.of(context).textTheme.bodyLarge?.copyWith(fontWeight: FontWeight.w600)),
                const SizedBox(height: 6),
                SelectableText(
                  settings?.localPeerId.isNotEmpty == true ? settings!.localPeerId : 'Unavailable',
                  style: TextStyle(color: cs.onSurfaceVariant, fontFamily: 'monospace'),
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
            subtitle: Text('TODO: display pairing QR', style: TextStyle(color: cs.onSurfaceVariant)),
            onTap: () {},
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
            subtitle: Text('TODO: display version from package info', style: TextStyle(color: cs.onSurfaceVariant)),
          ),
        ),
        const SizedBox(height: 12),
        Card(
          child: ListTile(
            leading: const Icon(Icons.description_outlined),
            title: const Text('Licenses'),
            subtitle: Text('TODO: open license page', style: TextStyle(color: cs.onSurfaceVariant)),
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
                Text('Local peer',
                    style: Theme.of(context).textTheme.bodyLarge?.copyWith(fontWeight: FontWeight.w600)),
                const SizedBox(height: 4),
                SelectableText(
                  widget.localPeerId?.isNotEmpty == true ? widget.localPeerId! : 'Unavailable',
                  style: TextStyle(color: cs.onSurfaceVariant, fontFamily: 'monospace', fontSize: 13),
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
                Text('Target peer ID',
                    style: Theme.of(context).textTheme.bodyLarge?.copyWith(fontWeight: FontWeight.w600)),
                const SizedBox(height: 8),
                TextField(
                  controller: _peerController,
                  decoration: const InputDecoration(
                    hintText: 'Enter peer ID or pairing code',
                    border: OutlineInputBorder(),
                  ),
                ),
                const SizedBox(height: 16),
                Text('Trust level',
                    style: Theme.of(context).textTheme.bodyMedium?.copyWith(fontWeight: FontWeight.w600)),
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
                Text('Verification method',
                    style: Theme.of(context).textTheme.bodyMedium?.copyWith(fontWeight: FontWeight.w600)),
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
                style: TextStyle(color: cs.onPrimaryContainer, fontWeight: FontWeight.w600),
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
