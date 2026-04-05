// identity_masks_screen.dart
//
// IdentityMasksScreen — manage the self-rooted identity model and additional
// contextual masks (§22.10.2).
//
// WHAT IS A MASK?
// ---------------
// A mask is a contextual identity — a different name, avatar, and set of
// permissions you use in a specific context.  For example:
//   - "Alex" for work colleagues (trust them but keep home life private)
//   - "A" for anonymous public Garden participation
//   - Your real name for close friends
//
// Masks derive from your self identity (Layer 2 in the identity model), while
// the transport-facing mesh identity is separate. Switching masks doesn't
// create a new transport identity or break existing sessions — it changes what
// name/profile people see in new interactions.
//
// The self root is NEVER directly exposed on the mesh. Only masks are.
//
// BACKEND STATUS:
// ---------------
// Masks are loaded from the backend and persisted with the unlocked identity.
// The screen shows the root peer ID plus the current mask list, and it can
// create additional masks through the backend bridge.
//
// Reached from: Settings → Identity & Masks.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../../../backend/backend_bridge.dart';
import '../settings_state.dart';

// ---------------------------------------------------------------------------
// IdentityMasksScreen
// ---------------------------------------------------------------------------

/// Shows the self-root summary and the list of additional configured masks.
class IdentityMasksScreen extends StatefulWidget {
  const IdentityMasksScreen({super.key});

  @override
  State<IdentityMasksScreen> createState() => _IdentityMasksScreenState();
}

class _IdentityMasksScreenState extends State<IdentityMasksScreen> {
  List<Map<String, dynamic>> _masks = const [];
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _loadMasks();
  }

  Future<void> _loadMasks() async {
    final masks = context.read<BackendBridge>().fetchMasks();
    if (!mounted) return;
    setState(() {
      _masks = masks;
      _loading = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    final settings = context.watch<SettingsState>();
    final identity = settings.identity;
    final tt = Theme.of(context).textTheme;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Identity & Masks'),
        actions: [
          // Global "New mask" button in the AppBar for easy access.
          TextButton.icon(
            onPressed: () => _createMask(),
            icon: const Icon(Icons.add, size: 18),
            label: const Text('New mask'),
          ),
        ],
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : ListView(
              padding: const EdgeInsets.all(16),
              children: [
                // ---------------------------------------------------------------------------
                // Root identity card
                // ---------------------------------------------------------------------------
                // Shows the root cryptographic peer ID.  This ID is the anchor of all masks
                // and is the identifier other users paired with you through.
                _IdentityCard(
                  peerId: identity?.peerId ?? '',
                  displayName: identity?.name ?? 'Unnamed',
                ),

                const SizedBox(height: 20),

                // ---------------------------------------------------------------------------
                // Masks section header with count
                // ---------------------------------------------------------------------------
                Row(
                  children: [
                    Text('Masks', style: tt.titleSmall),
                    const Spacer(),
                    // Secondary "New mask" link — matches spec layout exactly.
                    TextButton.icon(
                      onPressed: () => _createMask(),
                      icon: const Icon(Icons.add, size: 16),
                      label: const Text('New mask'),
                    ),
                  ],
                ),

                const SizedBox(height: 8),

                // ---------------------------------------------------------------------------
                if (_masks.isEmpty)
                  _MasksEmptyState(onAddMask: _createMask)
                else
                  for (final mask in _masks) _MaskTile(mask: mask),

                const SizedBox(height: 24),
              ],
            ),
    );
  }

  Future<void> _createMask() async {
    final nameController = TextEditingController();
    bool isAnonymous = false;
    final created = await showDialog<bool>(
      context: context,
      builder: (dialogContext) {
        return StatefulBuilder(
          builder: (dialogContext, setDialogState) {
            return AlertDialog(
              title: const Text('New mask'),
              content: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  TextField(
                    controller: nameController,
                    autofocus: true,
                    decoration: const InputDecoration(
                      labelText: 'Mask name',
                      hintText: 'Work, Public, Anonymous...',
                    ),
                  ),
                  const SizedBox(height: 12),
                  SwitchListTile(
                    contentPadding: EdgeInsets.zero,
                    title: const Text('Anonymous mask'),
                    subtitle: const Text(
                      'Generate independent keys instead of deriving from your self identity.',
                    ),
                    value: isAnonymous,
                    onChanged: (value) =>
                        setDialogState(() => isAnonymous = value),
                  ),
                ],
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.of(dialogContext).pop(false),
                  child: const Text('Cancel'),
                ),
                FilledButton(
                  onPressed: () {
                    final ok = context.read<BackendBridge>().createMask(
                      name: nameController.text.trim(),
                      isAnonymous: isAnonymous,
                    );
                    Navigator.of(dialogContext).pop(ok);
                  },
                  child: const Text('Create'),
                ),
              ],
            );
          },
        );
      },
    );
    nameController.dispose();

    if (!mounted || created == null) return;
    final messenger = ScaffoldMessenger.of(context);
    await _loadMasks();
    if (!mounted) return;
    messenger.showSnackBar(
      SnackBar(
        content: Text(created ? 'Mask created' : 'Failed to create mask'),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _IdentityCard — root identity peer ID display
// ---------------------------------------------------------------------------

/// Shows the root peer ID as selectable monospace text with copy and QR buttons.
///
/// The peer ID shown here is an identity-facing fingerprint, not the transport
/// mesh identity. Users may still need it for out-of-band verification.
class _IdentityCard extends StatelessWidget {
  const _IdentityCard({required this.peerId, required this.displayName});

  final String peerId;
  final String displayName;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    // Truncated peer ID: first 24 chars + ellipsis to keep the card compact.
    // The full ID is shown on SelectableText so the user can still read all of it.
    final shortId = peerId.length > 24 ? '${peerId.substring(0, 24)}…' : peerId;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Card header row: icon + label.
            Row(
              children: [
                Icon(Icons.hub_outlined, size: 20, color: cs.primary),
                const SizedBox(width: 8),
                Text('Your identity', style: tt.titleSmall),
              ],
            ),
            const SizedBox(height: 8),

            // Clarification: the self root is never directly on-mesh.
            Text(
              'The root of all your masks. Never exposed on the mesh directly.',
              style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
            ),
            const SizedBox(height: 12),

            // Peer ID row: selectable text + copy button + QR button.
            Row(
              children: [
                // SelectableText lets power users manually highlight and copy
                // partial segments for comparison (e.g. over a voice call).
                Expanded(
                  child: SelectableText(
                    shortId,
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 12,
                    ),
                  ),
                ),
                // One-tap copy.
                IconButton(
                  icon: const Icon(Icons.copy_outlined, size: 18),
                  tooltip: 'Copy peer ID',
                  onPressed: peerId.isNotEmpty
                      ? () {
                          Clipboard.setData(ClipboardData(text: peerId));
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(content: Text('Peer ID copied')),
                          );
                        }
                      : null,
                ),
                // QR code button — shows the peer ID as a scannable code.
                IconButton(
                  icon: const Icon(Icons.qr_code_outlined, size: 18),
                  tooltip: 'Show QR code',
                  onPressed: peerId.isNotEmpty ? () => _showQr(context) : null,
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  // Show the peer ID as a QR code in a bottom sheet.
  void _showQr(BuildContext context) {
    showModalBottomSheet<void>(
      context: context,
      showDragHandle: true,
      builder: (_) => Padding(
        padding: const EdgeInsets.fromLTRB(24, 8, 24, 40),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              displayName,
              style: Theme.of(
                context,
              ).textTheme.titleLarge?.copyWith(fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 16),
            Container(
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(12),
              ),
              padding: const EdgeInsets.all(12),
              child: QrImageView(
                data: peerId,
                version: QrVersions.auto,
                size: 200,
                backgroundColor: Colors.white,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _MasksEmptyState — shown when no masks are configured
// ---------------------------------------------------------------------------

/// Empty state for the masks list.  Shown until backend masks are implemented.
class _MasksEmptyState extends StatelessWidget {
  const _MasksEmptyState({required this.onAddMask});

  final VoidCallback onAddMask;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          children: [
            Icon(Icons.masks_outlined, size: 40, color: cs.outline),
            const SizedBox(height: 12),
            Text('No masks', style: tt.titleSmall),
            const SizedBox(height: 6),
            Text(
              'Masks let you present different identities in different contexts. '
              'Your root identity is never exposed directly.',
              style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 16),
            // Action button inside the card — mirrors the AppBar button.
            FilledButton.tonal(
              onPressed: onAddMask,
              child: const Text('Create first mask'),
            ),
          ],
        ),
      ),
    );
  }
}

class _MaskTile extends StatelessWidget {
  const _MaskTile({required this.mask});

  final Map<String, dynamic> mask;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;
    final name = mask['name'] as String? ?? 'Unnamed mask';
    final peerId = mask['peerId'] as String? ?? '';
    final isPublic = mask['isPublic'] == true;
    final isAnonymous = mask['isAnonymous'] == true;
    final badge = isPublic
        ? 'Public'
        : (isAnonymous ? 'Anonymous' : 'Contextual');

    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: ListTile(
        leading: CircleAvatar(
          backgroundColor: cs.primary.withValues(alpha: 0.12),
          child: Icon(
            isAnonymous ? Icons.visibility_off_outlined : Icons.person_outline,
            color: cs.primary,
          ),
        ),
        title: Text(name, style: tt.titleSmall),
        subtitle: Text(
          '$badge · ${peerId.isNotEmpty ? _short(peerId) : 'No peer ID'}',
          style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
        ),
      ),
    );
  }

  String _short(String value) =>
      value.length > 16 ? '${value.substring(0, 16)}…' : value;
}
