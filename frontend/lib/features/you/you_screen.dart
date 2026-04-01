import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../../app/app_theme.dart';
import '../../backend/models/settings_models.dart';
import '../settings/settings_state.dart';
import '../settings/screens/profile_edit_screen.dart';
import '../tidbits/tidbits.dart'; // Copy Confetti §22.12.5 #7, TapTrigger

// ---------------------------------------------------------------------------
// YouScreen
//
// Single-scroll identity screen per the UI/UX proposal (iterations 5–9).
// Shows: Self card + Masks list.
//
// Backend: Self is sourced from LocalIdentitySummary via SettingsState.
// Masks: not yet implemented in backend — section is shown empty.
// ---------------------------------------------------------------------------

class YouScreen extends StatelessWidget {
  const YouScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final settings = context.watch<SettingsState>();
    final identity = settings.identity;

    return Scaffold(
      body: identity == null
          ? const _LoadingIdentity()
          : RefreshIndicator(
              onRefresh: settings.loadAll,
              child: ListView(
                padding: const EdgeInsets.all(16),
                children: [
                  _SelfCard(identity: identity),
                  const SizedBox(height: 24),
                  _MasksSection(),
                ],
              ),
            ),
    );
  }
}

// ---------------------------------------------------------------------------
// _SelfCard — the user's Layer 1 / Layer 2 identity card
// ---------------------------------------------------------------------------

class _SelfCard extends StatelessWidget {
  const _SelfCard({required this.identity});
  final LocalIdentitySummary identity;

  @override
  Widget build(BuildContext context) {
    final displayName = identity.name ?? 'Unnamed';
    final shortId = identity.peerId.length > 16
        ? '${identity.peerId.substring(0, 16)}…'
        : identity.peerId;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          children: [
            // Avatar
            CircleAvatar(
              radius: 40,
              backgroundColor: MeshTheme.brand.withValues(alpha: 0.15),
              child: Text(
                displayName[0].toUpperCase(),
                style: const TextStyle(
                  fontSize: 36,
                  fontWeight: FontWeight.w700,
                  color: MeshTheme.brand,
                ),
              ),
            ),
            const SizedBox(height: 16),

            // Display name
            Text(
              displayName,
              style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                    fontWeight: FontWeight.w700,
                  ),
            ),
            const SizedBox(height: 4),

            // Peer ID (monospace, tappable to copy)
            GestureDetector(
              onTap: () {
                Clipboard.setData(ClipboardData(text: identity.peerId));
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Peer ID copied')),
                );
                // §22.12.5 #7 Copy Confetti — tiny celebration on peer ID copy.
                TidbitRegistry.instance.show('copy_confetti', context);
              },
              child: Text(
                shortId,
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                      fontFamily: 'monospace',
                      color: Theme.of(context).colorScheme.outline,
                    ),
              ),
            ),
            const SizedBox(height: 20),

            // QR code
            QrImageView(
              data: identity.peerId,
              version: QrVersions.auto,
              size: 160,
              backgroundColor: Colors.white,
            ),
            const SizedBox(height: 20),

            // Edit profile button
            OutlinedButton.icon(
              onPressed: () => Navigator.push(
                context,
                MaterialPageRoute(
                    builder: (_) => const ProfileEditScreen()),
              ),
              icon: const Icon(Icons.edit_outlined, size: 18),
              label: const Text('Edit profile'),
            ),
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _MasksSection — Layer 3 contextual identities
// Backend: Masks not yet implemented.
// ---------------------------------------------------------------------------

class _MasksSection extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Text(
              'Masks',
              style: Theme.of(context).textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.w600,
                  ),
            ),
            const Spacer(),
            TextButton.icon(
              onPressed: null, // Masks not yet implemented
              icon: const Icon(Icons.add, size: 18),
              label: const Text('New mask'),
            ),
          ],
        ),
        const SizedBox(height: 8),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Center(
              child: Column(
                children: [
                  Icon(
                    Icons.masks_outlined,
                    size: 40,
                    color: Theme.of(context).colorScheme.outline,
                  ),
                  const SizedBox(height: 12),
                  Text(
                    'No masks',
                    style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                          color: Theme.of(context).colorScheme.outline,
                        ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    'Masks are contextual identities coming in a future update.',
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                          color: Theme.of(context).colorScheme.outline,
                        ),
                    textAlign: TextAlign.center,
                  ),
                ],
              ),
            ),
          ),
        ),
      ],
    );
  }
}

class _LoadingIdentity extends StatelessWidget {
  const _LoadingIdentity();

  @override
  Widget build(BuildContext context) {
    return const Center(child: CircularProgressIndicator());
  }
}
