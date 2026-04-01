// profile_preview_screen.dart
//
// This file implements ProfilePreviewScreen — a lightweight read-only view
// of a contact's visible profile (§22.8.4).
//
// WHAT IS THIS SCREEN FOR?
// ------------------------
// ProfilePreviewScreen shows what a contact's profile looks like "from the
// outside" — the same view a peer would see when evaluating whether to
// accept a pairing request or a message request.
//
// Unlike ContactDetailScreen (§22.8.2), this screen:
//   - Does NOT require the contact to be in the local contact list.
//   - Does NOT show trust controls or action buttons for calls/files.
//   - DOES show a "Pair" button if the contact is not yet paired.
//   - DOES show a "View contact" button if they are already paired.
//
// USE CASES:
//   - Tapping an avatar in a group chat to preview a member's profile.
//   - Reviewing a message request sender before accepting/declining.
//   - Searching for a peer by peer ID before initiating pairing.
//
// PROFILE RESOLUTION TIERS (§9.2):
// ---------------------------------
// A contact's displayed name and bio can come from multiple sources,
// in priority order:
//   1. Explicitly paired profile (the peer signed and sent their profile
//      to us directly during pairing).
//   2. Public profile fetched from the mesh (less trusted — unauthenticated).
//   3. Local nickname set by the user in Settings.
//   4. Raw peer ID prefix (fallback — always available).
//
// The profile-source badge below the name tells the user which tier is
// being displayed so they know how much to trust the name shown.
//
// SPEC REFERENCE: §22.8.4

import 'package:flutter/material.dart';
// Provider — context.watch / context.read for state access.
import 'package:provider/provider.dart';

// PeerModel — the contact data model.
// Fields used: id, name, isOnline, trustLevel, isPaired (derived).
import '../../../backend/models/peer_models.dart';
// MeshTheme — kBrand and kSecGreen colour constants for source badge and
// online indicator.
import '../../../app/app_theme.dart';
// PeersState — findPeer() to look up the peer; null means not in contact list.
import '../../peers/peers_state.dart';
// ContactDetailScreen — pushed when "View contact" is tapped (peer is paired).
import 'contact_detail_screen.dart';
// PairContactScreen — pushed when "Pair" is tapped (peer not yet paired).
import 'pair_contact_screen.dart';

// ---------------------------------------------------------------------------
// ProfilePreviewScreen (§22.8.4)
// ---------------------------------------------------------------------------

/// Read-only profile view for a contact identified by [peerId].
///
/// The screen attempts to look up the peer in [PeersState].  If found, the
/// peer is considered "in the contact list" and "View contact" is shown.
/// If not found, the screen shows only the peer ID with a "Pair" button.
class ProfilePreviewScreen extends StatelessWidget {
  const ProfilePreviewScreen({super.key, required this.peerId});

  /// The cryptographic peer ID to display.
  final String peerId;

  @override
  Widget build(BuildContext context) {
    // context.watch so this screen rebuilds if the peer is added to contacts
    // while the screen is open (e.g. accept a request from another device).
    final peer = context.watch<PeersState>().findPeer(peerId);

    // A peer is "paired" if they appear in the local contact list.
    // This drives whether the AppBar shows "Pair" or "View contact".
    final isPaired = peer != null;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Profile'),
        actions: [
          // Conditional AppBar action: pair if not in contacts, else view full detail.
          if (!isPaired)
            // Filled prominent button — pairing is the primary action here.
            Padding(
              padding: const EdgeInsets.only(right: 8),
              child: FilledButton.icon(
                onPressed: () => Navigator.push(
                  context,
                  MaterialPageRoute(
                    builder: (_) =>
                        PairContactScreen(prefillPeerId: peerId),
                  ),
                ),
                icon: const Icon(Icons.person_add_outlined, size: 16),
                label: const Text('Pair'),
              ),
            )
          else
            // Text button — secondary action since they're already a contact.
            TextButton(
              onPressed: () => Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (_) => ContactDetailScreen(peerId: peerId),
                ),
              ),
              child: const Text('View contact'),
            ),
          const SizedBox(width: 8),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Avatar — large circle with initial letter; centred.
            _AvatarSection(peer: peer, peerId: peerId),
            const SizedBox(height: 16),

            // Display name — resolved from profile tier (§9.2).
            Center(
              child: Text(
                // Prefer the paired name; fall back to peer ID prefix.
                peer?.name.isNotEmpty == true
                    ? peer!.name
                    : '${peerId.substring(0, 16)}…',
                style: Theme.of(context).textTheme.headlineSmall,
                textAlign: TextAlign.center,
              ),
            ),
            const SizedBox(height: 12),

            // Profile source badge — shows how trustworthy the displayed name is.
            Center(child: _ProfileSourceBadge(peer: peer)),
            const SizedBox(height: 24),

            // Peer ID card — always shown, full hex string, copyable.
            _PeerIdSection(peerId: peerId),
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _AvatarSection — large centred avatar with optional online indicator
// ---------------------------------------------------------------------------

/// Displays a large circular avatar.  Shows an online dot if the peer is
/// currently reachable on the mesh.
class _AvatarSection extends StatelessWidget {
  const _AvatarSection({required this.peer, required this.peerId});

  /// Null if the peer is not in the contact list.
  final PeerModel? peer;

  /// Peer ID used to derive the initial letter when [peer] is null.
  final String peerId;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    // Determine the initial letter for the avatar.
    // If paired and named, use the first letter of their name.
    // Otherwise use the first character of the peer ID.
    final initial = (peer?.name.isNotEmpty == true)
        ? peer!.name[0].toUpperCase()
        : peerId[0].toUpperCase();

    return Center(
      child: Stack(
        clipBehavior: Clip.none,
        children: [
          // Avatar circle — 80px diameter as specified in §22.8.4.
          CircleAvatar(
            radius: 40,
            backgroundColor: cs.secondaryContainer,
            child: Text(
              initial,
              style: TextStyle(
                fontSize: 36,
                fontWeight: FontWeight.bold,
                color: cs.onSecondaryContainer,
              ),
            ),
          ),
          // Online indicator dot — shown only when the peer is reachable.
          if (peer?.isOnline == true)
            Positioned(
              bottom: 2,
              right: 2,
              child: Container(
                width: 16,
                height: 16,
                decoration: BoxDecoration(
                  // kSecGreen is consistent with OnlineIndicator widget.
                  color: MeshTheme.secGreen,
                  shape: BoxShape.circle,
                  border: Border.all(color: cs.surface, width: 2),
                ),
              ),
            ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _ProfileSourceBadge — pill showing which profile tier is displayed
// ---------------------------------------------------------------------------

/// A small coloured pill indicating the source of the displayed name/bio.
///
/// Profile tiers (§9.2):
///   - Paired profile:  brand blue  — highest trust, peer-signed.
///   - Public profile:  amber        — mesh-fetched, unauthenticated.
///   - Local nickname:  surface variant — user-set nickname, trust irrelevant.
///   - Peer ID only:    outline grey — no profile data at all.
///
/// This badge tells the user "how much to trust what they're seeing".
class _ProfileSourceBadge extends StatelessWidget {
  const _ProfileSourceBadge({required this.peer});

  /// Null when the peer is not in the contact list.
  final PeerModel? peer;

  @override
  Widget build(BuildContext context) {
    // Determine which tier we're showing based on available data.
    final (color, icon, label) = _profileSourceProps(context);

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.10),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: color.withValues(alpha: 0.3)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 12, color: color),
          const SizedBox(width: 4),
          Text(
            label,
            style: Theme.of(context).textTheme.labelSmall?.copyWith(
              color: color,
            ),
          ),
        ],
      ),
    );
  }

  /// Returns (color, icon, label) for the current profile tier.
  (Color, IconData, String) _profileSourceProps(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    if (peer == null) {
      // Peer not in contacts — no profile data, showing peer ID only.
      return (cs.outline, Icons.fingerprint_outlined, 'Peer ID only');
    }

    if (peer!.name.isNotEmpty) {
      // Peer is in contacts and has a name — it came from the paired profile.
      // TODO(backend): distinguish paired vs public profile when backend
      // exposes profile tier in PeerModel.
      return (MeshTheme.brand, Icons.verified_outlined, 'Paired profile');
    }

    // In contacts but name is empty — no profile sent yet.
    return (cs.outline, Icons.fingerprint_outlined, 'Peer ID only');
  }
}

// ---------------------------------------------------------------------------
// _PeerIdSection — full peer ID display card
// ---------------------------------------------------------------------------

/// Displays the full cryptographic peer ID in a labelled monospace card.
///
/// Unlike ContactDetailScreen which puts this in a card with a title, here
/// we use a simpler layout suited to the preview context.  The peer ID is
/// always shown regardless of profile tier — it is the ground-truth identity.
class _PeerIdSection extends StatelessWidget {
  const _PeerIdSection({required this.peerId});

  final String peerId;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // Section label.
        Text(
          'Peer ID',
          style: textTheme.labelMedium?.copyWith(
            color: cs.onSurfaceVariant,
          ),
        ),
        const SizedBox(height: 6),
        // Monospace container for the full hex peer ID.
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: cs.surfaceContainerHighest,
            borderRadius: BorderRadius.circular(8),
          ),
          child: SelectableText(
            peerId,
            style: textTheme.bodySmall?.copyWith(
              fontFamily: 'monospace',
              // Slightly relaxed height for long hex strings.
              height: 1.5,
            ),
          ),
        ),
      ],
    );
  }
}
