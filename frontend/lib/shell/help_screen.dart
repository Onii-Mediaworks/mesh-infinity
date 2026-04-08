// help_screen.dart
//
// HelpScreen — a simple curated entry point that directs new users to the
// most important parts of the app.
//
// DESIGN INTENT:
// --------------
// Mesh Infinity has no traditional "Help Centre" behind a URL because the app
// is intentionally designed to operate without internet access.  All help
// content is either embedded in the screens themselves (sub-titles,
// descriptive copy) or reachable by navigating to the relevant screen.
//
// HelpScreen is therefore a shortcut menu rather than a document viewer.
// It groups shortcuts into two sections:
//
//   "Start here" — tasks every new user should do in the first session:
//     • Understand what the app is good at (and not good at).
//     • Pair a first contact so the mesh can be used.
//     • Review security settings (PIN, emergency erase, threat context).
//     • Back up their identity before making any major changes.
//
//   "Understand tradeoffs" — context the user needs before making informed
//   privacy decisions:
//     • Notification privacy (what each tier reveals to third parties).
//     • Known limitations (scenarios the app CANNOT protect against).
//
// Each tile pushes to the relevant existing screen rather than duplicating
// information.  This makes the help system free-maintenance — updates to
// those screens are reflected here automatically.
//
// ACCESS:
// -------
// HelpScreen is pushed from NavDrawer via a non-section "Help" drawer item.
// It appears on a full-screen route (MaterialPageRoute) so it has its own
// AppBar back button and does not interfere with the main shell navigation.

import 'package:flutter/material.dart';

import '../features/contacts/screens/pair_contact_screen.dart';
import '../features/settings/screens/backup_screen.dart';
import '../features/settings/screens/known_limitations_screen.dart';
import '../features/settings/screens/notification_screen.dart';
import '../features/settings/screens/security_screen.dart';

/// Full-screen help hub that shortcuts to the most important parts of the app.
///
/// Shown from the nav drawer's Help item.  All items push onto the Navigator
/// so the user can return here with the back button.
class HelpScreen extends StatelessWidget {
  const HelpScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Help')),
      body: ListView(
        children: [
          // ----------------------------------------------------------------
          // Start here — foundational onboarding actions
          // ----------------------------------------------------------------
          const _SectionHeader('Start here'),

          // Static informational tile — no tap target, just an orientation note.
          const ListTile(
            leading: Icon(Icons.info_outline),
            title: Text('What this app is good at'),
            subtitle: Text(
              'Private messaging, mesh networking, and controlled routing without a central account.',
            ),
          ),

          // Pairing — the first action most users should take so they can
          // actually communicate with someone over the mesh.
          ListTile(
            leading: const Icon(Icons.person_add_outlined),
            title: const Text('Pair a contact'),
            subtitle: const Text(
              'Scan or paste a pairing code to add someone you trust.',
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _push(context, const PairContactScreen()),
          ),

          // Security — PIN setup, emergency erase, and threat context are
          // all grouped in SecurityScreen.  Users should configure these
          // before storing sensitive data.
          ListTile(
            leading: const Icon(Icons.security_outlined),
            title: const Text('Review security settings'),
            subtitle: const Text(
              'PIN, emergency erase, and threat context all live here.',
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _push(context, const SecurityScreen()),
          ),

          // Backup — strongly recommended before changing the identity or
          // resetting the app; the mesh identity keypair cannot be recovered
          // without a backup if the device is lost.
          ListTile(
            leading: const Icon(Icons.backup_outlined),
            title: const Text('Back up your data'),
            subtitle: const Text(
              'Create an encrypted backup before making high-risk changes.',
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _push(context, const BackupScreen()),
          ),

          const Divider(height: 1),

          // ----------------------------------------------------------------
          // Understand tradeoffs — decision support for informed choices
          // ----------------------------------------------------------------
          const _SectionHeader('Understand tradeoffs'),

          // Notification privacy — choosing a notification tier is one of the
          // biggest user-facing privacy decisions; this screen explains what
          // each tier reveals so the choice is informed, not arbitrary.
          ListTile(
            leading: const Icon(Icons.notifications_outlined),
            title: const Text('Notification privacy'),
            subtitle: const Text(
              'See what each notification mode reveals to third parties.',
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _push(context, const NotificationScreen()),
          ),

          // Known limitations — explicit enumeration of threat models the app
          // does NOT protect against.  Omitting this would be misleading to
          // users who rely on the app in high-risk situations.
          ListTile(
            leading: const Icon(Icons.warning_amber_outlined),
            title: const Text('Known limitations'),
            subtitle: const Text(
              'Read the situations this app cannot safely protect you from.',
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _push(context, const KnownLimitationsScreen()),
          ),

          // Bottom padding so the last tile doesn't sit flush against the edge.
          const SizedBox(height: 24),
        ],
      ),
    );
  }

  /// Push [screen] onto the Navigator stack.
  ///
  /// All tiles in this screen use a full MaterialPageRoute so the user can
  /// navigate back to this help menu with the OS back gesture.
  void _push(BuildContext context, Widget screen) {
    Navigator.push(context, MaterialPageRoute(builder: (_) => screen));
  }
}

// ---------------------------------------------------------------------------
// _SectionHeader — coloured small-caps label that groups related tiles
// ---------------------------------------------------------------------------

/// Small-caps section header in the primary brand colour.
///
/// Mirrors the style used in Settings screens so help feels consistent
/// with the rest of the app.
class _SectionHeader extends StatelessWidget {
  const _SectionHeader(this.title);

  /// The display text for this group heading.
  final String title;

  @override
  Widget build(BuildContext context) {
    return Padding(
      // Generous top padding creates visual separation between groups.
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
