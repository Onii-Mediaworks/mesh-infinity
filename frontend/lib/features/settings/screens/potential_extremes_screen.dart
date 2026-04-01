// potential_extremes_screen.dart
//
// PotentialExtremesScreen — advanced security features with explicit risk
// disclosures (§22.10.4).
//
// WHAT THIS SCREEN SHOWS:
// -----------------------
// Features that make security-privacy tradeoffs that the user needs to
// consciously understand before enabling.  Each card:
//   1. Describes what the feature does in plain language.
//   2. Lists the specific risks the user accepts by enabling it.
//   3. Provides a toggle to enable/disable.
//
// DESIGN PHILOSOPHY (§22.22):
// ----------------------------
// The spec prohibits fear-mongering and prohibits hiding tradeoffs.
// These features are presented neutrally — here's what it does, here's
// what an adversary can learn.  The user decides.
//
// FEATURES ON THIS SCREEN:
//   - Pre-committed distress message (dead man's switch)
//   - Periodic liveness signal
//   - Anonymous masks (link to IdentityMasksScreen)
//
// Reached from: Settings → Security → Potential extremes.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../app/app_theme.dart';
import '../settings_state.dart';
import 'identity_masks_screen.dart';

// ---------------------------------------------------------------------------
// PotentialExtremesScreen
// ---------------------------------------------------------------------------

/// Screen showing advanced security features with explicit risk disclosures.
class PotentialExtremesScreen extends StatelessWidget {
  const PotentialExtremesScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final settings = context.watch<SettingsState>();
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    return Scaffold(
      appBar: AppBar(title: const Text('Potential Extremes')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // Warning banner — sets expectations before the user reads feature cards.
          // Uses amber (warning colour) not red (danger) — these are tradeoffs,
          // not hazards.
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: MeshTheme.secAmber.withValues(alpha: 0.08),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(
                color: MeshTheme.secAmber.withValues(alpha: 0.3),
              ),
            ),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Icon(
                  Icons.warning_amber_outlined,
                  color: MeshTheme.secAmber,
                  size: 20,
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    'These features involve real tradeoffs. Each description '
                    'explains exactly what an adversary can learn when you use them.',
                    style: tt.bodySmall,
                  ),
                ),
              ],
            ),
          ),

          const SizedBox(height: 16),

          // ---------------------------------------------------------------------------
          // Pre-committed distress message
          // ---------------------------------------------------------------------------
          // Dead man's switch: the user checks in periodically.  If they stop,
          // a pre-written message is sent to their trusted contacts.
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Header row: label on the left, toggle on the right.
                  Row(
                    children: [
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'Pre-committed distress message',
                              style: tt.titleSmall,
                            ),
                            const SizedBox(height: 4),
                            Text(
                              'A message sends automatically if you stop checking in.',
                              style: tt.bodySmall?.copyWith(
                                color: cs.onSurfaceVariant,
                              ),
                            ),
                          ],
                        ),
                      ),
                      // Toggle changes state optimistically; backend stub returns false.
                      // TODO(backend/security): wire to real distress message API.
                      Switch(
                        value: settings.distressMessageEnabled,
                        onChanged: (_) => _stubNotImplemented(context),
                      ),
                    ],
                  ),

                  const SizedBox(height: 12),

                  // Risk disclosure — always visible, no expansion needed.
                  // Written in the second person so the user understands
                  // they personally accept these risks by enabling.
                  Text(
                    'Risks you accept:\n'
                    '• An adversary can observe when you stop cancelling. '
                    'A stopped signal reveals when something happened.\n'
                    '• False positives: arrest without device compromise will '
                    'trigger this.\n'
                    '• This is a partial mitigation, not a solution.',
                    style: tt.bodySmall?.copyWith(
                      color: cs.onSurfaceVariant,
                    ),
                  ),

                  // Configure button shown only when enabled.
                  if (settings.distressMessageEnabled) ...[
                    const SizedBox(height: 16),
                    OutlinedButton(
                      // TODO(backend/security): open distress message config flow.
                      onPressed: () => _stubNotImplemented(context),
                      child: const Text('Configure'),
                    ),
                  ],
                ],
              ),
            ),
          ),

          const SizedBox(height: 8),

          // ---------------------------------------------------------------------------
          // Periodic liveness signal
          // ---------------------------------------------------------------------------
          // Sends regular "I'm online" signals to trusted peers.
          // The tradeoff: creates a timing fingerprint an adversary can correlate.
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'Periodic liveness signal',
                              style: tt.titleSmall,
                            ),
                            const SizedBox(height: 4),
                            Text(
                              "Let trusted peers know when you're online.",
                              style: tt.bodySmall?.copyWith(
                                color: cs.onSurfaceVariant,
                              ),
                            ),
                          ],
                        ),
                      ),
                      Switch(
                        value: settings.livenessSignalEnabled,
                        onChanged: (_) => _stubNotImplemented(context),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  Text(
                    'Risks you accept:\n'
                    '• This creates a timing fingerprint. An adversary can '
                    'correlate your online patterns.\n'
                    '• Your activity periods become observable.',
                    style: tt.bodySmall?.copyWith(
                      color: cs.onSurfaceVariant,
                    ),
                  ),
                ],
              ),
            ),
          ),

          const SizedBox(height: 8),

          // ---------------------------------------------------------------------------
          // Anonymous masks (link tile)
          // ---------------------------------------------------------------------------
          // Not a toggle — links through to IdentityMasksScreen where the user
          // can create masks that cannot be linked back to their root identity.
          Card(
            child: ListTile(
              leading: const Icon(
                Icons.person_outline,
                color: MeshTheme.secPurple,
              ),
              title: const Text('Anonymous masks'),
              subtitle: const Text(
                'Masks that cannot be linked to your identity, '
                'even by trusted peers.',
              ),
              trailing: const Icon(Icons.chevron_right),
              onTap: () => Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (_) => const IdentityMasksScreen(),
                ),
              ),
            ),
          ),

          const SizedBox(height: 24),
        ],
      ),
    );
  }

  // Show a SnackBar when a feature isn't wired to the backend yet.
  // Better than silently toggling state that has no effect.
  void _stubNotImplemented(BuildContext context) {
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Feature not yet available — backend implementation pending.'),
        duration: Duration(seconds: 3),
      ),
    );
  }
}
