// known_limitations_screen.dart
//
// KnownLimitationsScreen — what Mesh Infinity cannot protect against (§22.10.5).
//
// WHY THIS SCREEN EXISTS:
// -----------------------
// Honest security tools tell users what they CAN'T do.  Overstating
// protection creates false confidence that can cost lives.  This screen
// presents six categories of limitations in plain language, structured
// as expandable cards so users who want full detail can read it and users
// who just need a quick mental model can skim the summaries.
//
// The spec (§22.22) requires plain language throughout.  Each card follows:
//   Title — short noun phrase
//   Summary — one sentence, reads like a warning label
//   Detail — two to four sentences explaining the real attack / failure mode
//
// Reached from: Settings → Security → Known limitations.

import 'package:flutter/material.dart';

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// One limitation entry — title, one-line summary, and full detail text.
class _Limitation {
  const _Limitation({
    required this.title,
    required this.summary,
    required this.detail,
  });

  final String title;
  final String summary;
  final String detail;
}

// ---------------------------------------------------------------------------
// KnownLimitationsScreen
// ---------------------------------------------------------------------------

/// Shows the full list of known Mesh Infinity limitations as expandable cards.
///
/// All content is static — no backend calls required for this screen.
class KnownLimitationsScreen extends StatelessWidget {
  const KnownLimitationsScreen({super.key});

  // The full list of limitations from §22.10.5.
  // Each entry is intentionally written to be honest and non-alarmist.
  // Ordered from most-likely to least-likely to affect everyday users.
  static const List<_Limitation> _limitations = [
    _Limitation(
      title: 'Ratchet window after device seizure',
      summary: 'An adversary who seizes a device can read future messages for a period.',
      detail:
          'Forward secrecy protects past messages. If a device is seized, the adversary '
          'holds the current ratchet state and can decrypt future messages until peers '
          'stop sending. The window depends on how quickly trusted peers are notified '
          'and stop communicating.',
    ),
    _Limitation(
      title: 'Dead man\'s switch / liveness dilemma',
      summary: 'Liveness signals and total privacy are in direct conflict.',
      detail:
          'Any periodic signal you send can be observed by adversaries. A pre-committed '
          'distress message (in Potential Extremes) is a partial mitigation — but the '
          'cancellation pattern itself is observable, and a stopped signal reveals when '
          'something happened.',
    ),
    _Limitation(
      title: 'Physical seizure without killswitch',
      summary: 'A sophisticated adversary who images your device prevents the killswitch from firing.',
      detail:
          'Imaging a powered device in a Faraday cage allows an adversary to read all '
          'local data before any remote wipe or killswitch can operate. Full-disk '
          'encryption reduces but does not eliminate this risk.',
    ),
    _Limitation(
      title: 'The \$5 hammer',
      summary: 'No technical system withstands physical coercion.',
      detail:
          'If an adversary can compel you to unlock your device or reveal a PIN through '
          'force, all technical protections are bypassed. This is outside the scope of '
          'any software solution.',
    ),
    _Limitation(
      title: 'Social engineering',
      summary: 'The trust system cannot protect against your own judgment.',
      detail:
          'If you grant high trust to a malicious party, they gain access to the '
          'capabilities that trust level provides. The system protects against technical '
          'attacks, not against granting trust to the wrong people.',
    ),
    _Limitation(
      title: 'Profile sharing permanence',
      summary: 'Once a private profile is shared, it cannot be recalled.',
      detail:
          'When you share your private profile with a trusted peer, that information '
          'exists on their device. Revoking trust does not delete the information they '
          'already received.',
    ),
  ];

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    return Scaffold(
      appBar: AppBar(title: const Text('Known Limitations')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // Intro paragraph — frames the purpose of this screen.
          // The tone is matter-of-fact, not alarming (§22.22).
          Text(
            'Understanding these limitations helps you make better decisions '
            'about when and how to use Mesh Infinity.',
            style: tt.bodyMedium?.copyWith(color: cs.onSurfaceVariant),
          ),
          const SizedBox(height: 20),

          // One expansion card per limitation.
          // Using ExpansionTile keeps the initial view scannable.
          for (final limitation in _limitations)
            _LimitationCard(limitation: limitation),

          const SizedBox(height: 24),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _LimitationCard — one expandable limitation row
// ---------------------------------------------------------------------------

/// Renders one [_Limitation] as an ExpansionTile.
///
/// The tile is collapsed by default — the summary is always visible,
/// and the full detail is revealed on tap.  This respects the reading
/// habits of both power users and casual readers.
class _LimitationCard extends StatelessWidget {
  const _LimitationCard({required this.limitation});

  final _Limitation limitation;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      // clipBehavior clips the ExpansionTile's animated height within the Card.
      clipBehavior: Clip.antiAlias,
      child: ExpansionTile(
        // Horizontal + vertical padding gives the tile breathing room.
        tilePadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),

        // Title: short, noun-phrase label for the limitation.
        title: Text(limitation.title, style: tt.titleSmall),

        // Subtitle: always visible one-sentence warning.
        subtitle: Text(
          limitation.summary,
          style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
        ),

        // Expanded body: full detail with additional context.
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
            child: Text(
              limitation.detail,
              style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
            ),
          ),
        ],
      ),
    );
  }
}
