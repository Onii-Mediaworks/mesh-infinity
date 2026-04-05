// tier_discovery_screen.dart
//
// TierDiscoveryScreen — "What else can Mesh Infinity do?" (§22.53).
//
// WHAT THIS SCREEN IS:
// --------------------
// Mesh Infinity is a tiered application.  Most people will only ever use
// Tier 1 (Social — chat, communities, contacts).  Higher tiers add:
//   Tier 2 — Network  : Mesh VPN, per-app routing, exit nodes, Funnel
//   Tier 3 — Infinet  : Private virtual LAN, mesh DNS, access control
//   Tier 4 — Services : Remote desktop, remote shell, file access, API gateway
//   Tier 5 — Power    : Purpose devices, Qubes Air, split operations, plugins
//
// This screen presents each tier in plain language so users who want more
// can understand what they're unlocking before they commit.  The spec
// (§22.28) calls this the "tier unlock flow" and requires:
//   1. Tagline — one sentence describing the tier's value proposition.
//   2. Feature bullets — 3-4 concrete capabilities, not marketing language.
//   3. "Unlock" button — shows a brief confirmation sheet, not a full dialog.
//
// PHILOSOPHY (§22.22):
// --------------------
// Higher tiers involve real complexity tradeoffs.  The screen doesn't
// pressure users — if you're happy at Social, that's fine.  The unlock
// button is present but not highlighted.  Power users will find it; casual
// users won't feel pushed.
//
// ENTRY POINTS:
//   - Settings → "Explore features" tile (§22.55.2)
//   - Settings → "Explore features" footer button (§22.55.2)
//   - ModuleEnablePrompt "Learn more" link (§22.52.7) — not yet wired
//   - First-run nudge after 7 days at Tier 1 — not yet wired
//
// Reached from: Settings → Explore features.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../app/app_theme.dart';
import '../settings_state.dart';

// ---------------------------------------------------------------------------
// TierDiscoveryScreen
// ---------------------------------------------------------------------------

/// Shows all five tiers with their feature sets and unlock buttons.
///
/// The active tier shows a green "Active" badge; locked tiers show an
/// "Unlock" button in the tier's accent colour.
class TierDiscoveryScreen extends StatelessWidget {
  const TierDiscoveryScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final settings = context.watch<SettingsState>();
    final tt = Theme.of(context).textTheme;
    final cs = Theme.of(context).colorScheme;

    return Scaffold(
      appBar: AppBar(title: const Text('Explore features')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // Intro paragraph — sets the right expectation before showing tiers.
          // The tone is inviting, not pressuring: most users stay at Tier 1.
          Text(
            'Mesh Infinity grows with you. Start with chat and add features '
            'when they make sense for how you use it.',
            style: tt.bodyMedium?.copyWith(color: cs.onSurfaceVariant),
          ),

          const SizedBox(height: 16),

          // One card per tier.  They're listed in order because you must unlock
          // them sequentially — Infinet requires Network, etc.
          for (final tier in MeshTier.values)
            _TierCard(
              tier: tier,
              isActive: settings.tierUnlocked(tier),
              // Only show the unlock button for the NEXT tier after active —
              // you can't jump from Social to Infinet without Network.
              canUnlock: tier.index == settings.activeTier.index + 1,
              onEnable: () => _enableTier(context, tier, settings),
            ),

          const SizedBox(height: 24),
        ],
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // Tier unlock flow
  // ---------------------------------------------------------------------------

  /// Shows a confirmation bottom sheet before unlocking a tier.
  ///
  /// A bottom sheet (not a dialog) matches the spec requirement — it's
  /// less alarming than a dialog for something that's reversible in practice.
  void _enableTier(
    BuildContext context,
    MeshTier tier,
    SettingsState settings,
  ) {
    final tt = Theme.of(context).textTheme;
    final cs = Theme.of(context).colorScheme;
    final tierColor = _tierColour(tier);

    showModalBottomSheet<void>(
      context: context,
      showDragHandle: true,
      builder: (_) => Padding(
        padding: const EdgeInsets.fromLTRB(16, 8, 16, 32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Unlock ${_tierName(tier)}?',
              style: tt.titleMedium?.copyWith(fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 8),
            Text(
              'This enables the ${_tierName(tier)} tier. '
              'Individual features within it are still off by default — '
              'you choose what to turn on.',
              style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
            ),
            const SizedBox(height: 16),
            Row(
              children: [
                Expanded(
                  child: OutlinedButton(
                    onPressed: () => Navigator.pop(context),
                    child: const Text('Not now'),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: FilledButton(
                    onPressed: () async {
                      Navigator.pop(context);
                      final ok = await settings.enableTier(tier);
                      if (!context.mounted) return;
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(
                          content: Text(
                            ok
                                ? '${_tierName(tier)} unlocked. Find new options in Settings.'
                                : 'Unable to unlock ${_tierName(tier).toLowerCase()} right now.',
                          ),
                        ),
                      );
                    },
                    style: FilledButton.styleFrom(backgroundColor: tierColor),
                    child: Text('Unlock ${_tierName(tier)}'),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _TierCard — one tier's full description card
// ---------------------------------------------------------------------------

/// Renders a single [MeshTier] as a Card with a coloured header strip,
/// tagline, feature bullets, and an optional unlock button.
///
/// The header strip uses the tier's accent colour at 12% opacity, keeping
/// the overall design calm rather than brash.
class _TierCard extends StatelessWidget {
  const _TierCard({
    required this.tier,
    required this.isActive,
    required this.canUnlock,
    required this.onEnable,
  });

  /// The tier this card represents.
  final MeshTier tier;

  /// True if this tier (and all below it) are already unlocked.
  final bool isActive;

  /// True only for the immediately next tier — shows the unlock button.
  final bool canUnlock;

  /// Called when the user taps the unlock button.
  final VoidCallback onEnable;

  @override
  Widget build(BuildContext context) {
    final tt = Theme.of(context).textTheme;
    final cs = Theme.of(context).colorScheme;
    final tierColor = _tierColour(tier);

    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      clipBehavior: Clip.antiAlias, // so the header strip respects card corners
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // ── Header strip ─────────────────────────────────────────────────
          // The strip gives each tier a distinct visual identity without
          // dominating the card.  Colour at 12% opacity + full-opacity icon.
          Container(
            width: double.infinity,
            padding: const EdgeInsets.fromLTRB(16, 12, 16, 12),
            color: tierColor.withValues(alpha: 0.12),
            child: Row(
              children: [
                Icon(_tierIcon(tier), size: 20, color: tierColor),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    _tierName(tier),
                    style: tt.titleSmall?.copyWith(color: tierColor),
                  ),
                ),
                // "Active" badge — shown for any tier the user has unlocked.
                if (isActive)
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 8,
                      vertical: 3,
                    ),
                    decoration: BoxDecoration(
                      color: MeshTheme.secGreen.withValues(alpha: 0.15),
                      borderRadius: BorderRadius.circular(999),
                    ),
                    child: Text(
                      'Active',
                      style: tt.labelSmall?.copyWith(color: MeshTheme.secGreen),
                    ),
                  ),
              ],
            ),
          ),

          // ── Body ─────────────────────────────────────────────────────────
          Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // One-sentence value proposition for this tier.
                Text(_tierTagline(tier), style: tt.bodyMedium),
                const SizedBox(height: 10),

                // 3-4 concrete capabilities — written as plain English, not
                // product-marketing language (§22.22 plain-language requirement).
                for (final feature in _tierFeatures(tier))
                  Padding(
                    padding: const EdgeInsets.only(bottom: 4),
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Icon(Icons.check_rounded, size: 14, color: tierColor),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            feature,
                            style: tt.bodySmall?.copyWith(
                              color: cs.onSurfaceVariant,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),

                // Unlock button — only for the immediately-next tier.
                // (You can't jump tiers — must unlock sequentially.)
                if (canUnlock) ...[
                  const SizedBox(height: 16),
                  FilledButton(
                    onPressed: onEnable,
                    style: FilledButton.styleFrom(
                      backgroundColor: tierColor,
                      minimumSize: const Size(double.infinity, 44),
                    ),
                    child: Text('Unlock ${_tierName(tier)}'),
                  ),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Tier metadata helpers
// ---------------------------------------------------------------------------
// These are module-level functions (not class methods) so both TierDiscoveryScreen
// and _TierCard can call them without passing a reference.

/// Human-readable name for each tier.
String _tierName(MeshTier t) =>
    const ['Social', 'Network', 'Infinet', 'Services', 'Power'][t.index];

/// Icon representing the tier in the header strip.
IconData _tierIcon(MeshTier t) => const [
  Icons.chat_outlined,
  Icons.vpn_key_outlined,
  Icons.lan_outlined,
  Icons.settings_ethernet_outlined,
  Icons.security_outlined,
][t.index];

/// Accent colour for the tier.  Each tier has a distinct colour so users
/// can quickly identify which tier a feature belongs to.
Color _tierColour(MeshTier t) => [
  MeshTheme.brand, // Social     — brand blue
  MeshTheme.secGreen, // Network    — green (VPN = go / active)
  MeshTheme.secAmber, // Infinet    — amber (advanced, proceed with thought)
  const Color(0xFF8B5CF6), // Services   — purple (power-user territory)
  MeshTheme.secRed, // Power      — red (maximum capability / maximum care)
][t.index];

/// One-sentence tagline for the tier.
String _tierTagline(MeshTier t) => const [
  'Chat, communities, and contacts. Everything a secure messaging app should be.',
  'Route your traffic through the mesh. Use your devices as your own VPN.',
  'A private virtual network for your devices. Your own internet, on your terms.',
  'Stream apps, share files, and expose services across your mesh.',
  'Compartmentalise your digital life across purpose-built devices.',
][t.index];

/// 3-4 concrete feature descriptions for each tier.
/// Written in plain English — no jargon, no marketing (§22.22).
List<String> _tierFeatures(MeshTier t) => const [
  [
    'Encrypted messaging with forward secrecy',
    'Communities (Gardens) — group chat and shared feeds',
    'Secure file transfers',
    'Layered contact trust system',
  ],
  [
    'Mesh VPN — route your traffic through trusted devices',
    'Per-app routing — choose which apps use the mesh',
    'Exit node support — reach the internet privately',
    'Local service exposure (Funnel)',
  ],
  [
    'Private virtual LAN across all your devices',
    'Mesh DNS — your devices get their own domain names',
    'Access control lists for granular permissions',
    'Shared services across Infinet devices',
  ],
  [
    "Remote desktop — access any device's screen",
    'Remote shell — terminal access from anywhere on the mesh',
    'Shared file access (MNFP)',
    'API and print service sharing',
  ],
  [
    'Purpose devices — compartmentalise by context (email, browsing, etc.)',
    'Qubes Air integration for hardware-isolated sessions',
    'Split operations — keys never leave their origin device',
    'Plugin runtime for third-party extensions',
  ],
][t.index];
