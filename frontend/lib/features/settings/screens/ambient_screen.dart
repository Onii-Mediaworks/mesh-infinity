import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../shell/badge_state.dart';
import '../../../shell/shell_state.dart';

// ---------------------------------------------------------------------------
// AmbientScreen — configure Tier-2 ambient badge indicators (iteration 9).
//
// Global toggle gates all per-section toggles.  All default to off per spec.
// ---------------------------------------------------------------------------

class AmbientScreen extends StatelessWidget {
  const AmbientScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final badge = context.watch<BadgeState>();
    final theme = Theme.of(context);
    final cs = theme.colorScheme;

    return Scaffold(
      appBar: AppBar(title: const Text('Ambient indicators')),
      body: ListView(
        children: [
          // ── Global toggle ────────────────────────────────────────────
          SwitchListTile(
            secondary: const Icon(Icons.circle_outlined),
            title: const Text('Enable ambient indicators'),
            subtitle: const Text(
              'Show low-priority activity dots on navigation items',
            ),
            value: badge.ambientGlobalEnabled,
            onChanged: context.read<BadgeState>().setGlobalAmbient,
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 12),
            child: Text(
              'Ambient dots are Tier-2 indicators — they appear as small '
              'muted squares distinct from the Tier-1 critical badges. '
              'They signal low-priority activity without demanding attention.',
              style: theme.textTheme.bodySmall?.copyWith(
                color: cs.onSurfaceVariant,
              ),
            ),
          ),
          const Divider(height: 1),

          // ── Per-section toggles ─────────────────────────────────────
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
            child: Text(
              'Per-section',
              style: theme.textTheme.labelMedium?.copyWith(
                color: cs.primary,
                fontWeight: FontWeight.w700,
                letterSpacing: 0.8,
              ),
            ),
          ),
          ...AppSection.values.map(
            (section) => SwitchListTile(
              title: Text(_sectionName(section)),
              subtitle: Text(_sectionDescription(section)),
              value: badge.sectionAmbientToggle(section),
              onChanged: badge.ambientGlobalEnabled
                  ? (v) =>
                      context.read<BadgeState>().setSectionAmbient(section, v)
                  : null,
            ),
          ),
          const SizedBox(height: 24),
        ],
      ),
    );
  }

  String _sectionName(AppSection section) => switch (section) {
    AppSection.chat => 'Chat',
    AppSection.garden => 'Garden',
    AppSection.files => 'Files',
    AppSection.contacts => 'Contacts',
    AppSection.services => 'Services',
    AppSection.you => 'You',
    AppSection.network => 'Network',
    AppSection.settings => 'Settings',
  };

  String _sectionDescription(AppSection section) => switch (section) {
    AppSection.chat => 'New messages in muted or low-priority rooms',
    AppSection.garden => 'Feed or channel activity',
    AppSection.files => 'Completed or pending transfers',
    AppSection.contacts => 'Presence and status changes',
    AppSection.services => 'Service health or availability changes',
    AppSection.you => 'Profile or identity activity',
    AppSection.network => 'Topology or transport changes',
    AppSection.settings => 'Configuration events',
  };
}
