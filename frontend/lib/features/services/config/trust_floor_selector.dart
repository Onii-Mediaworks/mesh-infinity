// trust_floor_selector.dart
//
// TrustFloorSelector — the §22.54.4 control for "who can connect".
//
// WHAT IT ENFORCES
// ----------------
// Every §20 server has a hard trust floor the operator may raise but never
// lower.  This selector only offers levels from that floor up to Level 8,
// so the UI physically cannot ask for what the protocol forbids; the
// backend re-checks on save as defence in depth.
//
// Each row shows the level number, its §8.1 name and its colour dot from
// `MeshColors.trust_color`, so the levels read the same here as on contact
// cards.  The helper line under the menu states the rule in plain words.

import 'package:flutter/material.dart';

import '../../../app/app_theme.dart';
import '../../../backend/models/service_config_models.dart';

/// Dropdown of trust levels from [minimum] to Level 8.
class TrustFloorSelector extends StatelessWidget {
  const TrustFloorSelector({
    super.key,
    required this.minimum,
    required this.value,
    required this.on_changed,
    required this.protocol,
    this.label = 'Trust floor',
    this.error,
  });

  /// The protocol's hard floor; lower levels are not offered.
  final int minimum;

  /// The currently selected level.
  final int value;

  /// Called with the newly selected level.
  final ValueChanged<int> on_changed;

  /// Plain-language protocol name for the helper line, e.g. "Remote Desktop".
  final String protocol;

  /// Field label shown in the menu's text field.
  final String label;

  /// Inline reason when the current value breaks a cross-field rule
  /// (e.g. "Must be at least the view-only level"); null when valid.
  final String? error;

  @override
  Widget build(BuildContext context) {
    final colors = MeshColors.of(context);
    final text = Theme.of(context).textTheme;
    final cs = Theme.of(context).colorScheme;
    // Clamp so a stored value below the floor (never written by this UI,
    // but possible from an older vault) still renders a valid selection.
    final selected = value.clamp(minimum, trustMax);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Semantics(
          label: '$label, level $selected ${trustLevelNames[selected]}',
          child: DropdownMenu<int>(
            initialSelection: selected,
            label: Text(label),
            expandedInsets: EdgeInsets.zero,
            errorText: error,
            onSelected: (level) {
              if (level != null) on_changed(level);
            },
            dropdownMenuEntries: [
              for (var level = minimum; level <= trustMax; level++)
                DropdownMenuEntry<int>(
                  value: level,
                  label: 'Level $level · ${trustLevelNames[level]}',
                  leadingIcon: Icon(
                    Icons.circle,
                    size: 12,
                    color: colors.trust_color(level),
                  ),
                ),
            ],
          ),
        ),
        Padding(
          padding: const EdgeInsets.only(top: 6, left: 12),
          child: Text(
            'Only contacts at this level or higher can connect. '
            '$protocol never allows below Level $minimum.',
            style: text.bodySmall?.copyWith(color: cs.onSurfaceVariant),
          ),
        ),
      ],
    );
  }
}
