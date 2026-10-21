// contact_picker_sheet.dart
//
// pick_contact — the bottom sheet the Remote Shell and File Access screens
// open from "+ Add person" / "+ Add exception" (§22.54.6, §22.54.7).
//
// The list comes from PeersState and is filtered to contacts at or above
// the server's trust floor: a grant to someone below the floor would be a
// grant the server could never honour, so the picker does not offer it.
// Contacts already in the list are left out too.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../app/app_theme.dart';
import '../../../backend/models/peer_models.dart';
import '../../../backend/models/service_config_models.dart';
import '../../../core/widgets/empty_state.dart';
import '../../../core/widgets/focusable_tile.dart';
import '../../peers/peers_state.dart';

/// Let the user choose a contact at or above [floor] who is not in
/// [exclude].  Resolves to null when the sheet is dismissed.
Future<PeerModel?> pick_contact(
  BuildContext context, {
  required int floor,
  required Set<String> exclude,
}) {
  return showModalBottomSheet<PeerModel>(
    context: context,
    showDragHandle: true,
    useSafeArea: true,
    builder: (sheet_context) => _ContactPicker(floor: floor, exclude: exclude),
  );
}

class _ContactPicker extends StatelessWidget {
  const _ContactPicker({required this.floor, required this.exclude});

  final int floor;
  final Set<String> exclude;

  @override
  Widget build(BuildContext context) {
    final colors = MeshColors.of(context);
    final text = Theme.of(context).textTheme;
    final peers = context
        .watch<PeersState>()
        .peers
        .where((p) => p.trustLevel.value >= floor && !exclude.contains(p.id))
        .toList();

    if (peers.isEmpty) {
      return SizedBox(
        height: 240,
        child: EmptyState(
          icon: Icons.person_search_outlined,
          title: 'No one to add',
          body:
              'Only contacts at Level $floor (${trustLevelNames[floor]}) '
              'or higher can be given access.',
        ),
      );
    }

    return ListView(
      shrinkWrap: true,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(20, 4, 20, 8),
          child: Text('Choose a contact', style: text.titleMedium),
        ),
        for (final peer in peers)
          FocusableTile(
            child: ListTile(
              // 48dp row (§22.34).
              minTileHeight: 48,
              leading: Icon(
                Icons.circle,
                size: 12,
                color: colors.trust_color(peer.trustLevel.value),
              ),
              title: Text(peer.name.isEmpty ? peer.id : peer.name),
              subtitle: Text(
                'Level ${peer.trustLevel.value} · ${peer.trustLevel.label}',
              ),
              onTap: () => Navigator.pop(context, peer),
            ),
          ),
        const SizedBox(height: 12),
      ],
    );
  }
}
