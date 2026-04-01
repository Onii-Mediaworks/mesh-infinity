import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../backend/backend_bridge.dart';
import '../../core/widgets/empty_state.dart';
import '../../app/app_theme.dart';
import '../tidbits/widgets/garden_gnome.dart'; // §22.12.5 #20 Garden Gnome

class GardenExploreScreen extends StatefulWidget {
  const GardenExploreScreen({super.key});
  @override
  State<GardenExploreScreen> createState() => _GardenExploreScreenState();
}

class _GardenExploreScreenState extends State<GardenExploreScreen> {
  List<Map<String, dynamic>> _gardens = const [];
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final bridge = context.read<BackendBridge>();
    final gardens = bridge.discoverGardens();
    if (mounted) setState(() { _gardens = gardens; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator());
    if (_gardens.isEmpty) {
      // GardenGnomeWidget appears on ~1-in-5 days (§22.12.5 #20).
      // It sits below the real empty state and never replaces it.
      return const Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          EmptyState(
            icon: Icons.explore_outlined,
            title: 'No gardens found nearby',
            body: 'Public and open gardens on the local mesh will appear here.',
          ),
          GardenGnomeWidget(),
        ],
      );
    }
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.symmetric(vertical: 4),
        itemCount: _gardens.length,
        itemBuilder: (context, i) => _GardenTile(garden: _gardens[i]),
      ),
    );
  }
}

class _GardenTile extends StatelessWidget {
  const _GardenTile({required this.garden});
  final Map<String, dynamic> garden;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;
    final name        = garden['name']        as String? ?? 'Unnamed garden';
    final description = garden['description'] as String? ?? '';
    final memberCount = (garden['memberCount'] as num?)?.toInt() ?? 0;
    final networkType = garden['networkType'] as String? ?? 'public';

    return ListTile(
      contentPadding:
          const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
      leading: ClipRRect(
        borderRadius: BorderRadius.circular(12),
        child: Container(
          width: 48, height: 48,
          color: MeshTheme.brand.withValues(alpha: 0.12),
          child: const Icon(Icons.groups_outlined, color: MeshTheme.brand),
        ),
      ),
      title: Row(children: [
        Expanded(
          child: Text(name,
            style: theme.textTheme.titleSmall,
            maxLines: 1,
            overflow: TextOverflow.ellipsis),
        ),
        _NetworkTypeBadge(type: networkType),
      ]),
      subtitle: Row(children: [
        Icon(Icons.people_outline, size: 14, color: cs.onSurfaceVariant),
        const SizedBox(width: 4),
        Text('$memberCount member${memberCount == 1 ? '' : 's'}',
          style: theme.textTheme.bodySmall
              ?.copyWith(color: cs.onSurfaceVariant)),
        if (description.isNotEmpty) ...[
          const SizedBox(width: 8),
          Expanded(
            child: Text(description,
              style: theme.textTheme.bodySmall
                  ?.copyWith(color: cs.onSurfaceVariant),
              maxLines: 1,
              overflow: TextOverflow.ellipsis),
          ),
        ],
      ]),
      trailing: TextButton(
        onPressed: () {}, // TODO: join garden action
        child: const Text('Join'),
      ),
    );
  }
}

class _NetworkTypeBadge extends StatelessWidget {
  const _NetworkTypeBadge({required this.type});
  final String type;

  @override
  Widget build(BuildContext context) {
    final color = _color();
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(4),
        border: Border.all(color: color.withValues(alpha: 0.3)),
      ),
      child: Text(
        _label(),
        style: TextStyle(
          fontSize: 10, color: color, fontWeight: FontWeight.w600),
      ),
    );
  }

  Color _color() => switch (type) {
    'public'  => MeshTheme.brand,
    'open'    => MeshTheme.secGreen,
    'closed'  => MeshTheme.secAmber,
    'private' => MeshTheme.secPurple,
    _         => MeshTheme.brand,
  };

  String _label() => switch (type) {
    'public'  => 'Public',
    'open'    => 'Open',
    'closed'  => 'Closed',
    'private' => 'Private',
    _         => type,
  };
}
