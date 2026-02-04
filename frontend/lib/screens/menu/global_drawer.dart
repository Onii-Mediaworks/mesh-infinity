import 'package:flutter/material.dart';

import 'menu_models.dart';

class GlobalMenuDrawer extends StatelessWidget {
  const GlobalMenuDrawer({
    super.key,
    required this.activeSection,
    required this.onSelect,
  });

  final GlobalMenuSection activeSection;
  final ValueChanged<GlobalMenuSection> onSelect;

  static const _items = [
    _DrawerItem(GlobalMenuSection.chat, Icons.chat_bubble_outline, 'Chat'),
    _DrawerItem(GlobalMenuSection.files, Icons.folder_open_outlined, 'Files'),
    _DrawerItem(GlobalMenuSection.networkOptions, Icons.hub_outlined, 'Network'),
    _DrawerItem(GlobalMenuSection.meshOptions, Icons.people_outlined, 'Peers'),
    _DrawerItem(GlobalMenuSection.applicationSettings, Icons.settings_outlined, 'Settings'),
  ];

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return SafeArea(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 20, 16, 12),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Mesh Infinity',
                    style: Theme.of(context).textTheme.titleLarge?.copyWith(fontWeight: FontWeight.w600)),
                const SizedBox(height: 4),
                Text('Navigation', style: TextStyle(color: cs.onSurfaceVariant)),
              ],
            ),
          ),
          const Divider(height: 1),
          Expanded(
            child: ListView.builder(
              padding: const EdgeInsets.symmetric(vertical: 8),
              itemCount: _items.length,
              itemBuilder: (context, index) {
                final item = _items[index];
                final active = item.section == activeSection ||
                    (item.section == GlobalMenuSection.meshOptions &&
                        activeSection == GlobalMenuSection.trustCenter);
                return ListTile(
                  onTap: () => onSelect(item.section),
                  leading: Icon(item.icon, color: active ? cs.primary : cs.onSurfaceVariant),
                  title: Text(item.label, style: TextStyle(color: active ? cs.primary : null)),
                  selected: active,
                );
              },
            ),
          ),
        ],
      ),
    );
  }
}

class _DrawerItem {
  const _DrawerItem(this.section, this.icon, this.label);

  final GlobalMenuSection section;
  final IconData icon;
  final String label;
}
