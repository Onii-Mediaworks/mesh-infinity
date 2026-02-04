import 'package:flutter/material.dart';

import '../../menu/menu_models.dart';

class SectionSidebar extends StatelessWidget {
  const SectionSidebar({
    super.key,
    required this.title,
    required this.items,
    required this.activeSectionId,
    required this.onSelect,
    this.trailingHeader,
    this.emptyState,
  });

  final String title;
  final List<SectionNavItem> items;
  final String? activeSectionId;
  final ValueChanged<String> onSelect;
  final Widget? trailingHeader;
  final Widget? emptyState;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Container(
      color: cs.surface,
      child: Column(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 16, 8, 12),
            child: Row(
              children: [
                Expanded(
                  child: Text(
                    title,
                    style: Theme.of(context).textTheme.titleMedium?.copyWith(fontWeight: FontWeight.w600),
                  ),
                ),
                if (trailingHeader != null) trailingHeader!,
              ],
            ),
          ),
          const Divider(height: 1),
          Expanded(
            child: items.isEmpty
                ? (emptyState ?? const SizedBox.shrink())
                : ListView.separated(
                    padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 8),
                    itemBuilder: (context, index) {
                      final item = items[index];
                      final selected = item.id == activeSectionId;
                      return ListTile(
                        onTap: () => onSelect(item.id),
                        leading: Icon(item.icon, color: selected ? cs.primary : cs.onSurfaceVariant),
                        title: Text(
                          item.title,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                                fontWeight: selected ? FontWeight.w600 : FontWeight.normal,
                              ),
                        ),
                        subtitle: item.subtitle == null
                            ? null
                            : Text(
                                item.subtitle!,
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                style: TextStyle(color: cs.onSurfaceVariant),
                              ),
                        selected: selected,
                        selectedTileColor: cs.primaryContainer.withValues(alpha: 0.2),
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                      );
                    },
                    separatorBuilder: (context, _) => const SizedBox(height: 4),
                    itemCount: items.length,
                  ),
          ),
        ],
      ),
    );
  }
}
