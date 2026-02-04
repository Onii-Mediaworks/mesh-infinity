import 'package:flutter/material.dart';

class TopBar extends StatelessWidget {
  const TopBar({
    super.key,
    required this.title,
    this.subtitle,
    this.sectionIcon, // when set, renders a coloured icon circle instead of the text avatar
    required this.showMenuButton,
    required this.onMenuTap,
    this.showBackButton = false,
    this.onBackTap,
    this.leading,
    this.trailing,
  });

  final String title;
  final String? subtitle;
  final IconData? sectionIcon;
  final bool showMenuButton;
  final VoidCallback onMenuTap;
  final bool showBackButton;
  final VoidCallback? onBackTap;
  final List<Widget>? leading;
  final List<Widget>? trailing;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 8),
      decoration: BoxDecoration(
        color: cs.surface,
        border: Border(bottom: BorderSide(color: cs.outline.withValues(alpha: 0.2))),
      ),
      child: Row(
        children: [
          if (showMenuButton) IconButton(onPressed: onMenuTap, icon: const Icon(Icons.menu)),
          if (showBackButton)
            IconButton(
              onPressed: onBackTap,
              icon: const Icon(Icons.arrow_back),
              tooltip: 'Back',
            ),
          if (leading != null) ...leading!,
          // avatar or section-icon circle
          if (sectionIcon != null)
            Container(
              width: 36,
              height: 36,
              decoration: BoxDecoration(color: cs.primaryContainer, shape: BoxShape.circle),
              child: Center(child: Icon(sectionIcon, color: cs.primary, size: 18)),
            )
          else
            CircleAvatar(
              radius: 18,
              backgroundColor: _avatarColor(title),
              child: Text(
                title.isNotEmpty ? title[0].toUpperCase() : '?',
                style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w600),
              ),
            ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(title, style: theme.textTheme.bodyLarge?.copyWith(fontWeight: FontWeight.w600)),
                if (subtitle != null)
                  Text(subtitle!, style: theme.textTheme.bodySmall?.copyWith(color: cs.onSurfaceVariant)),
              ],
            ),
          ),
          if (trailing != null) ...trailing!,
        ],
      ),
    );
  }
}

Color _avatarColor(String name) {
  int hash = 0;
  for (final c in name.codeUnits) {
    hash = ((hash << 5) - hash) + c;
    hash = hash & 0x7FFFFFFF;
  }
  const palette = [
    Color(0xFF1ABC9C), Color(0xFFE74C3C), Color(0xFF9B59B6), Color(0xFFE67E22),
    Color(0xFF3498DB), Color(0xFF2ECC71), Color(0xFFE91E63), Color(0xFF607D8B),
  ];
  return palette[hash % palette.length];
}
