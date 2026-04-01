import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'shell_state.dart';

// ---------------------------------------------------------------------------
// SectionBottomBar
//
// Shows the sub-pages for the currently active section. Hidden when:
//   - The section has no sub-pages (You, Settings)
//   - The user has drilled into a detail view
//
// Spec (iteration 4+):
//   "The bottom bar is hidden in drilled-in detail views."
//   "Mobile uses a contextual bottom bar only for sub-pages within a section."
// ---------------------------------------------------------------------------

class SectionBottomBar extends StatelessWidget {
  const SectionBottomBar({super.key});

  @override
  Widget build(BuildContext context) {
    final shell = context.watch<ShellState>();

    if (!shell.hasSubPages || shell.inDetailView) return const SizedBox.shrink();

    final labels = subPageLabels(shell.activeSection);
    if (labels.isEmpty) return const SizedBox.shrink();

    return NavigationBar(
      selectedIndex: shell.activeSubPageIndex.clamp(0, labels.length - 1),
      onDestinationSelected: context.read<ShellState>().selectSubPage,
      labelBehavior: NavigationDestinationLabelBehavior.alwaysShow,
      height: 60,
      destinations: [
        for (final label in labels)
          NavigationDestination(
            icon: const SizedBox.shrink(), // icon-free; label carries meaning
            label: label,
          ),
      ],
    );
  }
}
