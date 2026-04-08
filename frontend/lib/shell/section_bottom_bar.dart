// section_bottom_bar.dart
//
// SectionBottomBar — sub-page switcher shown at the bottom of the screen
// for sections that have multiple pages.
//
// WHAT THIS IS FOR:
// -----------------
// Several sections (Chat, Garden, Files, Contacts, Services, Network) have
// multiple "sub-pages" — for example, Chat has "Rooms" and "Direct", Garden
// has "Channels", "Feed", and "Explore".  These sub-pages are peer tabs
// *within* a section, distinct from the top-level section navigation (which
// lives in the drawer).
//
// On mobile the sub-page switcher lives at the bottom of the screen as a
// Material 3 NavigationBar.  This is consistent with the Material 3 pattern
// where a NavigationBar at the bottom handles secondary navigation within
// a top-level destination.
//
// WHEN THE BAR IS HIDDEN:
// -----------------------
// The bar hides itself in two situations to avoid cluttering the screen:
//
//   1. The active section has no sub-pages (You, Settings).
//      These sections have a single root screen and no sub-page tabs.
//
//   2. The user has navigated into a "detail view" (e.g. a chat thread,
//      a contact detail screen, a file transfer detail).
//      Per spec: "The bottom bar is hidden in drilled-in detail views."
//      Hiding the bar gives the detail content the full vertical space and
//      avoids confusion (the sub-page tabs are not relevant while inside
//      a detail).
//
// ICON-FREE DESTINATIONS:
// -----------------------
// SectionBottomBar uses label-only destinations (icons are hidden via an
// invisible SizedBox.shrink()).  This keeps the bar compact at 60 px height
// and follows the UX decision that sub-page tabs are textual — the section
// icon (in the drawer) already provides the section-level iconography.
//
// STATE:
// ------
// Reads from ShellState (context.watch) for the active section, active
// sub-page index, and detail-view flag.  Writes back to ShellState
// (context.read) via selectSubPage when the user taps a destination.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'shell_state.dart';

/// Bottom navigation bar for switching sub-pages within the current section.
///
/// Renders nothing (zero-height SizedBox) when:
///   - The active section has no sub-pages ([ShellState.hasSubPages] is false).
///   - The user is inside a detail view ([ShellState.inDetailView] is true).
///
/// Sub-page labels are provided by [subPageLabels] which maps each
/// [AppSection] to its list of tab names.
class SectionBottomBar extends StatelessWidget {
  const SectionBottomBar({super.key});

  @override
  Widget build(BuildContext context) {
    // Watch the full ShellState so any navigation change rebuilds this widget.
    final shell = context.watch<ShellState>();

    // Guard 1: no sub-pages for this section, or we're in a detail view.
    // Both return a zero-size widget so the bar takes no space and is not
    // included in the visual layout.
    if (!shell.hasSubPages || shell.inDetailView) return const SizedBox.shrink();

    // Resolve the label list for the current section.
    final labels = subPageLabels(shell.activeSection);

    // Guard 2: empty label list (defensive check — normally caught by guard 1
    // since hasSubPages is derived from subPageCount which mirrors this list).
    if (labels.isEmpty) return const SizedBox.shrink();

    return NavigationBar(
      // clamp guards against a stale index being out of bounds when the
      // section changes before a rebuild (e.g. rapid section switching).
      selectedIndex: shell.activeSubPageIndex.clamp(0, labels.length - 1),
      // Write directly to ShellState; context.read is used here because
      // we don't need to observe this provider — we're inside a build method
      // that already watches the full ShellState above.
      onDestinationSelected: context.read<ShellState>().selectSubPage,
      // Always show text labels so the bar is self-explanatory even without
      // icons.  Many Material 3 apps hide labels to save space but Mesh
      // Infinity's sub-page names are the primary navigation cue here.
      labelBehavior: NavigationDestinationLabelBehavior.alwaysShow,
      // 60 px is the minimum height for readable label-only destinations.
      height: 60,
      destinations: [
        for (final label in labels)
          NavigationDestination(
            // icon is required by NavigationDestination but we deliberately
            // use an invisible zero-size widget so only the text is visible.
            // Sub-page context is communicated by label, not icon.
            icon: const SizedBox.shrink(),
            label: label,
          ),
      ],
    );
  }
}
