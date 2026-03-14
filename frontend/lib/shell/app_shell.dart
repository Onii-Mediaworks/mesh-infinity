// app_shell.dart
//
// The "shell" is the persistent chrome that wraps the entire app after the
// user has completed onboarding.  It contains the navigation controls
// (bottom bar on mobile, sidebar rail on tablet/desktop) and decides which
// content screen to show based on the active section.
//
// WHAT is "chrome" in this context?
// ----------------------------------
// In UI design, "chrome" refers to the structural scaffolding around the
// real content — navigation bars, toolbars, sidebars.  The AppShell is
// chrome: it never displays messages or files itself, it just provides the
// frame that lets the user navigate to the feature that does.
//
// RESPONSIVE LAYOUT — why three different layouts?
// ------------------------------------------------
// Mesh Infinity runs on phones (small screens), tablets (medium screens), and
// desktop computers (large screens).  A single fixed layout would look broken
// on at least two of those form factors:
//   - A bottom navigation bar is thumb-friendly on a phone but wastes space
//     on a wide monitor.
//   - A three-column desktop layout is useless on a phone where each column
//     would be only ~130 pixels wide.
//
// Flutter measures the available width at build time and chooses the right
// shell variant.  The two magic numbers are:
//   _kTabletBreak  = 760 px  — roughly a 7-inch tablet in portrait
//   _kDesktopBreak = 1200 px — a typical laptop/desktop window
//
// Anything below 760 px → MobileShell  (one pane + bottom nav bar)
// 760–1199 px           → TabletShell  (one pane + side rail)
// 1200 px and above     → DesktopShell (three panes: rail + list + detail)
//
// HOW does Flutter measure the available width?
// ---------------------------------------------
// MediaQuery.sizeOf(context) returns the logical pixel dimensions of the
// current window (or screen, on mobile).  "Logical pixels" are
// device-independent: a 760-logical-pixel boundary looks similar in physical
// size on every device regardless of screen density.  This is different from
// raw physical pixels, which vary wildly across device models.
//
// WHY check width in AppShell rather than in each screen?
// --------------------------------------------------------
// If every screen did its own breakpoint check, adding a new screen would
// require duplicating the breakpoint logic.  By doing it once in AppShell
// we guarantee that ALL screens get the same layout tier, which prevents
// mismatches (e.g. a NavigationBar at the bottom on a screen that expected
// a NavigationRail on the left).
//
// NAVIGATION WIDGET GLOSSARY (for readers new to Flutter)
// --------------------------------------------------------
// NavigationBar      — horizontal tab bar fixed at the bottom of the screen.
//                      Best for mobile; typically shows 3–5 destinations.
//                      Introduced in Material 3; replaces BottomNavigationBar.
//
// NavigationRail     — vertical icon bar fixed to the left edge.
//                      Optimal for tablets and desktop where the screen is
//                      wide enough to spare 72 px on the left.
//
// NavigationDrawer   — a full-width panel that slides in from the left side.
//                      Used for apps with many destinations; we don't use
//                      it because we only have 5.
//
// Three-pane layout  — the desktop pattern of: narrow icon rail | list panel
//                      (~300 px) | expanding detail panel.  Popularised by
//                      email clients (Outlook, Gmail desktop) and messaging
//                      apps (Slack, Teams).  All three panes are visible at
//                      once so the user never loses context.

import 'package:flutter/material.dart';
// material.dart provides the complete Material Design widget library:
// Scaffold, NavigationBar, NavigationRail, Row, Icon, etc.

import 'package:provider/provider.dart';
// provider.dart lets us read ShellState from anywhere in the widget subtree
// without threading it through every constructor manually.

import 'shell_state.dart';
// Our own navigation state — which section is active and what is selected.

// Feature screens — each of these is the "list" view for its section.
import '../features/messaging/screens/conversation_list_screen.dart';
import '../features/messaging/screens/thread_screen.dart';
import '../features/files/screens/transfers_screen.dart';
import '../features/peers/screens/peer_list_screen.dart';
import '../features/peers/screens/peer_detail_screen.dart';
import '../features/network/screens/network_screen.dart';
import '../features/settings/screens/settings_screen.dart';

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

/// Width of the list pane on desktop (the middle column showing, e.g., the
/// conversation list).  300 pixels is a comfortable size — wide enough to
/// show sender names and message previews without eating too much screen real
/// estate.
const double _kSidebarWidth = 300.0;

/// Below this width (pixels) the app uses the mobile layout.
/// Above it (and below _kDesktopBreak) the tablet layout is used.
/// 760 px matches a typical 7-inch tablet held in portrait — the smallest
/// form factor where a side rail makes ergonomic sense.
const double _kTabletBreak = 760.0;

/// At this width and above the full three-pane desktop layout is used.
/// 1200 px is a common "laptop minimum" width and leaves room for all three
/// columns without them feeling cramped.
const double _kDesktopBreak = 1200.0;

// ---------------------------------------------------------------------------
// AppShell — the responsive entry point
// ---------------------------------------------------------------------------

/// AppShell is the top-level widget rendered after onboarding completes.
/// It reads the current screen width and delegates to the appropriate layout
/// class.
///
/// What is a StatelessWidget?
/// --------------------------
/// A StatelessWidget is a Flutter widget that holds no mutable data of its
/// own.  It just reads inputs (here: screen width) and returns a description
/// of the UI.  Every time something it depends on changes Flutter calls
/// build() again to get a fresh description, but the widget object itself
/// never mutates.
///
/// AppShell is an appropriate StatelessWidget because:
///   - It owns no state — ShellState (in shell_state.dart) owns all the
///     navigation state.
///   - It just reads screen width and picks a layout.  Width is provided by
///     MediaQuery, which is already part of Flutter's context machinery.
///
/// Why does AppShell NOT use LayoutBuilder?
/// ----------------------------------------
/// LayoutBuilder provides the constraints given by a parent widget, which
/// can differ from the actual window size if the widget is placed inside a
/// container.  MediaQuery.sizeOf gives the whole-window size, which is what
/// we want for top-level layout decisions.  Using LayoutBuilder here would
/// risk using a constrained sub-window size, breaking the breakpoints.
class AppShell extends StatelessWidget {
  const AppShell({super.key});

  @override
  Widget build(BuildContext context) {
    // MediaQuery.sizeOf(context) returns the screen (or window) dimensions.
    // We only care about width for choosing the layout variant.
    //
    // sizeOf() is a static method introduced in Flutter 3.10 as a performance
    // improvement over the older MediaQuery.of(context).size.  sizeOf() only
    // triggers a rebuild when the SIZE changes, not when any other
    // MediaQuery property (like text scale or accessibility settings) changes.
    // This avoids unnecessary rebuilds of the entire shell on every keyboard
    // pop-up or font-size change.
    final width = MediaQuery.sizeOf(context).width;

    // Check from largest to smallest so the most capable layout wins first.
    // If the window is >= 1200 px wide we always prefer the full desktop layout,
    // even if it's technically also >= 760 px (it satisfies both conditions).
    if (width >= _kDesktopBreak) return const _DesktopShell();
    if (width >= _kTabletBreak) return const _TabletShell();
    return const _MobileShell();
  }
}

// ---------------------------------------------------------------------------
// Desktop: sidebar + list pane + detail pane  (three-pane layout)
// ---------------------------------------------------------------------------
// The three-pane layout is the gold standard for productivity apps on wide
// screens (think: Outlook, Slack, VS Code).
//   Pane 1 — narrow vertical rail with section icons on the far left.
//   Pane 2 — a 300 px list (conversations, peers, etc.).
//   Pane 3 — the rest of the screen shows the selected item's detail view.
// All three panes are visible simultaneously, so the user can scan the list
// and the detail without any back/forward navigation.
//
// The panes are assembled inside a Row widget.  In Flutter, Row is a
// horizontal layout container — it places its children side by side from left
// to right.  Each child can have a fixed width (SizedBox), or expand to fill
// remaining space (Expanded).
//
// Visual representation for a 1400 px wide window:
//
//  ┌──────────┬─────────────────────────┬────────────────────────────────┐
//  │  Rail    │   List (300 px)         │   Detail (fills remainder)     │
//  │  ~72 px  │                         │                                │
//  │  [Chat]  │  > Alice     2 min ago  │   Alice                        │
//  │  [Files] │    Hello world…         │   ┌─────────────────────────┐  │
//  │  [Peers] │  > Bob       1 hr ago   │   │ Hey how are you?        │  │
//  │  [Net]   │    What's up?           │   └─────────────────────────┘  │
//  │  [Set]   │                         │                                │
//  └──────────┴─────────────────────────┴────────────────────────────────┘

class _DesktopShell extends StatelessWidget {
  const _DesktopShell();

  @override
  Widget build(BuildContext context) {
    // context.watch<ShellState>() does two things:
    //   1. Reads the current ShellState from the Provider above us in the tree.
    //   2. Subscribes this widget to ShellState changes — whenever the active
    //      section or selection changes, Flutter automatically calls build()
    //      again so the UI updates.
    //
    // The difference between watch and read:
    //   context.watch<T>()  — subscribe + read.  Causes rebuild on change.
    //   context.read<T>()   — read once.  Does NOT cause rebuild.
    // We use watch here because the shell itself must re-render every time the
    // active section or selected item changes.
    final shell = context.watch<ShellState>();

    // Scaffold is the Material Design page skeleton.  It provides a surface
    // colour and handles system UI insets (status bar, notches, etc.).
    // Even in a desktop app, Scaffold is used because it integrates with
    // Flutter's theming system and handles things like keyboard avoidance.
    return Scaffold(
      body: Row(
        // A Row lays out children left-to-right, which is how three panes
        // sit side by side.
        // The default crossAxisAlignment is CrossAxisAlignment.center, but
        // for full-height panes we need them all to stretch to the Row's
        // full height — that's the default for Scaffold body, so it works
        // without overriding.
        children: [
          // Pane 1 — navigation rail (icons + labels down the left edge).
          // We pass shell.selectSection as the callback so tapping a rail
          // item updates ShellState, which in turn rebuilds this widget.
          _SectionRail(selected: shell.activeSection, onSelect: shell.selectSection),

          // VerticalDivider draws a 1-pixel hairline between panes so they
          // look visually separated.  width: 1 means the divider takes up
          // exactly 1 logical pixel of horizontal space (plus the line itself).
          const VerticalDivider(width: 1),

          // Pane 2 — the list view for the active section, fixed at 300 px.
          // SizedBox enforces the exact width; _listPaneFor returns the right
          // screen widget for the active section.
          // SizedBox with only a width constraint: the child's height is
          // unconstrained and the Row will stretch it to the full height.
          SizedBox(
            width: _kSidebarWidth,
            child: _listPaneFor(shell.activeSection, context),
          ),

          const VerticalDivider(width: 1),

          // Pane 3 — the detail view.  Expanded fills the remaining horizontal
          // space automatically.  _detailPaneFor checks whether something is
          // selected and shows either the real detail screen or a placeholder.
          //
          // Expanded is a Flex-family widget that tells a Row/Column child:
          // "take all available space that your siblings didn't claim."
          // Here: total_width minus rail_width minus 300 minus dividers.
          Expanded(child: _detailPaneFor(shell, context)),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Tablet: side rail + single content pane  (two-pane layout)
// ---------------------------------------------------------------------------
// On a tablet there is enough width for a navigation rail on the left, but
// NOT enough for a permanent detail pane alongside the list.  Tapping an item
// in the list navigates the user into a full-screen detail view instead.
// This mirrors the tablet layouts of popular apps like Gmail.
//
// "Push navigation" means a new screen is pushed onto Flutter's Navigator
// stack.  The user sees an animated slide-in transition and a back arrow
// appears.  Pressing back (or swiping) pops the detail screen and returns
// to the list.  This is different from the desktop three-pane approach where
// detail and list coexist without any navigation stack changes.

class _TabletShell extends StatelessWidget {
  const _TabletShell();

  @override
  Widget build(BuildContext context) {
    final shell = context.watch<ShellState>();

    return Scaffold(
      body: Row(
        children: [
          // Same navigation rail as desktop — icons on the left edge.
          // The rail is identical regardless of whether we're in tablet or
          // desktop mode; only the right-side content differs.
          _SectionRail(selected: shell.activeSection, onSelect: shell.selectSection),

          const VerticalDivider(width: 1),

          // The single content pane expands to fill all remaining width.
          // No detail pane — selecting an item triggers push navigation.
          // Expanded ensures this pane claims all pixels the rail didn't use.
          Expanded(child: _listPaneFor(shell.activeSection, context)),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Mobile: bottom navigation bar + single full-screen pane
// ---------------------------------------------------------------------------
// On a phone the screen is too narrow for any side navigation.  Instead,
// we use a NavigationBar (Material 3's bottom tab bar) that sits at the very
// bottom of the screen where thumbs naturally reach.
// The content area is a single screen — the user drills into detail views
// by tapping items (push navigation), just like most native mobile apps.
//
// WHY is the nav bar at the bottom on mobile?
// --------------------------------------------
// Ergonomic research (and Apple/Google UX guidelines) show that on tall
// phones the bottom third of the screen is the most comfortable reach zone
// for the thumb when holding the phone one-handed.  Top navigation
// (common in older web designs) forces uncomfortable stretching.
//
// NavigationBar vs BottomNavigationBar
// -------------------------------------
// BottomNavigationBar is the older Material 2 widget; it still works but
// lacks Material 3 visuals.  NavigationBar is the Material 3 replacement
// with a pill-shaped indicator around the active destination, better colour
// semantics, and motion polish.  We use NavigationBar throughout.

class _MobileShell extends StatelessWidget {
  const _MobileShell();

  @override
  Widget build(BuildContext context) {
    final shell = context.watch<ShellState>();

    // Scaffold on mobile accepts a `bottomNavigationBar` parameter.
    // Flutter automatically shifts the body content upward so it is not
    // obscured by the navigation bar (this is called "system UI inset
    // avoidance").  We don't need to add any manual padding.
    return Scaffold(
      // The full-screen content area for the active section.
      // This occupies the entire screen above the navigation bar.
      body: _listPaneFor(shell.activeSection, context),

      // NavigationBar is Material 3's equivalent of the older
      // BottomNavigationBar.  It shows labelled icon destinations at the
      // bottom of the screen.
      bottomNavigationBar: NavigationBar(
        // Convert the enum value to an integer index so NavigationBar knows
        // which icon to highlight.  AppSection.values is the list of all
        // enum values in declaration order.
        //
        // indexOf() returns the position of an element in a list.  Because
        // AppSection.values returns [chat, files, peers, network, settings]
        // in that order, indexOf(AppSection.peers) returns 2.
        selectedIndex: AppSection.values.indexOf(shell.activeSection),

        // When the user taps a tab, convert the index back to an enum value
        // and tell ShellState to switch sections.
        //
        // AppSection.values[i] is the reverse conversion: index 2 → AppSection.peers.
        // This callback is typed as `void Function(int)` which matches
        // NavigationBar's `onDestinationSelected` parameter type.
        onDestinationSelected: (i) => shell.selectSection(AppSection.values[i]),

        destinations: const [
          // Each NavigationDestination pairs an icon with a text label.
          // The *_outlined variants are unselected; the filled variants would
          // be shown when selected (NavigationBar handles that automatically
          // using the selectedIndex).
          //
          // The convention of "outlined = inactive, filled = active" is a
          // Material 3 design guideline that makes the selected tab visually
          // stand out without relying on colour alone (important for
          // accessibility and colour-blind users).
          NavigationDestination(icon: Icon(Icons.chat_bubble_outline), label: 'Chat'),
          NavigationDestination(icon: Icon(Icons.folder_outlined),     label: 'Files'),
          NavigationDestination(icon: Icon(Icons.people_outline),      label: 'Peers'),
          NavigationDestination(icon: Icon(Icons.router_outlined),     label: 'Network'),
          NavigationDestination(icon: Icon(Icons.settings_outlined),   label: 'Settings'),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _SectionRail — the vertical navigation rail used on tablet and desktop
// ---------------------------------------------------------------------------
// NavigationRail is Material 3's vertical counterpart to NavigationBar.
// It sits along the left edge of the screen and shows section icons with
// optional labels beneath them.  It is narrower than a full sidebar drawer,
// making it ideal when horizontal space is limited (tablets) or when the
// designer wants the content to dominate (desktop).

class _SectionRail extends StatelessWidget {
  const _SectionRail({required this.selected, required this.onSelect});

  /// Which section is currently active — used to highlight the correct icon.
  final AppSection selected;

  /// Callback fired when the user taps a rail destination.
  /// ValueChanged<T> is Dart shorthand for `void Function(T value)`.
  final ValueChanged<AppSection> onSelect;

  @override
  Widget build(BuildContext context) {
    return NavigationRail(
      // Convert enum → index so the rail can highlight the correct icon.
      selectedIndex: AppSection.values.indexOf(selected),

      // Convert index → enum and call the callback when the user taps.
      onDestinationSelected: (i) => onSelect(AppSection.values[i]),

      // NavigationRailLabelType.all shows text labels under every icon
      // at all times (not just the selected one), which improves
      // discoverability for new users.
      labelType: NavigationRailLabelType.all,

      destinations: const [
        // Each destination has two icon states:
        //   icon         — displayed when this section is NOT active.
        //   selectedIcon — displayed when this section IS active.
        // The outlined variants convey "inactive"; the filled variants
        // convey "active" — a standard Material 3 icon convention.
        NavigationRailDestination(
          icon: Icon(Icons.chat_bubble_outline),
          selectedIcon: Icon(Icons.chat_bubble),
          label: Text('Chat'),
        ),
        NavigationRailDestination(
          icon: Icon(Icons.folder_outlined),
          selectedIcon: Icon(Icons.folder),
          label: Text('Files'),
        ),
        NavigationRailDestination(
          icon: Icon(Icons.people_outline),
          selectedIcon: Icon(Icons.people),
          label: Text('Peers'),
        ),
        NavigationRailDestination(
          icon: Icon(Icons.router_outlined),
          selectedIcon: Icon(Icons.router),
          label: Text('Network'),
        ),
        NavigationRailDestination(
          icon: Icon(Icons.settings_outlined),
          selectedIcon: Icon(Icons.settings),
          label: Text('Settings'),
        ),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// Content routing helpers
// ---------------------------------------------------------------------------
// These two free functions (not methods on any class) are pure mapping
// functions: given a section, return the right Widget.  Keeping them as
// top-level functions (rather than inlining them) makes the Shell build()
// methods shorter and easier to read.
//
// "Free function" means it is defined at the top level of the file, not
// inside any class.  In Dart this is perfectly valid — not everything needs
// to be a class member.  Functions that don't need access to `this` are
// better written as free functions because they are easier to test and reuse.
//
// Both functions start with `_` (underscore), making them *file-private*:
// only code in this file can call them.  That's appropriate because they are
// implementation details of the shell — nothing outside this file should
// need to call _listPaneFor() directly.

/// Returns the "list" screen for the given section.
/// This is always shown — on all form factors — as the primary content pane.
///
/// The [context] parameter is accepted for potential future use (e.g. if a
/// screen needs to read a Provider value here) even though it is not used now.
Widget _listPaneFor(AppSection section, BuildContext context) {
  // Dart's switch expression (introduced in Dart 3) exhaustively matches
  // every enum value.  If a new AppSection is added, the compiler will
  // produce an error here until a matching case is added.
  //
  // This is called a "switch expression" (not "switch statement") because it
  // returns a value.  The `=>` syntax means "evaluate the right side and
  // use it as the result for this case".
  //
  // All results are `const` widgets.  `const` in Flutter means the widget
  // object is created at compile time and reused across rebuilds — a free
  // performance optimisation for widgets that never need constructor arguments
  // to vary.
  return switch (section) {
    AppSection.chat     => const ConversationListScreen(),
    AppSection.files    => const TransfersScreen(),
    AppSection.peers    => const PeerListScreen(),
    AppSection.network  => const NetworkScreen(),
    AppSection.settings => const SettingsScreen(),
  };
}

/// Returns the "detail" widget for the given shell state.
/// Only used on desktop where the detail pane is always visible.
/// When nothing is selected, shows a friendly placeholder so the empty
/// pane doesn't look broken.
///
/// The ternary pattern used here:
///   condition ? valueIfTrue : valueIfFalse
/// is Dart's conditional expression.  It is equivalent to an if/else but
/// produces a value that can be returned directly.
Widget _detailPaneFor(ShellState shell, BuildContext context) {
  return switch (shell.activeSection) {
    // Chat section: show the message thread for the selected room, or a
    // placeholder if no room is selected yet.
    //
    // shell.selectedRoomId != null means the user has tapped a conversation
    // in the list pane.  The `!` at the end of selectedRoomId! is the
    // null-assertion operator: it tells Dart "I know this is non-null; treat
    // it as String (not String?)."  It is safe here because we just checked
    // `!= null` on the line above.
    AppSection.chat => shell.selectedRoomId != null
        ? ThreadScreen(roomId: shell.selectedRoomId!)
        : const _EmptyDetail(icon: Icons.chat_bubble_outline, label: 'Select a conversation'),

    // Peers section: show the peer detail card, or a placeholder.
    AppSection.peers => shell.selectedPeerId != null
        ? PeerDetailScreen(peerId: shell.selectedPeerId!)
        : const _EmptyDetail(icon: Icons.people_outline, label: 'Select a peer'),

    // Files, Network, Settings have no persistent "detail" concept — the
    // list screen IS the full view.  Shrink the detail pane to nothing.
    //
    // SizedBox.shrink() creates a zero-size box — it takes up no space.
    // This effectively hides the detail pane for these sections without
    // removing it from the tree (which would cause unnecessary layout work).
    //
    // The `_` wildcard pattern matches any remaining enum values.  It is
    // Dart's equivalent of a switch `default:` case.
    _ => const SizedBox.shrink(),
  };
}

// ---------------------------------------------------------------------------
// _EmptyDetail — placeholder shown when no item is selected in the detail pane
// ---------------------------------------------------------------------------

/// A centred icon + label displayed in the desktop detail pane when the user
/// hasn't selected anything yet.  Without this, the right-hand column would
/// just be a blank white rectangle, which looks unfinished.
class _EmptyDetail extends StatelessWidget {
  const _EmptyDetail({required this.icon, required this.label});

  /// The icon to show (e.g. a chat bubble for the Chat section).
  final IconData icon;

  /// The short hint text below the icon (e.g. "Select a conversation").
  final String label;

  @override
  Widget build(BuildContext context) {
    return Center(
      // Center positions its child at the exact middle of the available space.
      child: Column(
        // MainAxisSize.min makes the column only as tall as its children,
        // rather than stretching to fill the whole screen.  Combined with
        // Center, this produces a compact centred cluster.
        mainAxisSize: MainAxisSize.min,
        children: [
          // Large, muted icon — uses the theme's "outline" colour which is
          // intentionally low-contrast so it reads as a hint, not content.
          Icon(icon, size: 48, color: Theme.of(context).colorScheme.outline),

          // Small vertical gap between icon and label.
          const SizedBox(height: 12),

          // Short descriptive label in the same muted colour.
          Text(
            label,
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(
              color: Theme.of(context).colorScheme.outline,
            ),
          ),
        ],
      ),
    );
  }
}
