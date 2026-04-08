// app_shell.dart
//
// AppShell — the responsive navigation shell for the whole app.
//
// LAYOUT OVERVIEW (three responsive breakpoints):
// ------------------------------------------------
//
//   Mobile  (<760px)  — hamburger menu opens a slide-in drawer overlay.
//                       Section bottom bar appears for sub-page navigation.
//
//   Tablet  (760–1199px) — NavDrawer rendered permanently on the left side.
//                          Section bottom bar appears for sub-pages.
//
//   Desktop (≥1200px) — NavDrawer permanently on left.
//                       Section bottom bar for sub-pages.
//                       Optional 3-pane layout: list + detail for Chat/Contacts.
//
// NAVIGATION MODEL:
// -----------------
// Section switching  → always done via the NavDrawer (left panel).
// Sub-page switching → always done via SectionBottomBar (bottom).
// Detail views       → opened by tapping an item; bottom bar hides.
//
// WHY THREE SHELLS INSTEAD OF ADAPTIVE CODE IN ONE?
// --------------------------------------------------
// Keeping _MobileShell, _WideShell, and _DesktopShell as separate widgets
// means each one is simple and independent.  AppShell just picks which one
// to instantiate based on the screen width.  The alternative (one widget with
// conditional children) is harder to read and test.
//
// BREAKPOINTS:
//   760px  — NavDrawer becomes permanently visible (replaces hamburger).
//   1200px — Desktop layout with optional 3-pane mode.
// These match the Material 3 adaptive breakpoints for compact/medium/expanded.
//
// SECURITY STATUS BAR (§22.4.1):
// --------------------------------
// _BodyWithSecurityBar wraps every section body with SecurityStatusBar at the
// top.  This ensures the security status bar is always visible regardless of
// which section is active.  It is positioned above the section content,
// below the AppBar.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'package:qr_flutter/qr_flutter.dart';

import 'shell_state.dart';
import 'nav_drawer.dart';
import 'section_bottom_bar.dart';
import 'security_status_bar.dart';
import '../features/settings/settings_state.dart';

// Section screens and navigation targets
import '../features/chat/rooms_screen.dart';
import '../features/chat/direct_screen.dart';
import '../features/garden/channels_screen.dart';
import '../features/garden/feed_screen.dart';
import '../features/garden/explore_screen.dart';
import '../features/files/screens/transfers_screen.dart';
import '../features/files/shared_screen.dart';
import '../features/contacts/all_contacts_screen.dart';
import '../features/contacts/online_screen.dart';
import '../features/contacts/requests_screen.dart';
import '../features/services/my_services_screen.dart';
import '../features/services/browse_screen.dart';
import '../features/services/hosting_screen.dart';
import '../features/you/you_screen.dart';
import '../features/network/status_screen.dart';
import '../features/network/nodes_screen.dart';
import '../features/network/transports_screen.dart';
import '../features/settings/screens/settings_screen.dart';
import '../features/messaging/screens/thread_screen.dart';
import '../features/messaging/screens/conversation_search_screen.dart';
import '../features/messaging/screens/message_requests_screen.dart';
import '../features/messaging/screens/create_room_screen.dart';
import '../features/contacts/screens/contact_detail_screen.dart';
import '../features/contacts/screens/pair_contact_screen.dart';

// ---------------------------------------------------------------------------
// Layout breakpoints
// ---------------------------------------------------------------------------

/// Below this width, the NavDrawer is a slide-in overlay (hamburger button).
/// At or above this width, it is rendered permanently on the left.
const double _kPermanentDrawerBreak = 760.0;

/// At or above this width, the Desktop 3-pane layout is used.
const double _kDesktopBreak = 1200.0;

/// Fixed width of the permanent NavDrawer panel on tablet and desktop.
const double _kDrawerWidth = 280.0;

// ---------------------------------------------------------------------------
// AppShell — top-level responsive router
// ---------------------------------------------------------------------------

/// Selects the appropriate shell layout based on the current screen width.
///
/// This widget is stateless — it re-evaluates on every build, which means
/// the layout automatically adapts when the user resizes the window (desktop)
/// or rotates the device (tablet).
class AppShell extends StatelessWidget {
  const AppShell({super.key});

  @override
  Widget build(BuildContext context) {
    final width = MediaQuery.sizeOf(context).width;

    if (width >= _kPermanentDrawerBreak) {
      // Wide enough for a permanent drawer — choose between wide and desktop.
      return width >= _kDesktopBreak
          ? const _DesktopShell()
          : const _WideShell();
    }
    // Narrow screen — hamburger-based mobile layout.
    return const _MobileShell();
  }
}

// ---------------------------------------------------------------------------
// Mobile shell — hamburger drawer + bottom bar
// ---------------------------------------------------------------------------

/// Navigation shell for narrow screens (<760px).
///
/// The NavDrawer is a Scaffold drawer (overlay).  The AppBar shows a hamburger
/// icon that opens it.  The SectionBottomBar handles sub-page navigation.
class _MobileShell extends StatelessWidget {
  const _MobileShell();

  @override
  Widget build(BuildContext context) {
    final shell = context.watch<ShellState>();
    final section = shell.activeSection;
    final title = _sectionTitle(section);

    return Scaffold(
      appBar: AppBar(
        // Builder is needed because Scaffold.of(context) must be called in a
        // context that is a descendant of the Scaffold — Builder creates that
        // descendant context.
        leading: Builder(
          builder: (ctx) => IconButton(
            icon: const Icon(Icons.menu),
            tooltip: 'Menu',
            onPressed: () => Scaffold.of(ctx).openDrawer(),
          ),
        ),
        title: Text(title),
        // Section-specific actions (search, add, etc.) — computed based on
        // which section is active.
        actions: _appBarActions(context, shell),
      ),
      // The NavDrawer is an overlay drawer on mobile.  Flutter auto-handles
      // the swipe-from-left gesture and the scrim tap to dismiss.
      drawer: const NavDrawer(),
      body: _BodyWithSecurityBar(),
      bottomNavigationBar: const SectionBottomBar(),
    );
  }
}

// ---------------------------------------------------------------------------
// Wide (tablet) shell — permanent drawer + content pane
// ---------------------------------------------------------------------------

/// Navigation shell for medium screens (760–1199px).
///
/// The NavDrawer is rendered inline in a Row rather than as an overlay.
/// A VerticalDivider separates the drawer from the content area.
class _WideShell extends StatelessWidget {
  const _WideShell();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Row(
        children: [
          // Fixed-width drawer panel — always visible, never collapses.
          const SizedBox(
            width: _kDrawerWidth,
            child: _PermanentDrawerFrame(child: NavDrawer()),
          ),
          const VerticalDivider(width: 1),
          // The content area is a nested Scaffold so it gets its own
          // bottomNavigationBar independently of the outer Scaffold.
          Expanded(
            child: Scaffold(
              body: _BodyWithSecurityBar(),
              bottomNavigationBar: const SectionBottomBar(),
            ),
          ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Desktop shell — permanent drawer + content + optional detail pane
// ---------------------------------------------------------------------------

/// Navigation shell for wide screens (≥1200px).
///
/// Like _WideShell but also supports a 3-pane layout for Chat and Contacts:
///   pane 1 — NavDrawer (280px)
///   pane 2 — Section list (320px)
///   pane 3 — Detail view (remaining space)
///
/// When no item is selected (or the active section doesn't support 3-pane),
/// the section content expands to fill panes 2+3.
class _DesktopShell extends StatelessWidget {
  const _DesktopShell();

  @override
  Widget build(BuildContext context) {
    final shell = context.watch<ShellState>();

    // 3-pane is active when a specific item is selected in Chat or Contacts.
    // Other sections always use the single-pane layout.
    final showDetailPane =
        (shell.activeSection == AppSection.chat && shell.selectedRoomId != null) ||
        (shell.activeSection == AppSection.contacts && shell.selectedPeerId != null);

    return Scaffold(
      body: Row(
        children: [
          const SizedBox(
            width: _kDrawerWidth,
            child: _PermanentDrawerFrame(child: NavDrawer()),
          ),
          const VerticalDivider(width: 1),
          if (showDetailPane) ...[
            // 3-pane: fixed-width list pane on the left, detail pane on the right.
            SizedBox(
              width: 320,
              child: Scaffold(
                body: _SectionBody(),
                bottomNavigationBar: const SectionBottomBar(),
              ),
            ),
            const VerticalDivider(width: 1),
            // Detail pane fills remaining space.
            Expanded(child: _detailPane(shell)),
          ] else
            // Single-pane: section body fills all remaining space.
            Expanded(
              child: Scaffold(
                body: _SectionBody(),
                bottomNavigationBar: const SectionBottomBar(),
              ),
            ),
        ],
      ),
    );
  }

  /// Build the detail pane widget for the currently active section.
  ///
  /// Returns an empty-state placeholder if no item is selected (which should
  /// not happen in practice since showDetailPane guards the call, but this is
  /// a safety fallback).
  Widget _detailPane(ShellState shell) {
    return switch (shell.activeSection) {
      AppSection.chat => shell.selectedRoomId != null
          ? ThreadScreen(roomId: shell.selectedRoomId!)
          : const _EmptyDetail(icon: Icons.chat_bubble_outline, label: 'Select a chat'),
      AppSection.contacts => shell.selectedPeerId != null
          ? ContactDetailScreen(peerId: shell.selectedPeerId!)
          : const _EmptyDetail(icon: Icons.people_outline, label: 'Select a contact'),
      // Non-3-pane sections never reach here; return empty for completeness.
      _ => const SizedBox.shrink(),
    };
  }
}

// ---------------------------------------------------------------------------
// _PermanentDrawerFrame — Material wrapper for inline NavDrawer
// ---------------------------------------------------------------------------

/// Wraps NavDrawer in a Material layer so it renders correctly when placed
/// inline (as a Row child) rather than as a Scaffold drawer overlay.
///
/// Without this wrapper the drawer background colour would be transparent,
/// making the divider line disappear and the drawer text unreadable.
class _PermanentDrawerFrame extends StatelessWidget {
  const _PermanentDrawerFrame({required this.child});
  final Widget child;

  @override
  Widget build(BuildContext context) {
    // Use drawerTheme.backgroundColor if configured; fall back to surface.
    // This matches the colour the Scaffold uses for its own drawer overlay.
    return Material(
      color: Theme.of(context).drawerTheme.backgroundColor ??
          Theme.of(context).colorScheme.surface,
      child: child,
    );
  }
}

// ---------------------------------------------------------------------------
// _BodyWithSecurityBar — SecurityStatusBar above the section body (§22.4.1)
// ---------------------------------------------------------------------------

/// Stacks the [SecurityStatusBar] above the section content.
///
/// The SecurityStatusBar shows a coloured banner when a security condition
/// is active (exit-node exposure, elevated threat context, LoSec mode).
/// It animates to height 0 when no condition is active.
class _BodyWithSecurityBar extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        // SecurityStatusBar is always in the widget tree; it animates to
        // height 0 when inactive so there is no visual gap.
        const SecurityStatusBar(),
        Expanded(child: _SectionBody()),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// _SectionBody — routes to the correct screen for section + sub-page
// ---------------------------------------------------------------------------

/// Renders the correct screen widget for the currently active
/// [AppSection] + sub-page index combination.
///
/// Each section maps to its own set of sub-page widgets via a nested switch.
/// When the section changes, Flutter replaces the entire subtree so there is
/// no stale widget state from the previous section.
class _SectionBody extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    final shell = context.watch<ShellState>();

    return switch (shell.activeSection) {
      AppSection.chat => switch (shell.chatSubPage) {
          ChatSubPage.rooms => const RoomsScreen(),
          ChatSubPage.direct => const DirectScreen(),
        },
      AppSection.garden => switch (shell.gardenSubPage) {
          GardenSubPage.channels => const ChannelsScreen(),
          GardenSubPage.feed => const GardenFeedScreen(),
          GardenSubPage.explore => const GardenExploreScreen(),
        },
      AppSection.files => switch (shell.filesSubPage) {
          FilesSubPage.transfers => const TransfersScreen(),
          FilesSubPage.shared => const FilesSharedScreen(),
        },
      AppSection.contacts => switch (shell.contactsSubPage) {
          ContactsSubPage.all => const AllContactsScreen(),
          ContactsSubPage.online => const OnlineScreen(),
          ContactsSubPage.requests => const RequestsScreen(),
        },
      AppSection.services => switch (shell.servicesSubPage) {
          ServicesSubPage.myServices => const MyServicesScreen(),
          ServicesSubPage.browse => const BrowseScreen(),
          ServicesSubPage.hosting => const HostingScreen(),
        },
      AppSection.you => const YouScreen(),
      AppSection.network => switch (shell.networkSubPage) {
          NetworkSubPage.status => const NetworkStatusScreen(),
          NetworkSubPage.nodes => const NodesScreen(),
          NetworkSubPage.transports => const TransportsScreen(),
        },
      AppSection.settings => const SettingsScreen(),
    };
  }
}

// ---------------------------------------------------------------------------
// AppBar helpers
// ---------------------------------------------------------------------------

/// Return the display title for [section] shown in the mobile AppBar.
String _sectionTitle(AppSection section) => switch (section) {
  AppSection.chat => 'Chat',
  AppSection.garden => 'Garden',
  AppSection.files => 'Files',
  AppSection.contacts => 'Contacts',
  AppSection.services => 'Services',
  AppSection.you => 'You',
  AppSection.network => 'Network',
  AppSection.settings => 'Settings',
};

/// Return section-specific AppBar action buttons for the mobile shell.
///
/// Desktop and tablet layouts don't have an AppBar, so these actions are
/// only shown on mobile where the AppBar is visible.
List<Widget> _appBarActions(BuildContext context, ShellState shell) {
  return switch (shell.activeSection) {
    AppSection.chat => [
        IconButton(
          icon: const Icon(Icons.search),
          tooltip: 'Search messages',
          onPressed: () => Navigator.push(
            context,
            MaterialPageRoute(builder: (_) => const ConversationSearchScreen()),
          ),
        ),
        IconButton(
          icon: const Icon(Icons.mark_unread_chat_alt_outlined),
          tooltip: 'Message requests',
          onPressed: () => Navigator.push(
            context,
            MaterialPageRoute(builder: (_) => const MessageRequestsScreen()),
          ),
        ),
        IconButton(
          icon: const Icon(Icons.edit_outlined),
          tooltip: 'New room',
          onPressed: () => Navigator.push(
            context,
            MaterialPageRoute(builder: (_) => const CreateRoomScreen()),
          ),
        ),
      ],
    AppSection.contacts => [
        IconButton(
          icon: const Icon(Icons.person_add_outlined),
          tooltip: 'Add contact',
          onPressed: () => Navigator.push(
            context,
            MaterialPageRoute(builder: (_) => const PairContactScreen()),
          ),
        ),
      ],
    AppSection.you => [
        // QR code shortcut — opens the peer ID as a QR code in a bottom sheet
        // for easy in-person sharing without navigating to YouScreen first.
        IconButton(
          icon: const Icon(Icons.qr_code),
          tooltip: 'Show my QR code',
          onPressed: () => _showYouQrSheet(context),
        ),
      ],
    // Most sections have no special AppBar actions.
    _ => const [],
  };
}

/// Show the user's own QR code in a modal bottom sheet.
void _showYouQrSheet(BuildContext context) {
  showModalBottomSheet<void>(
    context: context,
    showDragHandle: true,
    builder: (ctx) => const _YouQrSheet(),
  );
}

// ---------------------------------------------------------------------------
// _EmptyDetail — placeholder for the empty desktop detail pane
// ---------------------------------------------------------------------------

/// Shown in the desktop 3-pane detail pane when nothing is selected.
///
/// Provides a gentle prompt that the user should select an item in the list
/// pane to the left.
class _EmptyDetail extends StatelessWidget {
  const _EmptyDetail({required this.icon, required this.label});
  final IconData icon;
  final String label;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 48, color: Theme.of(context).colorScheme.outline),
          const SizedBox(height: 12),
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

// ---------------------------------------------------------------------------
// _YouQrSheet — bottom sheet showing the user's peer ID as a QR code
// ---------------------------------------------------------------------------

/// Bottom sheet that displays the local user's peer ID as a scannable QR code.
///
/// Triggered by the QR icon in the mobile AppBar when the You section is active.
/// Also accessible from YouScreen itself via the inline card.
///
/// The QR code encodes the full peer ID so another device can scan it and
/// initiate the pairing flow without the user typing anything.
class _YouQrSheet extends StatelessWidget {
  const _YouQrSheet();

  @override
  Widget build(BuildContext context) {
    // Read identity once — no ongoing reactivity needed in a bottom sheet.
    final identity = context.read<SettingsState>().identity;
    final peerId = identity?.peerId ?? '';
    final name = identity?.name ?? 'Mesh Infinity';

    return Padding(
      padding: const EdgeInsets.fromLTRB(24, 8, 24, 40),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            name,
            style: Theme.of(context).textTheme.titleLarge?.copyWith(
                  fontWeight: FontWeight.w700,
                ),
          ),
          const SizedBox(height: 4),
          Text(
            'Scan to add me as a contact',
            style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  color: Theme.of(context).colorScheme.outline,
                ),
          ),
          const SizedBox(height: 24),
          // Only render the QR code when we have a peer ID.  Show a spinner
          // while identity is still loading (usually only for one frame).
          if (peerId.isNotEmpty)
            Container(
              // White container behind the QR code ensures high contrast
              // regardless of the system theme (QR codes need black-on-white).
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(12),
              ),
              padding: const EdgeInsets.all(12),
              child: QrImageView(
                data: peerId,
                version: QrVersions.auto,
                size: 220,
                backgroundColor: Colors.white,
              ),
            )
          else
            const SizedBox(
              height: 220,
              child: Center(child: CircularProgressIndicator()),
            ),
          const SizedBox(height: 20),
          // "Copy peer ID" button — disabled until we have a peer ID to copy.
          OutlinedButton.icon(
            onPressed: peerId.isNotEmpty
                ? () {
                    Clipboard.setData(ClipboardData(text: peerId));
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(content: Text('Peer ID copied')),
                    );
                  }
                : null,
            icon: const Icon(Icons.copy_outlined, size: 18),
            label: const Text('Copy peer ID'),
          ),
        ],
      ),
    );
  }
}
