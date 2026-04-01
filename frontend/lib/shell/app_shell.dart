import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'package:qr_flutter/qr_flutter.dart';

import 'shell_state.dart';
import 'nav_drawer.dart';
import 'section_bottom_bar.dart';
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
import '../features/messaging/screens/search_screen.dart';
import '../features/messaging/screens/create_room_screen.dart';
import '../features/peers/screens/peer_detail_screen.dart';
import '../features/peers/screens/pair_peer_screen.dart';

// ---------------------------------------------------------------------------
// Layout breakpoints
// ---------------------------------------------------------------------------

const double _kPermanentDrawerBreak = 760.0;
const double _kDesktopBreak = 1200.0;
const double _kDrawerWidth = 280.0;

// ---------------------------------------------------------------------------
// AppShell
//
// Responsive navigation shell implementing the iteration 4–9 architecture:
//
//   Mobile (<760px):   hamburger → slide-in drawer  +  contextual bottom bar
//   Tablet (760–1199): permanent drawer on left      +  contextual bottom bar
//   Desktop (≥1200):   permanent drawer on left      +  contextual bottom bar
//                      + detail pane for chat/contacts (3-pane)
//
// Section switching always happens via the drawer.
// Sub-page switching always happens via the bottom bar.
// The bottom bar is hidden when in a detail view or when the section has none.
// ---------------------------------------------------------------------------

class AppShell extends StatelessWidget {
  const AppShell({super.key});

  @override
  Widget build(BuildContext context) {
    final width = MediaQuery.sizeOf(context).width;

    if (width >= _kPermanentDrawerBreak) {
      return width >= _kDesktopBreak
          ? const _DesktopShell()
          : const _WideShell();
    }
    return const _MobileShell();
  }
}

// ---------------------------------------------------------------------------
// Mobile — hamburger opens a slide-in drawer; bottom bar for sub-pages
// ---------------------------------------------------------------------------

class _MobileShell extends StatelessWidget {
  const _MobileShell();

  @override
  Widget build(BuildContext context) {
    final shell = context.watch<ShellState>();
    final section = shell.activeSection;
    final title = _sectionTitle(section);

    return Scaffold(
      appBar: AppBar(
        // Hamburger — opens the drawer; always shows current section name
        leading: Builder(
          builder: (ctx) => IconButton(
            icon: const Icon(Icons.menu),
            tooltip: 'Menu',
            onPressed: () => Scaffold.of(ctx).openDrawer(),
          ),
        ),
        title: Text(title),
        actions: _appBarActions(context, shell),
      ),
      drawer: const NavDrawer(),
      body: _SectionBody(),
      bottomNavigationBar: const SectionBottomBar(),
    );
  }
}

// ---------------------------------------------------------------------------
// Wide (tablet) — permanent drawer + content pane
// ---------------------------------------------------------------------------

class _WideShell extends StatelessWidget {
  const _WideShell();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Row(
        children: [
          const SizedBox(
            width: _kDrawerWidth,
            child: _PermanentDrawerFrame(child: NavDrawer()),
          ),
          const VerticalDivider(width: 1),
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
}

// ---------------------------------------------------------------------------
// Desktop — permanent drawer + content pane + optional detail pane
// ---------------------------------------------------------------------------

class _DesktopShell extends StatelessWidget {
  const _DesktopShell();

  @override
  Widget build(BuildContext context) {
    final shell = context.watch<ShellState>();

    // Chat and Contacts get a 3-pane layout when something is selected
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
            SizedBox(
              width: 320,
              child: Scaffold(
                body: _SectionBody(),
                bottomNavigationBar: const SectionBottomBar(),
              ),
            ),
            const VerticalDivider(width: 1),
            Expanded(child: _detailPane(shell)),
          ] else
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

  Widget _detailPane(ShellState shell) {
    return switch (shell.activeSection) {
      AppSection.chat => shell.selectedRoomId != null
          ? ThreadScreen(roomId: shell.selectedRoomId!)
          : const _EmptyDetail(icon: Icons.chat_bubble_outline, label: 'Select a chat'),
      AppSection.contacts => shell.selectedPeerId != null
          ? PeerDetailScreen(peerId: shell.selectedPeerId!)
          : const _EmptyDetail(icon: Icons.people_outline, label: 'Select a contact'),
      _ => const SizedBox.shrink(),
    };
  }
}

// ---------------------------------------------------------------------------
// _PermanentDrawerFrame — wraps NavDrawer for tablet/desktop so it renders
// inline rather than as an overlay.
// ---------------------------------------------------------------------------

class _PermanentDrawerFrame extends StatelessWidget {
  const _PermanentDrawerFrame({required this.child});
  final Widget child;

  @override
  Widget build(BuildContext context) {
    return Material(
      color: Theme.of(context).drawerTheme.backgroundColor ??
          Theme.of(context).colorScheme.surface,
      child: child,
    );
  }
}

// ---------------------------------------------------------------------------
// _SectionBody — routes to the correct screen for section + sub-page
// ---------------------------------------------------------------------------

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

List<Widget> _appBarActions(BuildContext context, ShellState shell) {
  return switch (shell.activeSection) {
    AppSection.chat => [
        IconButton(
          icon: const Icon(Icons.search),
          tooltip: 'Search messages',
          onPressed: () => Navigator.push(
            context,
            MaterialPageRoute(builder: (_) => const MessageSearchScreen()),
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
            MaterialPageRoute(builder: (_) => const PairPeerScreen()),
          ),
        ),
      ],
    AppSection.you => [
        IconButton(
          icon: const Icon(Icons.qr_code),
          tooltip: 'Show my QR code',
          onPressed: () => _showYouQrSheet(context),
        ),
      ],
    _ => const [],
  };
}

void _showYouQrSheet(BuildContext context) {
  showModalBottomSheet<void>(
    context: context,
    showDragHandle: true,
    builder: (ctx) => const _YouQrSheet(),
  );
}

// ---------------------------------------------------------------------------
// _EmptyDetail — placeholder for empty desktop detail pane
// ---------------------------------------------------------------------------

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
// Triggered by the QR icon in the AppBar when the You section is active.
// ---------------------------------------------------------------------------

class _YouQrSheet extends StatelessWidget {
  const _YouQrSheet();

  @override
  Widget build(BuildContext context) {
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
          if (peerId.isNotEmpty)
            Container(
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
