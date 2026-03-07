import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'shell_state.dart';
import '../features/messaging/screens/conversation_list_screen.dart';
import '../features/messaging/screens/thread_screen.dart';
import '../features/files/screens/transfers_screen.dart';
import '../features/peers/screens/peer_list_screen.dart';
import '../features/peers/screens/peer_detail_screen.dart';
import '../features/network/screens/network_screen.dart';
import '../features/settings/screens/settings_screen.dart';

const double _kSidebarWidth = 300.0;
const double _kTabletBreak = 760.0;
const double _kDesktopBreak = 1200.0;

class AppShell extends StatelessWidget {
  const AppShell({super.key});

  @override
  Widget build(BuildContext context) {
    final width = MediaQuery.sizeOf(context).width;
    if (width >= _kDesktopBreak) return const _DesktopShell();
    if (width >= _kTabletBreak) return const _TabletShell();
    return const _MobileShell();
  }
}

// ---------------------------------------------------------------------------
// Desktop: sidebar + list pane + detail pane
// ---------------------------------------------------------------------------

class _DesktopShell extends StatelessWidget {
  const _DesktopShell();

  @override
  Widget build(BuildContext context) {
    final shell = context.watch<ShellState>();
    return Scaffold(
      body: Row(
        children: [
          _SectionRail(selected: shell.activeSection, onSelect: shell.selectSection),
          const VerticalDivider(width: 1),
          SizedBox(
            width: _kSidebarWidth,
            child: _listPaneFor(shell.activeSection, context),
          ),
          const VerticalDivider(width: 1),
          Expanded(child: _detailPaneFor(shell, context)),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Tablet: sidebar + content pane (no persistent detail)
// ---------------------------------------------------------------------------

class _TabletShell extends StatelessWidget {
  const _TabletShell();

  @override
  Widget build(BuildContext context) {
    final shell = context.watch<ShellState>();
    return Scaffold(
      body: Row(
        children: [
          _SectionRail(selected: shell.activeSection, onSelect: shell.selectSection),
          const VerticalDivider(width: 1),
          Expanded(child: _listPaneFor(shell.activeSection, context)),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Mobile: bottom nav + single pane
// ---------------------------------------------------------------------------

class _MobileShell extends StatelessWidget {
  const _MobileShell();

  @override
  Widget build(BuildContext context) {
    final shell = context.watch<ShellState>();
    return Scaffold(
      body: _listPaneFor(shell.activeSection, context),
      bottomNavigationBar: NavigationBar(
        selectedIndex: AppSection.values.indexOf(shell.activeSection),
        onDestinationSelected: (i) => shell.selectSection(AppSection.values[i]),
        destinations: const [
          NavigationDestination(icon: Icon(Icons.chat_bubble_outline), label: 'Chat'),
          NavigationDestination(icon: Icon(Icons.folder_outlined), label: 'Files'),
          NavigationDestination(icon: Icon(Icons.people_outline), label: 'Peers'),
          NavigationDestination(icon: Icon(Icons.router_outlined), label: 'Network'),
          NavigationDestination(icon: Icon(Icons.settings_outlined), label: 'Settings'),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Section NavigationRail (tablet/desktop sidebar)
// ---------------------------------------------------------------------------

class _SectionRail extends StatelessWidget {
  const _SectionRail({required this.selected, required this.onSelect});

  final AppSection selected;
  final ValueChanged<AppSection> onSelect;

  @override
  Widget build(BuildContext context) {
    return NavigationRail(
      selectedIndex: AppSection.values.indexOf(selected),
      onDestinationSelected: (i) => onSelect(AppSection.values[i]),
      labelType: NavigationRailLabelType.all,
      destinations: const [
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

Widget _listPaneFor(AppSection section, BuildContext context) {
  return switch (section) {
    AppSection.chat => const ConversationListScreen(),
    AppSection.files => const TransfersScreen(),
    AppSection.peers => const PeerListScreen(),
    AppSection.network => const NetworkScreen(),
    AppSection.settings => const SettingsScreen(),
  };
}

Widget _detailPaneFor(ShellState shell, BuildContext context) {
  return switch (shell.activeSection) {
    AppSection.chat => shell.selectedRoomId != null
        ? ThreadScreen(roomId: shell.selectedRoomId!)
        : const _EmptyDetail(icon: Icons.chat_bubble_outline, label: 'Select a conversation'),
    AppSection.peers => shell.selectedPeerId != null
        ? PeerDetailScreen(peerId: shell.selectedPeerId!)
        : const _EmptyDetail(icon: Icons.people_outline, label: 'Select a peer'),
    _ => const SizedBox.shrink(),
  };
}

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
