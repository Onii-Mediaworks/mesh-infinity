import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../app/app_theme.dart';
import '../features/messaging/messaging_state.dart';
import '../backend/models/file_transfer_models.dart';
import '../features/files/files_state.dart';
import '../features/network/network_state.dart';
import '../features/services/services_state.dart';
import '../features/settings/settings_state.dart';
import 'badge_state.dart';
import 'shell_state.dart';

// ---------------------------------------------------------------------------
// NavDrawer
//
// The left navigation drawer. Replaces NavigationBar / NavigationRail as the
// primary section switcher.
//
// Layout (from UI/UX proposal iterations 5–9):
//
//  ┌──────────────────────────────────────┐
//  │  [avatar]  Display name              │  ← header: active identity
//  │            peer-id short             │
//  │  ─────────────────────────────────   │
//  │  [icon]  Chat              [T2][T1]  │  ← social group
//  │  [icon]  Garden            [T2][T1]  │
//  │  [icon]  Files             [T2][T1]  │
//  │  [icon]  Contacts          [T2][T1]  │
//  │  [icon]  Services          [T2][T1]  │
//  │  [icon]  You                         │
//  │  ─── divider ──────────────────────  │
//  │  [icon]  Network               [T1]  │  ← operator group
//  │  [icon]  Settings                    │
//  │  [icon]  Help                        │
//  └──────────────────────────────────────┘
// ---------------------------------------------------------------------------

class NavDrawer extends StatelessWidget {
  const NavDrawer({super.key});

  @override
  Widget build(BuildContext context) {
    final shell = context.watch<ShellState>();
    final settings = context.watch<SettingsState>();
    final badges = context.watch<BadgeState>();

    return Drawer(
      child: SafeArea(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            _DrawerHeader(identity: settings.identity),
            const Divider(height: 1),
            Expanded(
              child: ListView(
                padding: const EdgeInsets.symmetric(vertical: 6),
                children: [
                  // Social group
                  _DrawerItem(
                    section: AppSection.chat,
                    icon: Icons.chat_bubble_outline,
                    selectedIcon: Icons.chat_bubble,
                    label: 'Chat',
                    active: shell.activeSection == AppSection.chat,
                    onTap: () => _select(context, AppSection.chat),
                    criticalBadge: _chatCritical(context),
                    ambientActive: badges.ambientVisibleFor(AppSection.chat),
                  ),
                  _DrawerItem(
                    section: AppSection.garden,
                    icon: Icons.forest_outlined,
                    selectedIcon: Icons.forest,
                    label: 'Garden',
                    active: shell.activeSection == AppSection.garden,
                    onTap: () => _select(context, AppSection.garden),
                    criticalBadge: _gardenCritical(context),
                    ambientActive: badges.ambientVisibleFor(AppSection.garden),
                  ),
                  _DrawerItem(
                    section: AppSection.files,
                    icon: Icons.folder_outlined,
                    selectedIcon: Icons.folder,
                    label: 'Files',
                    active: shell.activeSection == AppSection.files,
                    onTap: () => _select(context, AppSection.files),
                    criticalBadge: _filesCritical(context),
                    ambientActive: badges.ambientVisibleFor(AppSection.files),
                  ),
                  _DrawerItem(
                    section: AppSection.contacts,
                    icon: Icons.people_outline,
                    selectedIcon: Icons.people,
                    label: 'Contacts',
                    active: shell.activeSection == AppSection.contacts,
                    onTap: () => _select(context, AppSection.contacts),
                    criticalBadge: null, // TODO: pending requests count
                    ambientActive: badges.ambientVisibleFor(AppSection.contacts),
                  ),
                  _DrawerItem(
                    section: AppSection.services,
                    icon: Icons.hub_outlined,
                    selectedIcon: Icons.hub,
                    label: 'Services',
                    active: shell.activeSection == AppSection.services,
                    onTap: () => _select(context, AppSection.services),
                    criticalBadge: null,
                    criticalDot: _servicesDegradedDot(context),
                    ambientActive: badges.ambientVisibleFor(AppSection.services),
                  ),
                  _DrawerItem(
                    section: AppSection.you,
                    icon: Icons.person_outline,
                    selectedIcon: Icons.person,
                    label: 'You',
                    active: shell.activeSection == AppSection.you,
                    onTap: () => _select(context, AppSection.you),
                    criticalBadge: null,
                    ambientActive: false, // You never has ambient badge
                  ),

                  const Padding(
                    padding: EdgeInsets.symmetric(horizontal: 16, vertical: 6),
                    child: Divider(height: 1),
                  ),

                  // Operator group
                  _DrawerItem(
                    section: AppSection.network,
                    icon: Icons.router_outlined,
                    selectedIcon: Icons.router,
                    label: 'Network',
                    active: shell.activeSection == AppSection.network,
                    onTap: () => _select(context, AppSection.network),
                    criticalBadge: null,
                    criticalDot: _networkDot(context),
                    ambientActive: badges.ambientVisibleFor(AppSection.network),
                  ),
                  _DrawerItem(
                    section: AppSection.settings,
                    icon: Icons.settings_outlined,
                    selectedIcon: Icons.settings,
                    label: 'Settings',
                    active: shell.activeSection == AppSection.settings,
                    onTap: () => _select(context, AppSection.settings),
                    criticalBadge: null,
                    ambientActive: badges.ambientVisibleFor(AppSection.settings),
                  ),
                  _DrawerItem(
                    section: null,
                    icon: Icons.help_outline,
                    selectedIcon: Icons.help,
                    label: 'Help',
                    active: false,
                    onTap: () {
                      Navigator.pop(context);
                      // TODO: open help
                    },
                    criticalBadge: null,
                    ambientActive: false,
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  void _select(BuildContext context, AppSection section) {
    context.read<ShellState>().selectSection(section);
    // Close the drawer on mobile after selection
    if (Scaffold.of(context).isDrawerOpen) {
      Navigator.pop(context);
    }
  }

  // ---------------------------------------------------------------------------
  // Critical badge value helpers — computed from feature states
  // ---------------------------------------------------------------------------

  int? _chatCritical(BuildContext context) {
    final msg = context.read<MessagingState>();
    final total = msg.rooms
        .where((r) => !r.isGroup)
        .fold(0, (sum, r) => sum + r.unreadCount);
    return total > 0 ? total : null;
  }

  int? _gardenCritical(BuildContext context) {
    final msg = context.read<MessagingState>();
    final total = msg.rooms
        .where((r) => r.isGroup)
        .fold(0, (sum, r) => sum + r.unreadCount);
    return total > 0 ? total : null;
  }

  int? _filesCritical(BuildContext context) {
    final files = context.read<FilesState>();
    final active = files.transfers
        .where((t) =>
            t.status == TransferStatus.active ||
            t.status == TransferStatus.pending)
        .length;
    return active > 0 ? active : null;
  }

  _NetworkDotColor? _servicesDegradedDot(BuildContext context) {
    final svc = context.read<ServicesState>();
    final anyDegraded = svc.services.any((s) => s.enabled && !s.isHealthy);
    return anyDegraded ? _NetworkDotColor.red : null;
  }

  _NetworkDotColor _networkDot(BuildContext context) {
    final net = context.read<NetworkState>();
    final s = net.settings;
    final anyTransport = s != null &&
        (s.enableClearnet || s.enableTor || s.enableI2p || s.enableBluetooth);
    if (net.totalPeers > 0) return _NetworkDotColor.green;
    if (anyTransport) return _NetworkDotColor.amber;
    return _NetworkDotColor.red;
  }
}

enum _NetworkDotColor { green, amber, red }

// ---------------------------------------------------------------------------
// _DrawerHeader — identity area at the top of the drawer
// ---------------------------------------------------------------------------

class _DrawerHeader extends StatelessWidget {
  const _DrawerHeader({required this.identity});

  final dynamic identity; // LocalIdentitySummary?

  @override
  Widget build(BuildContext context) {
    final displayName = identity?.name ?? 'Mesh Infinity';
    final peerId = identity?.peerId ?? '';
    final shortId = peerId.length > 8 ? '${peerId.substring(0, 8)}…' : peerId;

    return InkWell(
      onTap: () {
        Navigator.pop(context);
        context.read<ShellState>().selectSection(AppSection.you);
      },
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 20, 16, 16),
        child: Row(
          children: [
            CircleAvatar(
              radius: 24,
              backgroundColor: MeshTheme.brand.withValues(alpha: 0.2),
              child: Text(
                displayName.isNotEmpty
                    ? displayName[0].toUpperCase()
                    : '?',
                style: const TextStyle(
                  fontSize: 20,
                  fontWeight: FontWeight.w600,
                  color: MeshTheme.brand,
                ),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    displayName,
                    style: Theme.of(context).textTheme.titleMedium?.copyWith(
                      fontWeight: FontWeight.w600,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                  if (shortId.isNotEmpty)
                    Text(
                      shortId,
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                        fontFamily: 'monospace',
                        color: Theme.of(context).colorScheme.outline,
                      ),
                      maxLines: 1,
                    ),
                ],
              ),
            ),
            Icon(
              Icons.chevron_right,
              size: 18,
              color: Theme.of(context).colorScheme.outline,
            ),
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _DrawerItem — one navigation row with two-tier badge columns
//
// Layout per spec (iteration 9):
//   [icon]  Label                [T2■]   [T1 pill/dot]
//
// T2 column: 16px reserved; muted square dot (ambient)
// T1 column: 28px reserved; brand pill (count) or red dot (health)
// Both columns always reserved to prevent label jump.
// ---------------------------------------------------------------------------

class _DrawerItem extends StatelessWidget {
  const _DrawerItem({
    required this.section,
    required this.icon,
    required this.selectedIcon,
    required this.label,
    required this.active,
    required this.onTap,
    required this.criticalBadge,
    required this.ambientActive,
    this.criticalDot,
  });

  final AppSection? section;
  final IconData icon;
  final IconData selectedIcon;
  final String label;
  final bool active;
  final VoidCallback onTap;
  final int? criticalBadge;        // Tier 1 count badge (null = none)
  final _NetworkDotColor? criticalDot; // Tier 1 dot (overrides count)
  final bool ambientActive;        // Tier 2 square dot

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final activeColor = MeshTheme.brand;

    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(12),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 150),
        margin: const EdgeInsets.symmetric(horizontal: 8, vertical: 1),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        decoration: BoxDecoration(
          color: active
              ? activeColor.withValues(alpha: 0.12)
              : Colors.transparent,
          borderRadius: BorderRadius.circular(12),
        ),
        child: Row(
          children: [
            Icon(
              active ? selectedIcon : icon,
              size: 22,
              color: active ? activeColor : cs.onSurfaceVariant,
            ),
            const SizedBox(width: 14),
            Expanded(
              child: Text(
                label,
                style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                  fontWeight: active ? FontWeight.w600 : FontWeight.normal,
                  color: active ? activeColor : cs.onSurface,
                ),
              ),
            ),
            // Tier-2 ambient column (16px reserved)
            SizedBox(
              width: 16,
              child: ambientActive
                  ? Center(
                      child: Container(
                        width: 6,
                        height: 6,
                        decoration: BoxDecoration(
                          color: MeshTheme.ambientBadge,
                          borderRadius: BorderRadius.circular(1),
                        ),
                      ),
                    )
                  : null,
            ),
            const SizedBox(width: 6),
            // Tier-1 critical column (28px reserved)
            SizedBox(
              width: 28,
              child: _tier1Widget(context),
            ),
          ],
        ),
      ),
    );
  }

  Widget? _tier1Widget(BuildContext context) {
    // Health dot (services degraded / network status) takes priority
    if (criticalDot != null) {
      final color = switch (criticalDot!) {
        _NetworkDotColor.green => MeshTheme.secGreen,
        _NetworkDotColor.amber => MeshTheme.secAmber,
        _NetworkDotColor.red => MeshTheme.secRed,
      };
      return Center(
        child: Container(
          width: 9,
          height: 9,
          decoration: BoxDecoration(color: color, shape: BoxShape.circle),
        ),
      );
    }

    // Count badge
    if (criticalBadge != null && criticalBadge! > 0) {
      return Center(
        child: Container(
          constraints: const BoxConstraints(minWidth: 20),
          padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
          decoration: BoxDecoration(
            color: MeshTheme.brand,
            borderRadius: BorderRadius.circular(10),
          ),
          child: Text(
            criticalBadge! > 99 ? '99+' : '$criticalBadge',
            style: const TextStyle(
              fontSize: 11,
              fontWeight: FontWeight.w700,
              color: Colors.white,
            ),
            textAlign: TextAlign.center,
          ),
        ),
      );
    }

    return null;
  }
}
