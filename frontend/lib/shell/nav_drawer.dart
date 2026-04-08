// nav_drawer.dart
//
// NavDrawer — the primary navigation surface for Mesh Infinity.
//
// ROLE IN THE SHELL:
// ------------------
// NavDrawer replaces the conventional Flutter NavigationRail / NavigationBar
// as the section switcher.  It is always present:
//   - On mobile (< 760 px): behind a hamburger icon, slides in over content.
//   - On wide (≥ 760 px):   permanently docked on the left side of the shell.
//   - On desktop (≥ 1200 px): same permanent dock, with a wider rail.
//
// LAYOUT (from UI/UX proposal iterations 5–9):
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
//
// TWO-TIER BADGE SYSTEM:
// ----------------------
// Each row has two reserved badge columns (width is always reserved so the
// label text does not shift when badges appear or disappear):
//
//   [T2] 16 px — Ambient (Tier-2) square dot.  Opt-in via BadgeState
//                (global + per-section toggle AND feature active flag).
//
//   [T1] 28 px — Critical (Tier-1) count pill or health dot.
//                Count pills appear for unread messages, active transfers,
//                and pending contact requests.
//                Health dots (green / amber / red) appear on Network and
//                Services where a numeric count doesn't make sense.
//
// BADGE COMPUTATION:
// ------------------
// Tier-1 counts are computed on every build from the live feature states
// (MessagingState, FilesState, …) using context.read rather than
// context.watch — the enclosing NavDrawer already watches ShellState and
// BadgeState, which rebuild it on navigation events.  Re-reading feature
// states inside the build is safe because context.read never subscribes.
//
// For a full description of the two-tier badge system see BadgeState.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../app/app_theme.dart';
import '../features/messaging/messaging_state.dart';
import '../backend/models/file_transfer_models.dart';
import '../features/files/files_state.dart';
import '../features/network/network_state.dart';
import '../features/services/services_state.dart';
import '../features/settings/settings_state.dart';
import '../features/tailscale/tailscale_state.dart';
import '../features/tailscale/tailscale_hub_screen.dart';
import '../features/zerotier/zerotier_state.dart';
import '../features/zerotier/zerotier_hub_screen.dart';
import 'help_screen.dart';
import 'badge_state.dart';
import 'shell_state.dart';

/// Left navigation drawer that switches the app between top-level sections.
///
/// Renders as a slide-in drawer on mobile and a permanent rail on wide/desktop
/// layouts.  The shell widget ([AppShell]) controls which mode is used by
/// wrapping or not wrapping [NavDrawer] inside a [Drawer] widget.
class NavDrawer extends StatelessWidget {
  const NavDrawer({super.key});

  @override
  Widget build(BuildContext context) {
    // Watch ShellState for active section (drives the selected highlight).
    // Watch SettingsState for the identity name displayed in the header.
    // Watch BadgeState for ambient dot visibility.
    // Watch TailscaleState and ZeroTierState so the dynamic overlay entries
    // appear/disappear as the user configures or removes overlay instances.
    final shell = context.watch<ShellState>();
    final settings = context.watch<SettingsState>();
    final badges = context.watch<BadgeState>();
    final tailscale = context.watch<TailscaleState>();
    final zerotier = context.watch<ZeroTierState>();

    return Drawer(
      child: SafeArea(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Identity header — tapping navigates to the You section.
            _DrawerHeader(identity: settings.identity),
            const Divider(height: 1),

            // Section list — fills remaining vertical space and scrolls if
            // the device is too short to show all items at once.
            Expanded(
              child: ListView(
                padding: const EdgeInsets.symmetric(vertical: 6),
                children: [
                  // ---- Social group ----------------------------------------
                  // Chat: Tier-1 count = total unread messages in direct rooms.
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

                  // Garden: Tier-1 count = total unread messages in group rooms.
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

                  // Files: Tier-1 count = active + pending transfers in progress.
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

                  // Contacts: Tier-1 count = pending contact requests awaiting
                  // the user's accept/reject decision.
                  _DrawerItem(
                    section: AppSection.contacts,
                    icon: Icons.people_outline,
                    selectedIcon: Icons.people,
                    label: 'Contacts',
                    active: shell.activeSection == AppSection.contacts,
                    onTap: () => _select(context, AppSection.contacts),
                    criticalBadge: _contactsCritical(context),
                    ambientActive: badges.ambientVisibleFor(
                      AppSection.contacts,
                    ),
                  ),

                  // Services: no count badge (services don't have an unread
                  // count); instead shows a red dot when any hosted service is
                  // degraded/erroring so the operator notices quickly.
                  _DrawerItem(
                    section: AppSection.services,
                    icon: Icons.hub_outlined,
                    selectedIcon: Icons.hub,
                    label: 'Services',
                    active: shell.activeSection == AppSection.services,
                    onTap: () => _select(context, AppSection.services),
                    criticalBadge: null,
                    criticalDot: _servicesDegradedDot(context),
                    ambientActive: badges.ambientVisibleFor(
                      AppSection.services,
                    ),
                  ),

                  // You: identity / QR / masks section.  No badges — the You
                  // screen shows static identity information, not incoming events.
                  _DrawerItem(
                    section: AppSection.you,
                    icon: Icons.person_outline,
                    selectedIcon: Icons.person,
                    label: 'You',
                    active: shell.activeSection == AppSection.you,
                    onTap: () => _select(context, AppSection.you),
                    criticalBadge: null,
                    // You never has an ambient badge — there is no background
                    // activity in the identity section.
                    ambientActive: false,
                  ),

                  // Horizontal rule separating social sections from operator
                  // sections (Network, Settings, Help).
                  const Padding(
                    padding: EdgeInsets.symmetric(horizontal: 16, vertical: 6),
                    child: Divider(height: 1),
                  ),

                  // ---- Operator group --------------------------------------
                  // Network: health dot reflects overall connectivity quality.
                  //   green = at least one peer connected.
                  //   amber = transports are configured but no peers yet.
                  //   red   = no transports enabled at all.
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

                  // Tailscale: shown only when at least one tailnet has been
                  // configured. This is not a section (no AppSection enum
                  // value) — it pushes a full-screen route instead.
                  // The entry appears dynamically so users who have never
                  // configured Tailscale don't see a confusing menu item.
                  if (tailscale.tailnets.isNotEmpty)
                    _DrawerItem(
                      section: null,
                      icon: Icons.vpn_lock_outlined,
                      selectedIcon: Icons.vpn_lock,
                      label: 'Tailscale',
                      active: false,
                      onTap: () {
                        if (Scaffold.of(context).isDrawerOpen) {
                          Navigator.pop(context);
                        }
                        Navigator.push(
                          context,
                          MaterialPageRoute(
                            builder: (_) => const TailscaleHubScreen(),
                          ),
                        );
                      },
                      // Key-expiry warning: show a red dot when any tailnet's
                      // key is expiring within 7 days (§5.22 key rotation).
                      criticalDot: tailscale.tailnets.any(
                        (t) => t.isKeyExpiringSoon,
                      )
                          ? _NetworkDotColor.red
                          : null,
                      criticalBadge: null,
                      ambientActive: false,
                    ),

                  // ZeroTier: same pattern — only shown when at least one
                  // zeronet instance exists. Tapping pushes ZeroTierHubScreen.
                  if (zerotier.zeronets.isNotEmpty)
                    _DrawerItem(
                      section: null,
                      icon: Icons.hub_outlined,
                      selectedIcon: Icons.hub,
                      label: 'ZeroTier',
                      active: false,
                      onTap: () {
                        if (Scaffold.of(context).isDrawerOpen) {
                          Navigator.pop(context);
                        }
                        Navigator.push(
                          context,
                          MaterialPageRoute(
                            builder: (_) => const ZeroTierHubScreen(),
                          ),
                        );
                      },
                      criticalBadge: null,
                      ambientActive: false,
                    ),

                  // Settings: no badge — settings changes are user-initiated,
                  // never event-driven.
                  _DrawerItem(
                    section: AppSection.settings,
                    icon: Icons.settings_outlined,
                    selectedIcon: Icons.settings,
                    label: 'Settings',
                    active: shell.activeSection == AppSection.settings,
                    onTap: () => _select(context, AppSection.settings),
                    criticalBadge: null,
                    ambientActive: badges.ambientVisibleFor(
                      AppSection.settings,
                    ),
                  ),

                  // Help: not a section (section == null), opens a full-screen
                  // push route.  Always inactive (never highlighted).
                  _DrawerItem(
                    section: null,
                    icon: Icons.help_outline,
                    selectedIcon: Icons.help,
                    label: 'Help',
                    active: false,
                    onTap: () {
                      // Close the drawer before pushing so the overlay doesn't
                      // appear on top of the drawer slide animation.
                      Navigator.pop(context);
                      Navigator.push(
                        context,
                        MaterialPageRoute(builder: (_) => const HelpScreen()),
                      );
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

  /// Select [section] and close the drawer on mobile.
  ///
  /// On mobile the drawer is an overlay — closing it after selection ensures
  /// the body content is fully visible.  On wide/desktop layouts the drawer
  /// is not on a stack ([Scaffold.isDrawerOpen] returns false), so the
  /// Navigator.pop call is skipped safely.
  void _select(BuildContext context, AppSection section) {
    context.read<ShellState>().selectSection(section);
    // Scaffold.of(context) is valid here because NavDrawer is always inside
    // the Scaffold tree (either embedded in the drawer slot or the permanent
    // rail column both of which are children of Scaffold).
    if (Scaffold.of(context).isDrawerOpen) {
      Navigator.pop(context);
    }
  }

  // -------------------------------------------------------------------------
  // Critical badge value helpers — computed from feature states
  // -------------------------------------------------------------------------

  /// Tier-1 count for Chat: total unread messages across all direct rooms.
  ///
  /// Direct rooms have [isGroup == false].  Group rooms are counted separately
  /// for the Garden section so each section's badge reflects only its own
  /// scope.  Returns null (no badge) when the count is zero.
  int? _chatCritical(BuildContext context) {
    final msg = context.read<MessagingState>();
    // Sum unread counts across direct rooms only.
    final total = msg.rooms
        .where((r) => !r.isGroup)
        .fold(0, (sum, r) => sum + r.unreadCount);
    return total > 0 ? total : null;
  }

  /// Tier-1 count for Garden: total unread messages across all group rooms.
  ///
  /// Group rooms (channels, group chats) have [isGroup == true].
  /// Returns null when the count is zero.
  int? _gardenCritical(BuildContext context) {
    final msg = context.read<MessagingState>();
    final total = msg.rooms
        .where((r) => r.isGroup)
        .fold(0, (sum, r) => sum + r.unreadCount);
    return total > 0 ? total : null;
  }

  /// Tier-1 count for Files: number of in-progress transfers.
  ///
  /// Counts transfers whose status is [TransferStatus.active] or
  /// [TransferStatus.pending] (starting up but not yet transferring).
  /// Completed and failed transfers are not counted — they don't need
  /// immediate action.  Returns null when the count is zero.
  int? _filesCritical(BuildContext context) {
    final files = context.read<FilesState>();
    final active = files.transfers
        .where(
          (t) =>
              t.status == TransferStatus.active ||
              t.status == TransferStatus.pending,
        )
        .length;
    return active > 0 ? active : null;
  }

  /// Tier-1 count for Contacts: pending incoming contact requests.
  ///
  /// A contact request requires the user to decide (accept or reject) so it
  /// is a Tier-1 action item.  Returns null when the count is zero.
  int? _contactsCritical(BuildContext context) {
    final msg = context.read<MessagingState>();
    return msg.requestCount > 0 ? msg.requestCount : null;
  }

  /// Tier-1 health dot for Services: red when any hosted service is degraded.
  ///
  /// Services don't have an unread count so a health dot is more meaningful.
  /// Returns null (no dot) when all services are healthy.
  _NetworkDotColor? _servicesDegradedDot(BuildContext context) {
    final svc = context.read<ServicesState>();
    // anyDegraded is true if at least one service has an error/degraded state.
    final anyDegraded = svc.anyDegraded;
    return anyDegraded ? _NetworkDotColor.red : null;
  }

  /// Tier-1 health dot for Network: reflects overall connectivity quality.
  ///
  /// Priority:
  ///   green — at least one mesh peer is currently connected.
  ///   amber — transports are enabled but no peers connected yet.
  ///   red   — no transports are enabled at all (node is isolated).
  ///
  /// The dot is always returned (never null) — the Network section always
  /// has a meaningful connectivity state to show.
  _NetworkDotColor _networkDot(BuildContext context) {
    final net = context.read<NetworkState>();
    final s = net.settings;
    // anyTransport: true if at least one transport type is enabled.
    // Used to distinguish "connecting" (amber) from "offline" (red).
    final anyTransport =
        s != null &&
        (s.enableClearnet || s.enableTor || s.enableI2p || s.enableBluetooth);
    if (net.totalPeers > 0) return _NetworkDotColor.green;
    if (anyTransport) return _NetworkDotColor.amber;
    return _NetworkDotColor.red;
  }
}

/// Three-state health dot colour used by the Network and Services items.
///
/// These are not generic "badge colours" — they specifically encode
/// connectivity health: green means working, amber means trying, red means
/// broken or disabled.
enum _NetworkDotColor { green, amber, red }

// ---------------------------------------------------------------------------
// _DrawerHeader — identity display at the top of the drawer
// ---------------------------------------------------------------------------

/// Drawer header showing the active identity's avatar, display name, and
/// short peer ID.
///
/// Tapping navigates to the You section so the user can view or edit
/// their identity without hunting for the right drawer item.
class _DrawerHeader extends StatelessWidget {
  const _DrawerHeader({required this.identity});

  /// The active local identity summary from [SettingsState].
  ///
  /// Typed as [dynamic] because the identity model is loaded lazily and may
  /// be null before the backend has loaded the identity.  Null-safe access
  /// (?.name, ?.peerId) means the widget renders a sensible fallback
  /// ('Mesh Infinity', no peer ID) until the real data arrives.
  final dynamic identity; // LocalIdentitySummary?

  @override
  Widget build(BuildContext context) {
    // Use 'Mesh Infinity' as the display name before the identity loads or
    // if the user has not set a name.
    final displayName = identity?.name ?? 'Mesh Infinity';
    final peerId = identity?.peerId ?? '';
    // The peer ID can be 64+ hex characters.  Truncate to 8 characters and
    // add an ellipsis so it fits on one line in the drawer header.
    // The full ID is shown in the You screen for copying/sharing.
    final shortId = peerId.length > 8 ? '${peerId.substring(0, 8)}…' : peerId;

    return InkWell(
      // Tapping the header navigates to the You section — a quick path for
      // users who want to show their QR code or switch masks.
      onTap: () {
        Navigator.pop(context); // close the drawer first on mobile
        context.read<ShellState>().selectSection(AppSection.you);
      },
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 20, 16, 16),
        child: Row(
          children: [
            // Fallback circular avatar using the first letter of the display
            // name.  Replaced by MaskAvatar once masks are fully wired.
            CircleAvatar(
              radius: 24,
              backgroundColor: MeshTheme.brand.withValues(alpha: 0.2),
              child: Text(
                // Show '?' if the name is empty (should not normally happen).
                displayName.isNotEmpty ? displayName[0].toUpperCase() : '?',
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
                  // Display name — clipped if it overflows.
                  Text(
                    displayName,
                    style: Theme.of(context).textTheme.titleMedium?.copyWith(
                      fontWeight: FontWeight.w600,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                  // Short peer ID in monospace — only shown when an identity
                  // is loaded and has a non-empty peer ID.
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
            // Chevron hints that tapping navigates to the You section.
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
// _DrawerItem — one navigation row in the drawer
// ---------------------------------------------------------------------------
//
// Layout per spec (iteration 9):
//   [icon]  Label                [T2■]   [T1 pill/dot]
//
// T2 column: 16 px reserved; muted 6×6 square dot (ambient indicator).
// T1 column: 28 px reserved; brand-colour count pill or health status dot.
//
// Both columns are ALWAYS reserved so the label text never shifts position
// as badges appear and disappear — the layout is stable.

/// A single navigation destination row in the drawer.
///
/// Shows a leading icon, a label, and optional Tier-1 and Tier-2 badges.
/// The active section is highlighted with a tinted background rounded rectangle.
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

  /// The section this item navigates to, or null for items that push a route
  /// (like Help) rather than selecting a section.
  final AppSection? section;

  /// Icon shown when this item is not selected.
  final IconData icon;

  /// Icon shown when this item is the active section (typically the filled
  /// variant of the outline icon).
  final IconData selectedIcon;

  /// Text label for this section.
  final String label;

  /// Whether this is the currently active section.  Drives the highlight and
  /// switches between [icon] and [selectedIcon].
  final bool active;

  /// Called when the row is tapped.
  final VoidCallback onTap;

  /// Tier-1 count badge value.  Null means no count badge is shown.
  ///
  /// Capped at 99 in the UI (displays "99+" beyond that) so the pill never
  /// grows too wide for the reserved 28 px column.
  final int? criticalBadge;

  /// Tier-1 health dot colour.  When non-null, overrides [criticalBadge].
  ///
  /// Health dots take priority over count badges because a red "degraded"
  /// signal is more urgent than a stale count.
  final _NetworkDotColor? criticalDot;

  /// Whether the Tier-2 ambient square dot should be shown.
  ///
  /// True only when BadgeState reports that all three conditions hold:
  /// global enabled, section enabled, and the feature has active content.
  final bool ambientActive;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    // The brand colour is used for the active item highlight and active text.
    final activeColor = MeshTheme.brand;

    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(12),
      child: AnimatedContainer(
        // 150 ms fade so the highlight transitions smoothly on section change.
        duration: const Duration(milliseconds: 150),
        margin: const EdgeInsets.symmetric(horizontal: 8, vertical: 1),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        decoration: BoxDecoration(
          // Active item gets a 12% opacity tinted background; inactive items
          // are transparent so the drawer background shows through.
          color: active
              ? activeColor.withValues(alpha: 0.12)
              : Colors.transparent,
          borderRadius: BorderRadius.circular(12),
        ),
        child: Row(
          children: [
            // Switch to the filled icon variant when this section is active.
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
                  // Active label is bold and brand-coloured; inactive is
                  // normal weight in the default surface colour.
                  fontWeight: active ? FontWeight.w600 : FontWeight.normal,
                  color: active ? activeColor : cs.onSurface,
                ),
              ),
            ),

            // ---- Tier-2 column (always 16 px wide) -----------------------
            // The SizedBox is always present whether the dot shows or not so
            // the label text doesn't reflow when the dot appears.
            SizedBox(
              width: 16,
              child: ambientActive
                  ? Center(
                      child: Container(
                        // 6×6 square dot with 1 px radius (slightly rounded
                        // corners distinguish it visually from the circular
                        // Tier-1 health dot).
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

            // ---- Tier-1 column (always 28 px wide) -----------------------
            SizedBox(width: 28, child: _tier1Widget(context)),
          ],
        ),
      ),
    );
  }

  /// Build the Tier-1 badge widget (health dot or count pill).
  ///
  /// Returns null when there is nothing to show, which leaves the 28 px
  /// column empty (but still reserve the space).
  ///
  /// Priority: health dot > count badge > nothing.
  Widget? _tier1Widget(BuildContext context) {
    // Health dot (for Services degraded / Network connectivity status).
    // Takes priority over a count badge so that critical service health is
    // never obscured by a stale number.
    if (criticalDot != null) {
      final color = switch (criticalDot!) {
        _NetworkDotColor.green => MeshTheme.secGreen,
        _NetworkDotColor.amber => MeshTheme.secAmber,
        _NetworkDotColor.red   => MeshTheme.secRed,
      };
      return Center(
        child: Container(
          // 9 px circle — slightly larger than the T2 square dot so it is
          // visually distinct and easier to see at a glance.
          width: 9,
          height: 9,
          decoration: BoxDecoration(color: color, shape: BoxShape.circle),
        ),
      );
    }

    // Count badge — shown when there are unread items or pending actions.
    if (criticalBadge != null && criticalBadge! > 0) {
      return Center(
        child: Container(
          // minWidth: 20 so single-digit counts get a circular pill;
          // wider for 2–3 digit counts.  The 28 px column clips anything
          // wider to prevent layout overflow on very large counts.
          constraints: const BoxConstraints(minWidth: 20),
          padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
          decoration: BoxDecoration(
            color: MeshTheme.brand,
            borderRadius: BorderRadius.circular(10),
          ),
          child: Text(
            // Cap at 99 to keep the pill within the reserved column width.
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

    // No badge to show — column is empty but its width is still reserved.
    return null;
  }
}
