// member_list_tile.dart
//
// MemberListTile — a ListTile for a single ZeroTier network member, shown in
// the Members tab of ZeroNetDetailScreen.
//
// CONTROLLER-ONLY VIEW
// ---------------------
// The Members tab is only meaningful when this Mesh Infinity node is the
// ZeroTier network controller — i.e. the node whose ID forms the first 10
// characters of the network ID.  Regular joined members can only see peers
// they can route to; they cannot see the full member roster or perform
// authorisation actions.
//
// The Members tab therefore shows an explanatory notice alongside the list
// so users who are not the controller understand why the list may be empty.
//
// AUTHORIZE / DEAUTHORIZE
// ------------------------
// Private networks require the controller admin to authorise each node before
// it can participate.  This tile surfaces the Authorize/Deauthorize action
// as a TextButton in the trailing area.  Tapping it calls [onToggleAuthorized]
// so the parent page can issue the bridge call and refresh state.
//
// Spec ref: §5.23 ZeroTier — member management.

import 'package:flutter/material.dart';

import '../models/zeronet_member.dart';
// ZeroNetMember is the data model rendered by this tile.

// ---------------------------------------------------------------------------
// MemberListTile
// ---------------------------------------------------------------------------

/// [ListTile] for one ZeroTier network member in the controller member roster.
///
/// Displays the member's name (or node ID), their virtual IPs, and the
/// network they belong to.  Provides an Authorize/Deauthorize action button.
///
/// [onToggleAuthorized] is called when the user taps the action button.
/// The caller is responsible for the bridge call and state refresh.
class MemberListTile extends StatelessWidget {
  /// The member to display.
  final ZeroNetMember member;

  /// Whether a bridge call is currently in flight.
  ///
  /// When true, the action button is disabled to prevent double-submission.
  final bool busy;

  /// Called when the user taps Authorize or Deauthorize.
  ///
  /// The bool argument is the desired new authorization state:
  ///   `true`  → authorize this member
  ///   `false` → deauthorize this member
  final void Function(bool newValue)? onToggleAuthorized;

  /// Creates a [MemberListTile].
  const MemberListTile({
    super.key,
    required this.member,
    this.busy = false,
    this.onToggleAuthorized,
  });

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    // The leading icon changes color based on authorization state so the
    // user can scan the roster at a glance without reading the button label.
    final iconColor = member.authorized
        ? const Color(0xFF22C55E) // secGreen — authorized, traffic flows
        : const Color(0xFFF59E0B); // secAmber — pending/denied, traffic blocked

    return ListTile(
      // Leading icon: person with a status-colored tint.
      leading: CircleAvatar(
        // Soft tinted background ties the avatar to the status color without
        // using the full saturated hue (which would be too visually loud in
        // a dense list).
        backgroundColor: iconColor.withValues(alpha: 0.12),
        radius: 18,
        child: Icon(
          member.authorized
              ? Icons.person_outline
              : Icons.person_off_outlined,
          size: 18,
          color: iconColor,
        ),
      ),

      // Title: display name (or node ID as fallback) in standard body text.
      title: Text(
        member.displayName,
        style: tt.bodyMedium?.copyWith(color: cs.onSurface),
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
      ),

      // Subtitle: IPs (comma-separated) and the network ID, separated by a
      // centered dot.  Network ID is shown in monospace for readability.
      subtitle: Text(
        _buildSubtitle(),
        style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
        maxLines: 2,
        overflow: TextOverflow.ellipsis,
      ),

      // Trailing: the authorize/deauthorize action button.
      // TextButton is used (rather than FilledButton) because it is subtle
      // — the action is secondary to browsing the list.
      trailing: member.networkId.isEmpty
          // No network ID means we can't scope the API call — hide the button.
          ? null
          : TextButton(
              onPressed: busy
                  ? null // Disabled while a call is in flight.
                  : () => onToggleAuthorized?.call(!member.authorized),
              child: Text(
                // Toggle label: "Authorize" when not yet authorized,
                // "Deauthorize" when currently authorized.
                member.authorized ? 'Deauthorize' : 'Authorize',
              ),
            ),
    );
  }

  // ---------------------------------------------------------------------------
  // _buildSubtitle
  // ---------------------------------------------------------------------------

  /// Builds the subtitle string from IPs and network ID.
  ///
  /// Format: "IPs · networkId"
  /// Falls back to just the network ID if no IPs are assigned.
  String _buildSubtitle() {
    final parts = <String>[];

    // IPs: comma-separated list of virtual addresses.
    // Empty when the member hasn't been assigned addresses yet (pre-auth).
    if (member.ips.isNotEmpty) {
      parts.add(member.ips.join(', '));
    }

    // Network ID: scopes which network this membership belongs to.
    if (member.networkId.isNotEmpty) {
      parts.add(member.networkId);
    }

    // Center-dot separator is a compact way to join metadata fields
    // without using multiple lines (saves vertical space in long lists).
    return parts.join(' · ');
  }
}
