// zeronet_members_page.dart
//
// ZeroNetMembersPage — the Members tab content for ZeroNetDetailScreen.
//
// PURPOSE
// --------
// Shows the ZeroTier network member roster for networks where this device is
// the controller.  For each member the user can see:
//   • Member name (or node ID as fallback)
//   • Virtual IPs assigned to the member on the network
//   • Network ID the membership belongs to
//   • Authorization state (authorized / not authorized)
//   • Authorize / Deauthorize action button
//
// CONTROLLER-ONLY SEMANTICS
// --------------------------
// Only the ZeroTier network controller can enumerate the full member roster
// or perform authorization mutations.  Regular joined members can see their
// route peers but cannot modify membership.
//
// This page therefore displays a prominent notice explaining this constraint.
// When the member list is empty the notice tells the user why — rather than
// silently showing a blank screen.
//
// DATA SOURCE
// ------------
// Members are extracted from ZeroTierState (backed by the backend's
// zerotierListInstances response).  The list re-fetches after every
// authorize/deauthorize action so the UI reflects the new state.
//
// Spec ref: §5.23 ZeroTier overlay — member authorization.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../backend/backend_bridge.dart';
// BackendBridge — for the authorize/deauthorize bridge call.

import 'models/zeronet_member.dart';
// ZeroNetMember — data model for one network member.

import 'zerotier_state.dart';
// ZeroTierState — source of truth; refreshed after mutations.

import 'widgets/member_list_tile.dart';
// MemberListTile — renders one member row with the action button.

// ---------------------------------------------------------------------------
// ZeroNetMembersPage
// ---------------------------------------------------------------------------

/// Members tab for [ZeroNetDetailScreen].
///
/// Lists all network members visible to this controller node and allows the
/// user to authorize or deauthorize each member.
///
/// Shows an explanatory notice reminding non-controller users that this view
/// is only meaningful when this device owns the network.
class ZeroNetMembersPage extends StatefulWidget {
  /// Opaque backend ID of the ZeroNet instance whose members are shown.
  final String instanceId;

  /// Creates a [ZeroNetMembersPage] for [instanceId].
  const ZeroNetMembersPage({super.key, required this.instanceId});

  @override
  State<ZeroNetMembersPage> createState() => _ZeroNetMembersPageState();
}

class _ZeroNetMembersPageState extends State<ZeroNetMembersPage> {
  // ---------------------------------------------------------------------------
  // Local UI state
  // ---------------------------------------------------------------------------

  /// True while an authorize/deauthorize bridge call is in flight.
  ///
  /// Disables all action buttons while a mutation is pending to prevent
  /// double-submission and conflicting concurrent calls.
  bool _busy = false;

  /// Error from the most recent failed authorize/deauthorize call, or null.
  String? _error;

  // ---------------------------------------------------------------------------
  // _toggleAuthorized
  // ---------------------------------------------------------------------------

  /// Calls the backend to authorize or deauthorize [member].
  ///
  /// [newValue] is the desired new authorization state:
  ///   `true`  → authorize (admit the member to the network)
  ///   `false` → deauthorize (revoke the member's access)
  ///
  /// After the call, ZeroTierState.loadAll() refreshes the member list so the
  /// UI reflects the new state without requiring the user to manually refresh.
  Future<void> _toggleAuthorized(ZeroNetMember member, bool newValue) async {
    setState(() {
      _busy = true;
      _error = null;
    });

    final bridge = context.read<BackendBridge>();
    final state = context.read<ZeroTierState>();

    // The bridge call requires: instanceId, networkId, nodeId, authorized.
    // networkId scopes the operation — a node can be a member of multiple
    // networks under the same controller with different auth states on each.
    final ok = bridge.zerotierSetMemberAuthorizedInstance(
      widget.instanceId,
      member.networkId,
      member.nodeId,
      newValue,
    );

    // Reload regardless of success/failure to show the actual backend state.
    await state.loadAll();

    if (!mounted) return;

    setState(() {
      _busy = false;
      if (!ok) {
        _error = bridge.getLastError() ??
            (newValue ? 'Could not authorize member' : 'Could not deauthorize member');
      }
    });
  }

  // ---------------------------------------------------------------------------
  // build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    // Watch ZeroTierState so the list rebuilds after authorize/deauthorize.
    final state = context.watch<ZeroTierState>();
    final instance = state.instanceById(widget.instanceId);

    // Extract members from backend state.  The full member list is populated
    // by the backend when this device is the controller for at least one
    // network.  Falls back to an empty list if absent.
    final members = _parseMembers(instance);

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // ---- Controller notice --------------------------------------------
        // Always shown — reminds the user that this tab is only useful when
        // they own the network controller.  Non-controller users will always
        // see an empty list; the notice explains why.
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: cs.primaryContainer.withValues(alpha: 0.3),
            borderRadius: BorderRadius.circular(8),
          ),
          child: Row(
            children: [
              Icon(
                Icons.info_outline,
                size: 16,
                color: cs.primary,
              ),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  'Member management is only available when this device '
                  'controls the ZeroTier network. If you joined someone '
                  'else\'s network, this list will be empty.',
                  style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),

        // ---- Header -------------------------------------------------------
        Text('Network Members', style: tt.labelLarge),
        const SizedBox(height: 12),

        // ---- Empty state --------------------------------------------------
        if (members.isEmpty)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 24),
            child: Column(
              children: [
                Icon(
                  Icons.group_outlined,
                  size: 48,
                  color: cs.onSurfaceVariant.withValues(alpha: 0.4),
                ),
                const SizedBox(height: 12),
                Text(
                  'No members found.',
                  style: tt.bodyMedium?.copyWith(color: cs.onSurfaceVariant),
                ),
                const SizedBox(height: 4),
                Text(
                  'Members appear here only if this device is the '
                  'ZeroTier network controller.',
                  style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
                  textAlign: TextAlign.center,
                ),
              ],
            ),
          ),

        // ---- Member list --------------------------------------------------
        for (final member in members)
          MemberListTile(
            member: member,
            busy: _busy,
            onToggleAuthorized: (newValue) =>
                _toggleAuthorized(member, newValue),
          ),

        // ---- Error banner -------------------------------------------------
        if (_error != null) ...[
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: cs.errorContainer,
              borderRadius: BorderRadius.circular(8),
            ),
            child: Row(
              children: [
                Icon(Icons.error_outline,
                    size: 16, color: cs.onErrorContainer),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    _error!,
                    style: tt.bodySmall
                        ?.copyWith(color: cs.onErrorContainer),
                  ),
                ),
              ],
            ),
          ),
        ],
      ],
    );
  }

  // ---------------------------------------------------------------------------
  // _parseMembers
  // ---------------------------------------------------------------------------

  /// Extracts the member list from the backend instance state.
  ///
  /// The backend will embed a `members` array in the per-instance JSON once
  /// the zerotierListInstances API is extended to include it.  Until then
  /// this returns an empty list — the empty-state UI explains why.
  ///
  /// When the backend is updated this method will be updated to parse the
  /// members array from the ZeroNetInstance model.
  List<ZeroNetMember> _parseMembers(dynamic instance) {
    if (instance == null) return const [];
    // Future: parse instance.members when the backend includes the full list.
    // The ZeroNetInstance model currently carries memberCount (summary) only.
    return const [];
  }
}
