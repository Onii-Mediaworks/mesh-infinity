// zeronet_member.dart
//
// Data model for a single ZeroTier network member visible to this node when
// it is acting as the network controller.
//
// WHAT IS A "MEMBER"?
// --------------------
// In ZeroTier's model, a "network member" is any node that has attempted to
// join a given network.  The controller (the node whose node ID forms the
// first 10 chars of the network ID) keeps a member roster.
//
// WHEN IS THE MEMBER LIST VISIBLE?
// ----------------------------------
// Only the controller can enumerate members.  A regular joined node can see
// other *authorised* peers (those it can route packets to) but NOT the full
// roster.  Therefore the Members tab in Mesh Infinity is only meaningful when
// the local node is the network's controller.  We display a notice for users
// who are not the controller.
//
// AUTHORIZATION (§5.23)
// ----------------------
// Private networks require explicit per-member authorisation.  The controller
// admin can authorise or deauthorise any member at any time.  Deauthorised
// members lose the ability to send/receive traffic on the network immediately.
//
// Spec ref: §5.23 ZeroTier overlay client, member management.

import 'package:flutter/foundation.dart';

// ---------------------------------------------------------------------------
// ZeroNetMember
// ---------------------------------------------------------------------------

/// Immutable snapshot of one ZeroTier network member as seen by the controller.
///
/// Parsed from the `members` array inside a per-instance detail response.
/// Only populated when the local node is the network controller.
@immutable
class ZeroNetMember {
  /// ZeroTier node ID of the member (10 hex chars, e.g. "deadbeef01").
  ///
  /// This is the stable, globally unique identity of the peer on the ZeroTier
  /// overlay.  It is derived from the peer's cryptographic public key.
  final String nodeId;

  /// Human-readable name for the member, as configured in the controller.
  ///
  /// Null if the controller hasn't been given a name for this member.
  /// Displayed as the primary title; falls back to [nodeId] when null.
  final String? name;

  /// The ZeroTier network this member belongs to (16 hex chars).
  ///
  /// Required to scope per-member API calls (authorise, deauthorise) because
  /// a single member can appear in multiple networks under the same controller.
  final String networkId;

  /// Virtual IPs assigned to this member on the network.
  ///
  /// A member can have multiple IPs (IPv4 + IPv6, or multiple subnets).
  /// Displayed as a comma-separated list in [MemberListTile].
  final List<String> ips;

  /// Whether the controller has authorised this member to participate.
  ///
  /// false → the member has joined but is not yet approved (or was revoked).
  /// true  → the member is admitted; traffic can flow to/from this peer.
  final bool authorized;

  /// Timestamp (Unix ms) when this member last checked in with the controller.
  ///
  /// Null if the controller has not recorded a last-seen time.  Used to
  /// indicate stale members that haven't been online recently.
  final int? lastSeenMs;

  /// Creates an immutable [ZeroNetMember].
  const ZeroNetMember({
    required this.nodeId,
    this.name,
    required this.networkId,
    required this.ips,
    required this.authorized,
    this.lastSeenMs,
  });

  /// Parses a [ZeroNetMember] from a backend JSON map.
  ///
  /// Expected JSON shape:
  /// ```json
  /// {
  ///   "nodeId":     "deadbeef01",
  ///   "name":       "Alice's laptop",
  ///   "networkId":  "8056c2e21c000001",
  ///   "ips":        ["10.147.17.5", "fd80::1"],
  ///   "authorized": true,
  ///   "lastSeenMs": 1712345678000
  /// }
  /// ```
  factory ZeroNetMember.fromJson(Map<String, dynamic> json) {
    // ips may be absent (controller not responding) → default to empty list.
    final rawIps = (json['ips'] as List?)?.cast<String>() ?? const <String>[];

    return ZeroNetMember(
      nodeId: json['nodeId'] as String? ?? '',
      name: json['name'] as String?,
      networkId: json['networkId'] as String? ?? '',
      ips: List.unmodifiable(rawIps),
      authorized: json['authorized'] as bool? ?? false,
      lastSeenMs: (json['lastSeenMs'] as num?)?.toInt(),
    );
  }

  /// Display name: [name] if set, otherwise the [nodeId].
  String get displayName =>
      (name != null && name!.isNotEmpty) ? name! : nodeId;

  /// Comma-separated list of assigned IPs, or an em-dash if none assigned.
  String get ipsDisplay => ips.isEmpty ? '—' : ips.join(', ');

  @override
  bool operator ==(Object other) =>
      other is ZeroNetMember &&
      other.nodeId == nodeId &&
      other.networkId == networkId;

  @override
  int get hashCode => Object.hash(nodeId, networkId);
}
