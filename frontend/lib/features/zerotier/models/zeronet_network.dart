// zeronet_network.dart
//
// Data model for a single ZeroTier network joined by one ZeroNet instance.
//
// ZEROTIER NETWORK CONCEPTS
// --------------------------
// Network ID
//   A 16-character hex string (e.g. "8056c2e21c000001").  The first 10 chars
//   are the controller's node ID; the last 6 identify the network within that
//   controller.  Example: controller node "8056c2e21c" → network "000001".
//
// Assigned IP
//   When you join a network, the controller assigns a virtual IP address
//   within the network's address range.  This is the IP other ZeroTier nodes
//   on the same network use to reach you.  It is NOT your real internet IP.
//
// Auth Status
//   Private networks require the controller admin to authorise each new
//   member before they can send or receive traffic.  The auth status tracks
//   whether this node is:
//     authorized           — admitted, traffic flows
//     awaitingauthorization — join request pending admin review
//     unauthorized         — explicitly denied by the admin
//
// Member Count
//   Number of ZeroTier nodes currently in the network.  Only the controller
//   can see the full list; regular members see only authorised peers.
//
// Spec ref: §5.23 ZeroTier overlay.

import 'package:flutter/foundation.dart';

// ---------------------------------------------------------------------------
// ZeroNetAuthStatus
// ---------------------------------------------------------------------------

/// Authorization state of this device's membership in a ZeroTier network.
///
/// Private ZeroTier networks gate access behind admin approval.  Public
/// networks auto-authorize all joiners.  The controller is the source of
/// truth; this enum is derived from the backend's serialised string.
enum ZeroNetAuthStatus {
  /// The controller has approved this node — traffic can flow.
  authorized,

  /// Join request sent; waiting for the network admin to approve.
  awaitingAuthorization,

  /// The network admin has explicitly denied this node.
  unauthorized,

  /// Status unknown (e.g. still fetching from the controller).
  unknown,
}

// ---------------------------------------------------------------------------
// ZeroNetNetwork
// ---------------------------------------------------------------------------

/// Immutable snapshot of one network joined by a [ZeroNetInstance].
///
/// Parsed from the `networks` array inside a per-instance detail response
/// from `zerotierListInstances`.
@immutable
class ZeroNetNetwork {
  /// The 16-hex-char network identifier.  Unique across all ZeroTier networks
  /// globally (since the first 10 chars derive from the controller node ID).
  final String networkId;

  /// Human-readable network name set by the controller admin, e.g. "Home Lab".
  ///
  /// Null if the backend hasn't fetched it yet or the controller didn't provide
  /// one.  Falls back to displaying [networkId] in that case.
  final String? name;

  /// The virtual IP address assigned to this device on this network, e.g.
  /// "10.147.17.5".  Null if authorization is still pending or the controller
  /// hasn't assigned one yet.
  final String? assignedIp;

  /// The authorization state of this device's membership in the network.
  final ZeroNetAuthStatus authStatus;

  /// Number of members in the network (all peers, not just authorised ones,
  /// if the controller allows it — varies by controller configuration).
  final int memberCount;

  /// Creates an immutable [ZeroNetNetwork].
  const ZeroNetNetwork({
    required this.networkId,
    this.name,
    this.assignedIp,
    required this.authStatus,
    required this.memberCount,
  });

  /// Parses a [ZeroNetNetwork] from a backend JSON map.
  ///
  /// Expected JSON shape:
  /// ```json
  /// {
  ///   "networkId":   "8056c2e21c000001",
  ///   "name":        "Home Lab",
  ///   "assignedIp":  "10.147.17.5",
  ///   "authStatus":  "authorized",
  ///   "memberCount": 7
  /// }
  /// ```
  factory ZeroNetNetwork.fromJson(Map<String, dynamic> json) {
    return ZeroNetNetwork(
      networkId: json['networkId'] as String? ?? '',
      name: json['name'] as String?,
      assignedIp: json['assignedIp'] as String?,
      authStatus: _parseAuthStatus(json['authStatus'] as String?),
      memberCount: (json['memberCount'] as num?)?.toInt() ?? 0,
    );
  }

  /// Converts the backend's raw auth-status string to [ZeroNetAuthStatus].
  ///
  /// The backend uses multiple historical spellings for "awaiting" —
  /// both forms are handled to protect against version skew.
  static ZeroNetAuthStatus _parseAuthStatus(String? raw) => switch (raw) {
    'authorized'              => ZeroNetAuthStatus.authorized,
    'awaitingauthorization'   => ZeroNetAuthStatus.awaitingAuthorization,
    'awaiting_authorization'  => ZeroNetAuthStatus.awaitingAuthorization,
    'unauthorized'            => ZeroNetAuthStatus.unauthorized,
    _                         => ZeroNetAuthStatus.unknown,
  };

  /// Returns the display name, falling back to [networkId] if no name was set.
  String get displayName => (name != null && name!.isNotEmpty) ? name! : networkId;

  @override
  bool operator ==(Object other) =>
      other is ZeroNetNetwork && other.networkId == networkId;

  @override
  int get hashCode => networkId.hashCode;
}
