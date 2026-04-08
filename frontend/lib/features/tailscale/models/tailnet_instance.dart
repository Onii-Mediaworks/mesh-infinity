// tailnet_instance.dart
//
// Dart-side model representing a single Tailscale instance (one tailnet
// connection) managed by the Mesh Infinity backend.
//
// WHAT IS A "TAILNET"?
// --------------------
// A tailnet is the private overlay network formed by all devices that share
// the same Tailscale account (or Headscale namespace). Every device enrolled
// in the same tailnet can reach every other device over WireGuard tunnels,
// regardless of NAT or firewalls.
//
// WHY MULTIPLE INSTANCES?
// -----------------------
// Mesh Infinity's multi-instance Tailscale feature lets a single node
// participate in more than one tailnet simultaneously — for example, a "Work"
// tailnet for corporate resources and a "Home" tailnet for personal devices.
// Each instance carries its own credentials, control server URL, and WireGuard
// key pair.  Only one instance is the "priority" instance at a time; the
// priority instance's exit node and routing policy take precedence when two
// instances would otherwise conflict.
//
// HOW THIS MODEL IS POPULATED
// ---------------------------
// TailscaleState.loadAll() calls bridge.tailscaleListInstances(), which returns
// a JSON array.  Each element in that array is parsed into a TailnetInstance
// via TailnetInstance.fromJson().
//
// See §5.22 of the spec for the full multi-instance overlay design.

import 'package:flutter/foundation.dart';
// @immutable is a lint-level marker telling Dart analysers that all fields
// should be final.  It does not add runtime behaviour.

import '../../../features/network/network_state.dart';
// OverlayClientStatus — the five-state enum shared across all overlay
// transports (Tailscale, ZeroTier).  Defined centrally so the UI components
// that render status badges work the same way regardless of overlay type.

// ---------------------------------------------------------------------------
// TailnetPeer — lightweight model for a single peer in a tailnet
// ---------------------------------------------------------------------------

/// A single peer visible within a tailnet.
///
/// Peers are other devices enrolled in the same tailnet as this instance.
/// Each peer has a Tailscale-assigned IP address (in the 100.x.x.x range) and
/// an optional exit-node capability flag.
///
/// This is intentionally a lightweight struct — all fields are optional except
/// [name] and [ip], which are always present in a valid Tailscale map response.
@immutable
class TailnetPeer {
  /// The human-readable hostname of the peer as assigned by the control server.
  /// Typically the machine name set at enrolment time (e.g. "laptop", "pi4").
  final String name;

  /// The peer's Tailscale-assigned IP address (100.x.x.x / fd7a:115c:a1e0:…).
  /// This is the stable address used for inter-peer communication.
  final String ip;

  /// True if the peer is currently reachable (has recently sent keepalives).
  final bool online;

  /// True if this peer advertises itself as an exit node.
  ///
  /// Exit nodes route internet-destined traffic out of the tailnet — websites
  /// see the exit node's IP rather than the originating device's IP.  Only
  /// peers where this is true should appear in the exit node picker.
  final bool isExitNode;

  /// Constructs a [TailnetPeer] with all fields.
  const TailnetPeer({
    required this.name,
    required this.ip,
    required this.online,
    required this.isExitNode,
  });

  /// Parse a [TailnetPeer] from the JSON object returned in the "peers" array
  /// of a tailnet instance status response.
  ///
  /// Unknown or missing fields are substituted with safe defaults so that a
  /// new backend version can add extra peer fields without crashing the older
  /// Flutter client.
  factory TailnetPeer.fromJson(Map<String, dynamic> json) {
    return TailnetPeer(
      // "name" is the MagicDNS short hostname.  Fallback to empty string so
      // the UI can still render the peer row with just the IP address.
      name: json['name'] as String? ?? '',
      ip:   json['ip']   as String? ?? '',
      // Treat absence of the "online" flag as offline (conservative default).
      online:     json['online']     as bool? ?? false,
      // Only true when the peer explicitly advertises exit-node capability.
      isExitNode: json['isExitNode'] as bool? ?? false,
    );
  }
}

// ---------------------------------------------------------------------------
// TailnetInstance — the main model class
// ---------------------------------------------------------------------------

/// Dart representation of a single Tailscale instance managed by Mesh Infinity.
///
/// One [TailnetInstance] maps one-to-one to a row in the backend's internal
/// tailnet table.  The backend stores WireGuard keys and credentials; this
/// Dart object is a read-only snapshot used solely for display.
///
/// IMPORTANT: This object is immutable.  To mutate state, call a method on
/// [TailscaleState] (which issues a bridge call and reloads from the backend).
/// Never modify a field on this object directly.
///
/// Spec reference: §5.22 (multi-instance Tailscale overlay)
@immutable
class TailnetInstance {
  /// Opaque UUID assigned by the backend when the instance was created.
  ///
  /// All bridge calls that target a specific instance (disconnect, set exit
  /// node, etc.) pass this id as the first argument.
  final String id;

  /// User-chosen display name for this tailnet, e.g. "Work" or "Home VPN".
  ///
  /// The label is set at creation time via TailnetSetupSheet and can be
  /// updated via the rename action in TailnetListTile.  It is stored in the
  /// backend and returned as part of the instance list JSON.
  final String label;

  /// Current connection state of this Tailscale instance.
  ///
  /// Mapped from the backend's status string to [OverlayClientStatus] by
  /// [_parseStatus].  The UI uses this to choose icon colour and status text.
  final OverlayClientStatus status;

  /// URL of the control server for this instance.
  ///
  /// Empty string / null means vendor Tailscale (controlplane.tailscale.com).
  /// A non-empty value is a self-hosted Headscale URL, e.g.:
  ///   "https://headscale.corp.example.com"
  final String? controller;

  /// The Tailscale-assigned IP address of this device within the tailnet
  /// (100.x.x.x range or the fd7a:… IPv6 prefix).
  ///
  /// Null when the device is not yet connected or the IP has not yet been
  /// assigned by the control server.
  final String? deviceIp;

  /// The MagicDNS hostname of this device within the tailnet, e.g. "laptop".
  ///
  /// Null when not connected.
  final String? deviceName;

  /// The tailnet's organisation name as returned by the control server.
  ///
  /// For Tailscale.com: the domain of the account (e.g. "example.com").
  /// For Headscale: the namespace name.
  /// Null when not connected or when the control server does not report it.
  final String? tailnetName;

  /// Unix timestamp (milliseconds) when this instance's WireGuard key expires.
  ///
  /// Zero means "does not expire" or "not available".
  /// A non-zero value within 7 days of now triggers [KeyExpiryBanner].
  ///
  /// WHY track key expiry?
  ///   Tailscale's control plane issues time-limited device certificates.
  ///   When a key expires the device is automatically removed from the tailnet
  ///   until the user re-authenticates.  Proactively warning the user 7 days
  ///   out prevents unexpected disconnections.
  final int keyExpiryUnixMs;

  /// Number of peers currently visible in this tailnet.
  ///
  /// Displayed as a badge in [TailnetListTile] and on the hub header.
  /// This is the count from the last successful status poll.
  final int peerCount;

  /// When true, Mesh Infinity will prefer its own relay infrastructure over
  /// Tailscale's DERP (Designated Encrypted Relay for Packets) servers.
  ///
  /// WHY prefer mesh relays?
  ///   DERP servers are operated by Tailscale Inc and can observe connection
  ///   metadata (which devices are communicating, when, and how much data).
  ///   Mesh relays are operated by Mesh Infinity nodes — distributed and
  ///   under user control.  For privacy-sensitive users, mesh relays are
  ///   preferable even if they add a small latency overhead.
  final bool preferMeshRelay;

  /// Name of the currently active exit node for this instance.
  ///
  /// Null means no exit node is selected (traffic goes directly to the
  /// internet from this device's own connection rather than being routed
  /// through a peer's connection).
  final String? activeExitNode;

  /// Full list of peers visible in this tailnet.
  ///
  /// Populated only when the backend includes peer data in the list response
  /// (this may be omitted for performance in the lightweight list view).
  /// The UI shows this in [TailnetPeersPage].
  final List<TailnetPeer> peers;

  /// Creates a [TailnetInstance] with all required fields.
  const TailnetInstance({
    required this.id,
    required this.label,
    required this.status,
    required this.keyExpiryUnixMs,
    required this.peerCount,
    required this.preferMeshRelay,
    this.controller,
    this.deviceIp,
    this.deviceName,
    this.tailnetName,
    this.activeExitNode,
    this.peers = const [],
  });

  /// Parse a [TailnetInstance] from one element in the JSON array returned by
  /// bridge.tailscaleListInstances().
  ///
  /// The expected JSON shape is:
  /// ```json
  /// {
  ///   "id":              "uuid-string",
  ///   "label":           "Work",
  ///   "status":          "connected",
  ///   "controller":      "https://headscale.example.com",
  ///   "deviceIp":        "100.x.x.x",
  ///   "deviceName":      "laptop",
  ///   "tailnetName":     "example.com",
  ///   "keyExpiryUnixMs": 1720000000000,
  ///   "peerCount":       4,
  ///   "preferMeshRelay": false,
  ///   "activeExitNode":  "exit-server",
  ///   "peers": [
  ///     { "name": "server", "ip": "100.x.x.x", "online": true, "isExitNode": false }
  ///   ]
  /// }
  /// ```
  factory TailnetInstance.fromJson(Map<String, dynamic> json) {
    // Parse the "peers" array — default to empty list if absent or malformed.
    final rawPeers = json['peers'];
    final peers = (rawPeers is List)
        ? rawPeers
            .whereType<Map<String, dynamic>>()
            .map(TailnetPeer.fromJson)
            .toList()
        : const <TailnetPeer>[];

    return TailnetInstance(
      id:              json['id']         as String? ?? '',
      label:           json['label']      as String? ?? 'Unnamed',
      status:          _parseStatus(json['status'] as String?),
      controller:      json['controller'] as String?,
      deviceIp:        json['deviceIp']   as String?,
      deviceName:      json['deviceName'] as String?,
      tailnetName:     json['tailnetName'] as String?,
      // Guard against null and wrong type; 0 = no expiry / not available.
      keyExpiryUnixMs: (json['keyExpiryUnixMs'] as num?)?.toInt() ?? 0,
      peerCount:       (json['peerCount']       as num?)?.toInt() ?? 0,
      preferMeshRelay: json['preferMeshRelay']  as bool? ?? false,
      activeExitNode:  json['activeExitNode']   as String?,
      peers:           peers,
    );
  }

  // ---------------------------------------------------------------------------
  // Derived helpers
  // ---------------------------------------------------------------------------

  /// True when the key expiry timestamp is set AND expiry is within 7 days.
  ///
  /// This is the condition under which [KeyExpiryBanner] should be shown.
  /// Seven days gives the user enough lead time to re-authenticate without
  /// service interruption.
  bool get isKeyExpiringSoon {
    if (keyExpiryUnixMs <= 0) return false;
    final expiryTime = DateTime.fromMillisecondsSinceEpoch(keyExpiryUnixMs);
    final daysUntilExpiry = expiryTime.difference(DateTime.now()).inDays;
    // Show banner when expiry is in the future but within the 7-day window.
    return daysUntilExpiry >= 0 && daysUntilExpiry < 7;
  }

  /// Whole days remaining until key expiry, or 0 if not expiring or already
  /// expired.
  int get daysUntilKeyExpiry {
    if (keyExpiryUnixMs <= 0) return 0;
    final expiryTime = DateTime.fromMillisecondsSinceEpoch(keyExpiryUnixMs);
    final diff = expiryTime.difference(DateTime.now()).inDays;
    // Clamp to 0 — negative means already expired, which the UI handles
    // separately as a disconnected state rather than a countdown.
    return diff < 0 ? 0 : diff;
  }

  /// The peers that are eligible as exit nodes.
  ///
  /// Filters the full peer list to only those with isExitNode == true.
  /// Used by [TailnetExitNodePage] to populate the exit node dropdown.
  List<TailnetPeer> get exitNodePeers =>
      peers.where((p) => p.isExitNode).toList();
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Convert the backend's status string to [OverlayClientStatus].
///
/// The backend stores status as a lowercase string in the database and
/// returns it in the JSON list response.  We map to the Dart enum here so
/// that the rest of the UI never has to deal with raw strings.
///
/// The switch uses a default/fall-through to [OverlayClientStatus.error] for
/// any unrecognised string — this ensures the UI always shows something rather
/// than crashing when a new status string is introduced in a future backend
/// version.
OverlayClientStatus _parseStatus(String? raw) => switch (raw) {
  'connected'      => OverlayClientStatus.connected,
  'connecting'     => OverlayClientStatus.connecting,
  'disconnected'   => OverlayClientStatus.disconnected,
  'not_configured' => OverlayClientStatus.notConfigured,
  _                => OverlayClientStatus.error,
};
