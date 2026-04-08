// zeronet_instance.dart
//
// Data model for a single ZeroTier instance ("zeronet") managed by Mesh
// Infinity.  Mesh Infinity supports running MULTIPLE simultaneous ZeroTier
// clients, each with its own API key, controller, and set of joined networks.
// Each independent client is called a "ZeroNet instance".
//
// WHY MULTIPLE INSTANCES?
// -----------------------
// A typical user has one ZeroTier account and one set of networks — this is
// the "simple" path.  Power users might want:
//   • A personal zeronet (their home lab VPN).
//   • A work zeronet (employer-managed, separate API key).
//   • A community zeronet (self-hosted controller, different trust domain).
//
// Keeping these separate prevents credential confusion, allows independent
// relay preferences per-network, and supports priority routing (one zeronet's
// traffic can be preferred over another).
//
// ZEROTIER CONCEPTS USED IN THIS MODEL
// --------------------------------------
// Node ID (§5.23)
//   Every ZeroTier node has a 10-character hex address (e.g. "deadbeef01").
//   This is the node's identity on the ZeroTier overlay.  The first 10 chars
//   of a network ID are the network controller's node ID.
//
// Controller
//   The controller manages membership in a network — who is authorised.
//   ZeroTier Central (my.zerotier.com) is the hosted controller SaaS.
//   Self-hosted controllers (e.g. ZeroTier-managed Docker image) give full
//   sovereignty: no vendor involvement in authorisation decisions.
//
// Prefer Mesh Relay
//   ZeroTier ordinarily uses its own relay infrastructure (PLANET / MOON nodes)
//   to relay packets between peers that cannot establish a direct path (NAT,
//   firewall, etc.).  Mesh Infinity can intercept this relay traffic and route
//   it through the mesh relay layer instead, keeping traffic off ZeroTier's
//   infrastructure — a privacy improvement for self-hosted controller users.
//
// Network Count / Member Count
//   networkCount = how many ZeroTier networks this instance has joined.
//   memberCount  = total peer nodes visible across all those networks.
//   Both are summary counts for display; the detail pages load full lists.

import 'package:flutter/foundation.dart';

// OverlayClientStatus is the shared enum for Tailscale/ZeroTier connection
// states — defined once in network_state.dart and reused across overlay
// features to avoid duplication.
import '../../network/network_state.dart';

// ---------------------------------------------------------------------------
// ZeroNetInstance
// ---------------------------------------------------------------------------

/// Immutable snapshot of one ZeroTier client instance managed by the backend.
///
/// Instances are created by [ZeroNetInstance.fromJson] when the backend returns
/// a JSON list from `zerotierListInstances`.  All fields are read-only; to
/// update an instance the caller requests a backend mutation and then calls
/// `loadAll()` to refresh the list.
///
/// Spec ref: §5.23 ZeroTier overlay client.
@immutable
class ZeroNetInstance {
  // ---------------------------------------------------------------------------
  // Fields
  // ---------------------------------------------------------------------------

  /// Opaque identifier assigned by the backend when the instance is created.
  ///
  /// Used as the stable key for all per-instance bridge calls (e.g.
  /// `zerotierRefreshInstance(instanceId)`).  Never shown raw to the user.
  final String id;

  /// Human-readable name chosen by the user (e.g. "Home Lab", "Work VPN").
  ///
  /// Displayed as the primary title in [ZeroNetListTile] and the AppBar of
  /// [ZeroNetDetailScreen].  Mutable via the backend but the model is
  /// immutable — a reload is required after a label change.
  final String label;

  /// Current connection state of this ZeroTier client instance.
  ///
  /// Matches the [OverlayClientStatus] enum:
  ///   notConfigured — no credentials (should not appear in a live list)
  ///   connecting    — credentials present, handshaking with controller
  ///   connected     — authenticated, at least one network is reachable
  ///   disconnected  — credentials present but offline / manually paused
  ///   error         — authentication rejected or network unreachable
  final OverlayClientStatus status;

  /// ZeroTier node ID for this instance (10 hex chars, e.g. "deadbeef01").
  ///
  /// Null if the client has not yet completed its first handshake with the
  /// controller and received its identity.  Shown in the status card and the
  /// Overview tab as a copyable field.
  final String? nodeId;

  /// Controller URL for this instance.
  ///
  /// "https://my.zerotier.com" for ZeroTier Central, or the URL of a
  /// self-hosted controller.  Null if not yet fetched from the backend.
  final String? controller;

  /// Number of ZeroTier networks this instance has joined.
  ///
  /// A summary count — the full list is loaded by the Networks tab.
  final int networkCount;

  /// Total number of member nodes visible across all joined networks.
  ///
  /// A summary count — the full member list is loaded by the Members tab.
  /// Only meaningful when this node is a controller for at least one network.
  final int memberCount;

  /// Whether this instance prefers mesh relay over ZeroTier's own relay nodes.
  ///
  /// When true the backend routes relayed traffic through Mesh Infinity relay
  /// infrastructure instead of ZeroTier's PLANET/MOON nodes.  This is a
  /// privacy improvement: traffic does not touch ZeroTier servers.
  ///
  /// Only possible advantage when using a self-hosted controller; using Central
  /// with this enabled still ties your metadata to ZeroTier at the control
  /// plane (API key, network membership).
  final bool preferMeshRelay;

  // ---------------------------------------------------------------------------
  // Constructor
  // ---------------------------------------------------------------------------

  /// Creates an immutable [ZeroNetInstance].
  ///
  /// All fields are required to prevent accidentally constructing a partially
  /// initialised model.  Use [ZeroNetInstance.fromJson] to parse backend JSON.
  const ZeroNetInstance({
    required this.id,
    required this.label,
    required this.status,
    this.nodeId,
    this.controller,
    required this.networkCount,
    required this.memberCount,
    required this.preferMeshRelay,
  });

  // ---------------------------------------------------------------------------
  // Factory: fromJson
  // ---------------------------------------------------------------------------

  /// Parses a [ZeroNetInstance] from a [Map] decoded from the backend's JSON
  /// response to `zerotierListInstances`.
  ///
  /// Unknown or missing fields fall back to safe defaults so a version mismatch
  /// between the Dart model and the Rust serialiser does not crash the UI.
  ///
  /// Expected JSON shape (non-normative — backend is authoritative):
  /// ```json
  /// {
  ///   "id":             "abc123",
  ///   "label":          "Home Lab",
  ///   "status":         "connected",
  ///   "nodeId":         "deadbeef01",
  ///   "controller":     "https://my.zerotier.com",
  ///   "networkCount":   2,
  ///   "memberCount":    14,
  ///   "preferMeshRelay": false
  /// }
  /// ```
  factory ZeroNetInstance.fromJson(Map<String, dynamic> json) {
    return ZeroNetInstance(
      // id is required — an instance without an ID cannot be operated on.
      id: json['id'] as String? ?? '',

      // label defaults to 'ZeroNet' if the backend omits it (shouldn't happen).
      label: json['label'] as String? ?? 'ZeroNet',

      // Parse the textual status string into our OverlayClientStatus enum.
      status: _parseStatus(json['status'] as String?),

      // nodeId and controller are optional — may be null before first connect.
      nodeId: json['nodeId'] as String?,
      controller: json['controller'] as String?,

      // Counts default to zero if absent — safe for display.
      networkCount: (json['networkCount'] as num?)?.toInt() ?? 0,
      memberCount: (json['memberCount'] as num?)?.toInt() ?? 0,

      // preferMeshRelay defaults to false — vendor relay is the safe default.
      preferMeshRelay: json['preferMeshRelay'] as bool? ?? false,
    );
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /// Converts a raw status string from the backend into [OverlayClientStatus].
  ///
  /// The backend serialises as lowercase strings matching the enum member names.
  /// Any unrecognised value maps to [OverlayClientStatus.notConfigured] so a
  /// future backend status does not crash the UI.
  static OverlayClientStatus _parseStatus(String? raw) => switch (raw) {
    'connected'     => OverlayClientStatus.connected,
    'connecting'    => OverlayClientStatus.connecting,
    'disconnected'  => OverlayClientStatus.disconnected,
    'error'         => OverlayClientStatus.error,
    _               => OverlayClientStatus.notConfigured,
  };

  // ---------------------------------------------------------------------------
  // Object overrides
  // ---------------------------------------------------------------------------

  /// Two instances are equal if and only if their [id] matches.
  ///
  /// All other fields are mutable state that can change between reloads;
  /// identity is stable over the lifetime of the instance.
  @override
  bool operator ==(Object other) =>
      other is ZeroNetInstance && other.id == id;

  @override
  int get hashCode => id.hashCode;

  @override
  String toString() =>
      'ZeroNetInstance(id: $id, label: $label, status: $status)';
}
