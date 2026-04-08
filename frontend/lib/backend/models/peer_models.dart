// =============================================================================
// peer_models.dart
//
// Typed Dart models for mesh peers and their trust level.
//
// WHAT IS A PEER?
// A "peer" is any other device running the Mesh Infinity node software.  Peers
// are identified not by IP address (which is mutable) but by a cryptographic
// identifier derived from their Ed25519 public key.  This ID is stable across
// network changes.
//
// TRUST MODEL (§8, §22.4.2)
// Every peer in the contact store has an associated trust level (0–8).  Trust
// affects what the peer can do: which messages reach the main inbox vs. the
// request queue, whether their annotations propagate in the web-of-trust, etc.
// The TrustLevel enum in this file is the Flutter representation of the
// backend's trust scale.
//
// HOW PEER DATA REACHES FLUTTER
// BackendBridge.fetchPeers() calls mi_get_peer_list() in Rust, which returns
// a JSON array.  Each element is decoded into a PeerModel.  PeerUpdatedEvent
// on the event bus delivers individual updates for already-known peers.
// PeerAddedEvent delivers newly discovered peers.
// =============================================================================

import 'package:flutter/material.dart';

/// Nine-level trust scale as defined in §22.4.2.
///
/// The numeric value of each level (0–8) is the canonical form stored in the
/// backend.  The enum is used throughout the Flutter UI for display, colour
/// coding, and gating features (e.g. message requests require level < 6).
///
/// The backend currently issues levels 0–3 via automatic heuristics; higher
/// values require explicit user attestation.  [fromInt] clamps to the defined
/// range safely.
enum TrustLevel {
  /// 0 — No trust relationship; peer has been seen but not evaluated.
  unknown,

  /// 1 — Public contact; peer announced themselves on the mesh but has not
  /// been vouched for by anyone the local user trusts.
  public,

  /// 2 — Vouched by at least one peer that the local user trusts at level ≥ 4.
  vouched,

  /// 3 — Referenced in the web-of-trust graph with a non-zero indirect path
  /// from the local node (§8.3 transitive trust).
  referenced,

  /// 4 — Active ally relationship; the user has explicitly confirmed this peer
  /// in the Ally tier.
  ally,

  /// 5 — Known acquaintance; less formal than Ally but still an explicit choice
  /// by the local user.
  acquaintance,

  /// 6 — Explicitly trusted; this peer's messages arrive directly in the main
  /// inbox (no message request gate).
  trusted,

  /// 7 — Highly trusted; peer's endorsements carry significant weight in the
  /// web-of-trust propagation algorithm (§8.4).
  highlyTrusted,

  /// 8 — Inner circle (maximum trust); typically reserved for close personal
  /// contacts.  Peer's attestations have the strongest transitive effect.
  innerCircle;

  /// Parse a trust level integer from backend data.
  ///
  /// [v] is clamped to the valid range [0, 8] rather than throwing, so a
  /// future backend version that adds level 9 does not crash older Flutter apps.
  static TrustLevel fromInt(int v) =>
      TrustLevel.values[v.clamp(0, TrustLevel.values.length - 1)];

  /// The raw integer representation stored in the backend.
  int get value => index;

  /// Full human-readable label for display in profile cards and detail screens.
  String get label => const [
    'Unknown', 'Public', 'Vouched', 'Referenced', 'Ally',
    'Acquaintance', 'Trusted', 'Highly Trusted', 'Inner Circle',
  ][index];

  /// Abbreviated label for compact display (e.g. badge dots).
  String get shortLabel => const [
    '?', 'P', 'V', 'R', 'A', 'Aq', 'T', 'HT', 'IC',
  ][index];

  /// The display colour for this trust level.
  ///
  /// Colours progress from grey (unknown) through blue/cyan (low trust) to
  /// green (trusted) and amber (inner circle).  These are duplicated in
  /// MeshTheme for code paths that do not have a TrustLevel value available.
  Color get color => const [
    Color(0xFF9CA3AF), // 0 unknown  — neutral grey
    Color(0xFF6B7280), // 1 public   — darker grey
    Color(0xFF60A5FA), // 2 vouched  — light blue
    Color(0xFF3B82F6), // 3 referenced — medium blue
    Color(0xFF22D3EE), // 4 ally     — cyan
    Color(0xFF6EE7B7), // 5 acquaintance — light green
    Color(0xFF34D399), // 6 trusted  — medium green
    Color(0xFF059669), // 7 highly trusted — dark green
    Color(0xFFF59E0B), // 8 inner circle — amber (warm, personal)
  ][index];

  /// The icon representing this trust level in the UI (e.g. trust badges).
  ///
  /// Icons are chosen to be semantically meaningful:
  ///   unknown → help/question mark, inner circle → premium/star.
  IconData get icon => const [
    Icons.help_outline,
    Icons.person_outline,
    Icons.thumb_up_outlined,
    Icons.star_outline,
    Icons.handshake_outlined,
    Icons.chat_outlined,
    Icons.verified_outlined,
    Icons.shield_outlined,
    Icons.workspace_premium_outlined,
  ][index];
}

/// A snapshot of one known peer, as reported by the Rust contact store.
///
/// Instances are immutable.  The event bus delivers [PeerUpdatedEvent] events
/// that contain a new [PeerModel] to replace the old one in [PeersState].
///
/// [PeerModel] is intentionally a flat data struct — it does not contain nested
/// message or trust history.  Richer per-peer data is fetched on demand when
/// the user opens a peer's detail screen.
class PeerModel {
  const PeerModel({
    required this.id,
    required this.name,
    this.trustLevel = TrustLevel.unknown,
    this.status = 'offline',
    this.canBeExitNode = false,
    this.canBeWrapperNode = false,
    this.canBeStoreForward = false,
    this.canEndorsePeers = false,
    this.latencyMs,
  });

  /// Hex-encoded cryptographic peer ID (derived from Ed25519 public key).
  final String id;

  /// Display name chosen by the peer.  May be empty if the peer has not set one.
  final String name;

  /// This peer's trust level from the local node's perspective.
  final TrustLevel trustLevel;

  /// Current connectivity status.  One of: "online", "idle", "offline".
  /// The Rust backend updates this as peers connect and disconnect.
  final String status;

  /// Whether this peer advertises itself as an available exit node (§6.9.2).
  /// Exit nodes route outbound traffic on behalf of other peers.
  final bool canBeExitNode;

  /// Whether this peer advertises itself as an available wrapper node (§6.9.3).
  /// Wrapper nodes provide onion-routing hops for high-anonymity paths.
  final bool canBeWrapperNode;

  /// Whether this peer advertises store-and-forward capability (§6.8).
  /// Store-and-forward nodes buffer messages for offline peers.
  final bool canBeStoreForward;

  /// Whether this peer can endorse other peers in the web of trust (§8.4).
  /// Endorser capability requires the peer to be at trust level ≥ 6.
  final bool canEndorsePeers;

  /// Round-trip latency to this peer in milliseconds.
  /// Null means the latency has not yet been measured (peer just came online,
  /// or no keepalive ACK has been received yet).
  final int? latencyMs;

  /// True when the peer currently has an active transport session.
  bool get isOnline => status == 'online';

  /// True when the peer is connected but has been quiet (idle keepalive only).
  bool get isIdle => status == 'idle';

  /// Deserialise from a single element in the mi_get_peer_list() JSON array.
  factory PeerModel.fromJson(Map<String, dynamic> json) => PeerModel(
    id: json['id'] as String? ?? '',
    name: json['name'] as String? ?? '',
    // trustLevel comes as an int from Rust; fromInt clamps to the valid range.
    trustLevel: TrustLevel.fromInt(json['trustLevel'] as int? ?? 0),
    status: json['status'] as String? ?? 'offline',
    canBeExitNode: json['canBeExitNode'] as bool? ?? false,
    canBeWrapperNode: json['canBeWrapperNode'] as bool? ?? false,
    canBeStoreForward: json['canBeStoreForward'] as bool? ?? false,
    canEndorsePeers: json['canEndorsePeers'] as bool? ?? false,
    // latencyMs is nullable — null means "not yet measured".
    // We do NOT use ?? 0 here because 0ms would be a misleading valid value.
    latencyMs: json['latencyMs'] as int?,
  );

  /// Return a copy with selected fields replaced.
  ///
  /// Used by PeersState when a [PeerUpdatedEvent] updates only a subset of
  /// a peer's attributes (e.g. status changed but trust level did not).
  PeerModel copyWith({
    String? id,
    String? name,
    TrustLevel? trustLevel,
    String? status,
    bool? canBeExitNode,
    bool? canBeWrapperNode,
    bool? canBeStoreForward,
    bool? canEndorsePeers,
    int? latencyMs,
  }) => PeerModel(
    id: id ?? this.id,
    name: name ?? this.name,
    trustLevel: trustLevel ?? this.trustLevel,
    status: status ?? this.status,
    canBeExitNode: canBeExitNode ?? this.canBeExitNode,
    canBeWrapperNode: canBeWrapperNode ?? this.canBeWrapperNode,
    canBeStoreForward: canBeStoreForward ?? this.canBeStoreForward,
    canEndorsePeers: canEndorsePeers ?? this.canEndorsePeers,
    latencyMs: latencyMs ?? this.latencyMs,
  );
}
