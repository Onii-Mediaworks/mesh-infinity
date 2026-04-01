import 'package:flutter/material.dart';

/// Nine-level trust scale as defined in §22.4.2.
///
/// The backend currently issues levels 0–3; higher values are reserved for
/// future implementation. [fromInt] clamps to the defined range safely.
enum TrustLevel {
  unknown,       // 0 — no trust relationship
  public,        // 1 — public contact, unverified
  vouched,       // 2 — vouched by a known peer
  referenced,    // 3 — referenced in the web-of-trust
  ally,          // 4 — active ally relationship
  acquaintance,  // 5 — known acquaintance
  trusted,       // 6 — explicitly trusted
  highlyTrusted, // 7 — highly trusted
  innerCircle;   // 8 — inner circle (maximum trust)

  static TrustLevel fromInt(int v) =>
      TrustLevel.values[v.clamp(0, TrustLevel.values.length - 1)];

  int get value => index;

  String get label => const [
    'Unknown', 'Public', 'Vouched', 'Referenced', 'Ally',
    'Acquaintance', 'Trusted', 'Highly Trusted', 'Inner Circle',
  ][index];

  String get shortLabel => const [
    '?', 'P', 'V', 'R', 'A', 'Aq', 'T', 'HT', 'IC',
  ][index];

  Color get color => const [
    Color(0xFF9CA3AF), Color(0xFF6B7280), Color(0xFF60A5FA),
    Color(0xFF3B82F6), Color(0xFF22D3EE), Color(0xFF6EE7B7),
    Color(0xFF34D399), Color(0xFF059669), Color(0xFFF59E0B),
  ][index];

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

  final String id;
  final String name;
  final TrustLevel trustLevel;
  final String status;

  /// Whether this peer advertises itself as an available exit node.
  final bool canBeExitNode;

  /// Whether this peer advertises itself as an available wrapper node.
  final bool canBeWrapperNode;

  /// Whether this peer advertises store-and-forward capability.
  final bool canBeStoreForward;

  /// Whether this peer can endorse other peers in the web of trust.
  final bool canEndorsePeers;

  /// Round-trip latency to this peer in milliseconds, if known.
  final int? latencyMs;

  bool get isOnline => status == 'online';
  bool get isIdle => status == 'idle';

  factory PeerModel.fromJson(Map<String, dynamic> json) => PeerModel(
    id: json['id'] as String? ?? '',
    name: json['name'] as String? ?? '',
    trustLevel: TrustLevel.fromInt(json['trustLevel'] as int? ?? 0),
    status: json['status'] as String? ?? 'offline',
    canBeExitNode: json['canBeExitNode'] as bool? ?? false,
    canBeWrapperNode: json['canBeWrapperNode'] as bool? ?? false,
    canBeStoreForward: json['canBeStoreForward'] as bool? ?? false,
    canEndorsePeers: json['canEndorsePeers'] as bool? ?? false,
    latencyMs: json['latencyMs'] as int?,
  );

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
