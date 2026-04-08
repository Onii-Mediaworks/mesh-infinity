// =============================================================================
// file_transfer_models.dart
//
// Typed Dart models for file transfers between mesh peers.
//
// WHERE DO THESE COME FROM?
// When the Rust backend processes a file transfer (either an outbound send or
// an inbound receive), it stores a FileTransfer record in its internal state.
// BackendBridge.fetchFileTransfers() calls mi_file_transfers_json() in Rust,
// which returns a JSON array of all current transfers.  This file converts
// that JSON into typed Dart objects.
//
// IMMUTABILITY PATTERN
// All model classes here are immutable (const constructors, final fields) and
// use copyWith() for updates.  This means the UI never mutates a model in place;
// instead it creates a new object with the changed field.  This makes state
// diffing straightforward — if two objects are identical, nothing changed.
//
// DESERIALIZATION PATTERN
// Every fromJson() factory uses `?? fallback` for every field so that a
// missing or null JSON key never causes a runtime type cast exception.  The
// worst case is that a field shows as its default value (e.g. 0 bytes
// transferred), which the user can see but which does not crash the app.
// =============================================================================

/// The lifecycle state of a single file transfer.
///
/// The backend drives these transitions — the Dart side only reads them.
/// Progress updates arrive as [TransferStatus.active] events from Rust
/// via [TransferUpdatedEvent] on the event bus.
enum TransferStatus {
  /// Transfer has been queued but not yet started.
  pending,

  /// Transfer is currently in progress (bytes are flowing).
  active,

  /// Transfer was paused by the user or the system (e.g. network unavailable).
  paused,

  /// Transfer finished successfully.
  completed,

  /// Transfer failed due to a network error, rejection, or timeout.
  failed;

  /// Parse a [TransferStatus] from its snake_case string name.
  ///
  /// Falls back to [TransferStatus.pending] for unknown strings so that a
  /// newer backend version that adds a new status does not crash the UI.
  static TransferStatus fromString(String s) =>
      TransferStatus.values.firstWhere(
        (e) => e.name == s,
        // Pending is the safest fallback — it shows as "not yet started"
        // rather than misleadingly claiming success or failure.
        orElse: () => TransferStatus.pending,
      );

  /// True while the transfer is actively transferring bytes.
  bool get isActive => this == TransferStatus.active;

  /// True once the transfer has reached a terminal state (success or failure).
  /// Transfers in a terminal state will not receive further progress events.
  bool get isDone => this == TransferStatus.completed || this == TransferStatus.failed;
}

/// Which direction the file is moving relative to this node.
enum TransferDirection {
  /// This node is sending the file to a remote peer.
  send,

  /// This node is receiving the file from a remote peer.
  receive;

  /// Parse from the string "send" or "receive".
  /// Any unrecognised string defaults to [receive] — a conservative choice
  /// that avoids accidentally presenting a receive as a send.
  static TransferDirection fromString(String s) =>
      s == 'send' ? TransferDirection.send : TransferDirection.receive;
}

/// A snapshot of one file transfer, as reported by the Rust backend.
///
/// Instances are immutable — the event bus delivers new [FileTransferModel]
/// objects whenever the backend emits a [TransferUpdatedEvent].  The UI state
/// object (FilesState) replaces the old record in its list with the new one.
///
/// Progress percentage is derived via [progress] rather than stored separately
/// to avoid the state getting out of sync with the raw byte counts.
class FileTransferModel {
  const FileTransferModel({
    required this.id,
    required this.peerId,
    required this.name,
    required this.sizeBytes,
    required this.transferredBytes,
    required this.status,
    required this.direction,
  });

  /// Opaque backend-assigned transfer ID.  Used to match update events to the
  /// existing record and to cancel or accept the transfer via [BackendBridge].
  final String id;

  /// The remote peer involved in this transfer (the sender for incoming, the
  /// recipient for outgoing).  Hex-encoded peer ID string.
  final String peerId;

  /// The filename as reported by the sender.  Not a local file path.
  final String name;

  /// Total size of the file in bytes, as reported by the sender.
  /// May be 0 for incoming transfers where the sender has not yet announced
  /// the size (e.g. streaming mode).
  final int sizeBytes;

  /// How many bytes have been transferred so far.
  /// For sends: bytes confirmed received by the remote peer.
  /// For receives: bytes written to the local buffer.
  final int transferredBytes;

  final TransferStatus status;
  final TransferDirection direction;

  /// Transfer completion fraction in [0.0, 1.0].
  ///
  /// Returns 0.0 when [sizeBytes] is zero (unknown total size) to avoid
  /// division by zero.  The .clamp() prevents floating-point rounding errors
  /// from producing values outside the 0–1 range that progress bars expect.
  double get progress =>
      sizeBytes > 0 ? (transferredBytes / sizeBytes).clamp(0.0, 1.0) : 0.0;

  /// Deserialise from the JSON object for a single transfer, as returned by
  /// mi_file_transfers_json() in the Rust backend.
  factory FileTransferModel.fromJson(Map<String, dynamic> json) => FileTransferModel(
    id: json['id'] as String? ?? '',
    peerId: json['peerId'] as String? ?? '',
    name: json['name'] as String? ?? '',
    // JSON numbers can be int or double depending on the serialiser, so we
    // always go through num and then convert to int.
    sizeBytes: (json['sizeBytes'] as num?)?.toInt() ?? 0,
    transferredBytes: (json['transferredBytes'] as num?)?.toInt() ?? 0,
    status: TransferStatus.fromString(json['status'] as String? ?? 'pending'),
    direction: TransferDirection.fromString(json['direction'] as String? ?? 'receive'),
  );

  /// Return a copy of this transfer with selected fields replaced.
  ///
  /// Used by FilesState when a [TransferUpdatedEvent] arrives — it calls
  /// copyWith() to update only the changed fields (e.g. transferredBytes and
  /// status) while keeping the rest (id, name, peerId) unchanged.
  FileTransferModel copyWith({
    String? id,
    String? peerId,
    String? name,
    int? sizeBytes,
    int? transferredBytes,
    TransferStatus? status,
    TransferDirection? direction,
  }) => FileTransferModel(
    id: id ?? this.id,
    peerId: peerId ?? this.peerId,
    name: name ?? this.name,
    sizeBytes: sizeBytes ?? this.sizeBytes,
    transferredBytes: transferredBytes ?? this.transferredBytes,
    status: status ?? this.status,
    direction: direction ?? this.direction,
  );
}
