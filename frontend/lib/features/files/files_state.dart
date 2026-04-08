// files_state.dart
//
// FilesState is the single ChangeNotifier that owns all data for the Files
// feature: active/queued transfers and published (shared) services.
//
// WHAT DOES THIS CLASS OWN?
// -------------------------
// • The list of all known FileTransferModels (incoming, active, and completed).
// • The list of ServiceModels — mesh services this device can offer or is
//   subscribed to (e.g. file-sharing service endpoints).
//
// HOW DOES THE UI STAY UP TO DATE?
// ---------------------------------
// On construction, FilesState subscribes to EventBus.instance.stream.
// When Rust emits a TransferUpdatedEvent (progress ticked, state changed,
// new inbound offer arrived) the _onEvent handler patches _transfers in-place
// and calls notifyListeners(), causing every widget that called
// context.watch<FilesState>() to rebuild.
//
// All mutations (accept, cancel, send) go through methods on this class —
// widgets never write to the backend directly.  This keeps a single call site
// for "things that change transfer state", making future logging / undo
// straightforward to add.

import 'dart:async';
// dart:async provides StreamSubscription — the receipt for our EventBus
// listener.  Storing it in _sub lets us call _sub?.cancel() in dispose()
// so we stop receiving events after the widget tree tears down.

import 'package:flutter/foundation.dart';
// flutter/foundation.dart provides ChangeNotifier.
// It is a no-widget import — keeps this class light and testable without
// a full Flutter rendering runtime.

import '../../backend/backend_bridge.dart';
// BackendBridge wraps all Rust FFI calls into typed Dart methods.
import '../../backend/event_bus.dart';
// EventBus — background-isolate poller that converts backend events into a
// Dart broadcast Stream.  See event_bus.dart for the polling architecture.
import '../../backend/event_models.dart';
// Typed event hierarchy — we specifically handle TransferUpdatedEvent here.
import '../../backend/models/file_transfer_models.dart';
// FileTransferModel, TransferStatus, TransferDirection — typed transfer data.
import '../../backend/models/settings_models.dart';
// ServiceModel — describes a mesh service (name, config, active status).

/// Manages all file-transfer state for the Files section of the app.
///
/// Provided via `Provider<FilesState>` at the app root so that
/// [TransfersScreen], [FilesSharedScreen], and [SendFileSheet] all share the
/// same data without independent backend calls.
///
/// INVARIANTS
/// ----------
/// • [_transfers] is always in backend order (backend is source of truth).
/// • notifyListeners() is always called after any mutation — never call backend
///   methods directly from the UI.
/// • [_disposed] must be checked before notifyListeners() because stream events
///   can arrive slightly after dispose() returns (see dispose() docs).
class FilesState extends ChangeNotifier {
  /// Creates the state and immediately kicks off initial data loads.
  ///
  /// [_bridge] is injected from outside (dependency-injection pattern) so that
  /// tests can substitute a fake bridge without real FFI calls.
  ///
  /// The constructor cannot be async, so both loads are fire-and-forget:
  /// the UI starts with empty lists and rebuilds when data arrives.
  FilesState(this._bridge) {
    // Register for live transfer updates from the Rust backend.
    // The EventBus polls Rust ~5×/s and broadcasts typed events here.
    _sub = EventBus.instance.stream.listen(_onEvent);

    // Populate the lists immediately so the UI has data on first render.
    loadTransfers();
    _loadServices();
  }

  // ---------------------------------------------------------------------------
  // Dependencies & bookkeeping
  // ---------------------------------------------------------------------------

  /// The FFI gateway to Rust — all backend calls go through this.
  final BackendBridge _bridge;

  /// Handle to our EventBus subscription.  Stored so we can cancel it in
  /// dispose() and prevent callbacks from firing on a dead object.
  StreamSubscription<BackendEvent>? _sub;

  /// Guard flag: set to true in dispose() so _onEvent and loadTransfers()
  /// do not call notifyListeners() after the ChangeNotifier is torn down.
  ///
  /// WHY is this needed? Stream cancellation is async — a TransferUpdatedEvent
  /// may already be queued in the Dart event loop by the time cancel() is
  /// called, so the callback fires one more time after dispose() returns.
  /// Checking _disposed before notifyListeners() prevents the "used after
  /// dispose" exception.
  bool _disposed = false;

  // ---------------------------------------------------------------------------
  // Data
  // ---------------------------------------------------------------------------

  /// All file transfers known to the local node (pending, active, done).
  /// Starts empty; populated by [loadTransfers].
  List<FileTransferModel> _transfers = const [];

  /// Mesh services configured on this device.
  /// Used by FilesSharedScreen to show what the device is offering.
  List<ServiceModel> _services = const [];

  // ---------------------------------------------------------------------------
  // Public getters — computed views over _transfers
  // ---------------------------------------------------------------------------

  /// All transfers, unfiltered.  Used when the UI needs to group them itself.
  List<FileTransferModel> get transfers => _transfers;

  /// Inbound transfer offers waiting for the user to accept or decline.
  ///
  /// A transfer is an "incoming offer" when:
  ///   - Its status is [TransferStatus.pending] (no action taken yet), AND
  ///   - Its direction is [TransferDirection.receive] (the remote peer is
  ///     sending us something, not the other way around).
  ///
  /// WHY filter here instead of in the widget?  Centralising the filter keeps
  /// widget code simple and ensures consistent definitions across the app.
  List<FileTransferModel> get incomingOffers => _transfers
      .where((t) =>
          t.status == TransferStatus.pending &&
          t.direction == TransferDirection.receive)
      .toList();

  /// Transfers currently in progress (either uploading or downloading).
  ///
  /// Uses [TransferStatus.isActive] — a helper getter on the status enum
  /// that returns true for the subset of statuses that represent in-flight
  /// transfers (active, paused-resumable, etc.).
  List<FileTransferModel> get activeTransfers =>
      _transfers.where((t) => t.status.isActive).toList();

  /// Transfers that have reached a terminal state (completed, failed,
  /// cancelled).  Uses [TransferStatus.isDone].
  List<FileTransferModel> get completedTransfers =>
      _transfers.where((t) => t.status.isDone).toList();

  /// The services list, for widgets that display or configure mesh services.
  List<ServiceModel> get services => _services;

  // ---------------------------------------------------------------------------
  // Load / refresh operations
  // ---------------------------------------------------------------------------

  /// Fetches the current transfer list from the backend and notifies listeners.
  ///
  /// Exposed as public so [TransfersScreen] can use it as a pull-to-refresh
  /// handler.  Also called after any action that might change the list
  /// (sendFile, cancelTransfer, acceptTransfer).
  Future<void> loadTransfers() async {
    // fetchFileTransfers() calls into Rust via FFI and returns a
    // List<FileTransferModel> decoded from JSON.  It is synchronous today
    // (the backend returns cached in-memory state), but the Future<void>
    // return type leaves room for a truly async implementation.
    _transfers = _bridge.fetchFileTransfers();
    if (!_disposed) notifyListeners();
  }

  /// Fetches the service list from the backend.
  ///
  /// Private because this is an internal detail — services are loaded once
  /// on construction and refreshed via [configureService].  External callers
  /// have no reason to trigger a service reload independently.
  Future<void> _loadServices() async {
    _services = _bridge.fetchServices();
    if (!_disposed) notifyListeners();
  }

  // ---------------------------------------------------------------------------
  // User-initiated actions
  // ---------------------------------------------------------------------------

  /// Initiates an outgoing file transfer to [peerId].
  ///
  /// [filePath] must be an absolute path to a readable file on the local
  /// filesystem.  The backend validates the path before starting.
  ///
  /// Returns true if the backend accepted the request and a new transfer was
  /// queued; false if the backend rejected it (e.g. peer not reachable,
  /// path invalid).
  ///
  /// On success, reloads the transfer list so the new entry appears immediately
  /// in [TransfersScreen] without waiting for a TransferUpdatedEvent.
  Future<bool> sendFile({
    required String peerId,
    required String filePath,
  }) async {
    // startFileTransfer returns a FileTransferModel stub if the backend
    // accepted the request, or null if it failed.
    final result = _bridge.startFileTransfer(
      direction: 'send',
      peerId: peerId,
      filePath: filePath,
    );
    if (result != null) {
      // Reload so the outgoing transfer appears immediately in the UI.
      await loadTransfers();
      return true;
    }
    return false;
  }

  /// Updates the configuration for a named service and refreshes the service
  /// list.
  ///
  /// [serviceId] is the opaque identifier returned by fetchServices().
  /// [config] is a key-value map whose shape depends on the service type.
  ///
  /// Returns true if the backend applied the config successfully.
  Future<bool> configureService(
    String serviceId,
    Map<String, dynamic> config,
  ) async {
    final ok = _bridge.configureService(serviceId, config);
    // Only reload if the call succeeded — avoids a redundant round-trip on
    // failure when the service list has not changed.
    if (ok) await _loadServices();
    return ok;
  }

  /// Cancels an in-progress or pending transfer identified by [transferId].
  ///
  /// Works for both outgoing (upload) and incoming (download) transfers.
  /// Returns true if the backend confirmed cancellation.
  ///
  /// After cancellation, reloads so the tile updates to "cancelled" state
  /// instead of waiting for the next TransferUpdatedEvent.
  Future<bool> cancelTransfer(String transferId) async {
    final ok = _bridge.cancelFileTransfer(transferId);
    if (ok) await loadTransfers();
    return ok;
  }

  /// Accepts an incoming file transfer offer.
  ///
  /// [transferId] is the opaque ID of the pending offer (from incomingOffers).
  /// [savePath] is where the file should be written on disk.  An empty string
  /// tells the backend to use its default download directory.
  ///
  /// Returns true if the backend began the download.  After acceptance the
  /// transfer status changes from pending → active and will receive progress
  /// events via TransferUpdatedEvent.
  Future<bool> acceptTransfer(String transferId, {String savePath = ''}) async {
    final ok = _bridge.acceptFileTransfer(transferId, savePath: savePath);
    // Reload immediately so the tile moves from "Incoming Offers" to "Active"
    // without waiting for the first progress event.
    if (ok) await loadTransfers();
    return ok;
  }

  // ---------------------------------------------------------------------------
  // Event handling
  // ---------------------------------------------------------------------------

  /// Handles live transfer-progress events from the backend.
  ///
  /// Called by the EventBus stream listener for every [BackendEvent].
  /// Only [TransferUpdatedEvent] is relevant here — all other event types
  /// are silently ignored so that this state class does not interfere with
  /// PeersState, MessagingState, etc. which own their own event types.
  ///
  /// On a TransferUpdatedEvent we patch _transfers in-place rather than
  /// reloading the full list from the backend.  This keeps the UI smooth
  /// during high-frequency progress ticks (e.g. large file in progress).
  void _onEvent(BackendEvent event) {
    // Early-return for all non-transfer events.
    if (event is! TransferUpdatedEvent) return;

    final updated = event.transfer;

    // Replace the matching transfer in _transfers with the updated version.
    // The list-comprehension pattern (collection-for with conditional) creates
    // a new List object, which is required for notifyListeners() to trigger
    // a proper widget rebuild diff.
    _transfers = [
      for (final t in _transfers)
        if (t.id == updated.id) updated else t,
    ];

    // If the backend event references a transfer we don't have locally yet
    // (race condition on first launch, or a transfer started on another device
    // synced here), append it so it appears in the UI.
    if (!_transfers.any((t) => t.id == updated.id)) {
      _transfers = [..._transfers, updated];
    }

    if (!_disposed) notifyListeners();
  }

  // ---------------------------------------------------------------------------
  // Cleanup
  // ---------------------------------------------------------------------------

  @override
  void dispose() {
    // Set the guard first so no in-flight callback can call notifyListeners()
    // after we begin teardown.
    _disposed = true;

    // Cancel the EventBus subscription so _onEvent is never called again.
    // The ?. null-safe call handles the (theoretical) case where _sub was
    // never assigned — e.g. if the constructor threw before reaching the
    // listen() call.
    _sub?.cancel();

    super.dispose();
  }
}
