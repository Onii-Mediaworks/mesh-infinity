import 'dart:async';

import 'package:flutter/foundation.dart';

import '../../backend/backend_bridge.dart';
import '../../backend/event_bus.dart';
import '../../backend/event_models.dart';
import '../../backend/models/file_transfer_models.dart';
import '../../backend/models/settings_models.dart';

class FilesState extends ChangeNotifier {
  FilesState(this._bridge) {
    _sub = EventBus.instance.stream.listen(_onEvent);
    loadTransfers();
    _loadServices();
  }

  final BackendBridge _bridge;
  StreamSubscription<BackendEvent>? _sub;
  bool _disposed = false;

  List<FileTransferModel> _transfers = const [];
  List<ServiceModel> _services = const [];

  List<FileTransferModel> get transfers => _transfers;
  List<FileTransferModel> get incomingOffers => _transfers
      .where((t) =>
          t.status == TransferStatus.pending &&
          t.direction == TransferDirection.receive)
      .toList();
  List<FileTransferModel> get activeTransfers =>
      _transfers.where((t) => t.status.isActive).toList();
  List<FileTransferModel> get completedTransfers =>
      _transfers.where((t) => t.status.isDone).toList();
  List<ServiceModel> get services => _services;

  Future<void> loadTransfers() async {
    _transfers = _bridge.fetchFileTransfers();
    if (!_disposed) notifyListeners();
  }

  Future<void> _loadServices() async {
    _services = _bridge.fetchServices();
    if (!_disposed) notifyListeners();
  }

  Future<bool> sendFile({
    required String peerId,
    required String filePath,
  }) async {
    final result = _bridge.startFileTransfer(
      direction: 'send',
      peerId: peerId,
      filePath: filePath,
    );
    if (result != null) {
      await loadTransfers();
      return true;
    }
    return false;
  }

  Future<bool> configureService(
    String serviceId,
    Map<String, dynamic> config,
  ) async {
    final ok = _bridge.configureService(serviceId, config);
    if (ok) await _loadServices();
    return ok;
  }

  Future<bool> cancelTransfer(String transferId) async {
    final ok = _bridge.cancelFileTransfer(transferId);
    if (ok) await loadTransfers();
    return ok;
  }

  Future<bool> acceptTransfer(String transferId, {String savePath = ''}) async {
    final ok = _bridge.acceptFileTransfer(transferId, savePath: savePath);
    if (ok) await loadTransfers();
    return ok;
  }

  void _onEvent(BackendEvent event) {
    if (event is! TransferUpdatedEvent) return;
    final updated = event.transfer;
    _transfers = [
      for (final t in _transfers)
        if (t.id == updated.id) updated else t,
    ];
    if (!_transfers.any((t) => t.id == updated.id)) {
      _transfers = [..._transfers, updated];
    }
    if (!_disposed) notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    _sub?.cancel();
    super.dispose();
  }
}
