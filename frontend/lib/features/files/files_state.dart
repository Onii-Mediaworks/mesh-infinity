import 'dart:async';

import 'package:flutter/foundation.dart';

import '../../backend/backend_bridge.dart';
import '../../backend/event_bus.dart';
import '../../backend/event_models.dart';
import '../../backend/models/file_transfer_models.dart';

class FilesState extends ChangeNotifier {
  FilesState(this._bridge) {
    _sub = EventBus.instance.stream.listen(_onEvent);
    loadTransfers();
  }

  final BackendBridge _bridge;
  StreamSubscription<BackendEvent>? _sub;

  List<FileTransferModel> _transfers = const [];

  List<FileTransferModel> get transfers => _transfers;
  List<FileTransferModel> get activeTransfers =>
      _transfers.where((t) => t.status.isActive).toList();
  List<FileTransferModel> get completedTransfers =>
      _transfers.where((t) => t.status.isDone).toList();

  Future<void> loadTransfers() async {
    _transfers = _bridge.fetchFileTransfers();
    notifyListeners();
  }

  Future<bool> cancelTransfer(String transferId) async {
    final ok = _bridge.cancelFileTransfer(transferId);
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
    notifyListeners();
  }

  @override
  void dispose() {
    _sub?.cancel();
    super.dispose();
  }
}
