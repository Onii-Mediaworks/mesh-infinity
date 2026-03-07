import 'package:flutter/foundation.dart';

enum AppSection { chat, files, peers, network, settings }

class ShellState extends ChangeNotifier {
  AppSection _activeSection = AppSection.chat;
  String? _selectedRoomId;
  String? _selectedPeerId;
  String? _selectedTransferId;

  AppSection get activeSection => _activeSection;
  String? get selectedRoomId => _selectedRoomId;
  String? get selectedPeerId => _selectedPeerId;
  String? get selectedTransferId => _selectedTransferId;

  void selectSection(AppSection section) {
    if (_activeSection == section) return;
    _activeSection = section;
    notifyListeners();
  }

  void selectRoom(String? roomId) {
    if (_selectedRoomId == roomId) return;
    _selectedRoomId = roomId;
    notifyListeners();
  }

  void selectPeer(String? peerId) {
    if (_selectedPeerId == peerId) return;
    _selectedPeerId = peerId;
    notifyListeners();
  }

  void selectTransfer(String? transferId) {
    if (_selectedTransferId == transferId) return;
    _selectedTransferId = transferId;
    notifyListeners();
  }

  void clearSelections() {
    _selectedRoomId = null;
    _selectedPeerId = null;
    _selectedTransferId = null;
    notifyListeners();
  }
}
