import 'package:flutter/foundation.dart';

// ---------------------------------------------------------------------------
// Section and sub-page enumerations
// ---------------------------------------------------------------------------

enum AppSection {
  chat,
  garden,
  files,
  contacts,
  services,
  you,
  network,
  settings,
}

enum ChatSubPage { rooms, direct }
enum GardenSubPage { channels, feed, explore }
enum FilesSubPage { transfers, shared }
enum ContactsSubPage { all, online, requests }
enum ServicesSubPage { myServices, browse, hosting }
enum NetworkSubPage { status, nodes, transports }

// ---------------------------------------------------------------------------
// Sub-page label helper (used by SectionBottomBar)
// ---------------------------------------------------------------------------

List<String> subPageLabels(AppSection section) => switch (section) {
  AppSection.chat => ['Rooms', 'Direct'],
  AppSection.garden => ['Channels', 'Feed', 'Explore'],
  AppSection.files => ['Transfers', 'Shared'],
  AppSection.contacts => ['All', 'Online', 'Requests'],
  AppSection.services => ['My Services', 'Browse', 'Hosting'],
  AppSection.network => ['Status', 'Nodes', 'Transports'],
  AppSection.you => [],
  AppSection.settings => [],
};

// ---------------------------------------------------------------------------
// ShellState — navigation state for sections and sub-pages
// ---------------------------------------------------------------------------

class ShellState extends ChangeNotifier {
  AppSection _activeSection = AppSection.chat;
  int _activeSubPageIndex = 0;

  String? _selectedRoomId;
  String? _selectedPeerId;
  String? _selectedTransferId;

  // Whether a detail view is open (hides the bottom bar per spec)
  bool _inDetailView = false;

  // ---------------------------------------------------------------------------
  // Getters
  // ---------------------------------------------------------------------------

  AppSection get activeSection => _activeSection;
  int get activeSubPageIndex => _activeSubPageIndex;
  bool get inDetailView => _inDetailView;

  String? get selectedRoomId => _selectedRoomId;
  String? get selectedPeerId => _selectedPeerId;
  String? get selectedTransferId => _selectedTransferId;

  int subPageCount(AppSection section) => switch (section) {
    AppSection.chat => ChatSubPage.values.length,
    AppSection.garden => GardenSubPage.values.length,
    AppSection.files => FilesSubPage.values.length,
    AppSection.contacts => ContactsSubPage.values.length,
    AppSection.services => ServicesSubPage.values.length,
    AppSection.network => NetworkSubPage.values.length,
    AppSection.you => 0,
    AppSection.settings => 0,
  };

  bool get hasSubPages => subPageCount(_activeSection) > 0;

  ChatSubPage get chatSubPage => ChatSubPage.values[
    _activeSection == AppSection.chat
        ? _activeSubPageIndex.clamp(0, ChatSubPage.values.length - 1)
        : 0];

  GardenSubPage get gardenSubPage => GardenSubPage.values[
    _activeSection == AppSection.garden
        ? _activeSubPageIndex.clamp(0, GardenSubPage.values.length - 1)
        : 0];

  FilesSubPage get filesSubPage => FilesSubPage.values[
    _activeSection == AppSection.files
        ? _activeSubPageIndex.clamp(0, FilesSubPage.values.length - 1)
        : 0];

  ContactsSubPage get contactsSubPage => ContactsSubPage.values[
    _activeSection == AppSection.contacts
        ? _activeSubPageIndex.clamp(0, ContactsSubPage.values.length - 1)
        : 0];

  ServicesSubPage get servicesSubPage => ServicesSubPage.values[
    _activeSection == AppSection.services
        ? _activeSubPageIndex.clamp(0, ServicesSubPage.values.length - 1)
        : 0];

  NetworkSubPage get networkSubPage => NetworkSubPage.values[
    _activeSection == AppSection.network
        ? _activeSubPageIndex.clamp(0, NetworkSubPage.values.length - 1)
        : 0];

  // ---------------------------------------------------------------------------
  // Mutators
  // ---------------------------------------------------------------------------

  void selectSection(AppSection section) {
    if (_activeSection == section) return;
    _activeSection = section;
    _activeSubPageIndex = 0;
    _inDetailView = false;
    notifyListeners();
  }

  void selectSubPage(int index) {
    if (_activeSubPageIndex == index) return;
    _activeSubPageIndex = index;
    _inDetailView = false;
    notifyListeners();
  }

  void enterDetailView() {
    if (_inDetailView) return;
    _inDetailView = true;
    notifyListeners();
  }

  void exitDetailView() {
    if (!_inDetailView) return;
    _inDetailView = false;
    notifyListeners();
  }

  void selectRoom(String? roomId) {
    _selectedRoomId = roomId;
    _inDetailView = roomId != null;
    notifyListeners();
  }

  void selectPeer(String? peerId) {
    _selectedPeerId = peerId;
    _inDetailView = peerId != null;
    notifyListeners();
  }

  void selectTransfer(String? transferId) {
    _selectedTransferId = transferId;
    notifyListeners();
  }

  void clearSelections() {
    _selectedRoomId = null;
    _selectedPeerId = null;
    _selectedTransferId = null;
    _inDetailView = false;
    notifyListeners();
  }
}
