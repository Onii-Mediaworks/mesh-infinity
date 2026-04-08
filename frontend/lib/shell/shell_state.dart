// shell_state.dart
//
// ShellState — the single source of truth for which part of the app is
// currently visible.
//
// THE NAVIGATION MODEL:
// ----------------------
// Mesh Infinity uses a two-level navigation model:
//
//   Level 1 — Sections.  The top-level destinations listed in the drawer:
//     Chat, Garden, Files, Contacts, Services, You, Network, Settings.
//     Selecting a section is always a full reset — the sub-page index goes
//     back to 0 and any open detail view is closed.
//
//   Level 2 — Sub-pages.  Several sections have multiple peer tabs:
//     Chat → Rooms / Direct
//     Garden → Channels / Feed / Explore
//     Files → Transfers / Shared
//     Contacts → All / Online / Requests
//     Services → My Services / Browse / Hosting
//     Network → Status / Nodes / Transports
//     You and Settings have no sub-pages.
//
//   Level 3 — Detail views.  Within a sub-page, the user can drill into
//     a specific item (a chat thread, a contact detail, a transfer detail).
//     Detail views hide the bottom sub-page bar to give content full height.
//
// SELECTED ITEM IDs:
// ------------------
// Three optional IDs track the currently-open item in key sections:
//   selectedRoomId    — the open chat/garden thread (if any).
//   selectedPeerId    — the contact being viewed (if any).
//   selectedTransferId — the file transfer being viewed (if any).
//
// These IDs are stored here (rather than in their feature states) so the
// shell can pass them to the detail pane on wide/desktop layouts, where
// both the list and the detail view are visible simultaneously.
//
// DESIGN NOTES:
// -------------
// ShellState extends ChangeNotifier so it can be consumed with
// context.watch<ShellState>() in any widget that needs to react to
// navigation changes.  It is provided at the root of the widget tree in
// app.dart.
//
// Mutators are no-ops if the value would not change — this avoids spurious
// rebuilds on redundant calls (e.g. tapping the already-active section item
// in the drawer).

import 'package:flutter/foundation.dart';

// ---------------------------------------------------------------------------
// Section enumeration
// ---------------------------------------------------------------------------

/// The top-level sections of the app, corresponding to the main drawer items.
///
/// Order here matches the drawer layout: social group first, then You,
/// then operator group (Network, Settings).
enum AppSection {
  /// Direct and group message rooms (Level 1: Rooms tab, Level 2: Direct tab).
  chat,
  /// Public channels, activity feed, and discovery (Garden).
  garden,
  /// Inbound and outbound file transfers, and shared files.
  files,
  /// All known contacts, online contacts, and pending requests.
  contacts,
  /// Hosted and browsable mesh services.
  services,
  /// The user's own identity: display name, QR code, masks.
  you,
  /// Node network status, connected peers, and active transports.
  network,
  /// All app settings screens.
  settings,
}

// ---------------------------------------------------------------------------
// Sub-page enumerations — one per section that has multiple tabs
// ---------------------------------------------------------------------------

/// Sub-pages within the Chat section.
enum ChatSubPage {
  /// Group and direct message rooms list.
  rooms,
  /// Direct (1-to-1) message conversations only.
  direct,
}

/// Sub-pages within the Garden section.
enum GardenSubPage {
  /// Subscribed channels list.
  channels,
  /// Activity feed across all subscribed channels.
  feed,
  /// Discover and join new public channels.
  explore,
}

/// Sub-pages within the Files section.
enum FilesSubPage {
  /// Active and completed transfers.
  transfers,
  /// Files the user has shared with contacts.
  shared,
}

/// Sub-pages within the Contacts section.
enum ContactsSubPage {
  /// All known contacts regardless of online status.
  all,
  /// Contacts that are currently online.
  online,
  /// Incoming contact requests awaiting the user's decision.
  requests,
}

/// Sub-pages within the Services section.
enum ServicesSubPage {
  /// Services the user is running or has configured.
  myServices,
  /// Browse services offered by contacts and mesh nodes.
  browse,
  /// Hosting settings and service provisioning.
  hosting,
}

/// Sub-pages within the Network section.
enum NetworkSubPage {
  /// Overall node status: connectivity, peers, transport health.
  status,
  /// Detailed list of known mesh nodes.
  nodes,
  /// Active transport configurations (clearnet, Tor, I2P, Bluetooth).
  transports,
}

// ---------------------------------------------------------------------------
// Sub-page label helper
// ---------------------------------------------------------------------------

/// Returns the display labels for the sub-page tabs of [section].
///
/// Used by [SectionBottomBar] to build its [NavigationDestination] list.
/// Returns an empty list for sections with no sub-pages (You, Settings).
///
/// The order must match the corresponding enum's `.values` order so that
/// tab index 0 = first label = first enum value.
List<String> subPageLabels(AppSection section) => switch (section) {
  AppSection.chat     => ['Rooms', 'Direct'],
  AppSection.garden   => ['Channels', 'Feed', 'Explore'],
  AppSection.files    => ['Transfers', 'Shared'],
  AppSection.contacts => ['All', 'Online', 'Requests'],
  AppSection.services => ['My Services', 'Browse', 'Hosting'],
  AppSection.network  => ['Status', 'Nodes', 'Transports'],
  // You and Settings have a single root screen with no tab bar.
  AppSection.you      => [],
  AppSection.settings => [],
};

// ---------------------------------------------------------------------------
// ShellState — ChangeNotifier for navigation
// ---------------------------------------------------------------------------

/// Holds and mutates the current navigation state of the app shell.
///
/// Provided at the root via MultiProvider in app.dart.  Consumed with
/// [context.watch] in the shell widgets and [context.read] for one-shot
/// navigation mutations.
class ShellState extends ChangeNotifier {
  // -------------------------------------------------------------------------
  // Internal state
  // -------------------------------------------------------------------------

  /// The currently visible top-level section.  Defaults to Chat on startup.
  AppSection _activeSection = AppSection.chat;

  /// The currently selected sub-page index within [_activeSection].
  ///
  /// Reset to 0 whenever the active section changes.  Clamped to the valid
  /// range in getters to guard against stale values after a section switch.
  int _activeSubPageIndex = 0;

  // ---- Selected item IDs ----

  /// ID of the currently open chat room or null if none is open.
  ///
  /// Set by [selectRoom]; drives the detail pane on wide/desktop layouts.
  String? _selectedRoomId;

  /// ID of the contact being viewed in detail, or null.
  ///
  /// Set by [selectPeer]; drives the contact detail pane on wide layouts.
  String? _selectedPeerId;

  /// ID of the file transfer being viewed in detail, or null.
  ///
  /// Set by [selectTransfer]; used on wide layouts and for deep-linking.
  String? _selectedTransferId;

  /// Whether a detail view is currently open within the active section.
  ///
  /// When true, [SectionBottomBar] hides itself to give the detail content
  /// the full vertical height.  Set to true by [selectRoom], [selectPeer],
  /// and [enterDetailView]; set to false by any top-level navigation action.
  bool _inDetailView = false;

  // -------------------------------------------------------------------------
  // Read API — getters
  // -------------------------------------------------------------------------

  /// The currently active top-level section.
  AppSection get activeSection => _activeSection;

  /// The active sub-page index within the current section (0-based).
  int get activeSubPageIndex => _activeSubPageIndex;

  /// Whether a detail view is open (hides the bottom sub-page tab bar).
  bool get inDetailView => _inDetailView;

  /// ID of the open room, or null if no room is open.
  String? get selectedRoomId => _selectedRoomId;

  /// ID of the viewed peer, or null if no peer detail is open.
  String? get selectedPeerId => _selectedPeerId;

  /// ID of the viewed transfer, or null.
  String? get selectedTransferId => _selectedTransferId;

  /// Returns the number of sub-pages for [section].
  ///
  /// Delegates to the corresponding sub-page enum's length.
  /// Returns 0 for You and Settings (no sub-page tabs).
  int subPageCount(AppSection section) => switch (section) {
    AppSection.chat     => ChatSubPage.values.length,
    AppSection.garden   => GardenSubPage.values.length,
    AppSection.files    => FilesSubPage.values.length,
    AppSection.contacts => ContactsSubPage.values.length,
    AppSection.services => ServicesSubPage.values.length,
    AppSection.network  => NetworkSubPage.values.length,
    AppSection.you      => 0,
    AppSection.settings => 0,
  };

  /// True when the current section has more than one sub-page.
  ///
  /// Used by [SectionBottomBar] to decide whether to render at all.
  bool get hasSubPages => subPageCount(_activeSection) > 0;

  // ---- Typed sub-page getters ----
  // Each getter returns the strongly-typed enum value for the active sub-page.
  // The _activeSection guard returns the first enum value (index 0) if the
  // section is not currently active — callers should only read a section's
  // sub-page when that section is active, but these guards prevent out-of-range
  // exceptions if called defensively.

  /// The active Chat sub-page, or [ChatSubPage.rooms] if Chat is not active.
  ChatSubPage get chatSubPage => ChatSubPage.values[
    _activeSection == AppSection.chat
        ? _activeSubPageIndex.clamp(0, ChatSubPage.values.length - 1)
        : 0];

  /// The active Garden sub-page, or [GardenSubPage.channels] if not active.
  GardenSubPage get gardenSubPage => GardenSubPage.values[
    _activeSection == AppSection.garden
        ? _activeSubPageIndex.clamp(0, GardenSubPage.values.length - 1)
        : 0];

  /// The active Files sub-page, or [FilesSubPage.transfers] if not active.
  FilesSubPage get filesSubPage => FilesSubPage.values[
    _activeSection == AppSection.files
        ? _activeSubPageIndex.clamp(0, FilesSubPage.values.length - 1)
        : 0];

  /// The active Contacts sub-page, or [ContactsSubPage.all] if not active.
  ContactsSubPage get contactsSubPage => ContactsSubPage.values[
    _activeSection == AppSection.contacts
        ? _activeSubPageIndex.clamp(0, ContactsSubPage.values.length - 1)
        : 0];

  /// The active Services sub-page, or [ServicesSubPage.myServices] if not active.
  ServicesSubPage get servicesSubPage => ServicesSubPage.values[
    _activeSection == AppSection.services
        ? _activeSubPageIndex.clamp(0, ServicesSubPage.values.length - 1)
        : 0];

  /// The active Network sub-page, or [NetworkSubPage.status] if not active.
  NetworkSubPage get networkSubPage => NetworkSubPage.values[
    _activeSection == AppSection.network
        ? _activeSubPageIndex.clamp(0, NetworkSubPage.values.length - 1)
        : 0];

  // -------------------------------------------------------------------------
  // Write API — mutators
  // -------------------------------------------------------------------------

  /// Switch the active section to [section].
  ///
  /// Resets the sub-page index to 0 and clears the detail view flag so the
  /// new section always opens at its root state.  No-op if [section] is
  /// already active (prevents spurious rebuilds from double-taps).
  void selectSection(AppSection section) {
    if (_activeSection == section) return;
    _activeSection = section;
    _activeSubPageIndex = 0;
    _inDetailView = false;
    notifyListeners();
  }

  /// Switch to sub-page [index] within the current section.
  ///
  /// Also clears the detail view flag — navigating to a different sub-page
  /// implicitly exits any open detail view within the previous sub-page.
  /// No-op if [index] is already selected.
  void selectSubPage(int index) {
    if (_activeSubPageIndex == index) return;
    _activeSubPageIndex = index;
    _inDetailView = false;
    notifyListeners();
  }

  /// Mark that the user has drilled into a detail view.
  ///
  /// Causes [SectionBottomBar] to hide itself.  Call this when pushing a
  /// detail screen (e.g. ThreadScreen, PeerDetailScreen) for sections where
  /// the bottom bar would otherwise still be visible.  No-op if already in
  /// a detail view.
  void enterDetailView() {
    if (_inDetailView) return;
    _inDetailView = true;
    notifyListeners();
  }

  /// Return from a detail view to the sub-page list.
  ///
  /// Causes [SectionBottomBar] to reappear.  Call this when the back button
  /// or a close action pops the detail screen.  No-op if not in a detail view.
  void exitDetailView() {
    if (!_inDetailView) return;
    _inDetailView = false;
    notifyListeners();
  }

  /// Open a specific chat or garden room.
  ///
  /// Sets [_selectedRoomId] and marks the shell as in a detail view so the
  /// bottom tab bar hides.  Pass null to close the room (e.g. when the back
  /// button is pressed from a thread).
  void selectRoom(String? roomId) {
    _selectedRoomId = roomId;
    // A non-null roomId means a thread is open → enter detail view.
    // A null roomId means the thread was closed → exit detail view.
    _inDetailView = roomId != null;
    notifyListeners();
  }

  /// Open a specific peer detail view.
  ///
  /// Sets [_selectedPeerId] and marks the shell as in a detail view.
  /// Pass null to close the peer detail.
  void selectPeer(String? peerId) {
    _selectedPeerId = peerId;
    _inDetailView = peerId != null;
    notifyListeners();
  }

  /// Set the selected transfer ID without forcing a detail view.
  ///
  /// Unlike [selectRoom] and [selectPeer], this does NOT automatically set
  /// [_inDetailView] because transfer details may be shown in a side pane
  /// on wide layouts without hiding the bottom bar on mobile.  Call
  /// [enterDetailView] separately if needed.
  void selectTransfer(String? transferId) {
    _selectedTransferId = transferId;
    notifyListeners();
  }

  /// Clear all selected item IDs and exit any open detail view.
  ///
  /// Call this when navigating away from a section, or on a hard back-to-root
  /// action.  Useful in tests and as a programmatic "go home" operation.
  void clearSelections() {
    _selectedRoomId = null;
    _selectedPeerId = null;
    _selectedTransferId = null;
    _inDetailView = false;
    notifyListeners();
  }
}
