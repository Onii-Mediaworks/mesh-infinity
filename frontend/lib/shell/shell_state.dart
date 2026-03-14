// shell_state.dart
//
// This file defines ShellState — the single source of truth for "where the
// user is in the app right now" and "what item they have selected".
//
// WHY do we need a separate file for this?
// ------------------------------------------
// In a multi-pane desktop layout (e.g. sidebar + list + detail), several
// completely separate widgets need to know:
//   - Which section (Chat, Files, Peers…) is active?
//   - Which room/peer/transfer has the user tapped?
//
// If each widget tried to manage this on its own they would fall out of sync.
// Instead we keep one ShellState object and share it through the widget tree
// using the Provider package.  Any widget that reads ShellState always sees
// the same data.
//
// HOW does this file fit into the bigger picture?
// ------------------------------------------------
// app.dart creates a single ShellState and wraps the widget tree in a
// ChangeNotifierProvider<ShellState>.  That makes ShellState available to
// every widget below it via context.watch<ShellState>() (rebuild on change)
// or context.read<ShellState>() (read once without subscribing).
//
// AppShell reads activeSection to decide which layout to render.
// Feature screens read selectedRoomId / selectedPeerId / selectedTransferId
// to know what detail view to display.
// Nav items call selectSection() when the user taps them.
//
// The flow looks like this:
//
//   User taps "Chat" icon
//         │
//         ▼
//   NavigationBar.onDestinationSelected()
//         │
//         ▼
//   shell.selectSection(AppSection.chat)
//         │  (sets _activeSection, calls notifyListeners)
//         ▼
//   Every context.watch<ShellState>() widget rebuilds
//         │
//         ▼
//   AppShell re-renders with AppSection.chat as the active section

import 'package:flutter/foundation.dart';
// flutter/foundation.dart gives us ChangeNotifier — the Flutter class that
// powers the "observable state" pattern used throughout this app.
// It is part of the Flutter SDK's lowest-level library (no UI concepts here —
// just utilities like ChangeNotifier, ValueNotifier, and debugPrint).

// ---------------------------------------------------------------------------
// AppSection — the five top-level areas of the app
// ---------------------------------------------------------------------------

/// AppSection is a Dart *enum* — a fixed list of named constants.
/// Each value represents one top-level destination visible in the navigation
/// bar (mobile) or navigation rail (tablet/desktop).
///
/// Using an enum instead of raw integers or strings means the compiler will
/// tell us if we forget to handle a case (e.g. in a switch statement).
///
/// Dart enums have a built-in `.values` property that returns all values in
/// declaration order as a List.  For example:
///   AppSection.values  →  [chat, files, peers, network, settings]
///
/// This is used in app_shell.dart to convert between the integer index that
/// NavigationBar/NavigationRail requires (e.g. 0, 1, 2…) and the named
/// enum value (e.g. AppSection.chat) that the rest of the code uses.
///
/// Declaration order therefore matters: it must match the visual order of
/// tabs/rail items in the navigation widgets.
enum AppSection {
  chat,      // Encrypted group chats / direct messages
  files,     // Peer-to-peer file transfers
  peers,     // Known contacts and trust management
  network,   // Transport settings, mDNS discovery, stats
  settings,  // Identity, appearance, and app-level settings
}

// ---------------------------------------------------------------------------
// ShellState — observable navigation state
// ---------------------------------------------------------------------------

/// ShellState tracks "where the user is" inside the app shell (the frame that
/// wraps all the screens) and "what item is selected" within each section.
///
/// What is a ChangeNotifier?
/// -------------------------
/// ChangeNotifier is a Flutter mixin/class that lets an object *announce*
/// when its data changes.  Widgets that say `context.watch<ShellState>()`
/// register themselves as listeners.  Whenever ShellState calls
/// `notifyListeners()`, Flutter automatically rebuilds those widgets so the
/// UI reflects the latest data.  This is the foundation of the Provider
/// state-management pattern used in this app.
///
/// Why not just use a global variable or a StatefulWidget?
/// --------------------------------------------------------
/// - A global variable cannot trigger widget rebuilds automatically.
/// - StatefulWidget state is private to a single widget and cannot easily be
///   shared with sibling or parent widgets.
/// - ChangeNotifier + Provider solves both: it's accessible anywhere in the
///   widget tree and automatically drives rebuilds.
class ShellState extends ChangeNotifier {
  // -------------------------------------------------------------------------
  // Fields — the actual state being tracked
  // -------------------------------------------------------------------------
  //
  // All four fields below are *private* (leading underscore in Dart).
  // "Private" in Dart means the field is accessible only within the same
  // library (roughly: the same .dart file or files in the same library
  // declaration).  This prevents other files from accidentally bypassing the
  // setter methods and mutating state without calling notifyListeners().
  //
  // The pattern of private fields + public getters + controlled setters is
  // sometimes called "encapsulated state" or the "accessor pattern".  It is
  // the standard way to protect ChangeNotifier subclasses from being mutated
  // incorrectly.

  /// Which of the five top-level sections is currently visible.
  /// Starts on Chat because that is the app's primary use-case.
  /// The leading underscore (_) marks this as *private* — only code inside
  /// this file can write to it.  External code must call selectSection().
  AppSection _activeSection = AppSection.chat;

  /// The ID of the conversation (room) the user has tapped in the chat list.
  /// Null means no room is open (e.g. user just switched to the Chat section
  /// but hasn't tapped any conversation yet).
  /// Used by the desktop shell to decide whether to show ThreadScreen or the
  /// "Select a conversation" placeholder in the detail pane.
  ///
  /// The `?` suffix on `String?` means the type is *nullable* — the variable
  /// can hold either a String value or the special null value.  In Dart's
  /// null-safety system you MUST check for null before using a nullable
  /// variable (or use the `!` operator to assert it is non-null).
  String? _selectedRoomId;

  /// The ID of the peer the user has tapped in the Peers list.
  /// Null means no peer detail panel is open.
  String? _selectedPeerId;

  /// The ID of the file transfer the user has selected in the Files list.
  /// Null means no transfer is highlighted.
  String? _selectedTransferId;

  // -------------------------------------------------------------------------
  // Getters — read-only access for the rest of the app
  // -------------------------------------------------------------------------
  // Dart getters (the `get` keyword) look like public fields to callers but
  // are actually computed.  By only exposing getters (not the private fields
  // directly), we guarantee that all writes go through the setter methods
  // below, which always call notifyListeners() so the UI stays in sync.
  //
  // From the caller's perspective:
  //   shell.activeSection       // reads the getter — looks just like a field
  //   shell.activeSection = … // would be a COMPILE ERROR — no setter exposed
  //
  // This is different from most languages where you'd need explicit
  // getActiveSection() methods.  Dart getters make read-only access feel
  // natural while still preventing accidental writes.

  /// The section currently displayed.  Widgets read this to highlight the
  /// correct nav item and to decide which screen to render.
  AppSection get activeSection => _activeSection;

  /// The room that is open in the detail pane (desktop) or thread screen
  /// (mobile/tablet).  Null when no conversation is open.
  String? get selectedRoomId => _selectedRoomId;

  /// The peer whose detail card is open.  Null when none is selected.
  String? get selectedPeerId => _selectedPeerId;

  /// The file transfer that is focused.  Null when none is selected.
  String? get selectedTransferId => _selectedTransferId;

  // -------------------------------------------------------------------------
  // Mutators — the only way to change state
  // -------------------------------------------------------------------------
  //
  // Every method that changes state follows the same three-step pattern:
  //   1. Guard: if nothing actually changed, return early to avoid wasted work.
  //   2. Mutate: update the private field(s).
  //   3. Notify: call notifyListeners() so Flutter schedules a rebuild of all
  //      widgets that subscribed via context.watch<ShellState>().
  //
  // This pattern is so common in Flutter ChangeNotifier classes that it is
  // worth memorising:
  //   if (same value) return;
  //   _field = newValue;
  //   notifyListeners();

  /// Switch the active top-level section (e.g. from Chat to Peers).
  ///
  /// The `if (_activeSection == section) return;` guard is a performance
  /// optimisation: if the user taps the section they're already on, we skip
  /// calling notifyListeners() so Flutter doesn't unnecessarily rebuild every
  /// widget that is watching ShellState.
  ///
  /// Dart's `void` return type means the function produces no value — it is
  /// called purely for its side-effect (updating the navigation state).
  void selectSection(AppSection section) {
    if (_activeSection == section) return; // Already here — nothing to do.
    _activeSection = section;
    notifyListeners(); // Tell all listening widgets to rebuild.
  }

  /// Mark a conversation as open.  Pass null to close any open conversation.
  ///
  /// On desktop this causes the detail pane to switch from the empty
  /// placeholder to ThreadScreen(roomId: roomId).
  /// On mobile this triggers navigation to a new full-screen ThreadScreen.
  ///
  /// The `String?` parameter type means callers can pass either a string ID
  /// or null.  Passing null acts as a "close" signal.
  void selectRoom(String? roomId) {
    if (_selectedRoomId == roomId) return; // No change — skip rebuild.
    _selectedRoomId = roomId;
    notifyListeners();
  }

  /// Mark a peer as selected so their detail card appears.
  /// Pass null to deselect.
  void selectPeer(String? peerId) {
    if (_selectedPeerId == peerId) return;
    _selectedPeerId = peerId;
    notifyListeners();
  }

  /// Mark a file transfer as selected.
  /// Pass null to deselect.
  void selectTransfer(String? transferId) {
    if (_selectedTransferId == transferId) return;
    _selectedTransferId = transferId;
    notifyListeners();
  }

  /// Clear all per-section selections at once.
  ///
  /// Called when the user navigates away from a section entirely so that when
  /// they come back they don't land on a stale selection.  For example, if a
  /// peer was deleted in the background while the user was in another section,
  /// we don't want the old peer ID to still be "selected" on return.
  ///
  /// Setting all fields to null is safe here because:
  ///   - The getters return nullable types (String?) so callers already expect
  ///     null as a valid "nothing selected" value.
  ///   - The detail-pane widgets check for null and show placeholders instead
  ///     of trying to render a detail view with a missing ID.
  void clearSelections() {
    _selectedRoomId = null;
    _selectedPeerId = null;
    _selectedTransferId = null;
    notifyListeners(); // Rebuild the detail pane — it should show the placeholder.
  }
}
