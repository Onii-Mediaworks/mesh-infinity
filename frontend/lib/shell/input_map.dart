// input_map.dart
//
// The one intent table for keyboard and controller input (§22.36 rule 1).
//
// WHAT LIVES HERE
// ---------------
//   * The Intent classes a screen can respond to (context menu, secondary
//     action, back, section switch, search, main menu, detail pane).  Move
//     focus, activate and page scroll reuse Flutter's own
//     DirectionalFocusIntent, ActivateIntent and ScrollIntent so Material
//     widgets answer them natively.
//   * `InputMap.shortcuts()` — the key/button → intent table.  Keyboard keys
//     and gamepad buttons map to the *same* intents, so no screen ever looks
//     at a raw key.
//   * `ShellInputScope` — the widget that installs the table above the
//     Navigator (via MaterialApp.builder) together with the shell-level
//     actions, tracks which device the user is driving with, and arms the
//     "first D-pad press after a touch lands on the primary action" rule.
//   * `InputMap.back()` — the single back handler shared by Escape, the
//     cancel face button, and the system back gesture (rule 7).
//
// WHERE THE TABLE SITS IN THE KEY PIPELINE
// -----------------------------------------
// WidgetsApp already installs default Shortcuts (Enter/Space/A/select →
// ActivateIntent, arrows → DirectionalFocusIntent, Escape → DismissIntent,
// Page Up/Down → ScrollIntent on desktop/Android) and, below them,
// DefaultTextEditingShortcuts, which stops Space/Enter/arrows from leaking
// out of a focused text field.  Our Shortcuts sit *below* both (nearer the
// focus), so:
//   - keys we bind win over the defaults;
//   - keys we do not bind (arrows, Tab, Space, Enter) keep Flutter's
//     behaviour, including the text-field protection;
//   - the few bound keys that could collide with typing (`/`, Page Up/Down)
//     have actions whose isEnabled() is false inside a text field, which makes
//     the Shortcuts widget report "ignored" and lets the key bubble up.
//
// CONFIRM / CANCEL SWAP (rule 8)
// ------------------------------
// The face-button pair is resolved exactly once, in `shortcuts()`, from
// ShellState.confirm_swap.  Hints name physical buttons (A, B, X, Y) and the
// hint row looks up which physical button currently confirms.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../features/messaging/screens/conversation_search_screen.dart';
import 'primary_focus.dart';
import 'shell_state.dart';

// ---------------------------------------------------------------------------
// Intents
// ---------------------------------------------------------------------------

/// Go back one shell level: Escape, cancel face button, system back (rule 7).
class ShellBackIntent extends Intent {
  const ShellBackIntent();
}

/// Open the focused item's long-press sheet: Shift+F10, Menu key, X/□ button.
class ContextMenuIntent extends Intent {
  const ContextMenuIntent();
}

/// The screen-declared secondary action: Y/△ button (reply, mark as read…).
class SecondaryActionIntent extends Intent {
  const SecondaryActionIntent();
}

/// Step through sections and their tabs: Ctrl+Tab / Ctrl+Shift+Tab, L1 / R1.
///
/// [delta] is +1 for forward and -1 for backward.  The walk is flat: the
/// last tab of Chat steps into the first tab of Garden, so a pad user can
/// reach every list from the two shoulder buttons alone.
class SectionStepIntent extends Intent {
  const SectionStepIntent(this.delta);

  /// Direction of travel through the flat section/tab list.
  final int delta;
}

/// Jump straight to section N (Ctrl+1 … Ctrl+9).
class SectionJumpIntent extends Intent {
  const SectionJumpIntent(this.index);

  /// Zero-based index into [AppSection.values].
  final int index;
}

/// Open the current section's search: Ctrl+K, `/` outside a field, Start+Y.
class SearchIntent extends Intent {
  const SearchIntent();
}

/// Open the navigation drawer, or focus the permanent one: F10, Start.
class MainMenuIntent extends Intent {
  const MainMenuIntent();
}

/// Close the desktop detail pane: Ctrl+] (rule 4, two-finger swipe route).
class DetailPaneIntent extends Intent {
  const DetailPaneIntent();
}

// ---------------------------------------------------------------------------
// Start-button chord activators (Start+Y = search, Start alone = menu)
// ---------------------------------------------------------------------------

/// Shared bookkeeping between the two Start activators.
///
/// Start cannot be a modifier in a [SingleActivator], and firing the main
/// menu on Start *down* would open the drawer every time the user begins a
/// Start+Y chord.  So the menu fires on Start *up*, unless Y was pressed
/// while Start was held — which this flag records.
class _StartChordState {
  /// True once Y fired while Start was held; cleared on the next Start down.
  bool used = false;
}

/// Accepts [trigger] pressed while the Start button is held.
class _StartChordActivator extends ShortcutActivator {
  const _StartChordActivator(this.trigger, this.state);

  /// The face button that completes the chord.
  final LogicalKeyboardKey trigger;

  /// Shared flag telling the release activator the chord was consumed.
  final _StartChordState state;

  @override
  bool accepts(KeyEvent event, HardwareKeyboard hardware) {
    if (event is! KeyDownEvent || event.logicalKey != trigger) return false;
    if (!hardware.logicalKeysPressed.contains(
      LogicalKeyboardKey.gameButtonStart,
    )) {
      return false;
    }
    state.used = true;
    return true;
  }

  @override
  Iterable<LogicalKeyboardKey> get triggers => <LogicalKeyboardKey>[trigger];

  @override
  String debugDescribeKeys() => 'Start+${trigger.keyLabel}';
}

/// Accepts the Start button's *release* when no chord was used meanwhile.
class _StartReleaseActivator extends ShortcutActivator {
  const _StartReleaseActivator(this.state);

  /// Shared flag set by [_StartChordActivator].
  final _StartChordState state;

  @override
  bool accepts(KeyEvent event, HardwareKeyboard hardware) {
    if (event.logicalKey != LogicalKeyboardKey.gameButtonStart) return false;
    if (event is KeyDownEvent) {
      // A fresh press starts a new chord window; never fires on its own.
      state.used = false;
      return false;
    }
    if (event is KeyUpEvent) {
      final fire = !state.used;
      state.used = false;
      return fire;
    }
    return false;
  }

  @override
  Iterable<LogicalKeyboardKey> get triggers => const <LogicalKeyboardKey>[
    LogicalKeyboardKey.gameButtonStart,
  ];

  @override
  String debugDescribeKeys() => 'Start (release)';
}

// ---------------------------------------------------------------------------
// InputMap — the table and the shared helpers
// ---------------------------------------------------------------------------

/// Static home of the §22.36 intent table and the shell back handler.
abstract final class InputMap {
  /// Chord bookkeeping shared by every table built in this process.
  static final _StartChordState _start_chord = _StartChordState();

  /// Gamepad logical keys, used to classify an event as [InputSource.gamepad].
  ///
  /// `static final` rather than `const`: LogicalKeyboardKey overrides `==`,
  /// which Dart forbids in a const set.
  ///
  /// D-pad presses arrive as arrow keys and are indistinguishable from a
  /// keyboard, so the pad is recognised from its buttons; `select` is the
  /// D-pad centre / TV-remote OK key.
  static final Set<LogicalKeyboardKey> pad_keys = <LogicalKeyboardKey>{
    LogicalKeyboardKey.gameButtonA,
    LogicalKeyboardKey.gameButtonB,
    LogicalKeyboardKey.gameButtonX,
    LogicalKeyboardKey.gameButtonY,
    LogicalKeyboardKey.gameButtonLeft1,
    LogicalKeyboardKey.gameButtonRight1,
    LogicalKeyboardKey.gameButtonLeft2,
    LogicalKeyboardKey.gameButtonRight2,
    LogicalKeyboardKey.gameButtonStart,
    LogicalKeyboardKey.gameButtonSelect,
    LogicalKeyboardKey.gameButtonThumbLeft,
    LogicalKeyboardKey.gameButtonThumbRight,
    LogicalKeyboardKey.select,
  };

  /// Keys whose press counts as "key-driven focus" for the hint row (rule 5).
  ///
  /// Typing letters into a field must not reveal the hint row; moving focus
  /// with arrows or Tab must.
  static final Set<LogicalKeyboardKey> focus_keys = <LogicalKeyboardKey>{
    LogicalKeyboardKey.arrowUp,
    LogicalKeyboardKey.arrowDown,
    LogicalKeyboardKey.arrowLeft,
    LogicalKeyboardKey.arrowRight,
    LogicalKeyboardKey.tab,
  };

  /// The physical face button that confirms under the current swap setting.
  static String confirm_label(bool confirm_swap) => confirm_swap ? 'B' : 'A';

  /// The physical face button that cancels under the current swap setting.
  static String cancel_label(bool confirm_swap) => confirm_swap ? 'A' : 'B';

  /// Build the key → intent table (§22.36 rule 1).
  ///
  /// Keyboard and gamepad bindings for one intent sit next to each other so
  /// the table reads like the spec's.  Keys that Flutter's defaults already
  /// bind correctly (arrows, Tab, Enter, Space) are deliberately absent so
  /// text-field protection in DefaultTextEditingShortcuts keeps working.
  static Map<ShortcutActivator, Intent> shortcuts({
    required bool confirm_swap,
  }) {
    final confirm = confirm_swap
        ? LogicalKeyboardKey.gameButtonB
        : LogicalKeyboardKey.gameButtonA;
    final cancel = confirm_swap
        ? LogicalKeyboardKey.gameButtonA
        : LogicalKeyboardKey.gameButtonB;

    return <ShortcutActivator, Intent>{
      // ── Activate ─────────────────────────────────────────────────────
      // Enter and Space come from WidgetsApp's defaults; `select` is the
      // D-pad centre, bound here too so the table is complete on its own.
      SingleActivator(confirm): const ActivateIntent(),
      const SingleActivator(LogicalKeyboardKey.select): const ActivateIntent(),

      // ── Back ─────────────────────────────────────────────────────────
      const SingleActivator(LogicalKeyboardKey.escape): const ShellBackIntent(),
      SingleActivator(cancel): const ShellBackIntent(),

      // ── Context menu ─────────────────────────────────────────────────
      const SingleActivator(LogicalKeyboardKey.f10, shift: true):
          const ContextMenuIntent(),
      const SingleActivator(LogicalKeyboardKey.contextMenu):
          const ContextMenuIntent(),
      const SingleActivator(LogicalKeyboardKey.gameButtonX):
          const ContextMenuIntent(),

      // ── Search (Start+Y must precede the plain Y binding: the Shortcuts
      //    manager tries activators in insertion order) ──────────────────
      _StartChordActivator(LogicalKeyboardKey.gameButtonY, _start_chord):
          const SearchIntent(),
      const SingleActivator(LogicalKeyboardKey.keyK, control: true):
          const SearchIntent(),
      const SingleActivator(LogicalKeyboardKey.slash): const SearchIntent(),

      // ── Secondary action ─────────────────────────────────────────────
      const SingleActivator(LogicalKeyboardKey.gameButtonY):
          const SecondaryActionIntent(),

      // ── Section / tab switch ─────────────────────────────────────────
      const SingleActivator(LogicalKeyboardKey.tab, control: true):
          const SectionStepIntent(1),
      const SingleActivator(LogicalKeyboardKey.tab, control: true, shift: true):
          const SectionStepIntent(-1),
      const SingleActivator(LogicalKeyboardKey.gameButtonRight1):
          const SectionStepIntent(1),
      const SingleActivator(LogicalKeyboardKey.gameButtonLeft1):
          const SectionStepIntent(-1),
      const SingleActivator(LogicalKeyboardKey.digit1, control: true):
          const SectionJumpIntent(0),
      const SingleActivator(LogicalKeyboardKey.digit2, control: true):
          const SectionJumpIntent(1),
      const SingleActivator(LogicalKeyboardKey.digit3, control: true):
          const SectionJumpIntent(2),
      const SingleActivator(LogicalKeyboardKey.digit4, control: true):
          const SectionJumpIntent(3),
      const SingleActivator(LogicalKeyboardKey.digit5, control: true):
          const SectionJumpIntent(4),
      const SingleActivator(LogicalKeyboardKey.digit6, control: true):
          const SectionJumpIntent(5),
      const SingleActivator(LogicalKeyboardKey.digit7, control: true):
          const SectionJumpIntent(6),
      const SingleActivator(LogicalKeyboardKey.digit8, control: true):
          const SectionJumpIntent(7),
      const SingleActivator(LogicalKeyboardKey.digit9, control: true):
          const SectionJumpIntent(8),

      // ── Page scroll ──────────────────────────────────────────────────
      // Handled by Flutter's ScrollAction on the Scrollable around the
      // focused control.  Page Up/Down are rebound here (same intent as the
      // defaults) so the triggers and the keys share one line of the table.
      const SingleActivator(LogicalKeyboardKey.pageUp): const ScrollIntent(
        direction: AxisDirection.up,
        type: ScrollIncrementType.page,
      ),
      const SingleActivator(LogicalKeyboardKey.pageDown): const ScrollIntent(
        direction: AxisDirection.down,
        type: ScrollIncrementType.page,
      ),
      const SingleActivator(
        LogicalKeyboardKey.gameButtonLeft2,
      ): const ScrollIntent(
        direction: AxisDirection.up,
        type: ScrollIncrementType.page,
      ),
      const SingleActivator(
        LogicalKeyboardKey.gameButtonRight2,
      ): const ScrollIntent(
        direction: AxisDirection.down,
        type: ScrollIncrementType.page,
      ),

      // ── Main menu ────────────────────────────────────────────────────
      // Start fires on release so it can double as the chord modifier.
      const SingleActivator(LogicalKeyboardKey.f10): const MainMenuIntent(),
      _StartReleaseActivator(_start_chord): const MainMenuIntent(),

      // ── Detail pane (desktop) ────────────────────────────────────────
      const SingleActivator(LogicalKeyboardKey.bracketRight, control: true):
          const DetailPaneIntent(),
    };
  }

  /// True when the primary focus is inside an editable text field.
  ///
  /// Used both by rule 6 (Back leaves the field first) and to disable the
  /// bindings that would otherwise swallow typed characters.
  static bool in_text_field() {
    final ctx = primaryFocus?.context;
    return ctx != null &&
        ctx.findAncestorStateOfType<EditableTextState>() != null;
  }

  /// True when a route is stacked above the shell (thread, settings page,
  /// drawer, sheet, dialog).  Section-level intents are disabled then, since
  /// switching the section under a covering route would be invisible.
  static bool route_pushed(BuildContext context) =>
      Navigator.maybeOf(context)?.canPop() ?? false;

  /// The shell back handler (§22.36 rule 7, §22.3 levels).
  ///
  /// Order of precedence:
  ///   1. A focused text field loses focus (rule 6: Back leaves the field
  ///      and closes the IME before anything else happens).
  ///   2. A pushed route (thread, settings page, drawer, sheet) pops.
  ///   3. An open desktop detail pane closes.
  ///   4. At the shell root nothing happens here; `AppShell`'s PopScope
  ///      lets the platform minimise on mobile, and desktop is a no-op.
  /// Sideways moves (tab or section switches) are never undone, matching
  /// "sideways moves aren't history".
  static void back(BuildContext context, ShellState shell) {
    final focus = primaryFocus;
    if (focus != null && in_text_field()) {
      focus.unfocus();
      return;
    }
    final navigator = Navigator.maybeOf(context);
    if (navigator != null && navigator.canPop()) {
      navigator.maybePop();
      return;
    }
    if (shell.inDetailView ||
        shell.selectedRoomId != null ||
        shell.selectedPeerId != null) {
      shell.clearSelections();
    }
  }

  /// Dispatch [intent] the way a key press would: to the focused control's
  /// Actions first, falling back to [context].
  ///
  /// This is what makes a tapped hint identical to the button it names
  /// (rule 5): the context-menu hint opens the sheet of whatever is focused.
  static void dispatch(BuildContext context, Intent intent) {
    final focus_ctx = primaryFocus?.context;
    final target =
        focus_ctx != null &&
            Actions.maybeFind<Intent>(focus_ctx, intent: intent) != null
        ? focus_ctx
        : context;
    Actions.maybeInvoke(target, intent);
  }
}

// ---------------------------------------------------------------------------
// ShellInputScope — installs the table and the shell-level actions
// ---------------------------------------------------------------------------

/// Installs the §22.36 Shortcuts and Actions above the Navigator.
///
/// Placed through `MaterialApp.builder` so every route — the shell, pushed
/// detail screens, sheets and dialogs — shares one table.  Also observes raw
/// input to keep [ShellState.last_input] current and to arm the primary
/// focus claim after a touch (rule 2).
class ShellInputScope extends StatefulWidget {
  const ShellInputScope({super.key, required this.child});

  /// The Navigator (or the whole app body) the table applies to.
  final Widget child;

  @override
  State<ShellInputScope> createState() => _ShellInputScopeState();
}

class _ShellInputScopeState extends State<ShellInputScope> {
  /// The shell state, read once: the scope lives and dies with the shell.
  late final ShellState _shell = context.read<ShellState>();

  /// Set after a touch/pointer event or a touch → traditional highlight flip.
  ///
  /// The next directional intent then lands on the screen's primary focus
  /// instead of moving relative to whatever happened to be focused before.
  bool _claim_pending = false;

  @override
  void initState() {
    super.initState();
    // Key classification runs before the focus tree sees the event, so the
    // actions below already observe the updated last_input.
    HardwareKeyboard.instance.addHandler(_on_key);
    // Flutter flips to traditional highlighting on the first key after a
    // touch — exactly the moment rule 2 wants the primary to be re-claimed.
    FocusManager.instance.addHighlightModeListener(_on_highlight_mode);
  }

  @override
  void dispose() {
    HardwareKeyboard.instance.removeHandler(_on_key);
    FocusManager.instance.removeHighlightModeListener(_on_highlight_mode);
    super.dispose();
  }

  /// Classify a key press as gamepad or keyboard input.  Never consumes it.
  bool _on_key(KeyEvent event) {
    if (event is! KeyDownEvent) return false;
    if (InputMap.pad_keys.contains(event.logicalKey)) {
      _shell.note_input(InputSource.gamepad);
    } else if (InputMap.focus_keys.contains(event.logicalKey)) {
      // Arrows from a D-pad look like keyboard arrows; keep whatever class
      // the pad buttons established rather than downgrading to keyboard.
      if (_shell.last_input.value != InputSource.gamepad) {
        _shell.note_input(InputSource.keyboard);
      } else {
        _shell.note_input(InputSource.gamepad);
      }
    } else if (_shell.last_input.value == InputSource.pointer) {
      // A typed character after touch means a keyboard is in use, but it is
      // not key-driven focus, so last_input changes without arming hints.
      _shell.last_input.value = InputSource.keyboard;
    }
    return false;
  }

  /// Arm the primary-focus claim when highlighting switches to traditional.
  void _on_highlight_mode(FocusHighlightMode mode) {
    if (mode == FocusHighlightMode.traditional) _claim_pending = true;
  }

  /// Any pointer-down means the next D-pad press should re-seat focus.
  void _on_pointer(PointerDownEvent event) {
    _shell.note_input(InputSource.pointer);
    _claim_pending = true;
  }

  /// Consume a pending claim, focusing the primary of the focused scope.
  ///
  /// Returns true when a primary control took focus, in which case the
  /// directional move that triggered it is swallowed.
  bool _claim_primary() {
    final focus = primaryFocus;
    final nothing_focused = focus == null || focus is FocusScopeNode;
    if (!_claim_pending && !nothing_focused) return false;
    _claim_pending = false;
    return PrimaryFocus.claim(FocusRole.primary, within: focus?.nearestScope);
  }

  @override
  Widget build(BuildContext context) {
    return Listener(
      onPointerDown: _on_pointer,
      // Translucent: observe the press without stealing it from the app.
      behavior: HitTestBehavior.translucent,
      child: ValueListenableBuilder<bool>(
        valueListenable: _shell.confirm_swap,
        // The Actions subtree is passed as `child` so a swap only rebuilds
        // the Shortcuts table, not the Navigator beneath it.
        child: Actions(
          actions: <Type, Action<Intent>>{
            DirectionalFocusIntent: _DirectionalAction(_claim_primary),
            ShellBackIntent: _BackAction(_shell),
            SectionStepIntent: _SectionStepAction(_shell),
            SectionJumpIntent: _SectionJumpAction(_shell),
            SearchIntent: _SearchAction(_shell),
            MainMenuIntent: _MainMenuAction(),
            DetailPaneIntent: _DetailPaneAction(_shell),
          },
          child: widget.child,
        ),
        builder: (context, swap, child) => Shortcuts(
          debugLabel: 'mesh_input_map',
          shortcuts: InputMap.shortcuts(confirm_swap: swap),
          child: child!,
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Shell-level actions
// ---------------------------------------------------------------------------

/// Directional focus that first honours a pending primary-focus claim.
class _DirectionalAction extends DirectionalFocusAction {
  _DirectionalAction(this.claim);

  /// Returns true when it seated focus on a primary control.
  final bool Function() claim;

  @override
  void invoke(DirectionalFocusIntent intent) {
    if (claim()) return;
    super.invoke(intent);
  }
}

/// Routes every back source through [InputMap.back].
class _BackAction extends ContextAction<ShellBackIntent> {
  _BackAction(this.shell);
  final ShellState shell;

  @override
  Object? invoke(ShellBackIntent intent, [BuildContext? context]) {
    // The context is the focused widget's when invoked from a key, or the
    // caller's when dispatched from a hint; either reaches the root Navigator.
    if (context != null) InputMap.back(context, shell);
    return null;
  }
}

/// Walks the flat list of (section, tab) positions.
class _SectionStepAction extends ContextAction<SectionStepIntent> {
  _SectionStepAction(this.shell);
  final ShellState shell;

  @override
  bool isEnabled(SectionStepIntent intent, [BuildContext? context]) =>
      context != null && !InputMap.route_pushed(context);

  @override
  Object? invoke(SectionStepIntent intent, [BuildContext? context]) {
    // Every section contributes max(1, tabs) positions so You and Settings
    // (no tabs) still occupy one stop in the walk.
    final positions = <(AppSection, int)>[
      for (final section in AppSection.values)
        for (var tab = 0; tab < shell.subPageCount(section).clamp(1, 9); tab++)
          (section, tab),
    ];
    final current = positions.indexOf((
      shell.activeSection,
      shell.hasSubPages ? shell.activeSubPageIndex : 0,
    ));
    final next = positions[(current + intent.delta) % positions.length];
    shell.selectSection(next.$1);
    shell.selectSubPage(next.$2);
    return null;
  }
}

/// Ctrl+N jumps to the N-th section in drawer order.
class _SectionJumpAction extends ContextAction<SectionJumpIntent> {
  _SectionJumpAction(this.shell);
  final ShellState shell;

  @override
  bool isEnabled(SectionJumpIntent intent, [BuildContext? context]) =>
      context != null &&
      !InputMap.route_pushed(context) &&
      intent.index < AppSection.values.length;

  @override
  Object? invoke(SectionJumpIntent intent, [BuildContext? context]) {
    shell.selectSection(AppSection.values[intent.index]);
    return null;
  }
}

/// Opens the section's search.  Only Chat has one today.
class _SearchAction extends ContextAction<SearchIntent> {
  _SearchAction(this.shell);
  final ShellState shell;

  @override
  bool isEnabled(SearchIntent intent, [BuildContext? context]) =>
      context != null &&
      shell.activeSection == AppSection.chat &&
      !InputMap.route_pushed(context) &&
      // `/` must still type a slash inside a field.
      !InputMap.in_text_field();

  @override
  Object? invoke(SearchIntent intent, [BuildContext? context]) {
    Navigator.push(
      context!,
      MaterialPageRoute<void>(builder: (_) => const ConversationSearchScreen()),
    );
    return null;
  }
}

/// Opens the overlay drawer on mobile, or focuses the permanent drawer.
class _MainMenuAction extends ContextAction<MainMenuIntent> {
  @override
  Object? invoke(MainMenuIntent intent, [BuildContext? context]) {
    if (context == null) return null;
    // The focused control usually sits in a nested Scaffold (each section
    // screen has its own); walk outward until one owns a drawer.
    var scaffold = Scaffold.maybeOf(context);
    while (scaffold != null && !scaffold.hasDrawer) {
      scaffold = scaffold.context.findAncestorStateOfType<ScaffoldState>();
    }
    if (scaffold != null) {
      scaffold.isDrawerOpen ? scaffold.closeDrawer() : scaffold.openDrawer();
      return null;
    }
    // Tablet/desktop: no overlay drawer, so move focus into the rail.
    PrimaryFocus.claim(FocusRole.menu);
    return null;
  }
}

/// Closes the desktop detail pane (the keyboard route for the two-finger
/// swipe in §22.35).  Re-opening is just activating a list row.
class _DetailPaneAction extends ContextAction<DetailPaneIntent> {
  _DetailPaneAction(this.shell);
  final ShellState shell;

  @override
  bool isEnabled(DetailPaneIntent intent, [BuildContext? context]) =>
      context != null &&
      !InputMap.route_pushed(context) &&
      (shell.selectedRoomId != null || shell.selectedPeerId != null);

  @override
  Object? invoke(DetailPaneIntent intent, [BuildContext? context]) {
    shell.clearSelections();
    return null;
  }
}
