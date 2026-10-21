// primary_focus.dart
//
// PrimaryFocus — how a screen declares where focus should land (§22.36 rule 2).
//
// WHY A WRAPPER INSTEAD OF `autofocus: true`?
// --------------------------------------------
// `autofocus` only fires when the enclosing FocusScope has no focused child
// at mount time.  In the shell the scope usually *does* have a focused child
// (the drawer row or bottom-bar tab that was just activated), so the new
// screen would never take focus.  It also cannot express "the first row of a
// lazily built list", because the row widget does not exist until layout.
//
// PrimaryFocus instead registers an anchor FocusNode around the screen's
// primary region.  When the shell decides focus should land on a screen —
// on open while the user is on keys/pad, or on the first D-pad press after
// a touch — it asks the anchor for its first traversable descendant in
// reading order and focuses that.  The anchor itself is never focusable, so
// it adds no stop to Tab order.
//
// ROLES
// -----
// Most screens register with FocusRole.primary.  NavDrawer registers its
// first row with FocusRole.menu so the "main menu" intent (F10 / Start) can
// move focus into the permanent drawer on tablet and desktop layouts, where
// there is no overlay drawer to open.
//
// LAYERING
// --------
// The decision *when* to claim focus lives in input_map.dart; this file only
// knows *where*, plus the one "on open" check that needs ShellState.

import 'package:flutter/widgets.dart';
import 'package:provider/provider.dart';

import 'shell_state.dart';

/// What a [PrimaryFocus] anchor stands for.
enum FocusRole {
  /// The screen's primary action or first list row (§22.36 rule 2).
  primary,

  /// The first row of the navigation drawer, targeted by the main-menu intent.
  menu,
}

/// Declares the region whose first traversable control is this screen's
/// primary focus target.
///
/// Wrap the list, the empty-state button, or the composer — whatever the
/// user should land on first.  The widget adds no visual and no Tab stop.
class PrimaryFocus extends StatefulWidget {
  const PrimaryFocus({
    super.key,
    required this.child,
    this.role = FocusRole.primary,
  });

  /// The subtree whose first focusable descendant becomes the target.
  final Widget child;

  /// Which intent this anchor answers to; see [FocusRole].
  final FocusRole role;

  /// Every mounted anchor, in mount order.
  ///
  /// Mount order matters on the desktop three-pane layout: the list pane is
  /// built before the detail pane, so a claim scoped to the shell lands on
  /// the list first.  States remove themselves on dispose.
  static final List<_PrimaryFocusState> _mounted = <_PrimaryFocusState>[];

  /// Focus the first traversable control of the first mounted anchor with
  /// [role] that lives inside [within] (or anywhere, when [within] is null).
  ///
  /// Returns true when a control took focus.  Returns false when no anchor
  /// matches or the matching anchors have nothing focusable (a pure status
  /// screen), in which case the caller falls back to ordinary traversal.
  static bool claim(FocusRole role, {FocusScopeNode? within}) {
    for (final state in List<_PrimaryFocusState>.of(_mounted)) {
      if (state.widget.role != role) continue;
      // Scope filter: an anchor on a route that is covered by a pushed
      // route is still mounted, but its ancestors do not include the
      // focused scope, so it is skipped.
      if (within != null && !state._anchor.ancestors.contains(within)) {
        continue;
      }
      if (state._focus_first()) return true;
    }
    return false;
  }

  @override
  State<PrimaryFocus> createState() => _PrimaryFocusState();
}

class _PrimaryFocusState extends State<PrimaryFocus> {
  /// The anchor node.  Never focusable itself and skipped by traversal, so
  /// it is invisible to Tab order and only serves as a subtree handle.
  final FocusNode _anchor = FocusNode(
    canRequestFocus: false,
    skipTraversal: true,
    debugLabel: 'primary_focus',
  );

  @override
  void initState() {
    super.initState();
    PrimaryFocus._mounted.add(this);
    // "On open" claim: once the first frame has laid out the subtree, land
    // focus on the primary control — but only when the user is driving by
    // keys or pad.  A touch or mouse user keeps the current (lack of) focus,
    // so opening a thread by tap never pops the keyboard (rule 2 and rule 6
    // together: the pad user *wants* the IME on the composer, the touch
    // user does not).
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted || widget.role != FocusRole.primary) return;
      final shell = context.read<ShellState>();
      if (shell.last_input.value == InputSource.pointer) return;
      _focus_first();
    });
  }

  @override
  void dispose() {
    PrimaryFocus._mounted.remove(this);
    _anchor.dispose();
    super.dispose();
  }

  /// Focus the first traversable descendant in reading order.
  ///
  /// Reading order is top-to-bottom, then left-to-right, by the nodes'
  /// global rects — the same order Tab follows in a list or a button row.
  /// Returns false when the subtree has nothing focusable yet (a list that
  /// is still loading), so the caller can fall back to plain traversal.
  bool _focus_first() {
    if (!mounted) return false;
    // Only attached, traversable leaves qualify: the FocusRing wrappers and
    // this anchor are canRequestFocus=false and drop out here.
    final candidates = _anchor.descendants
        .where(
          (node) =>
              node.canRequestFocus &&
              !node.skipTraversal &&
              node.context != null,
        )
        .toList();
    if (candidates.isEmpty) return false;
    candidates.sort((a, b) {
      final vertical = a.rect.top.compareTo(b.rect.top);
      return vertical != 0 ? vertical : a.rect.left.compareTo(b.rect.left);
    });
    final first = candidates.first;
    first.requestFocus();
    // A row further down a long list would be focused off-screen otherwise;
    // ensureVisible is a no-op when there is no enclosing Scrollable.
    final ctx = first.context;
    if (ctx != null) Scrollable.ensureVisible(ctx);
    return true;
  }

  @override
  Widget build(BuildContext context) {
    // includeSemantics=false keeps the anchor out of the accessibility tree
    // so TalkBack/VoiceOver see the child controls directly (§22.36 non-goals).
    return Focus(
      focusNode: _anchor,
      includeSemantics: false,
      child: widget.child,
    );
  }
}
