import 'dart:async';

import 'package:flutter/material.dart';

import '../../app/app_theme.dart';
import '../../app/motion.dart';
import '../../app/ui_prefs.dart';

/// How a hint is drawn while animations are allowed.
enum HintVisual { slide, pulse, pinch }

/// One gesture that gets a first-use hint (SPEC §22.35.1 table): its id, text,
/// visual, placement over the content and on-screen lifetime.
///
/// A class with `static final` instances rather than an enum, because the
/// project names these in snake_case and Dart only allows that for
/// non-constant identifiers.
class GestureHint {
  const GestureHint._(this.id, this.text, this.visual, this.align, this.life);

  /// Stable id used in the `gesture_hint_seen_<id>` preference key.
  final String id;

  /// Hint text shown in the pill.
  final String text;

  final HintVisual visual;
  final Alignment align;

  /// Auto-dismiss delay.  3 s is the spec value for the swipe and long-press
  /// hints, 2 s for pinch; the one row that gives no time uses 3 s.
  final Duration life;

  /// Swipe a conversation tile right to archive it.
  static final GestureHint swipe_to_archive = const GestureHint._(
    'swipe_to_archive',
    'Swipe right to archive',
    HintVisual.slide,
    Alignment.centerLeft,
    Duration(seconds: 3),
  );

  /// Swipe a received bubble to reply.
  static final GestureHint swipe_to_reply = const GestureHint._(
    'swipe_to_reply',
    'Swipe to reply',
    HintVisual.slide,
    Alignment.centerLeft,
    Duration(seconds: 3),
  );

  /// Hold a received bubble to open reactions.
  static final GestureHint long_press_reactions = const GestureHint._(
    'long_press_reactions',
    'Hold for reactions',
    HintVisual.pulse,
    Alignment.center,
    Duration(seconds: 3),
  );

  /// Double-tap a bubble to react with a heart.
  static final GestureHint double_tap_react = const GestureHint._(
    'double_tap_react',
    'Double-tap for ❤️',
    HintVisual.pulse,
    Alignment.bottomCenter,
    Duration(seconds: 3),
  );

  /// Pinch the fullscreen image viewer to zoom.
  static final GestureHint pinch_to_zoom = const GestureHint._(
    'pinch_to_zoom',
    'Pinch to zoom',
    HintVisual.pinch,
    Alignment.center,
    Duration(seconds: 2),
  );
}

/// Preference key for [hint]: `gesture_hint_seen_<gesture_id>` (§22.35.1).
String gesture_hint_key(GestureHint hint) => 'gesture_hint_seen_${hint.id}';

/// Teaches an invisible gesture once (SPEC §22.35.1).
///
/// Wraps [child].  When [trigger] is true and the hint has never been shown
/// or performed on this device, a translucent hand (or pulsing dot / pinch
/// icon) and a text pill appear over the child.  The overlay never blocks
/// interaction: it ignores pointers, and any touch on the child dismisses it.
///
/// Rules implemented here:
///  * exactly once: the seen flag is stored the moment the hint appears;
///  * suppressed if the user already performed the gesture: the screen
///    calls [mark_performed], which stores the flag and removes a live hint;
///  * reduced motion: a static pill, no moving hand, no pulse.
class GestureHintOverlay extends StatefulWidget {
  const GestureHintOverlay({
    super.key,
    required this.hint,
    required this.trigger,
    required this.child,
  });

  /// Which gesture this overlay teaches.
  final GestureHint hint;

  /// True once the screen reached the §22.35.1 condition for this hint.
  final bool trigger;

  /// The content the hint floats over.
  final Widget child;

  /// Records that the user performed [hint]'s gesture, so the hint never
  /// fires, and dismisses it if it is currently on screen.
  static Future<void> mark_performed(GestureHint hint) async {
    // Dismiss first so the pill disappears without waiting for the disk.
    for (final live in List.of(_live)) {
      if (live.widget.hint == hint) live._dismiss();
    }
    await UiPrefs.instance.set_flag(gesture_hint_key(hint));
  }

  static final Set<_GestureHintOverlayState> _live = {};

  @override
  State<GestureHintOverlay> createState() => _GestureHintOverlayState();
}

class _GestureHintOverlayState extends State<GestureHintOverlay> {
  bool _visible = false;
  bool _done = false;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    GestureHintOverlay._live.add(this);
    // The flags load asynchronously; check again once they are known.
    UiPrefs.instance.load().then((_) => _maybe_show());
  }

  @override
  void didUpdateWidget(GestureHintOverlay old) {
    super.didUpdateWidget(old);
    if (widget.trigger && !old.trigger) _maybe_show();
  }

  @override
  void dispose() {
    GestureHintOverlay._live.remove(this);
    _timer?.cancel();
    super.dispose();
  }

  /// Shows the hint if its condition holds and it has never been seen.
  void _maybe_show() {
    if (!mounted || !widget.trigger || _done || _visible) return;
    final key = gesture_hint_key(widget.hint);
    if (UiPrefs.instance.flag(key)) {
      _done = true;
      return;
    }
    // Persist at show time: a hint that appeared counts as shown even if the
    // app is killed before it times out.
    UiPrefs.instance.set_flag(key);
    setState(() => _visible = true);
    _timer = Timer(widget.hint.life, _dismiss);
  }

  void _dismiss() {
    _timer?.cancel();
    _done = true;
    if (mounted && _visible) setState(() => _visible = false);
  }

  @override
  Widget build(BuildContext context) {
    if (!_visible) return widget.child;
    final spec = widget.hint;
    return Stack(
      children: [
        // Listener (not GestureDetector) observes the touch without joining
        // the gesture arena, so the child's own gesture still works.
        Listener(
          behavior: HitTestBehavior.translucent,
          onPointerDown: (_) => _dismiss(),
          child: widget.child,
        ),
        Positioned.fill(
          child: IgnorePointer(
            child: Align(
              alignment: spec.align,
              child: Semantics(
                liveRegion: true,
                label: spec.text,
                child: _HintGlyphView(spec: spec),
              ),
            ),
          ),
        ),
      ],
    );
  }
}

/// The moving visual plus the text pill.  Kept separate so its animation
/// controller exists only while a hint is on screen.
class _HintGlyphView extends StatefulWidget {
  const _HintGlyphView({required this.spec});

  final GestureHint spec;

  @override
  State<_HintGlyphView> createState() => _HintGlyphState();
}

class _HintGlyphState extends State<_HintGlyphView>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: 1200),
  );

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    // Reduced motion (§22.35.1): no hand, no pulse, just the static pill.
    if (reduced_motion(context)) {
      _controller.stop();
    } else if (!_controller.isAnimating) {
      _controller.repeat();
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  /// Icon for the animated visual.
  IconData _icon() => switch (widget.spec.visual) {
    HintVisual.slide => Icons.touch_app,
    HintVisual.pulse => Icons.circle,
    HintVisual.pinch => Icons.pinch,
  };

  /// The icon on a translucent pill-coloured disc, so it reads on any ground.
  Widget _glyph(double size) {
    return Opacity(
      opacity: 0.7,
      child: DecoratedBox(
        decoration: const BoxDecoration(
          color: MeshTheme.hintPill,
          shape: BoxShape.circle,
        ),
        child: Padding(
          padding: const EdgeInsets.all(6),
          child: Icon(_icon(), size: size, color: MeshTheme.hintForeground),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final pill = DecoratedBox(
      decoration: BoxDecoration(
        color: MeshTheme.hintPill,
        borderRadius: BorderRadius.circular(999),
      ),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
        child: Text(
          widget.spec.text,
          style: Theme.of(
            context,
          ).textTheme.labelMedium?.copyWith(color: MeshTheme.hintForeground),
        ),
      ),
    );

    // Static tooltip variant.
    if (reduced_motion(context)) return pill;

    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        AnimatedBuilder(
          animation: _controller,
          builder: (context, _) {
            final t = Curves.easeInOut.transform(_controller.value);
            return switch (widget.spec.visual) {
              // Hand slides left to right across 80 px.
              HintVisual.slide => Transform.translate(
                offset: Offset(-40 + 80 * t, 0),
                child: _glyph(28),
              ),
              // Dot breathes between 60% and 100% size.
              HintVisual.pulse => Transform.scale(
                scale: 0.6 + 0.4 * t,
                child: _glyph(12),
              ),
              // Pinch icon shrinks in and out.
              HintVisual.pinch => Transform.scale(
                scale: 1.2 - 0.4 * t,
                child: _glyph(32),
              ),
            };
          },
        ),
        const SizedBox(height: 6),
        pill,
      ],
    );
  }
}
