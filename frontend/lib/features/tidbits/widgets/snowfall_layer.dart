// snowfall_layer.dart
//
// SnowfallLayer — ambient snowfall behind the app on winter dates (§22.12.5 #25).
//
// WHAT IT DOES:
// -------------
// Wraps the entire app body in a Stack.  When the current date falls in
// the winter window (Dec 1 – Jan 15), gently falling snowflakes are drawn
// behind the main content.  The snowflakes are rendered with IgnorePointer
// so they never interfere with any touch event.
//
// The effect is subtle — snowflakes are small (2–5 px), semi-transparent
// (15–40% opacity), and slow.  They should read as "oh, it's snowing!" not
// "there is snow covering the screen".
//
// ACTIVATION:
// -----------
// Wrap CallOverlay/AppShell with SnowfallLayer in app.dart's _buildHome().
// The widget self-deactivates outside the winter window, so no conditional
// is needed at the call site.
//
// PERFORMANCE:
// ------------
// CustomPainter + AnimationController is efficient for 40 simple circles.
// The painter uses shouldRepaint to avoid unnecessary redraws.
// The AnimationController is disposed when the widget is removed.

import 'dart:math' as math;

import 'package:flutter/material.dart';

// ---------------------------------------------------------------------------
// SnowfallLayer
// ---------------------------------------------------------------------------

/// Wraps [child] with an ambient snowfall overlay on winter dates.
///
/// Pass your normal app body as [child].  On non-winter dates this widget is
/// a zero-overhead passthrough (no animation, no paint).
class SnowfallLayer extends StatefulWidget {
  const SnowfallLayer({super.key, required this.child});

  // The app content that sits beneath the snowflakes.
  final Widget child;

  @override
  State<SnowfallLayer> createState() => _SnowfallLayerState();
}

class _SnowfallLayerState extends State<SnowfallLayer>
    with SingleTickerProviderStateMixin {
  // ---------------------------------------------------------------------------
  // Winter detection
  // ---------------------------------------------------------------------------

  // Returns true when the current local date is within the winter snow window:
  // December 1 → January 15.
  static bool _isWinterNow() {
    final now = DateTime.now();
    // December = month 12; January 1–15 = month 1, day 1–15.
    return now.month == 12 || (now.month == 1 && now.day <= 15);
  }

  // ---------------------------------------------------------------------------
  // Animation + snowflakes
  // ---------------------------------------------------------------------------

  late final AnimationController _controller;
  late final List<_Snowflake> _flakes;
  final math.Random _rng = math.Random();

  // Whether we should actually run the animation.
  // Computed once in initState; changes require a widget rebuild (app restart).
  late final bool _active;

  @override
  void initState() {
    super.initState();

    _active = _isWinterNow();

    if (!_active) {
      // Stub out the controller so dispose() can safely call it.
      _controller = AnimationController(vsync: this);
      _flakes = const [];
      return;
    }

    // 40 snowflakes is enough for a pleasant density without visual clutter.
    _flakes = List.generate(40, (_) => _Snowflake.random(_rng));

    // Looping controller drives a 0→1 "cycle" value.  One cycle = 6 seconds.
    // Each snowflake uses the cycle value (modulo its own period) to determine
    // its vertical position, creating staggered, independent motion.
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 6),
    )..repeat(); // loops forever while the widget is in the tree
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  // ---------------------------------------------------------------------------
  // Build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    // Outside the winter window, return the child with no overhead.
    if (!_active) return widget.child;

    return Stack(
      children: [
        // The real app content — behind the snow.
        widget.child,

        // Snow layer: non-interactive, fills the entire screen.
        Positioned.fill(
          child: IgnorePointer(
            child: AnimatedBuilder(
              animation: _controller,
              builder: (_, _) => CustomPaint(
                painter: _SnowPainter(
                  flakes: _flakes,
                  cycle: _controller.value, // 0.0 → 1.0, repeating
                ),
              ),
            ),
          ),
        ),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// _Snowflake — per-flake parameters
// ---------------------------------------------------------------------------

/// Immutable parameters for one snowflake.  Position is computed each frame
/// from [cycle] and the flake's individual speed/phase/drift values.
class _Snowflake {
  const _Snowflake({
    required this.x,          // normalised horizontal rest position (0–1)
    required this.radius,     // visual radius in logical pixels (1–3)
    required this.speed,      // fall speed (cycles per full cycle, >1 = faster)
    required this.phase,      // vertical phase offset (0–1)
    required this.driftAmp,   // horizontal drift amplitude (normalised)
    required this.driftFreq,  // horizontal drift frequency
    required this.opacity,    // base opacity (0.15–0.40)
  });

  factory _Snowflake.random(math.Random rng) => _Snowflake(
        x: rng.nextDouble(),
        radius: 1.0 + rng.nextDouble() * 2.0,    // 1–3 px
        speed: 0.5 + rng.nextDouble() * 1.5,     // slow to moderate
        phase: rng.nextDouble(),
        driftAmp: 0.01 + rng.nextDouble() * 0.02, // gentle horizontal drift
        driftFreq: 0.5 + rng.nextDouble() * 1.5,
        opacity: 0.15 + rng.nextDouble() * 0.25,  // subtle
      );

  final double x;
  final double radius;
  final double speed;
  final double phase;
  final double driftAmp;
  final double driftFreq;
  final double opacity;
}

// ---------------------------------------------------------------------------
// _SnowPainter — CustomPainter that draws all snowflakes
// ---------------------------------------------------------------------------

class _SnowPainter extends CustomPainter {
  const _SnowPainter({required this.flakes, required this.cycle});

  final List<_Snowflake> flakes;
  final double cycle; // 0.0 → 1.0, looping

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()..style = PaintingStyle.fill;

    for (final f in flakes) {
      // Vertical position: (phase + speed * cycle) mod 1 → 0..1 top-to-bottom.
      // Adding phase staggers the flakes so they don't all start at the top.
      final yFrac = ((f.phase + f.speed * cycle) % 1.0);

      // Horizontal drift: sinusoidal oscillation around the base x position.
      final xFrac = f.x +
          f.driftAmp * math.sin(2 * math.pi * f.driftFreq * cycle + f.phase);

      final px = xFrac * size.width;
      final py = yFrac * size.height;

      paint.color = Colors.white.withValues(alpha: f.opacity);
      canvas.drawCircle(Offset(px, py), f.radius, paint);
    }
  }

  @override
  bool shouldRepaint(_SnowPainter old) => old.cycle != cycle;
}
