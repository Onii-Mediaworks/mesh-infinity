// confetti_burst.dart
//
// ConfettiBurst — a short-lived particle animation overlaid on the screen.
//
// WHAT IT DOES:
// -------------
// 24 coloured rectangles shoot upward from a configurable origin point,
// arc under simulated gravity, spin, and fade out over 1.5 seconds.
// The widget is typically inserted as an OverlayEntry so it floats above
// all other content without needing Stack in every caller.
//
// Used by:
//   §22.12.5 #7  Copy Confetti — fires when the user copies their peer ID.
//   §22.12.5 #52 Unread Fireworks — fires on inbox zero (multiple bursts).
//
// IMPLEMENTATION APPROACH:
// ------------------------
// We use AnimationController (1.5 s, one-shot) + CustomPainter.  Each
// particle is a _Particle struct with a fixed random initial velocity.
// On each paint tick, we compute position via kinematic equations:
//   x(t) = x₀ + vx·t
//   y(t) = y₀ + vy·t + ½·g·t²   (g = gravity constant, positive = down)
//   α(t) = max(0, 1 - t/duration)  (fade out linearly)
// No external package is required — Flutter's canvas API is sufficient.

import 'dart:math' as math;

import 'package:flutter/material.dart';

import '../../../app/app_theme.dart'; // MeshTheme brand colours

// ---------------------------------------------------------------------------
// Public API — TidbitOverlay helper (also used by callers directly)
// ---------------------------------------------------------------------------

/// Inserts a [ConfettiBurst] overlay entry and removes it when done.
///
/// [origin] is the normalised screen position of the burst origin.
/// Defaults to (0.5, 0.35) — upper-centre — which looks great for the
/// "copy peer ID" action in YouScreen.
///
/// The overlay entry is self-removing; callers do not need to clean up.
void showConfettiBurst(
  BuildContext context, {
  Offset origin = const Offset(0.5, 0.35),
}) {
  // We need an OverlayState to insert the entry above all other widgets.
  // Overlay.of(context) walks up the widget tree and finds the nearest one.
  final overlay = Overlay.of(context);
  late OverlayEntry entry;

  entry = OverlayEntry(
    builder: (_) => IgnorePointer(
      // IgnorePointer: the confetti animation must NEVER capture touch events.
      // The user should be able to tap through it without disruption.
      child: ConfettiBurst(
        origin: origin,
        // When the animation finishes, remove the entry from the overlay.
        // Using addPostFrameCallback ensures we don't remove during a build.
        onComplete: () => WidgetsBinding.instance.addPostFrameCallback(
          (_) {
            if (entry.mounted) entry.remove();
          },
        ),
      ),
    ),
  );

  overlay.insert(entry);
}

// ---------------------------------------------------------------------------
// ConfettiBurst widget
// ---------------------------------------------------------------------------

/// Full-screen confetti animation widget.
///
/// Normally shown via [showConfettiBurst] rather than placed directly in a
/// widget tree.  The widget fills the available space and is transparent
/// except for the particle paths.
class ConfettiBurst extends StatefulWidget {
  const ConfettiBurst({
    super.key,
    this.origin = const Offset(0.5, 0.35),
    this.particleCount = 24,
    this.onComplete,
  });

  // Burst origin as a fraction of screen size.
  // (0.5, 0.35) = horizontal centre, 35% down from top.
  final Offset origin;

  // Number of coloured rectangles to emit.
  final int particleCount;

  // Optional callback fired once the animation finishes.
  // Used by [showConfettiBurst] to remove the overlay entry.
  final VoidCallback? onComplete;

  @override
  State<ConfettiBurst> createState() => _ConfettiBurstState();
}

class _ConfettiBurstState extends State<ConfettiBurst>
    with SingleTickerProviderStateMixin {
  // ---------------------------------------------------------------------------
  // Animation + particles
  // ---------------------------------------------------------------------------

  late final AnimationController _controller;

  // The list of particles is fixed at creation time.
  // _rng provides reproducible variety — seeded from current time.
  late final List<_Particle> _particles;
  final math.Random _rng = math.Random();

  // Palette: brand blue + pastels to match the app's visual language.
  // Deliberately excludes dark/heavy colours so confetti looks celebratory.
  static const List<Color> _palette = [
    MeshTheme.brand,           // brand blue
    Color(0xFF6EE7B7),         // mint green (trust6)
    Color(0xFFF59E0B),         // amber
    Color(0xFFEC4899),         // pink
    Color(0xFFA78BFA),         // violet
    Color(0xFF34D399),         // green
    Color(0xFFFBBF24),         // yellow
    Color(0xFF60A5FA),         // sky blue
  ];

  @override
  void initState() {
    super.initState();

    // Single-play animation: 1500 ms, fires [onComplete] when finished.
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1500),
    )..addStatusListener((status) {
        if (status == AnimationStatus.completed) {
          widget.onComplete?.call();
        }
      });

    // Build the particle list.  We use a factory method so the initial
    // velocities are randomised once, not recalculated on every paint tick.
    _particles = List.generate(
      widget.particleCount,
      (_) => _Particle.random(_rng, _palette),
    );

    // Start immediately.
    _controller.forward();
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
    return AnimatedBuilder(
      animation: _controller,
      builder: (ctx, _) {
        return CustomPaint(
          // SizedBox.expand fills the overlay entry's allotted space,
          // which is the whole screen (OverlayEntry has unconstrained size).
          size: Size.infinite,
          painter: _ConfettiPainter(
            particles: _particles,
            progress: _controller.value, // 0.0 → 1.0
            origin: widget.origin,
          ),
        );
      },
    );
  }
}

// ---------------------------------------------------------------------------
// _Particle — data for one confetti rectangle
// ---------------------------------------------------------------------------

/// Immutable per-particle parameters.  Velocity and rotation are randomised
/// at construction and remain fixed; position is computed each frame from
/// the animation [progress] value.
class _Particle {
  const _Particle({
    required this.velocityX,  // horizontal speed in normalised units/second
    required this.velocityY,  // initial upward speed (negative = up)
    required this.color,
    required this.width,      // particle width in logical pixels
    required this.height,     // particle height in logical pixels
    required this.rotationSpeed, // radians per second
    required this.initialRotation,
  });

  /// Create a particle with randomised properties from [rng].
  factory _Particle.random(math.Random rng, List<Color> palette) {
    // Horizontal spread: ±0.35 screen widths per second, centred on origin.
    final vx = (rng.nextDouble() - 0.5) * 0.7;

    // Upward velocity: 0.3–0.8 screen heights per second (negative = up).
    final vy = -(0.3 + rng.nextDouble() * 0.5);

    return _Particle(
      velocityX: vx,
      velocityY: vy,
      color: palette[rng.nextInt(palette.length)],
      width: 6.0 + rng.nextDouble() * 6.0,    // 6–12 px
      height: 4.0 + rng.nextDouble() * 4.0,   // 4–8 px
      rotationSpeed: (rng.nextDouble() - 0.5) * 12.0, // ±6 rad/s
      initialRotation: rng.nextDouble() * math.pi * 2,
    );
  }

  final double velocityX;
  final double velocityY;
  final Color color;
  final double width;
  final double height;
  final double rotationSpeed;
  final double initialRotation;
}

// ---------------------------------------------------------------------------
// _ConfettiPainter — CustomPainter that draws all particles each frame
// ---------------------------------------------------------------------------

class _ConfettiPainter extends CustomPainter {
  const _ConfettiPainter({
    required this.particles,
    required this.progress,   // 0.0 = start, 1.0 = end
    required this.origin,
  });

  final List<_Particle> particles;
  final double progress;
  final Offset origin;

  // Gravity constant: how many screen heights per second² the particles fall.
  static const double _gravity = 1.2;

  @override
  void paint(Canvas canvas, Size size) {
    final t = progress; // current time as fraction of total duration (0→1)
    final tSeconds = t * 1.5; // real seconds elapsed (duration = 1.5 s)

    // Origin in logical pixels.
    final ox = origin.dx * size.width;
    final oy = origin.dy * size.height;

    final paint = Paint();

    for (final p in particles) {
      // Kinematic position:
      //   x = x₀ + vx·t  (horizontal, no drag)
      //   y = y₀ + vy·t + ½·g·t²  (vertical with gravity)
      final x = ox + p.velocityX * size.width * tSeconds;
      final y = oy +
          p.velocityY * size.height * tSeconds +
          0.5 * _gravity * size.height * tSeconds * tSeconds;

      // Opacity fades from 1.0 to 0.0 linearly over the full duration.
      // Using a smooth curve makes the fade less abrupt at the end.
      final alpha = (1.0 - t).clamp(0.0, 1.0);
      paint.color = p.color.withValues(alpha: alpha);

      // Current rotation angle.
      final angle = p.initialRotation + p.rotationSpeed * tSeconds;

      // Save canvas state, translate to particle centre, rotate, draw rectangle.
      canvas.save();
      canvas.translate(x, y);
      canvas.rotate(angle);

      // Draw a flat rectangle centred on (0, 0) in the rotated frame.
      canvas.drawRect(
        Rect.fromCenter(
          center: Offset.zero,
          width: p.width,
          height: p.height,
        ),
        paint,
      );

      canvas.restore();
    }
  }

  // Only repaint when [progress] changes — which happens every animation tick.
  @override
  bool shouldRepaint(_ConfettiPainter old) => old.progress != progress;
}
