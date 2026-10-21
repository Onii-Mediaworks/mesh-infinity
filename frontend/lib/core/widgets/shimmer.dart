import 'package:flutter/material.dart';

import '../../app/motion.dart';

/// Loading placeholder block (SPEC §22.50).
///
/// An animated gradient that runs from `surfaceContainerHighest` to the same
/// colour at 50% alpha and back, one loop every 1.5 s.  When the user asked
/// for reduced motion (§22.1.7) the block is a flat, static
/// `surfaceContainerHighest` box and no ticker runs at all.
class Shimmer extends StatefulWidget {
  const Shimmer({super.key, this.height, this.width, this.radius = 12});

  /// Block height; null fills the parent's height.
  final double? height;

  /// Block width; null fills the parent's width.
  final double? width;

  /// Corner radius of the block.
  final double radius;

  /// Length of one gradient loop, from §22.50.
  static const loop = Duration(milliseconds: 1500);

  @override
  State<Shimmer> createState() => _ShimmerState();
}

class _ShimmerState extends State<Shimmer> with SingleTickerProviderStateMixin {
  late final AnimationController _controller = AnimationController(
    vsync: this,
    duration: Shimmer.loop,
  );

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    // The preference lives in MediaQuery, so it is read here and the ticker
    // follows it: stopped under reduced motion, looping otherwise.
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

  @override
  Widget build(BuildContext context) {
    final base = Theme.of(context).colorScheme.surfaceContainerHighest;
    final radius = BorderRadius.circular(widget.radius);

    // Static variant: a flat placeholder, no AnimatedBuilder, no ticker.
    if (reduced_motion(context)) {
      return SizedBox(
        height: widget.height,
        width: widget.width,
        child: DecoratedBox(
          decoration: BoxDecoration(color: base, borderRadius: radius),
        ),
      );
    }

    return SizedBox(
      height: widget.height,
      width: widget.width,
      child: AnimatedBuilder(
        animation: _controller,
        builder: (context, _) => DecoratedBox(
          decoration: BoxDecoration(
            borderRadius: radius,
            gradient: LinearGradient(
              // base -> base@50% -> base: the band of fading colour sweeps
              // across the block while the loop runs.
              colors: [base, base.withValues(alpha: 0.5), base],
              stops: const [0.0, 0.5, 1.0],
              transform: _SweepTransform(_controller.value),
            ),
          ),
        ),
      ),
    );
  }
}

/// Slides a gradient horizontally by `-1 .. +1` widths as [progress] goes
/// from 0 to 1, so the faded band travels from left to right.
class _SweepTransform extends GradientTransform {
  const _SweepTransform(this.progress);

  final double progress;

  @override
  Matrix4? transform(Rect bounds, {TextDirection? textDirection}) {
    final dx = bounds.width * (progress * 2 - 1);
    return Matrix4.translationValues(dx, 0, 0);
  }
}

/// A list of [count] shimmer tiles, each exactly [height] logical pixels
/// tall (the per-screen counts and heights are the §22.50 table).
///
/// Scrollable with always-scrollable physics so it can sit inside a
/// `RefreshIndicator`, and announced to screen readers as a single
/// "Loading" region rather than as N anonymous boxes.
class ShimmerList extends StatelessWidget {
  const ShimmerList({super.key, required this.count, required this.height});

  /// How many placeholder tiles to draw.
  final int count;

  /// Height of each tile, matching the real tile it stands in for.
  final double height;

  @override
  Widget build(BuildContext context) {
    return Semantics(
      label: 'Loading',
      container: true,
      child: ExcludeSemantics(
        child: ListView.builder(
          physics: const AlwaysScrollableScrollPhysics(),
          itemCount: count,
          itemBuilder: (context, _) => SizedBox(
            height: height,
            child: const Padding(
              padding: EdgeInsets.symmetric(horizontal: 16, vertical: 6),
              child: Shimmer(),
            ),
          ),
        ),
      ),
    );
  }
}
