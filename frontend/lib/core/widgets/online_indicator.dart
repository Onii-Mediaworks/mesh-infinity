import 'package:flutter/material.dart';

import '../../app/app_theme.dart';

/// Small colored dot overlaid on an avatar to show peer presence (§22.4.4).
///
/// Wrap a [child] avatar with this widget; the dot appears at the bottom-right
/// corner, consistent with the platform convention for presence indicators.
///
/// The dot has a thin border that matches [Scaffold.backgroundColor], which
/// creates a visual separation between the dot and the avatar beneath it.
/// Without the border, the green dot would bleed visually into a dark avatar,
/// making it hard to read.
///
/// Example usage:
/// ```dart
/// OnlineIndicator(
///   isOnline: peer.isOnline,
///   child: CircleAvatar(child: Text(peer.name[0])),
/// )
/// ```
class OnlineIndicator extends StatelessWidget {
  const OnlineIndicator({
    super.key,
    required this.child,
    required this.isOnline,
  });

  /// The avatar widget to overlay the indicator dot on.
  final Widget child;

  /// Whether the peer is currently reachable on the mesh.
  /// True → green dot; false → grey dot.
  final bool isOnline;

  @override
  Widget build(BuildContext context) {
    // Capture the scaffold background colour so the dot border can match it.
    // This is done here rather than hardcoding white/black because the app
    // supports both light and dark modes.
    final bgColor = Theme.of(context).scaffoldBackgroundColor;
    return Stack(
      children: [
        // The avatar being decorated — e.g. a CircleAvatar.
        child,
        // Positioned places the dot at the bottom-right corner of the Stack,
        // which overlaps the avatar.  The offset (1, 1) nudges the dot
        // slightly inward so it remains within the avatar's visual boundary.
        Positioned(
          bottom: 1,
          right: 1,
          child: Container(
            width: 10,
            height: 10,
            decoration: BoxDecoration(
              // MeshTheme.secGreen is the app's canonical "online" colour
              // (a bright green).  Grey signals the peer is offline.
              color: isOnline ? MeshTheme.secGreen : Colors.grey,
              shape: BoxShape.circle,
              // 2px border in the scaffold background colour creates a visible
              // ring that visually separates the dot from the avatar underneath,
              // improving readability regardless of the avatar's colour.
              border: Border.all(color: bgColor, width: 2),
            ),
          ),
        ),
      ],
    );
  }
}
