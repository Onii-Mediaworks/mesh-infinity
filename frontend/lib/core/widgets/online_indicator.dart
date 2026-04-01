import 'package:flutter/material.dart';

import '../../app/app_theme.dart';

/// Small colored dot overlaid on an avatar to show peer presence (§22.4.4).
///
/// Wrap a [child] avatar with this widget; the dot appears bottom-right.
class OnlineIndicator extends StatelessWidget {
  const OnlineIndicator({
    super.key,
    required this.child,
    required this.isOnline,
  });

  final Widget child;
  final bool isOnline;

  @override
  Widget build(BuildContext context) {
    final bgColor = Theme.of(context).scaffoldBackgroundColor;
    return Stack(
      children: [
        child,
        Positioned(
          bottom: 1,
          right: 1,
          child: Container(
            width: 10,
            height: 10,
            decoration: BoxDecoration(
              color: isOnline ? MeshTheme.secGreen : Colors.grey,
              shape: BoxShape.circle,
              border: Border.all(color: bgColor, width: 2),
            ),
          ),
        ),
      ],
    );
  }
}
