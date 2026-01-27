import 'package:flutter/widgets.dart';

class LayoutSpec {
  const LayoutSpec({
    required this.showSidebar,
    required this.sidebarWidth,
    required this.contentPadding,
  });

  final bool showSidebar;
  final double sidebarWidth;
  final double contentPadding;

  static LayoutSpec resolve(BoxConstraints constraints) {
    final width = constraints.maxWidth;
    if (width < 760) {
      return const LayoutSpec(showSidebar: false, sidebarWidth: 0, contentPadding: 12);
    }
    if (width > 1200) {
      return const LayoutSpec(showSidebar: true, sidebarWidth: 340, contentPadding: 20);
    }
    return const LayoutSpec(showSidebar: true, sidebarWidth: 300, contentPadding: 16);
  }
}
