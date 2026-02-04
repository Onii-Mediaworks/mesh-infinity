import 'package:flutter/widgets.dart';

class LayoutSpec {
  const LayoutSpec({
    required this.showSidebar,
    required this.sidebarWidth,
    required this.showSecondaryPane,
    required this.secondaryPaneWidth,
    required this.contentPadding,
    required this.showDrawer,
  });

  final bool showSidebar;
  final double sidebarWidth;
  final bool showSecondaryPane;
  final double secondaryPaneWidth;
  final double contentPadding;
  final bool showDrawer;

  static LayoutSpec resolve(BoxConstraints constraints) {
    final width = constraints.maxWidth;
    if (width < 760) {
      return const LayoutSpec(
        showSidebar: false,
        sidebarWidth: 0,
        showSecondaryPane: false,
        secondaryPaneWidth: 0,
        contentPadding: 12,
        showDrawer: true,
      );
    }
    if (width > 1200) {
      return const LayoutSpec(
        showSidebar: true,
        sidebarWidth: 320,
        showSecondaryPane: true,
        secondaryPaneWidth: 360,
        contentPadding: 20,
        showDrawer: false,
      );
    }
    return const LayoutSpec(
      showSidebar: true,
      sidebarWidth: 300,
      showSecondaryPane: false,
      secondaryPaneWidth: 0,
      contentPadding: 16,
      showDrawer: false,
    );
  }
}
