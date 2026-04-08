import 'package:flutter/material.dart';

/// Centralised light / dark themes and shared design tokens for Mesh Infinity.
///
/// Design token table (from UI/UX proposal iterations 8–9):
///   brand       #2C6EE2   Primary actions, active nav indicators
///   brandDark   #1A4FB5   Pressed states
///   bgDark      #0F1117   Dark page background
///   surfaceDark #1C1F2A   Dark cards, panels
///   secGreen    #22C55E   Online, success, healthy
///   secAmber    #F59E0B   Warning, degraded
///   secRed      #EF4444   Error, offline, danger
///   secPurple   #7C3AED   Anonymous / max security
///   ambient     #4A5280   Tier-2 ambient badge dot
///
/// Material 3 is used on all platforms — no platform-specific branching in UI.
///
/// Usage:
///   ThemeData light = MeshTheme.light();
///   ThemeData dark  = MeshTheme.dark();
///   MaterialApp(theme: MeshTheme.light(), darkTheme: MeshTheme.dark(), ...)
///
/// Static color constants (e.g. [brand], [secGreen]) are available directly as
/// `MeshTheme.brand` for use in widgets that need to reference theme colors
/// without a [BuildContext].
class MeshTheme {
  // Primary brand colour — used across light and dark themes as the seed for
  // Material 3's tonal palette generation.  All shades of the primary,
  // secondary, and tertiary roles are derived from this by Flutter's
  // ColorScheme.fromSeed() algorithm.
  static const Color brand = Color(0xFF2C6EE2);

  /// Darker variant of the brand color — used for pressed/active states where
  /// a stronger contrast is needed (e.g. filled button press feedback).
  static const Color brandDark = Color(0xFF1A4FB5);

  // ---------------------------------------------------------------------------
  // Semantic status colours
  //
  // These are FIXED colours — they do not shift with the Material 3 tonal
  // palette because their meaning must remain unambiguous regardless of theme.
  // Changing them would break the universal "green = online" mental model.
  // ---------------------------------------------------------------------------

  /// Peer online, transfer succeeded, health check passed.
  static const Color secGreen = Color(0xFF22C55E);

  /// Warning, degraded transport, partial failure.
  static const Color secAmber = Color(0xFFF59E0B);

  /// Error, offline, security violation, danger state.
  static const Color secRed = Color(0xFFEF4444);

  /// Anonymous / max-security mode indicator (§6.9.6 LoSec, §3.9 erase modes).
  static const Color secPurple = Color(0xFF7C3AED);

  // ---------------------------------------------------------------------------
  // Badge colours
  // ---------------------------------------------------------------------------

  /// Tier-2 ambient badge dot colour — shown on the nav rail/drawer when
  /// a background notification tier is active but below direct-message priority.
  static const Color ambientBadge = Color(0xFF4A5280);

  // ---------------------------------------------------------------------------
  // Trust level colours (indices 0–8)
  //
  // These mirror the TrustLevel.color extension in peer_models.dart.
  // They are duplicated here so that code that only has a raw trust integer
  // (not a TrustLevel enum value) can look up the colour without importing
  // the peer model.  The two tables MUST stay in sync.
  //
  // Index 0 = TrustLevel.unknown (grey), 8 = TrustLevel.innerCircle (amber).
  // Amber at the top feels counter-intuitive but matches the brand palette —
  // "inner circle" is warm and personal, not cold and clinical.
  // ---------------------------------------------------------------------------
  static const Color trust0 = Color(0xFF9CA3AF); // unknown
  static const Color trust1 = Color(0xFF6B7280); // public
  static const Color trust2 = Color(0xFF60A5FA); // vouched
  static const Color trust3 = Color(0xFF3B82F6); // referenced
  static const Color trust4 = Color(0xFF22D3EE); // ally
  static const Color trust5 = Color(0xFF6EE7B7); // acquaintance
  static const Color trust6 = Color(0xFF34D399); // trusted
  static const Color trust7 = Color(0xFF059669); // highly trusted
  static const Color trust8 = Color(0xFFF59E0B); // inner circle

  // ---------------------------------------------------------------------------
  // light()
  //
  // Builds the light-mode ThemeData.  Flutter's Material 3 theming system
  // derives an entire tonal palette from the [brand] seed color.  We then
  // override specific component themes to match the Mesh Infinity design spec.
  //
  // Light mode uses off-white (#F7F8FA) as the scaffold background rather than
  // pure white — this reduces eye strain and gives cards enough contrast to
  // appear elevated without shadows.
  // ---------------------------------------------------------------------------

  /// Constructs the light [ThemeData] for the application.
  ///
  /// Uses [ColorScheme.fromSeed] with [brand] to generate all tonal roles
  /// automatically, then applies per-component overrides.
  static ThemeData light() {
    // Let Flutter derive the full Material 3 color scheme from the brand seed.
    // The resulting scheme has primary, secondary, tertiary, and all their
    // container/on-color variants automatically computed for WCAG contrast.
    final scheme = ColorScheme.fromSeed(
      seedColor: brand,
      brightness: Brightness.light,
    );

    return ThemeData(
      colorScheme: scheme,
      useMaterial3: true,

      // Slightly tinted white instead of pure white — reduces glare and gives
      // surface-colored cards a visible lift even at elevation: 0.
      scaffoldBackgroundColor: const Color(0xFFF7F8FA),

      // AppBar — flat (elevation: 0) by default; gains a 1dp shadow only when
      // content scrolls underneath it (scrolledUnderElevation: 1).
      // centerTitle: false keeps the title left-aligned, per Material 3 spec.
      appBarTheme: AppBarTheme(
        centerTitle: false,
        elevation: 0,
        scrolledUnderElevation: 1,
        backgroundColor: scheme.surface,
        foregroundColor: scheme.onSurface,
        titleTextStyle: TextStyle(
          fontSize: 16,
          fontWeight: FontWeight.w600,
          color: scheme.onSurface,
        ),
      ),

      // ListTile — horizontal padding of 16 keeps content aligned with most
      // other page content.  Rounded corners (r=12) soften the tile appearance.
      listTileTheme: ListTileThemeData(
        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      ),

      // Card — flat (elevation: 0) cards use a semi-transparent surface tint
      // to lift from the page background without heavy shadows.  Zero margin
      // means callers control spacing, keeping layouts predictable.
      cardTheme: CardThemeData(
        elevation: 0,
        color: scheme.surfaceContainerHighest.withValues(alpha: 0.5),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        margin: EdgeInsets.zero,
      ),

      // Text fields — filled style (no visible border) with rounded corners
      // matches Material 3 guidelines and avoids noisy border lines in forms.
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: scheme.surfaceContainerHighest,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(14),
          borderSide: BorderSide.none,
        ),
      ),

      // Dividers — very subtle (20% opacity) so list separators don't
      // compete with content for visual attention.
      dividerTheme: DividerThemeData(
        color: scheme.outline.withValues(alpha: 0.2),
      ),

      // Navigation drawer — fixed at 280dp wide, which fits 5-7 nav items
      // comfortably and leaves room for two-tier badge columns.
      drawerTheme: const DrawerThemeData(width: 280),

      // SnackBars — floating (not pinned to bottom) with rounded corners to
      // avoid the harsh rectangular default style.
      snackBarTheme: const SnackBarThemeData(
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.all(Radius.circular(10)),
        ),
      ),

      // Bottom sheets — drag handle shown to indicate the sheet can be
      // dismissed by swiping down.  Rounded top corners (r=20) match the
      // overall rounded aesthetic.
      bottomSheetTheme: const BottomSheetThemeData(
        showDragHandle: true,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
        ),
      ),

      // Chips — rounded (r=8) and borderless; the chip background provides
      // sufficient visual differentiation from surrounding text.
      chipTheme: ChipThemeData(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
        side: BorderSide.none,
      ),

      // Bottom navigation bar — smaller font (11sp) fits up to 5 labels
      // without truncation on compact phones.
      navigationBarTheme: NavigationBarThemeData(
        labelTextStyle: WidgetStateProperty.all(
          const TextStyle(fontSize: 11, fontWeight: FontWeight.w500),
        ),
      ),

      // Navigation rail (tablet/wide layout) — always shows labels and
      // aligns items to the top (groupAlignment: -1) so they don't float
      // in the vertical middle.
      navigationRailTheme: const NavigationRailThemeData(
        labelType: NavigationRailLabelType.all,
        groupAlignment: -1,
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // dark()
  //
  // Builds the dark-mode ThemeData.  Starts from ThemeData.dark() (which sets
  // sensible Material 3 dark defaults) and then applies the same per-component
  // overrides as light(), adapted for dark surfaces.
  //
  // The dark theme uses deep navy (#0F1117) for the scaffold and a slightly
  // lighter navy (#1C1F2A) for surfaces — this two-level system lets cards
  // appear elevated without any shadow (matching flat design on OLED screens,
  // where true black saves power).
  // ---------------------------------------------------------------------------

  /// Constructs the dark [ThemeData] for the application.
  ///
  /// Starts from [ThemeData.dark] as a base and applies overrides via
  /// [ThemeData.copyWith] so only the explicitly customised properties differ
  /// from Flutter's dark mode defaults.
  static ThemeData dark() {
    // Generate the dark color scheme from the same brand seed so hue is
    // consistent between light and dark modes.
    final scheme = ColorScheme.fromSeed(
      seedColor: brand,
      brightness: Brightness.dark,
    );

    // Start from ThemeData.dark() rather than ThemeData() so we inherit all
    // the Material 3 dark-mode typography, icon, and ripple defaults.
    final base = ThemeData.dark(useMaterial3: true);

    return base.copyWith(
      colorScheme: scheme,

      // Deep navy page background — darker than the surface colour so there
      // is a visible hierarchy: page → surface (cards, panels) → elements.
      scaffoldBackgroundColor: const Color(0xFF0F1117),

      // AppBar uses the surface colour (#1C1F2A) rather than the scaffold
      // background (#0F1117) so it blends with the card layer rather than
      // disappearing into the page.
      appBarTheme: AppBarTheme(
        centerTitle: false,
        elevation: 0,
        scrolledUnderElevation: 1,
        backgroundColor: const Color(0xFF1C1F2A),
        foregroundColor: scheme.onSurface,
        titleTextStyle: TextStyle(
          fontSize: 16,
          fontWeight: FontWeight.w600,
          color: scheme.onSurface,
        ),
      ),

      // Same list tile shape as light — consistent rounding across modes.
      listTileTheme: ListTileThemeData(
        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      ),

      // Cards in dark mode use a solid surface colour rather than a
      // semi-transparent tint because there is no light background to tint
      // against — a solid colour gives better control over contrast.
      cardTheme: CardThemeData(
        elevation: 0,
        color: const Color(0xFF1C1F2A),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        margin: EdgeInsets.zero,
      ),

      // Text fields — same filled style as light but using Material 3's
      // auto-derived dark surface container colour.
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: scheme.surfaceContainerHighest,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(14),
          borderSide: BorderSide.none,
        ),
      ),

      // Dividers at 30% opacity (slightly higher than light's 20%) because
      // dark-on-dark separators need a touch more contrast to remain visible.
      dividerTheme: DividerThemeData(
        color: scheme.outline.withValues(alpha: 0.3),
      ),

      // Drawer in dark mode needs an explicit background colour override;
      // without it Flutter would use the Material 3 surface tonal layer which
      // does not match our custom dark surface.
      drawerTheme: const DrawerThemeData(
        backgroundColor: Color(0xFF1C1F2A),
        width: 280,
      ),

      // Snack bars — same floating rounded style as light.
      snackBarTheme: const SnackBarThemeData(
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.all(Radius.circular(10)),
        ),
      ),

      // Bottom sheets — same drag handle and rounded top as light.
      bottomSheetTheme: const BottomSheetThemeData(
        showDragHandle: true,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
        ),
      ),

      // Chips — same rounded borderless style as light.
      chipTheme: ChipThemeData(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
        side: BorderSide.none,
      ),

      // Navigation bar — same compact font as light.
      navigationBarTheme: NavigationBarThemeData(
        labelTextStyle: WidgetStateProperty.all(
          const TextStyle(fontSize: 11, fontWeight: FontWeight.w500),
        ),
      ),

      // Navigation rail — same top-aligned always-visible labels as light.
      navigationRailTheme: const NavigationRailThemeData(
        labelType: NavigationRailLabelType.all,
        groupAlignment: -1,
      ),
    );
  }
}
