import 'package:flutter/material.dart';

/// Centralised light / dark themes and shared design tokens for Mesh Infinity.
///
/// Every colour the UI draws lives in this file (SPEC §22.1.1). Screens read
/// colour *roles*, never hex values, so a palette change is a one-file edit.
///
/// Fixed brand/background tokens (same in both themes):
///   brand        #2C6EE2   Primary actions, active nav indicators, seed colour
///   brandDark    #1A4FB5   Pressed states
///   bgDark       #0F1117   Dark page background
///   surfaceDark  #1C1F2A   Dark cards, panels
///   bgLight      #F7F8FA   Light page background
///   surfaceLight #FFFFFF   Light cards, panels
///   ambient      #4A5280   Tier-2 ambient badge dot
///
/// Security-status and trust-level colours are *per theme* (CMR-001). They are
/// published through the [MeshColors] theme extension, so widgets resolve them
/// with `MeshColors.of(context)` and automatically get the variant that meets
/// WCAG 2.1 AA (§22.34) against the ground it is drawn on. The dark variants
/// are the historical values; the light variants keep the same hue but are
/// darkened until they reach 4.5:1 on both light grounds. The test in
/// `test/theme_contrast_test.dart` enforces this for every token.
///
/// Material 3 is used on all platforms — no platform-specific branching in UI.
///
/// Usage:
///   MaterialApp(theme: MeshTheme.light(), darkTheme: MeshTheme.dark(), ...)
///   final colors = MeshColors.of(context);
///   Icon(Icons.circle, color: colors.sec_green);
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
  // Ground colours (§22.1.1 kBg* / kSurface*)
  //
  // These are the surfaces every foreground token is contrast-tested against.
  // They are public so the contrast test and the shell can reference the same
  // values instead of repeating hex literals.
  // ---------------------------------------------------------------------------

  /// Light scaffold background — off-white rather than pure white to reduce
  /// glare and let elevation-0 cards still read as lifted.
  static const Color bgLight = Color(0xFFF7F8FA);

  /// Light card / panel surface.
  static const Color surfaceLight = Color(0xFFFFFFFF);

  /// Dark scaffold background — deep navy, not pure black, so the surface
  /// layer above it still has somewhere to go.
  static const Color bgDark = Color(0xFF0F1117);

  /// Dark card / panel surface — one step lighter than [bgDark] so cards
  /// appear elevated without shadows.
  static const Color surfaceDark = Color(0xFF1C1F2A);

  // ---------------------------------------------------------------------------
  // Badge colours
  // ---------------------------------------------------------------------------

  /// Tier-2 ambient badge dot colour — shown on the nav rail/drawer when
  /// a background notification tier is active but below direct-message priority.
  static const Color ambientBadge = Color(0xFF4A5280);

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

      // Per-theme semantic colours (security status, trust levels, disabled).
      // Widgets read them via MeshColors.of(context); see the class docs.
      extensions: const [MeshColors.light],

      // Material's stock disabled colour is onSurface at 38% alpha, which is
      // roughly 2.3:1 on a light ground and fails §22.34's 3:1 bar for UI
      // elements. CMR-003 replaces it with an opaque token that passes.
      disabledColor: MeshColors.light.disabled,

      // Slightly tinted white instead of pure white — reduces glare and gives
      // surface-colored cards a visible lift even at elevation: 0.
      scaffoldBackgroundColor: bgLight,

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

      // Disabled controls (CMR-003): every button family, switches and
      // checkboxes draw their disabled foreground with the opaque token
      // rather than Material's translucent default.
      filledButtonTheme: FilledButtonThemeData(
        style: _disabled_button_style(MeshColors.light.disabled),
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: _disabled_button_style(MeshColors.light.disabled),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: _disabled_button_style(MeshColors.light.disabled),
      ),
      textButtonTheme: TextButtonThemeData(
        style: _disabled_button_style(MeshColors.light.disabled),
      ),
      iconButtonTheme: IconButtonThemeData(
        style: _disabled_button_style(MeshColors.light.disabled),
      ),
      switchTheme: _disabled_switch_theme(MeshColors.light.disabled),
      checkboxTheme: _disabled_checkbox_theme(MeshColors.light.disabled),
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

      // Per-theme semantic colours; the dark variants are the historical
      // palette, which already clears 4.5:1 on both dark grounds.
      extensions: const [MeshColors.dark],

      // Opaque disabled token (CMR-003); see light() for the rationale.
      disabledColor: MeshColors.dark.disabled,

      // Deep navy page background — darker than the surface colour so there
      // is a visible hierarchy: page → surface (cards, panels) → elements.
      scaffoldBackgroundColor: bgDark,

      // AppBar uses the surface colour (#1C1F2A) rather than the scaffold
      // background (#0F1117) so it blends with the card layer rather than
      // disappearing into the page.
      appBarTheme: AppBarTheme(
        centerTitle: false,
        elevation: 0,
        scrolledUnderElevation: 1,
        backgroundColor: surfaceDark,
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
        color: surfaceDark,
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
        backgroundColor: surfaceDark,
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

      // Disabled controls (CMR-003) — same component set as light().
      filledButtonTheme: FilledButtonThemeData(
        style: _disabled_button_style(MeshColors.dark.disabled),
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: _disabled_button_style(MeshColors.dark.disabled),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: _disabled_button_style(MeshColors.dark.disabled),
      ),
      textButtonTheme: TextButtonThemeData(
        style: _disabled_button_style(MeshColors.dark.disabled),
      ),
      iconButtonTheme: IconButtonThemeData(
        style: _disabled_button_style(MeshColors.dark.disabled),
      ),
      switchTheme: _disabled_switch_theme(MeshColors.dark.disabled),
      checkboxTheme: _disabled_checkbox_theme(MeshColors.dark.disabled),
    );
  }

  // ---------------------------------------------------------------------------
  // Disabled-state helpers (CMR-003)
  //
  // Each helper only touches the disabled state and leaves every other state
  // null, so Material 3's own defaults (and the ColorScheme) still drive the
  // enabled, hovered, pressed and focused looks.
  // ---------------------------------------------------------------------------

  /// A [ButtonStyle] whose foreground is [disabled] when the button is
  /// disabled and otherwise undefined (null → component default).
  static ButtonStyle _disabled_button_style(Color disabled) {
    return ButtonStyle(
      foregroundColor: WidgetStateProperty.resolveWith(
        (states) => states.contains(WidgetState.disabled) ? disabled : null,
      ),
      iconColor: WidgetStateProperty.resolveWith(
        (states) => states.contains(WidgetState.disabled) ? disabled : null,
      ),
    );
  }

  /// Switch theme that paints a disabled thumb with the opaque token; the
  /// track is left to Material so the on/off position still reads.
  static SwitchThemeData _disabled_switch_theme(Color disabled) {
    return SwitchThemeData(
      thumbColor: WidgetStateProperty.resolveWith(
        (states) => states.contains(WidgetState.disabled) ? disabled : null,
      ),
    );
  }

  /// Checkbox theme that uses the opaque token for a disabled box outline
  /// and fill, so an unavailable option is still visible as a box.
  static CheckboxThemeData _disabled_checkbox_theme(Color disabled) {
    return CheckboxThemeData(
      side: WidgetStateBorderSide.resolveWith(
        (states) => states.contains(WidgetState.disabled)
            ? BorderSide(color: disabled, width: 2)
            : null,
      ),
      fillColor: WidgetStateProperty.resolveWith(
        (states) => states.contains(WidgetState.disabled) &&
                states.contains(WidgetState.selected)
            ? disabled
            : null,
      ),
    );
  }
}

/// Per-theme semantic colour tokens (SPEC §22.1.1, CMR-001/002/003).
///
/// Registered on both [ThemeData]s as a [ThemeExtension], so a widget asks
/// `MeshColors.of(context)` and gets the variant that passes WCAG 2.1 AA
/// against the current theme's grounds. The same role has the same hue in
/// both themes; only lightness differs.
///
/// Fixed semantic meaning — do not reassign roles:
///   sec_green   All clear / verified / online
///   sec_amber   LoSec mode / warning / degraded
///   sec_red     Direct mode / critical / error / offline
///   sec_purple  Compromised peer / critical threat context
///   trust[n]    Trust level n (0 Unknown … 8 InnerCircle), see §8 / §22.31
///   disabled    Foreground of a disabled control (≥3:1 on every ground)
///   focus_ring  Keyboard/controller focus ring (≥3:1 on every ground, §22.36)
@immutable
class MeshColors extends ThemeExtension<MeshColors> {
  /// All-clear / verified / online.
  final Color sec_green;

  /// LoSec mode, warnings, degraded transport.
  final Color sec_amber;

  /// Direct mode, critical state, errors, offline.
  final Color sec_red;

  /// Compromised peer, critical threat context.
  final Color sec_purple;

  /// Trust-level colours indexed 0 (Unknown) … 8 (InnerCircle).
  final List<Color> trust;

  /// Foreground for disabled controls (CMR-003).
  final Color disabled;

  /// Keyboard / controller focus ring, drawn by the shell (§22.36 rule 3).
  final Color focus_ring;

  const MeshColors({
    required this.sec_green,
    required this.sec_amber,
    required this.sec_red,
    required this.sec_purple,
    required this.trust,
    required this.disabled,
    required this.focus_ring,
  });

  /// Light-theme variants: each hue darkened until it reaches ≥4.5:1 on both
  /// [MeshTheme.bgLight] and [MeshTheme.surfaceLight] (CMR-001).
  static const MeshColors light = MeshColors(
    sec_green: Color(0xFF16823E),
    sec_amber: Color(0xFF9D6507),
    sec_red: Color(0xFFCE3A3A),
    sec_purple: Color(0xFF7C3AED),
    trust: [
      Color(0xFF6D727A), // 0 Unknown — gray
      Color(0xFF4B5563), // 1 Public — dark gray
      Color(0xFF4374AF), // 2 Vouched — light blue
      Color(0xFF326DCF), // 3 Referenced — blue
      Color(0xFF147A8A), // 4 Ally — cyan
      Color(0xFF3B7D63), // 5 Acquaintance — light green
      Color(0xFF1F7F5C), // 6 Trusted — green
      Color(0xFF04815A), // 7 HighlyTrusted — dark green
      Color(0xFF8C6B05), // 8 InnerCircle — gold (CMR-002)
    ],
    disabled: Color(0xFF858A94),
    focus_ring: Color(0xFF1A4FB5),
  );

  /// Dark-theme variants: the historical palette, with brand-blue, purple,
  /// Public, Referenced, HighlyTrusted and red nudged lighter so every token
  /// reaches ≥4.5:1 on both [MeshTheme.bgDark] and [MeshTheme.surfaceDark].
  static const MeshColors dark = MeshColors(
    sec_green: Color(0xFF22C55E),
    sec_amber: Color(0xFFF59E0B),
    sec_red: Color(0xFFF04B4B),
    sec_purple: Color(0xFF9E6DF2),
    trust: [
      Color(0xFF9CA3AF), // 0 Unknown — gray
      Color(0xFF838994), // 1 Public — dark gray
      Color(0xFF60A5FA), // 2 Vouched — light blue
      Color(0xFF3F84F6), // 3 Referenced — blue
      Color(0xFF22D3EE), // 4 Ally — cyan
      Color(0xFF6EE7B7), // 5 Acquaintance — light green
      Color(0xFF34D399), // 6 Trusted — green
      Color(0xFF0F9A6F), // 7 HighlyTrusted — dark green
      Color(0xFFEAB308), // 8 InnerCircle — gold (CMR-002)
    ],
    disabled: Color(0xFF6B7280),
    focus_ring: Color(0xFF7FA8F0),
  );

  /// Resolve the tokens for the ambient theme. Falls back to the dark set if
  /// a test pumps a bare [ThemeData] without the extension, so widgets never
  /// null-crash over a missing theme registration.
  static MeshColors of(BuildContext context) {
    return Theme.of(context).extension<MeshColors>() ?? dark;
  }

  /// Colour for a raw trust integer. Out-of-range values clamp to the ends so
  /// a newer backend adding a level 9 can't index past the table.
  Color trust_color(int level) {
    return trust[level.clamp(0, trust.length - 1)];
  }

  @override
  MeshColors copyWith({
    Color? sec_green,
    Color? sec_amber,
    Color? sec_red,
    Color? sec_purple,
    List<Color>? trust,
    Color? disabled,
    Color? focus_ring,
  }) {
    return MeshColors(
      sec_green: sec_green ?? this.sec_green,
      sec_amber: sec_amber ?? this.sec_amber,
      sec_red: sec_red ?? this.sec_red,
      sec_purple: sec_purple ?? this.sec_purple,
      trust: trust ?? this.trust,
      disabled: disabled ?? this.disabled,
      focus_ring: focus_ring ?? this.focus_ring,
    );
  }

  /// Interpolates every token so a light↔dark theme switch cross-fades the
  /// status colours alongside the rest of the ThemeData.
  @override
  MeshColors lerp(ThemeExtension<MeshColors>? other, double t) {
    if (other is! MeshColors) return this;
    return MeshColors(
      sec_green: Color.lerp(sec_green, other.sec_green, t) ?? sec_green,
      sec_amber: Color.lerp(sec_amber, other.sec_amber, t) ?? sec_amber,
      sec_red: Color.lerp(sec_red, other.sec_red, t) ?? sec_red,
      sec_purple: Color.lerp(sec_purple, other.sec_purple, t) ?? sec_purple,
      trust: [
        for (var i = 0; i < trust.length; i++)
          Color.lerp(trust[i], other.trust_color(i), t) ?? trust[i],
      ],
      disabled: Color.lerp(disabled, other.disabled, t) ?? disabled,
      focus_ring: Color.lerp(focus_ring, other.focus_ring, t) ?? focus_ring,
    );
  }
}
