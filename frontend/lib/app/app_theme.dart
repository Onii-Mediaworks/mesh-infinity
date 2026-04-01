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
class MeshTheme {
  // Primary brand colour — used across light and dark themes
  static const Color brand = Color(0xFF2C6EE2);
  static const Color brandDark = Color(0xFF1A4FB5);

  // Semantic status colours — shared between mobile app and WebUI
  static const Color secGreen = Color(0xFF22C55E);
  static const Color secAmber = Color(0xFFF59E0B);
  static const Color secRed = Color(0xFFEF4444);
  static const Color secPurple = Color(0xFF7C3AED);

  // Tier-2 ambient badge dot colour
  static const Color ambientBadge = Color(0xFF4A5280);

  // Trust level colours (indices 0–8, matching TrustLevel.color extension)
  static const Color trust0 = Color(0xFF9CA3AF);
  static const Color trust1 = Color(0xFF6B7280);
  static const Color trust2 = Color(0xFF60A5FA);
  static const Color trust3 = Color(0xFF3B82F6);
  static const Color trust4 = Color(0xFF22D3EE);
  static const Color trust5 = Color(0xFF6EE7B7);
  static const Color trust6 = Color(0xFF34D399);
  static const Color trust7 = Color(0xFF059669);
  static const Color trust8 = Color(0xFFF59E0B);

  static ThemeData light() {
    final scheme = ColorScheme.fromSeed(
      seedColor: brand,
      brightness: Brightness.light,
    );
    return ThemeData(
      colorScheme: scheme,
      useMaterial3: true,
      scaffoldBackgroundColor: const Color(0xFFF7F8FA),
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
      listTileTheme: ListTileThemeData(
        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      ),
      cardTheme: CardThemeData(
        elevation: 0,
        color: scheme.surfaceContainerHighest.withValues(alpha: 0.5),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        margin: EdgeInsets.zero,
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: scheme.surfaceContainerHighest,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(14),
          borderSide: BorderSide.none,
        ),
      ),
      dividerTheme: DividerThemeData(
        color: scheme.outline.withValues(alpha: 0.2),
      ),
      drawerTheme: const DrawerThemeData(width: 280),
      snackBarTheme: const SnackBarThemeData(
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.all(Radius.circular(10)),
        ),
      ),
      bottomSheetTheme: const BottomSheetThemeData(
        showDragHandle: true,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
        ),
      ),
    );
  }

  static ThemeData dark() {
    final scheme = ColorScheme.fromSeed(
      seedColor: brand,
      brightness: Brightness.dark,
    );
    final base = ThemeData.dark(useMaterial3: true);
    return base.copyWith(
      colorScheme: scheme,
      scaffoldBackgroundColor: const Color(0xFF0F1117),
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
      listTileTheme: ListTileThemeData(
        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      ),
      cardTheme: CardThemeData(
        elevation: 0,
        color: const Color(0xFF1C1F2A),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        margin: EdgeInsets.zero,
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: scheme.surfaceContainerHighest,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(14),
          borderSide: BorderSide.none,
        ),
      ),
      dividerTheme: DividerThemeData(
        color: scheme.outline.withValues(alpha: 0.3),
      ),
      drawerTheme: const DrawerThemeData(
        backgroundColor: Color(0xFF1C1F2A),
        width: 280,
      ),
      snackBarTheme: const SnackBarThemeData(
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.all(Radius.circular(10)),
        ),
      ),
      bottomSheetTheme: const BottomSheetThemeData(
        showDragHandle: true,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
        ),
      ),
    );
  }
}
