import 'package:flutter/material.dart';
import 'dart:io';

/// Centralised light / dark themes for Mesh Infinity.
class MeshTheme {
  static const Color brand = Color(0xFF2C6EE2);
  static bool get _isApple => Platform.isIOS || Platform.isMacOS;

  static ThemeData light() {
    final baseScheme = _isApple
        ? ColorScheme.fromSeed(seedColor: brand, brightness: Brightness.light)
        : ColorScheme.fromSeed(seedColor: brand, brightness: Brightness.light);
    return ThemeData(
      colorScheme: baseScheme,
      useMaterial3: !_isApple,
      scaffoldBackgroundColor: const Color(0xFFF7F8FA),
      appBarTheme: const AppBarTheme(centerTitle: false, elevation: 0),
      listTileTheme: ListTileThemeData(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      ),
      cardTheme: CardThemeData(
        elevation: 0,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        margin: EdgeInsets.zero,
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: baseScheme.surfaceContainerHighest,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(14),
          borderSide: BorderSide.none,
        ),
      ),
      dividerTheme: DividerThemeData(color: baseScheme.outline.withValues(alpha: 0.2)),
    );
  }

  static ThemeData dark() {
    final base = ThemeData.dark(useMaterial3: !_isApple);
    final scheme = ColorScheme.fromSeed(seedColor: brand, brightness: Brightness.dark);
    return base.copyWith(
      colorScheme: scheme,
      listTileTheme: ListTileThemeData(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      ),
      cardTheme: CardThemeData(
        elevation: 0,
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
      dividerTheme: DividerThemeData(color: scheme.outline.withValues(alpha: 0.3)),
    );
  }
}
