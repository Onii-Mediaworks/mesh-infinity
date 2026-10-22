import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:mesh_infinity_frontend/app/app_theme.dart';

/// WCAG 2.1 relative luminance of one sRGB channel (0..255).
///
/// Implements the piecewise gamma expansion from WCAG 2.1 §1.4.3 so the test
/// measures the same ratio an accessibility auditor would.
double _channel(int value) {
  final c = value / 255.0;
  return c <= 0.03928 ? c / 12.92 : math.pow((c + 0.055) / 1.055, 2.4) as double;
}

/// WCAG relative luminance of a fully opaque colour.
double _luminance(Color color) {
  return 0.2126 * _channel((color.r * 255).round()) +
      0.7152 * _channel((color.g * 255).round()) +
      0.0722 * _channel((color.b * 255).round());
}

/// Contrast ratio between two opaque colours, always ≥ 1.
double _contrast(Color a, Color b) {
  final la = _luminance(a);
  final lb = _luminance(b);
  final hi = math.max(la, lb);
  final lo = math.min(la, lb);
  return (hi + 0.05) / (lo + 0.05);
}

/// Every named foreground token in one [MeshColors] set, so a new field
/// added to the extension must also be added here or the test fails to
/// cover it (the length assertion below guards that).
Map<String, Color> _tokens(MeshColors c) {
  return {
    'sec_green': c.sec_green,
    'sec_amber': c.sec_amber,
    'sec_red': c.sec_red,
    'sec_purple': c.sec_purple,
    // Brand blue as foreground (CMR-019): held to the same 4.5:1 text bar
    // because it is drawn as icon and caption colour, never only as a fill.
    'brand_fg': c.brand_fg,
    for (var i = 0; i < c.trust.length; i++) 'trust[$i]': c.trust[i],
  };
}

void main() {
  // §22.34: text needs 4.5:1, UI elements 3:1. Every semantic token may be
  // used as text (badge labels, status captions), so all of them are held to
  // the stricter bar against both grounds of their theme.
  final text_bar = 4.5;
  final ui_bar = 3.0;

  final light_grounds = {
    'bgLight': MeshTheme.bgLight,
    'surfaceLight': MeshTheme.surfaceLight,
  };
  final dark_grounds = {
    'bgDark': MeshTheme.bgDark,
    'surfaceDark': MeshTheme.surfaceDark,
  };

  void check_set(String name, MeshColors set, Map<String, Color> grounds) {
    test('$name semantic tokens reach $text_bar:1 on every ground', () {
      final tokens = _tokens(set);
      // 4 security + 1 brand foreground + 9 trust colours; bump this when
      // adding a role so the new token cannot silently skip the gate.
      expect(tokens.length, 14);
      for (final token in tokens.entries) {
        for (final ground in grounds.entries) {
          final ratio = _contrast(token.value, ground.value);
          expect(
            ratio,
            greaterThanOrEqualTo(text_bar),
            reason: '${token.key} on ${ground.key} is ${ratio.toStringAsFixed(2)}:1',
          );
        }
      }
    });

    test('$name disabled token reaches $ui_bar:1 on every ground', () {
      for (final ground in grounds.entries) {
        final ratio = _contrast(set.disabled, ground.value);
        expect(
          ratio,
          greaterThanOrEqualTo(ui_bar),
          reason: 'disabled on ${ground.key} is ${ratio.toStringAsFixed(2)}:1',
        );
      }
    });

    test('$name focus ring reaches $ui_bar:1 on every ground (§22.36)', () {
      for (final ground in grounds.entries) {
        final ratio = _contrast(set.focus_ring, ground.value);
        expect(
          ratio,
          greaterThanOrEqualTo(ui_bar),
          reason: 'focus_ring on ${ground.key} is ${ratio.toStringAsFixed(2)}:1',
        );
      }
    });

    test('$name disabled is dimmer than body text', () {
      // A disabled control must still read as disabled: it sits below the
      // text bar on the scaffold ground so it does not look like live text.
      final ratio = _contrast(set.disabled, grounds.values.first);
      expect(ratio, lessThan(text_bar));
    });

    test('$name InnerCircle gold is not the LoSec amber (CMR-002)', () {
      expect(set.trust[8], isNot(equals(set.sec_amber)));
    });

    test('$name trust table has nine levels', () {
      expect(set.trust.length, 9);
      // Clamping keeps a future level 9 from indexing past the table.
      expect(set.trust_color(99), set.trust[8]);
      expect(set.trust_color(-1), set.trust[0]);
    });
  }

  check_set('light', MeshColors.light, light_grounds);
  check_set('dark', MeshColors.dark, dark_grounds);

  test('brand_fg keeps the brand hue and only shifts lightness (CMR-019)', () {
    // The seed itself is allowed to miss the text bar (it is a fill colour);
    // brand_fg exists precisely because the seed measures 4.46:1 on bgLight.
    // Both variants must still read as "the brand blue": same hue within a
    // few degrees of the seed, so a colour means the same in both themes.
    final seed_hue = HSLColor.fromColor(MeshTheme.brand).hue;
    for (final set in [MeshColors.light, MeshColors.dark]) {
      final hue = HSLColor.fromColor(set.brand_fg).hue;
      expect((hue - seed_hue).abs(), lessThan(6.0));
    }
    // The seed is not reused as the foreground token in either theme.
    expect(MeshColors.light.brand_fg, isNot(equals(MeshTheme.brand)));
    expect(MeshColors.dark.brand_fg, isNot(equals(MeshTheme.brand)));
  });

  test('both ThemeData register their MeshColors extension', () {
    expect(MeshTheme.light().extension<MeshColors>(), MeshColors.light);
    expect(MeshTheme.dark().extension<MeshColors>(), MeshColors.dark);
  });

  test('ThemeData.disabledColor is the opaque token (CMR-003)', () {
    expect(MeshTheme.light().disabledColor, MeshColors.light.disabled);
    expect(MeshTheme.dark().disabledColor, MeshColors.dark.disabled);
  });

  testWidgets('MeshColors.of resolves per theme', (tester) async {
    MeshColors? seen;
    await tester.pumpWidget(
      MaterialApp(
        theme: MeshTheme.light(),
        home: Builder(
          builder: (context) {
            seen = MeshColors.of(context);
            return const SizedBox();
          },
        ),
      ),
    );
    expect(seen, MeshColors.light);
  });
}
