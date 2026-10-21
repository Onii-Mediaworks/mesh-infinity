// reduced_motion_test.dart
//
// SPEC §22.1.7 / §22.34: when the platform asks for reduced motion
// (`MediaQuery.disableAnimations`), every duration is zero and every looping
// or one-shot decorative animation is replaced by a static equivalent.
//
// The preference is switched on the way a real device does it, through the
// platform's accessibility features, so MaterialApp's own MediaQuery picks it
// up.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:mesh_infinity_frontend/app/app_theme.dart';
import 'package:mesh_infinity_frontend/app/motion.dart';
import 'package:mesh_infinity_frontend/core/widgets/shimmer.dart';
import 'package:mesh_infinity_frontend/features/tidbits/widgets/confetti_burst.dart';

/// Turn the platform "remove animations" setting on or off for [tester].
void set_reduced_motion(WidgetTester tester, bool on) {
  tester.platformDispatcher.accessibilityFeaturesTestValue =
      FakeAccessibilityFeatures(disableAnimations: on);
  addTearDown(tester.platformDispatcher.clearAccessibilityFeaturesTestValue);
}

/// Pump [child] inside a themed MaterialApp.
Future<void> pump_host(WidgetTester tester, Widget child) {
  return tester.pumpWidget(
    MaterialApp(theme: MeshTheme.light(), home: Scaffold(body: child)),
  );
}

void main() {
  group('motion helper', () {
    testWidgets('durations become zero when reduced motion is on', (
      tester,
    ) async {
      set_reduced_motion(tester, true);
      late Duration got;
      late bool flag;
      await pump_host(
        tester,
        Builder(
          builder: (context) {
            got = motion_duration(context, const Duration(milliseconds: 400));
            flag = reduced_motion(context);
            return const SizedBox();
          },
        ),
      );
      expect(flag, isTrue);
      expect(got, Duration.zero);
    });

    testWidgets('durations pass through when animations are allowed', (
      tester,
    ) async {
      set_reduced_motion(tester, false);
      late Duration got;
      late bool flag;
      await pump_host(
        tester,
        Builder(
          builder: (context) {
            got = motion_duration(context, const Duration(milliseconds: 400));
            flag = reduced_motion(context);
            return const SizedBox();
          },
        ),
      );
      expect(flag, isFalse);
      expect(got, const Duration(milliseconds: 400));
    });
  });

  group('shimmer', () {
    testWidgets('loops while animations are allowed', (tester) async {
      set_reduced_motion(tester, false);
      await pump_host(tester, const Shimmer(height: 72));
      await tester.pump(const Duration(milliseconds: 100));
      expect(tester.hasRunningAnimations, isTrue);
    });

    testWidgets('is a static placeholder under reduced motion', (tester) async {
      set_reduced_motion(tester, true);
      await pump_host(tester, const Shimmer(height: 72));
      // No ticker is running, so the tree settles immediately.
      expect(tester.hasRunningAnimations, isFalse);
      await tester.pumpAndSettle();

      // The flat fill is surfaceContainerHighest, per §22.50.
      final box = tester.widget<DecoratedBox>(
        find.descendant(
          of: find.byType(Shimmer),
          matching: find.byType(DecoratedBox),
        ),
      );
      final decoration = box.decoration as BoxDecoration;
      expect(decoration.gradient, isNull);
      expect(
        decoration.color,
        MeshTheme.light().colorScheme.surfaceContainerHighest,
      );
    });

    testWidgets('follows the preference when it changes at runtime', (
      tester,
    ) async {
      set_reduced_motion(tester, false);
      await pump_host(tester, const Shimmer(height: 72));
      await tester.pump(const Duration(milliseconds: 100));
      expect(tester.hasRunningAnimations, isTrue);

      set_reduced_motion(tester, true);
      await tester.pump();
      await tester.pumpAndSettle();
      expect(tester.hasRunningAnimations, isFalse);
    });
  });

  group('confetti burst', () {
    testWidgets('plays one-shot animation when allowed', (tester) async {
      set_reduced_motion(tester, false);
      var done = false;
      await pump_host(tester, ConfettiBurst(onComplete: () => done = true));
      await tester.pump(const Duration(milliseconds: 200));
      expect(tester.hasRunningAnimations, isTrue);
      expect(done, isFalse);
      await tester.pump(const Duration(seconds: 2));
      expect(done, isTrue);
    });

    testWidgets('draws nothing and completes at once under reduced motion', (
      tester,
    ) async {
      set_reduced_motion(tester, true);
      var done = false;
      await pump_host(tester, ConfettiBurst(onComplete: () => done = true));
      await tester.pump();
      expect(tester.hasRunningAnimations, isFalse);
      // The overlay host is told to remove the entry on the first frame.
      expect(done, isTrue);
      expect(
        find.descendant(
          of: find.byType(ConfettiBurst),
          matching: find.byType(CustomPaint),
        ),
        findsNothing,
      );
    });
  });
}
