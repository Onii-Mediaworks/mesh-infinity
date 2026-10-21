// gesture_hint_test.dart
//
// SPEC §22.35.1: each gesture hint is shown exactly once, never blocks
// interaction, is suppressed once the gesture has been performed, and is a
// static tooltip under reduced motion.

import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:mesh_infinity_frontend/app/app_theme.dart';
import 'package:mesh_infinity_frontend/app/ui_prefs.dart';
import 'package:mesh_infinity_frontend/core/widgets/gesture_hint_overlay.dart';

/// A hint over a tappable child; [taps] counts child taps.
Widget host({bool trigger = true, List<int>? taps}) {
  return MaterialApp(
    theme: MeshTheme.light(),
    home: Scaffold(
      body: GestureHintOverlay(
        hint: GestureHint.long_press_reactions,
        trigger: trigger,
        child: SizedBox(
          width: 300,
          height: 80,
          child: GestureDetector(
            onTap: () => taps?.add(1),
            child: const ColoredBox(color: Colors.blue),
          ),
        ),
      ),
    ),
  );
}

final hint_text = 'Hold for reactions';

void main() {
  setUp(() {
    // Fresh in-memory flags for every test.
    UiPrefs.instance = UiPrefs();
  });

  testWidgets('shows once, auto-dismisses after 3 s, never again', (
    tester,
  ) async {
    await tester.pumpWidget(host());
    await tester.pump();
    expect(find.text(hint_text), findsOneWidget);

    await tester.pump(const Duration(seconds: 3));
    await tester.pump();
    expect(find.text(hint_text), findsNothing);

    // A second screen visit (new overlay instance) stays quiet.
    await tester.pumpWidget(const SizedBox());
    await tester.pumpWidget(host());
    await tester.pump();
    expect(find.text(hint_text), findsNothing);
    expect(
      UiPrefs.instance.flag('gesture_hint_seen_long_press_reactions'),
      isTrue,
    );
  });

  testWidgets('waits for its trigger', (tester) async {
    await tester.pumpWidget(host(trigger: false));
    await tester.pump();
    expect(find.text(hint_text), findsNothing);

    await tester.pumpWidget(host(trigger: true));
    await tester.pump();
    expect(find.text(hint_text), findsOneWidget);
    await tester.pump(const Duration(seconds: 3));
  });

  testWidgets('is suppressed when the gesture was already performed', (
    tester,
  ) async {
    await GestureHintOverlay.mark_performed(GestureHint.long_press_reactions);
    await tester.pumpWidget(host());
    await tester.pump();
    expect(find.text(hint_text), findsNothing);
  });

  testWidgets('performing the gesture dismisses a visible hint', (
    tester,
  ) async {
    await tester.pumpWidget(host());
    await tester.pump();
    expect(find.text(hint_text), findsOneWidget);

    await GestureHintOverlay.mark_performed(GestureHint.long_press_reactions);
    await tester.pump();
    expect(find.text(hint_text), findsNothing);
  });

  testWidgets('any touch dismisses it and still reaches the child', (
    tester,
  ) async {
    final taps = <int>[];
    await tester.pumpWidget(host(taps: taps));
    await tester.pump();
    expect(find.text(hint_text), findsOneWidget);

    await tester.tap(find.byType(GestureDetector));
    await tester.pump();
    expect(find.text(hint_text), findsNothing);
    expect(taps, hasLength(1));
  });

  testWidgets('animated visual is shown when animations are allowed', (
    tester,
  ) async {
    await tester.pumpWidget(host());
    await tester.pump();
    expect(find.byIcon(Icons.circle), findsOneWidget);
    await tester.pump(const Duration(milliseconds: 100));
    expect(tester.hasRunningAnimations, isTrue);
    await tester.pump(const Duration(seconds: 3));
  });

  testWidgets('reduced motion shows a static tooltip with no animation', (
    tester,
  ) async {
    tester.platformDispatcher.accessibilityFeaturesTestValue =
        const FakeAccessibilityFeatures(disableAnimations: true);
    addTearDown(tester.platformDispatcher.clearAccessibilityFeaturesTestValue);

    await tester.pumpWidget(host());
    await tester.pump();
    expect(find.text(hint_text), findsOneWidget);
    // No pulsing dot, and no ticker running.
    expect(find.byIcon(Icons.circle), findsNothing);
    expect(tester.hasRunningAnimations, isFalse);
    await tester.pump(const Duration(seconds: 3));
  });

  group('UiPrefs persistence', () {
    test('flags survive a restart', () async {
      final dir = Directory.systemTemp.createTempSync('ui_prefs_test');
      addTearDown(() => dir.deleteSync(recursive: true));

      final first = UiPrefs(directory: dir);
      await first.set_flag('gesture_hint_seen_swipe_to_reply');

      final second = UiPrefs(directory: dir);
      await second.load();
      expect(second.flag('gesture_hint_seen_swipe_to_reply'), isTrue);
      expect(second.flag('gesture_hint_seen_pinch_to_zoom'), isFalse);
    });

    test('a corrupt file starts clean instead of throwing', () async {
      final dir = Directory.systemTemp.createTempSync('ui_prefs_test');
      addTearDown(() => dir.deleteSync(recursive: true));
      File('${dir.path}/ui_prefs.json').writeAsStringSync('{not json');

      final prefs = UiPrefs(directory: dir);
      await prefs.load();
      expect(prefs.flag('gesture_hint_seen_swipe_to_reply'), isFalse);
    });
  });
}
