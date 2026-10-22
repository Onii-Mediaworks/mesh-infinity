// onboarding_resume_test.dart
//
// §22.42 onboarding gates, pumped without the native library
// (BackendBridge.open(allowMissing: true): every bridge call returns empty
// data), so each test pins a single rule:
//
//   1. resolve_startup_screen(): an unlocked identity without the persisted
//      onboarding_complete flag resumes onboarding; with it, opens the shell;
//      a locked identity reaches the unlock screens first.
//   2. OnboardingScreen resumed at the identity step shows "Your identity"
//      and never offers to create a second identity; system Back steps
//      backwards inside the flow (PopScope) rather than leaving it.
//   3. The disclosures "I understand" gate unlocks without scrolling when
//      the list already fits its box, and the scroll hint is hidden; on a
//      short window the gate stays locked until the list is scrolled to the
//      bottom.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';

import 'package:mesh_infinity_frontend/app/app.dart';
import 'package:mesh_infinity_frontend/app/app_theme.dart';
import 'package:mesh_infinity_frontend/backend/backend_bridge.dart';
import 'package:mesh_infinity_frontend/onboarding/onboarding_screen.dart';

/// Pump the onboarding wizard opened at [step] inside a window of [size].
Future<void> pump_onboarding(
  WidgetTester tester, {
  required OnboardingStep step,
  Size size = const Size(400, 800),
}) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.reset);

  final bridge = BackendBridge.open(allowMissing: true);
  await tester.pumpWidget(
    Provider<BackendBridge>.value(
      value: bridge,
      child: MaterialApp(
        theme: MeshTheme.light(),
        home: OnboardingScreen(initial_step: step, onComplete: (_) {}),
      ),
    ),
  );
  // Settle the AnimatedSwitcher fade and the post-layout metrics microtask.
  await tester.pumpAndSettle();
}

/// Simulate the system Back gesture: Navigator.maybePop() consults the
/// route's PopScope exactly as the hardware button and predictive back do.
Future<void> press_back(WidgetTester tester) async {
  await tester.state<NavigatorState>(find.byType(Navigator)).maybePop();
  await tester.pumpAndSettle();
}

/// The "I understand" button of the disclosures step.
FilledButton understand_button(WidgetTester tester) => tester
    .widget<FilledButton>(find.widgetWithText(FilledButton, 'I understand'));

/// Opacity of the "Scroll to read all" hint (0 = hidden, 1 = shown).
double hint_opacity(WidgetTester tester) => tester
    .widget<AnimatedOpacity>(
      find.ancestor(
        of: find.text('Scroll to read all'),
        matching: find.byType(AnimatedOpacity),
      ),
    )
    .opacity;

void main() {
  group('resolve_startup_screen', () {
    test('identity present and flag unset resumes onboarding', () {
      expect(
        resolve_startup_screen(
          has_identity: true,
          unlocked: true,
          pin_enabled: false,
          onboarding_complete: false,
        ),
        StartupScreen.resume,
      );
    });

    test('identity present and flag set opens the shell', () {
      expect(
        resolve_startup_screen(
          has_identity: true,
          unlocked: true,
          pin_enabled: true,
          onboarding_complete: true,
        ),
        StartupScreen.shell,
      );
    });

    test('no identity starts onboarding from Welcome', () {
      expect(
        resolve_startup_screen(
          has_identity: false,
          unlocked: false,
          pin_enabled: false,
          onboarding_complete: false,
        ),
        StartupScreen.onboarding,
      );
    });

    test('locked identity unlocks before the onboarding flag is consulted', () {
      // The flag reads false while locked, so a locked identity must never
      // be routed to a resumed onboarding that would fail every write.
      expect(
        resolve_startup_screen(
          has_identity: true,
          unlocked: false,
          pin_enabled: true,
          onboarding_complete: false,
        ),
        StartupScreen.pin,
      );
      expect(
        resolve_startup_screen(
          has_identity: true,
          unlocked: false,
          pin_enabled: false,
          onboarding_complete: false,
        ),
        StartupScreen.locked,
      );
    });
  });

  group('OnboardingScreen resume', () {
    testWidgets('opens on the identity step, not Welcome', (tester) async {
      await pump_onboarding(tester, step: OnboardingStep.identity);
      expect(find.text('Your identity'), findsOneWidget);
      // A second identity must not be creatable from a resumed run.
      expect(find.text('Create new identity'), findsNothing);
      expect(find.text('Import from backup'), findsNothing);
    });

    testWidgets('system Back steps backwards inside the flow', (tester) async {
      await pump_onboarding(tester, step: OnboardingStep.identity);
      // Identity → Public presence needs a name (Next is disabled otherwise).
      await tester.enterText(find.byType(TextField), 'Ann');
      await tester.pumpAndSettle();
      await tester.tap(find.widgetWithText(FilledButton, 'Next'));
      await tester.pumpAndSettle();
      expect(find.text('Public presence'), findsOneWidget);

      // Back returns to the identity step rather than leaving onboarding.
      await press_back(tester);
      expect(find.text('Your identity'), findsOneWidget);
      expect(find.text('Public presence'), findsNothing);

      // Back on the identity step stays put: there is nothing safe before it.
      await press_back(tester);
      expect(find.text('Your identity'), findsOneWidget);
      expect(find.byType(OnboardingScreen), findsOneWidget);
    });
  });

  group('disclosures gate', () {
    testWidgets('unlocks without scrolling when the list fits', (tester) async {
      await pump_onboarding(
        tester,
        step: OnboardingStep.disclosures,
        size: const Size(800, 1600),
      );
      expect(understand_button(tester).enabled, isTrue);
      // No scroll is possible, so no scroll is asked for.
      expect(hint_opacity(tester), 0.0);
    });

    testWidgets('stays locked on a short window until scrolled', (
      tester,
    ) async {
      await pump_onboarding(
        tester,
        step: OnboardingStep.disclosures,
        size: const Size(400, 600),
      );
      expect(understand_button(tester).enabled, isFalse);
      expect(hint_opacity(tester), 1.0);

      // Scroll the disclosure list to its end.
      await tester.drag(find.byType(ListView), const Offset(0, -2000));
      await tester.pumpAndSettle();
      expect(understand_button(tester).enabled, isTrue);
      expect(hint_opacity(tester), 0.0);
    });
  });
}
