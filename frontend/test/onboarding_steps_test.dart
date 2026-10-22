// onboarding_steps_test.dart
//
// §22.42 onboarding step list and forward actions (CMR-020, CMR-021), pumped
// without the native library (BackendBridge.open(allowMissing: true): every
// bridge write returns false), so each test pins a single UI rule:
//
//   1. OnboardingStep *is* the §22.42 list: eight steps in the spec's order,
//      each with the spec's title, and no "N of M" counter anywhere.
//   2. Your identity: Next is disabled while the name is empty and a helper
//      line says why; the keyboard Done key is the same action as Next.
//   3. Public presence: exactly one forward button, labelled "Skip" while the
//      field is empty and "Next" once it has text.
//   4. Disclosures lead to Privacy style; Privacy style pre-selects Everyday,
//      lets the user pick another preset, and reports a failed write instead
//      of moving on.
//   5. PIN: "4 to 16 digits" is always visible under the form, Set PIN stays
//      disabled below the minimum, and Skip is double-confirmed.
//   6. Done: "Add a contact" (primary) and "Go to Chat" (secondary); a failed
//      flag write keeps the user on the step and never calls onComplete.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';

import 'package:mesh_infinity_frontend/app/app_theme.dart';
import 'package:mesh_infinity_frontend/backend/backend_bridge.dart';
import 'package:mesh_infinity_frontend/onboarding/onboarding_screen.dart';

/// Pump the onboarding wizard opened at [step] inside a tall window, so the
/// disclosures list fits and its gate unlocks without scrolling.
///
/// [on_complete] records the exit the Done step reports, if any.
Future<void> pump_onboarding(
  WidgetTester tester, {
  required OnboardingStep step,
  void Function(OnboardingExit exit)? on_complete,
}) async {
  tester.view.physicalSize = const Size(800, 1600);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.reset);

  final bridge = BackendBridge.open(allowMissing: true);
  await tester.pumpWidget(
    Provider<BackendBridge>.value(
      value: bridge,
      child: MaterialApp(
        theme: MeshTheme.light(),
        home: OnboardingScreen(
          initial_step: step,
          onComplete: on_complete ?? (_) {},
        ),
      ),
    ),
  );
  // Settle the AnimatedSwitcher fade and the post-layout metrics microtask.
  await tester.pumpAndSettle();
}

/// The one filled button carrying [label].
FilledButton filled_button(WidgetTester tester, String label) =>
    tester.widget<FilledButton>(find.widgetWithText(FilledButton, label));

/// Title text the spec gives each step (§22.42.1 – §22.42.7).  Welcome has
/// no step header, so its app name stands in for the title.
final Map<OnboardingStep, String> step_titles = {
  OnboardingStep.welcome: 'Mesh Infinity',
  OnboardingStep.importBackup: 'Import Backup',
  OnboardingStep.identity: 'Your identity',
  OnboardingStep.publicProfile: 'Public presence',
  OnboardingStep.disclosures: 'How Mesh Infinity works',
  OnboardingStep.privacyStyle: 'Choose your default privacy style',
  OnboardingStep.pinSetup: 'Protect your messages',
  OnboardingStep.done: "You're set up",
};

void main() {
  group('step list (§22.42, CMR-020)', () {
    test('OnboardingStep is the eight-step spec list, in order', () {
      expect(OnboardingStep.values, [
        OnboardingStep.welcome,
        OnboardingStep.importBackup,
        OnboardingStep.identity,
        OnboardingStep.publicProfile,
        OnboardingStep.disclosures,
        OnboardingStep.privacyStyle,
        OnboardingStep.pinSetup,
        OnboardingStep.done,
      ]);
    });

    for (final entry in step_titles.entries) {
      testWidgets('${entry.key.name} shows its title and no N-of-M counter', (
        tester,
      ) async {
        await pump_onboarding(tester, step: entry.key);
        expect(find.text(entry.value), findsWidgets);
        // The Import branch makes the total move, so no step counts the
        // steps: nothing like "3 of 8" may appear on any screen.
        expect(find.textContaining(RegExp(r'\d+\s+of\s+\d+')), findsNothing);
      });
    }
  });

  group('Your identity forward action (§22.42.3, CMR-021)', () {
    testWidgets('disabled Next says why until a name exists', (tester) async {
      await pump_onboarding(tester, step: OnboardingStep.identity);
      expect(filled_button(tester, 'Next').enabled, isFalse);
      expect(find.text('Add a name to continue'), findsOneWidget);

      await tester.enterText(find.byType(TextField), 'Ann');
      await tester.pumpAndSettle();
      expect(filled_button(tester, 'Next').enabled, isTrue);
      expect(find.text('Add a name to continue'), findsNothing);
    });

    testWidgets('keyboard Done is Next and ignores an empty name', (
      tester,
    ) async {
      await pump_onboarding(tester, step: OnboardingStep.identity);
      // Done with nothing typed: stay put.
      await tester.showKeyboard(find.byType(TextField));
      await tester.testTextInput.receiveAction(TextInputAction.done);
      await tester.pumpAndSettle();
      expect(find.text('Your identity'), findsOneWidget);

      // Done with a name: same destination as the Next button.
      await tester.enterText(find.byType(TextField), 'Ann');
      await tester.testTextInput.receiveAction(TextInputAction.done);
      await tester.pumpAndSettle();
      expect(find.text('Public presence'), findsOneWidget);
    });
  });

  group('Public presence forward action (§22.42.3b, CMR-021)', () {
    testWidgets('one button, labelled Skip then Next', (tester) async {
      await pump_onboarding(tester, step: OnboardingStep.publicProfile);
      // Exactly one way forward, and no separate text Skip button.
      expect(find.byType(FilledButton), findsOneWidget);
      expect(find.widgetWithText(FilledButton, 'Skip'), findsOneWidget);
      expect(find.widgetWithText(TextButton, 'Skip'), findsNothing);

      await tester.enterText(find.byType(TextField), 'ann');
      await tester.pumpAndSettle();
      expect(find.widgetWithText(FilledButton, 'Next'), findsOneWidget);
      expect(find.widgetWithText(FilledButton, 'Skip'), findsNothing);

      // Clearing the field flips the label back: it tells the truth.
      await tester.enterText(find.byType(TextField), '   ');
      await tester.pumpAndSettle();
      expect(find.widgetWithText(FilledButton, 'Skip'), findsOneWidget);
    });
  });

  group('Privacy style (§22.42.4a, §22.27 item 3)', () {
    testWidgets('follows the disclosures', (tester) async {
      await pump_onboarding(tester, step: OnboardingStep.disclosures);
      // The tall window fits the list, so the gate is already open.
      await tester.tap(find.widgetWithText(FilledButton, 'I understand'));
      await tester.pumpAndSettle();
      expect(find.text('Choose your default privacy style'), findsOneWidget);
    });

    testWidgets('offers the three presets with Everyday pre-selected', (
      tester,
    ) async {
      await pump_onboarding(tester, step: OnboardingStep.privacyStyle);
      for (final title in ['Everyday', 'More private', 'Lockdown']) {
        expect(find.text(title), findsOneWidget);
      }
      expect(
        find.text('You can change this any time in Settings → Privacy & Safety.'),
        findsOneWidget,
      );
      RadioGroup<int> group() =>
          tester.widget<RadioGroup<int>>(find.byType(RadioGroup<int>));
      expect(group().groupValue, 0);
      // A preset is always selected, so Next is always enabled.
      expect(filled_button(tester, 'Next').enabled, isTrue);

      await tester.tap(find.text('Lockdown'));
      await tester.pumpAndSettle();
      expect(group().groupValue, 2);
    });

    testWidgets('a failed write keeps the user on the step', (tester) async {
      await pump_onboarding(tester, step: OnboardingStep.privacyStyle);
      // No native library: setThreatContext returns false.
      await tester.tap(find.widgetWithText(FilledButton, 'Next'));
      await tester.pumpAndSettle();
      expect(find.text('Choose your default privacy style'), findsOneWidget);
      expect(find.text("Couldn't save your privacy style."), findsOneWidget);
      expect(find.text('Protect your messages'), findsNothing);
    });
  });

  group('PIN step (§22.42.5, CMR-021)', () {
    testWidgets('shows the length rule and gates Set PIN on it', (
      tester,
    ) async {
      await pump_onboarding(tester, step: OnboardingStep.pinSetup);
      await tester.tap(find.widgetWithText(FilledButton, 'Set a PIN'));
      await tester.pumpAndSettle();
      // The disabled button says why, always, not only on an error.
      expect(find.text('4 to 16 digits'), findsOneWidget);
      expect(filled_button(tester, 'Set PIN').enabled, isFalse);

      final fields = find.byType(TextField);
      await tester.enterText(fields.at(0), '1234');
      await tester.enterText(fields.at(1), '1234');
      await tester.pumpAndSettle();
      expect(filled_button(tester, 'Set PIN').enabled, isTrue);
      expect(find.text('4 to 16 digits'), findsOneWidget);
    });

    testWidgets('Skip is double-confirmed before reaching Done', (
      tester,
    ) async {
      await pump_onboarding(tester, step: OnboardingStep.pinSetup);
      await tester.tap(find.text('Skip for now'));
      await tester.pumpAndSettle();
      // First tap only opens the warning; the user is still on the PIN step.
      expect(find.text('Protect your messages'), findsOneWidget);
      expect(find.text('Continue without PIN'), findsOneWidget);

      await tester.tap(find.text('Continue without PIN'));
      await tester.pumpAndSettle();
      expect(find.text("You're set up"), findsOneWidget);
    });
  });

  group('Done step (§22.42.7, CMR-020)', () {
    testWidgets('offers Add a contact and Go to Chat', (tester) async {
      await pump_onboarding(tester, step: OnboardingStep.done);
      expect(find.widgetWithText(FilledButton, 'Add a contact'), findsOneWidget);
      expect(find.widgetWithText(TextButton, 'Go to Chat'), findsOneWidget);
      expect(
        find.text(
          'Mesh Infinity is ready. Nothing works until you have someone to '
          'talk to.',
        ),
        findsOneWidget,
      );
    });

    testWidgets('a failed flag write stays put and never completes', (
      tester,
    ) async {
      final exits = <OnboardingExit>[];
      await pump_onboarding(
        tester,
        step: OnboardingStep.done,
        on_complete: exits.add,
      );
      // No native library: setOnboardingComplete returns false, so the
      // flag and the shell transition cannot diverge.
      await tester.tap(find.widgetWithText(FilledButton, 'Add a contact'));
      await tester.pumpAndSettle();
      expect(find.text("Couldn't finish setup. Try again."), findsOneWidget);
      expect(exits, isEmpty);

      await tester.tap(find.widgetWithText(TextButton, 'Go to Chat'));
      await tester.pumpAndSettle();
      expect(find.text("You're set up"), findsOneWidget);
      expect(exits, isEmpty);
    });
  });
}
