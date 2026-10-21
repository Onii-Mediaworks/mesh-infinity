// pin_and_mask_intro_test.dart
//
// CMR-023: wrong-PIN feedback is text + icon kept until the next key press,
// and "N tries left" appears only for the last two attempts with wrong-PIN
// wipe armed.  CMR-024: the "What's a mask?" card shows once and stays
// re-readable from Help.
//
// The Rust library is absent on the test host, so BackendBridge.open
// (allowMissing: true) makes every unlock attempt fail, which is exactly the
// wrong-PIN path under test.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';

import 'package:mesh_infinity_frontend/app/ui_prefs.dart';
import 'package:mesh_infinity_frontend/backend/backend_bridge.dart';
import 'package:mesh_infinity_frontend/features/settings/screens/pin_screen.dart';
import 'package:mesh_infinity_frontend/features/settings/settings_state.dart';
import 'package:mesh_infinity_frontend/features/you/mask_intro_card.dart';
import 'package:mesh_infinity_frontend/shell/help_screen.dart';

/// SettingsState whose wrong-PIN wipe is armed at [threshold] attempts.
class _Armed extends SettingsState {
  _Armed(super.bridge, this.threshold);

  final int threshold;

  @override
  bool get wrongPinWipeEnabled => true;

  @override
  int get wrongPinWipeThreshold => threshold;
}

/// Pump the unlock screen with [settings] as the SettingsState.
Future<void> pump_pin(
  WidgetTester tester,
  SettingsState Function(BackendBridge) settings,
) async {
  final bridge = BackendBridge.open(allowMissing: true);
  await tester.pumpWidget(
    MultiProvider(
      providers: [
        Provider<BackendBridge>.value(value: bridge),
        ChangeNotifierProvider<SettingsState>(create: (_) => settings(bridge)),
      ],
      child: const MaterialApp(home: PinScreen(mode: PinScreenMode.unlock)),
    ),
  );
}

/// Types a 4-digit PIN and submits it with the keyboard action.
Future<void> enter_wrong_pin(WidgetTester tester) async {
  await tester.enterText(find.byType(TextField), '1234');
  await tester.pump();
  await tester.tap(find.byType(FilledButton));
  await tester.pump();
}

void main() {
  group('wrong PIN feedback', () {
    testWidgets('shows text and icon until the next key press', (tester) async {
      await pump_pin(tester, SettingsState.new);
      expect(find.text('Wrong PIN'), findsNothing);

      await enter_wrong_pin(tester);
      expect(find.text('Wrong PIN'), findsOneWidget);
      expect(find.byIcon(Icons.error_outline), findsOneWidget);

      // Well past the old 400 ms flash: still there.
      await tester.pump(const Duration(seconds: 2));
      expect(find.text('Wrong PIN'), findsOneWidget);

      // The next key press clears it.
      await tester.enterText(find.byType(TextField), '1');
      await tester.pump();
      expect(find.text('Wrong PIN'), findsNothing);
    });

    testWidgets('tries left shows only on the last two armed attempts', (
      tester,
    ) async {
      await pump_pin(tester, (b) => _Armed(b, 4));
      const tries = 'before this device erases';

      // Attempt 1 of 4: three left, no warning.
      await enter_wrong_pin(tester);
      expect(find.textContaining(tries), findsNothing);

      // Attempt 2: two left.
      await enter_wrong_pin(tester);
      expect(find.text('2 tries left $tries'), findsOneWidget);

      // Attempt 3: one left, singular.
      await enter_wrong_pin(tester);
      expect(find.text('1 try left $tries'), findsOneWidget);
    });

    testWidgets('no count is ever shown when the wipe is not armed', (
      tester,
    ) async {
      await pump_pin(tester, SettingsState.new);
      for (var i = 0; i < 3; i++) {
        await enter_wrong_pin(tester);
      }
      expect(find.textContaining('tries left'), findsNothing);
      expect(find.textContaining('try left'), findsNothing);
    });

    testWidgets('lockout countdown appears from the sixth failure', (
      tester,
    ) async {
      await pump_pin(tester, SettingsState.new);
      for (var i = 0; i < 6; i++) {
        await enter_wrong_pin(tester);
      }
      expect(find.textContaining('Try again in 0:30'), findsOneWidget);
      // Submit is disabled during the wait.
      await tester.enterText(find.byType(TextField), '1234');
      await tester.pump();
      expect(
        tester.widget<FilledButton>(find.byType(FilledButton)).onPressed,
        isNull,
      );
    });

    test('backoff schedule matches the backend', () {
      expect(pin_backoff_secs(5), 0);
      expect(pin_backoff_secs(6), 30);
      expect(pin_backoff_secs(7), 120);
      expect(pin_backoff_secs(11), 259200);
      expect(format_wait(30), '0:30');
      expect(format_wait(3600), '1:00:00');
    });
  });

  group('mask intro card', () {
    setUp(() => UiPrefs.instance = UiPrefs());

    Widget host(Widget child) => MaterialApp(home: Scaffold(body: child));

    testWidgets('shows once and stays dismissed', (tester) async {
      await tester.pumpWidget(host(const MaskIntroGate()));
      await tester.pump();
      expect(find.text(mask_intro_title), findsOneWidget);

      await tester.tap(find.text('Got it'));
      await tester.pump();
      expect(find.text(mask_intro_title), findsNothing);
      expect(UiPrefs.instance.flag(mask_intro_flag), isTrue);

      // A second surface (sheet after You) opens without the card.
      await tester.pumpWidget(host(const MaskIntroGate()));
      await tester.pump();
      expect(find.text(mask_intro_title), findsNothing);
    });

    testWidgets('re-opens from Help after dismissal', (tester) async {
      await UiPrefs.instance.set_flag(mask_intro_flag);
      await tester.pumpWidget(const MaterialApp(home: HelpScreen()));

      await tester.tap(find.text(mask_intro_title));
      await tester.pumpAndSettle();
      expect(find.text(mask_intro_body), findsOneWidget);
      // Read-only copy: no dismiss button.
      expect(find.text('Got it'), findsNothing);
    });
  });
}
