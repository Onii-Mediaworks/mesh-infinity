// contact_detail_trust_test.dart
//
// §22.8.2 / §22.31 ContactDetailScreen rules, pumped without the native
// library.  PeersState and SettingsState are subclassed so the screen sees
// one contact and a local identity, and so every attestation or block call
// is recorded instead of reaching the (absent) backend:
//
//   1. A trust change across the Acquaintance/Trusted boundary — either way —
//      shows the §22.31 confirmation and attests nothing until confirmed.
//   2. A change on one side of the boundary attests at once.
//   3. More-vert "Remove contact" opens the removal confirmation.
//   4. More-vert "Block contact" confirms, then blocks through PeersState.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';

import 'package:mesh_infinity_frontend/app/app_theme.dart';
import 'package:mesh_infinity_frontend/backend/backend_bridge.dart';
import 'package:mesh_infinity_frontend/backend/models/peer_models.dart';
import 'package:mesh_infinity_frontend/backend/models/settings_models.dart';
import 'package:mesh_infinity_frontend/features/contacts/screens/contact_detail_screen.dart';
import 'package:mesh_infinity_frontend/features/peers/peers_state.dart';
import 'package:mesh_infinity_frontend/features/settings/settings_state.dart';

/// PeersState holding exactly one contact and recording every mutation.
class _FakePeers extends PeersState {
  _FakePeers(super.bridge, this.peer);

  /// The one contact the screen shows.
  final PeerModel peer;

  /// Trust levels attested, in order.
  final attested = <int>[];

  /// Block flags written, in order.
  final blocked_calls = <bool>[];

  @override
  List<PeerModel> get peers => [peer];

  @override
  PeerModel? findPeer(String peerId) => peerId == peer.id ? peer : null;

  @override
  Future<bool> attestTrust({
    required String localPeerId,
    required String targetPeerId,
    required int trustLevel,
  }) async {
    attested.add(trustLevel);
    return true;
  }

  @override
  Future<bool> setPeerBlocked(String peerId, {required bool blocked}) async {
    blocked_calls.add(blocked);
    return true;
  }
}

/// SettingsState with a local peer ID, so attestations have a signer.
class _FakeSettings extends SettingsState {
  _FakeSettings(super.bridge);

  @override
  SettingsModel? get settings => const SettingsModel(localPeerId: 'me');
}

/// Pump the contact screen for [peer].
///
/// The window is tall enough for the nine-row trust sheet, which is not
/// itself scrollable and would overflow a phone-height test window.
Future<_FakePeers> _pump_contact(WidgetTester tester, PeerModel peer) async {
  tester.view.physicalSize = const Size(400, 1400);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.reset);

  final bridge = BackendBridge.open(allowMissing: true);
  final peers = _FakePeers(bridge, peer);
  await tester.pumpWidget(
    MultiProvider(
      providers: [
        Provider<BackendBridge>.value(value: bridge),
        ChangeNotifierProvider<PeersState>.value(value: peers),
        ChangeNotifierProvider<SettingsState>.value(
          value: _FakeSettings(bridge),
        ),
      ],
      child: MaterialApp(
        theme: MeshTheme.light(),
        home: const ContactDetailScreen(peerId: 'p1'),
      ),
    ),
  );
  await tester.pumpAndSettle();
  return peers;
}

/// Pump the screen for a contact "Alice" at [level], not blocked.
Future<_FakePeers> _pump_alice(WidgetTester tester, TrustLevel level) =>
    _pump_contact(
      tester,
      PeerModel(id: 'p1', name: 'Alice', trustLevel: level),
    );

/// Open the trust sheet and tap the tile labelled [label].
Future<void> pick_trust(WidgetTester tester, String label) async {
  await tester.tap(find.text('Set Trust Level'));
  await tester.pumpAndSettle();
  await tester.tap(find.text(label));
  await tester.pumpAndSettle();
}

/// Open the AppBar more-vert sheet and tap the row labelled [label].
Future<void> pick_more(WidgetTester tester, String label) async {
  await tester.tap(find.byIcon(Icons.more_vert));
  await tester.pumpAndSettle();
  await tester.tap(find.text(label));
  await tester.pumpAndSettle();
}

void main() {
  group('trust boundary confirmation (§22.31)', () {
    testWidgets('5 → 6 shows the promote dialog and attests only on confirm', (
      tester,
    ) async {
      final peers = await _pump_alice(tester, TrustLevel.acquaintance);
      await pick_trust(tester, 'Trusted');

      // The §22.31 promote text, with the contact's name, and nothing sent.
      expect(find.text('Share your identity with Alice?'), findsOneWidget);
      expect(peers.attested, isEmpty);

      await tester.tap(find.text('Trust Alice'));
      await tester.pumpAndSettle();
      expect(peers.attested, [TrustLevel.trusted.value]);
      expect(find.text('Share your identity with Alice?'), findsNothing);
    });

    testWidgets('6 → 5 shows the demote dialog and Cancel sends nothing', (
      tester,
    ) async {
      final peers = await _pump_alice(tester, TrustLevel.trusted);
      await pick_trust(tester, 'Acquaintance');

      expect(find.text('Remove trust from Alice?'), findsOneWidget);
      expect(peers.attested, isEmpty);

      await tester.tap(find.text('Cancel'));
      await tester.pumpAndSettle();
      expect(peers.attested, isEmpty);
      expect(find.text('Remove trust from Alice?'), findsNothing);
    });

    testWidgets('a same-tier change attests at once', (tester) async {
      final peers = await _pump_alice(tester, TrustLevel.acquaintance);
      await pick_trust(tester, 'Ally');
      expect(peers.attested, [TrustLevel.ally.value]);
      expect(find.byType(AlertDialog), findsNothing);
    });
  });

  group('more-vert menu (§22.8.2)', () {
    testWidgets('"Remove contact" opens the removal confirmation', (
      tester,
    ) async {
      final peers = await _pump_alice(tester, TrustLevel.acquaintance);
      await pick_more(tester, 'Remove contact');
      expect(find.text('Remove Contact?'), findsOneWidget);
      // Nothing is removed until the dialog's Remove is pressed.
      expect(peers.attested, isEmpty);
    });

    testWidgets('"Block contact" confirms, then blocks', (tester) async {
      final peers = await _pump_alice(tester, TrustLevel.acquaintance);
      await pick_more(tester, 'Block contact');
      expect(find.text('Block Alice?'), findsOneWidget);
      expect(peers.blocked_calls, isEmpty);

      await tester.tap(find.widgetWithText(FilledButton, 'Block'));
      await tester.pumpAndSettle();
      expect(peers.blocked_calls, [true]);
    });

    testWidgets('a blocked contact is offered "Unblock contact"', (
      tester,
    ) async {
      final peers = await _pump_contact(
        tester,
        const PeerModel(
          id: 'p1',
          name: 'Alice',
          trustLevel: TrustLevel.acquaintance,
          blocked: true,
        ),
      );
      // The header says so, and the menu offers the reverse action.
      expect(find.text('Blocked'), findsOneWidget);
      await pick_more(tester, 'Unblock contact');
      expect(peers.blocked_calls, [false]);
    });
  });
}
