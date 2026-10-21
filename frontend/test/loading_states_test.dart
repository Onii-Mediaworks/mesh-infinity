// loading_states_test.dart
//
// SPEC §22.49-§22.51: list screens show shimmer tiles while a load is in
// flight, the inline ErrorBanner after a failed load, and the EmptyState
// only after a successful load that found nothing.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';

import 'package:mesh_infinity_frontend/app/app_theme.dart';
import 'package:mesh_infinity_frontend/backend/backend_bridge.dart';
import 'package:mesh_infinity_frontend/core/widgets/empty_state.dart';
import 'package:mesh_infinity_frontend/core/widgets/error_banner.dart';
import 'package:mesh_infinity_frontend/core/widgets/load_gate.dart';
import 'package:mesh_infinity_frontend/core/widgets/shimmer.dart';
import 'package:mesh_infinity_frontend/features/messaging/messaging_state.dart';
import 'package:mesh_infinity_frontend/features/messaging/screens/conversation_list_screen.dart';
import 'package:mesh_infinity_frontend/shell/shell_state.dart';

/// MessagingState whose load status is set by the test.
class _StatusMessaging extends MessagingState {
  _StatusMessaging(super.bridge);

  bool loading = false;
  String? error;

  @override
  bool get loading_rooms => loading;

  @override
  String? get rooms_error => error;

  /// Re-run listeners after the test changes [loading] / [error].
  void changed() => notifyListeners();
}

/// A LoadGate with recognisable content for the precedence tests.
Widget gate({
  bool loading = false,
  String? error,
  bool is_empty = true,
  VoidCallback? on_retry,
}) {
  return MaterialApp(
    theme: MeshTheme.light(),
    home: Scaffold(
      body: LoadGate(
        loading: loading,
        error: error,
        is_empty: is_empty,
        shimmer_count: 6,
        shimmer_height: 72,
        on_retry: on_retry,
        empty: const EmptyState(icon: Icons.inbox, title: 'Empty', body: 'b'),
        child: const Text('content'),
      ),
    ),
  );
}

void main() {
  group('LoadGate', () {
    testWidgets('shows shimmer, never EmptyState, while loading', (
      tester,
    ) async {
      await tester.pumpWidget(gate(loading: true));
      expect(find.byType(ShimmerList), findsOneWidget);
      // 6 tiles of 72 px fit in the 600 px test window.
      expect(find.byType(Shimmer), findsNWidgets(6));
      expect(find.byType(EmptyState), findsNothing);
      expect(find.byType(ErrorBanner), findsNothing);
    });

    testWidgets('loading wins over a stale error', (tester) async {
      await tester.pumpWidget(gate(loading: true, error: 'old failure'));
      expect(find.byType(ShimmerList), findsOneWidget);
      expect(find.byType(EmptyState), findsNothing);
    });

    testWidgets('failed load shows ErrorBanner, never EmptyState', (
      tester,
    ) async {
      await tester.pumpWidget(gate(error: 'Could not load'));
      expect(find.byType(ErrorBanner), findsOneWidget);
      expect(find.text('Could not load'), findsOneWidget);
      expect(find.byType(EmptyState), findsNothing);
      expect(find.byType(Shimmer), findsNothing);
      // No retry callback means no Retry button (pull-to-refresh retries).
      expect(find.text('Retry'), findsNothing);
    });

    testWidgets('retry button appears when a callback is given', (
      tester,
    ) async {
      var retried = 0;
      await tester.pumpWidget(gate(error: 'x', on_retry: () => retried++));
      await tester.tap(find.text('Retry'));
      expect(retried, 1);
    });

    testWidgets('successful empty load shows EmptyState only', (tester) async {
      await tester.pumpWidget(gate());
      expect(find.byType(EmptyState), findsOneWidget);
      expect(find.byType(Shimmer), findsNothing);
      expect(find.byType(ErrorBanner), findsNothing);
    });

    testWidgets('rows are kept visible when a refresh fails', (tester) async {
      await tester.pumpWidget(gate(error: 'refresh failed', is_empty: false));
      expect(find.text('content'), findsOneWidget);
      expect(find.text('refresh failed'), findsOneWidget);
      expect(find.byType(EmptyState), findsNothing);
    });
  });

  group('ConversationListScreen', () {
    Future<_StatusMessaging> pump_list(WidgetTester tester) async {
      final bridge = BackendBridge.open(allowMissing: true);
      final messaging = _StatusMessaging(bridge);
      addTearDown(messaging.dispose);
      await tester.pumpWidget(
        MultiProvider(
          providers: [
            ChangeNotifierProvider<MessagingState>.value(value: messaging),
            ChangeNotifierProvider(create: (_) => ShellState()),
          ],
          child: MaterialApp(
            theme: MeshTheme.light(),
            home: const ConversationListScreen(),
          ),
        ),
      );
      await tester.pump();
      return messaging;
    }

    testWidgets('shimmer then empty state, never both', (tester) async {
      final messaging = await pump_list(tester);

      // Loaded and empty: the EmptyState shows.
      expect(find.text('No conversations yet'), findsOneWidget);
      expect(find.byType(Shimmer), findsNothing);

      // A load starts: shimmer replaces the empty state immediately.
      messaging.loading = true;
      messaging.changed();
      await tester.pump();
      expect(find.byType(Shimmer), findsNWidgets(6));
      expect(find.text('No conversations yet'), findsNothing);

      // The load fails: ErrorBanner, still no empty state.
      messaging.loading = false;
      messaging.error = "Couldn't load conversations. Pull down to retry.";
      messaging.changed();
      await tester.pump();
      expect(find.byType(ErrorBanner), findsOneWidget);
      expect(find.byType(Shimmer), findsNothing);
      expect(find.text('No conversations yet'), findsNothing);

      // The next load succeeds with nothing: now the empty state is true.
      messaging.error = null;
      messaging.changed();
      await tester.pump();
      expect(find.text('No conversations yet'), findsOneWidget);
      expect(find.byType(ErrorBanner), findsNothing);
    });
  });

  group('MessagingState', () {
    test('a successful load leaves no loading flag and no error', () async {
      final state = MessagingState(BackendBridge.open(allowMissing: true));
      await state.loadRooms();
      await state.loadRequests();
      expect(state.loading_rooms, isFalse);
      expect(state.rooms_error, isNull);
      expect(state.loading_requests, isFalse);
      expect(state.requests_error, isNull);
      state.dispose();
    });
  });
}
