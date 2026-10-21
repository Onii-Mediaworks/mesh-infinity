// keyboard_navigation_test.dart
//
// §22.36 rule 9: every top-level screen is driven by key events only — no
// taps — and every interactive widget is reachable from the primary focus.
//
// The real Rust library is not on the test host, so the shell is pumped with
// BackendBridge.open(allowMissing: true): every bridge call returns empty
// data and the screens render their empty states.  Where a list row is
// needed (Chat → Direct), a MessagingState subclass overrides `rooms`.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';

import 'package:mesh_infinity_frontend/app/app_theme.dart';
import 'package:mesh_infinity_frontend/backend/backend_bridge.dart';
import 'package:mesh_infinity_frontend/backend/models/room_models.dart';
import 'package:mesh_infinity_frontend/features/calls/calls_state.dart';
import 'package:mesh_infinity_frontend/features/files/files_state.dart';
import 'package:mesh_infinity_frontend/features/messaging/messaging_state.dart';
import 'package:mesh_infinity_frontend/features/messaging/screens/create_room_screen.dart';
import 'package:mesh_infinity_frontend/features/messaging/screens/thread_screen.dart';
import 'package:mesh_infinity_frontend/features/messaging/widgets/thread_list_tile.dart';
import 'package:mesh_infinity_frontend/features/network/network_state.dart';
import 'package:mesh_infinity_frontend/features/peers/peers_state.dart';
import 'package:mesh_infinity_frontend/features/services/services_state.dart';
import 'package:mesh_infinity_frontend/features/settings/screens/notification_screen.dart';
import 'package:mesh_infinity_frontend/features/settings/settings_state.dart';
import 'package:mesh_infinity_frontend/features/tailscale/tailscale_state.dart';
import 'package:mesh_infinity_frontend/features/zerotier/zerotier_state.dart';
import 'package:mesh_infinity_frontend/shell/app_shell.dart';
import 'package:mesh_infinity_frontend/shell/badge_state.dart';
import 'package:mesh_infinity_frontend/shell/input_map.dart';
import 'package:mesh_infinity_frontend/shell/security_status_bar.dart';
import 'package:mesh_infinity_frontend/shell/shell_state.dart';

/// MessagingState with two direct rooms, so the Chat lists have rows.
class _FakeMessaging extends MessagingState {
  _FakeMessaging(super.bridge);

  @override
  List<RoomSummary> get rooms => const [
    RoomSummary(id: 'room-a', name: 'Alice', lastMessage: 'hi'),
    RoomSummary(id: 'room-b', name: 'Bob', lastMessage: 'yo'),
  ];
}

/// Pump the shell (or [home]) with the same provider tree app.dart builds,
/// the §22.36 input scope, and a phone-sized window.
Future<ShellState> pump_shell(WidgetTester tester, {Widget? home}) async {
  tester.view.physicalSize = const Size(400, 800);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.reset);

  final bridge = BackendBridge.open(allowMissing: true);
  final shell = ShellState();
  await tester.pumpWidget(
    MultiProvider(
      providers: [
        Provider<BackendBridge>.value(value: bridge),
        ChangeNotifierProvider<ShellState>.value(value: shell),
        ChangeNotifierProvider(create: (_) => BadgeState()),
        ChangeNotifierProvider<MessagingState>(
          create: (_) => _FakeMessaging(bridge),
        ),
        ChangeNotifierProvider(create: (_) => PeersState(bridge)),
        ChangeNotifierProvider(create: (_) => FilesState(bridge)),
        ChangeNotifierProvider(create: (_) => NetworkState(bridge)),
        ChangeNotifierProvider(create: (_) => SettingsState(bridge)),
        ChangeNotifierProvider(create: (_) => ServicesState(bridge)),
        ChangeNotifierProvider(create: (_) => CallsState(bridge)),
        ChangeNotifierProvider(create: (_) => TailscaleState(bridge)),
        ChangeNotifierProvider(create: (_) => ZeroTierState(bridge)),
        ChangeNotifierProvider(create: (_) => SecurityState()),
      ],
      child: MaterialApp(
        theme: MeshTheme.light(),
        builder: (context, child) => ShellInputScope(child: child!),
        home: home ?? const AppShell(),
      ),
    ),
  );
  await tester.pump();
  return shell;
}

/// Press and release [key], then settle the frame.
Future<void> press(WidgetTester tester, LogicalKeyboardKey key) async {
  await tester.sendKeyEvent(key);
  await tester.pumpAndSettle();
}

/// True when the focused control contains [text].
bool focused_shows(String text) {
  final ctx = primaryFocus?.context;
  if (ctx == null) return false;
  return find
      .descendant(
        of: find.byElementPredicate((e) => identical(e, ctx)),
        matching: find.text(text),
      )
      .evaluate()
      .isNotEmpty;
}

/// A stable name for a focusable control: its text, else its tooltip, else
/// its widget type.
///
/// Lazy lists dispose and recreate rows (and their FocusNodes) as they
/// scroll, so node identity cannot say whether a *control* was visited;
/// its label can.
String label(FocusNode node) {
  final ctx = node.context;
  if (ctx == null) return node.toStringShort();
  final texts = find
      .descendant(
        of: find.byElementPredicate((e) => identical(e, ctx)),
        matching: find.byType(Text),
      )
      .evaluate()
      .map((e) => (e.widget as Text).data)
      .whereType<String>();
  if (texts.isNotEmpty) return texts.first;
  final tooltip = ctx.findAncestorWidgetOfExactType<Tooltip>()?.message;
  return tooltip ?? ctx.widget.runtimeType.toString();
}

/// Labels of every attached, traversable control in the tree right now.
///
/// Scopes (view, navigator, route) are containers, not controls, so they
/// are excluded: Tab never stops on them.
Set<String> focusables() => FocusManager.instance.rootScope.descendants
    .where(
      (n) =>
          n is! FocusScopeNode &&
          n.canRequestFocus &&
          !n.skipTraversal &&
          n.context != null,
    )
    .map(label)
    .toSet();

/// Walk Tab (or Shift+Tab) from the current focus until a control repeats;
/// return the labels seen.  Bounded by a cap in case a list never cycles.
Future<Set<String>> tab_cycle(
  WidgetTester tester, {
  bool backward = false,
}) async {
  final seen = <String>{};
  for (var i = 0; i < 200; i++) {
    final node = primaryFocus;
    if (node == null || !seen.add(label(node))) break;
    if (backward) await tester.sendKeyDownEvent(LogicalKeyboardKey.shiftLeft);
    await tester.sendKeyEvent(LogicalKeyboardKey.tab);
    if (backward) await tester.sendKeyUpEvent(LogicalKeyboardKey.shiftLeft);
    await tester.pumpAndSettle();
  }
  return seen;
}

void main() {
  testWidgets('Chat: first arrow lands on primary, Enter opens, Escape backs', (
    tester,
  ) async {
    await pump_shell(tester);
    // Rooms sub-page with no group rooms shows the "Create a room" button as
    // its primary action (rule 2).  The first arrow press claims it.
    await press(tester, LogicalKeyboardKey.arrowDown);
    expect(focused_shows('Create a room'), isTrue);

    // Enter activates it exactly like a tap: the create-room route opens.
    await press(tester, LogicalKeyboardKey.enter);
    expect(find.byType(CreateRoomScreen), findsOneWidget);

    // Escape goes through the shell back handler and pops it (rule 7).
    // The create screen autofocuses its name field, so the first Escape
    // leaves the field (rule 6) and the second leaves the screen.
    await press(tester, LogicalKeyboardKey.escape);
    await press(tester, LogicalKeyboardKey.escape);
    expect(find.byType(CreateRoomScreen), findsNothing);
    expect(find.text('Create a room'), findsOneWidget);
  });

  testWidgets('Direct list: row focus, Enter opens thread, Escape returns', (
    tester,
  ) async {
    final shell = await pump_shell(tester);
    shell.selectSubPage(ChatSubPage.direct.index);
    await tester.pumpAndSettle();
    expect(find.text('Alice'), findsOneWidget);

    await press(tester, LogicalKeyboardKey.arrowDown);
    expect(focused_shows('Alice'), isTrue);

    // Second arrow moves relatively, not back to the primary.
    await press(tester, LogicalKeyboardKey.arrowDown);
    expect(focused_shows('Bob'), isTrue);

    await press(tester, LogicalKeyboardKey.enter);
    expect(find.byType(ThreadScreen), findsOneWidget);
    // On open with a keyboard in use, the composer is the thread's primary.
    expect(
      primaryFocus?.context?.findAncestorStateOfType<EditableTextState>(),
      isNotNull,
    );

    // Escape leaves the field first, then the thread (rules 6 and 7).
    await press(tester, LogicalKeyboardKey.escape);
    expect(find.byType(ThreadScreen), findsOneWidget);
    await press(tester, LogicalKeyboardKey.escape);
    expect(find.byType(ThreadScreen), findsNothing);
    expect(find.text('Bob'), findsOneWidget);
  });

  testWidgets('Settings: primary row, Enter opens page, Escape returns', (
    tester,
  ) async {
    final shell = await pump_shell(tester);
    shell.selectSection(AppSection.settings);
    await tester.pumpAndSettle();

    await press(tester, LogicalKeyboardKey.arrowDown);
    expect(focused_shows('Push notifications'), isTrue);

    await press(tester, LogicalKeyboardKey.enter);
    expect(find.byType(NotificationScreen), findsOneWidget);

    await press(tester, LogicalKeyboardKey.escape);
    expect(find.byType(NotificationScreen), findsNothing);
    expect(find.text('Push notifications'), findsOneWidget);
  });

  testWidgets('Gamepad: face buttons follow the confirm swap setting', (
    tester,
  ) async {
    final shell = await pump_shell(tester);
    await press(tester, LogicalKeyboardKey.arrowDown);
    expect(focused_shows('Create a room'), isTrue);

    // Xbox layout: A confirms.
    await press(tester, LogicalKeyboardKey.gameButtonA);
    expect(find.byType(CreateRoomScreen), findsOneWidget);
    // B cancels: field first, then the route.
    await press(tester, LogicalKeyboardKey.gameButtonB);
    await press(tester, LogicalKeyboardKey.gameButtonB);
    expect(find.byType(CreateRoomScreen), findsNothing);

    // Swapped layout: B confirms, A cancels — resolved in the one table.
    // Popping the route restored focus to the button, so no arrow is needed.
    shell.confirm_swap.value = true;
    await tester.pumpAndSettle();
    expect(focused_shows('Create a room'), isTrue);
    await press(tester, LogicalKeyboardKey.gameButtonB);
    expect(find.byType(CreateRoomScreen), findsOneWidget);
    await press(tester, LogicalKeyboardKey.gameButtonA);
    await press(tester, LogicalKeyboardKey.gameButtonA);
    expect(find.byType(CreateRoomScreen), findsNothing);
    // A pad was seen, so hint rows may show from now on (rule 5).
    expect(shell.hints_wanted.value, isTrue);
    expect(shell.last_input.value, InputSource.gamepad);
  });

  testWidgets('Shoulder buttons step through tabs and sections', (
    tester,
  ) async {
    final shell = await pump_shell(tester);
    await press(tester, LogicalKeyboardKey.gameButtonRight1);
    expect(shell.activeSection, AppSection.chat);
    expect(shell.chatSubPage, ChatSubPage.direct);
    // Past the last Chat tab the walk continues into Garden (flat walk).
    await press(tester, LogicalKeyboardKey.gameButtonRight1);
    expect(shell.activeSection, AppSection.garden);
    await press(tester, LogicalKeyboardKey.gameButtonLeft1);
    expect(shell.activeSection, AppSection.chat);
    expect(shell.chatSubPage, ChatSubPage.direct);
  });

  testWidgets('Context-menu key opens the row long-press sheet (rule 4)', (
    tester,
  ) async {
    await pump_shell(
      tester,
      home: Scaffold(
        body: ThreadListTile(
          room: const RoomSummary(id: 'r', name: 'Alice'),
          selected: false,
          onTap: () {},
          onDelete: () {},
        ),
      ),
    );
    await press(tester, LogicalKeyboardKey.tab);
    expect(focused_shows('Alice'), isTrue);
    await tester.sendKeyDownEvent(LogicalKeyboardKey.shiftLeft);
    await tester.sendKeyEvent(LogicalKeyboardKey.f10);
    await tester.sendKeyUpEvent(LogicalKeyboardKey.shiftLeft);
    await tester.pumpAndSettle();
    expect(find.text('Delete Room'), findsOneWidget);
    // Escape dismisses the dialog through the same back handler.
    await press(tester, LogicalKeyboardKey.escape);
    expect(find.text('Delete Room'), findsNothing);
  });

  group('traversal: every focusable is reachable from the primary', () {
    Future<void> check(WidgetTester tester, ShellState shell) async {
      await tester.pumpAndSettle();
      await press(tester, LogicalKeyboardKey.arrowDown);
      // Forward from the primary, then backward from wherever that ended.
      // A long lazy list unmounts rows that scroll out of its cache, so a
      // single forward cycle wraps to the topmost *attached* row instead of
      // the top of the screen; the reverse pass covers that edge.
      final seen = {
        ...await tab_cycle(tester),
        ...await tab_cycle(tester, backward: true),
      };
      // Snapshot after the walks: every control attached now must have
      // been visited by one of the two passes.
      final all = focusables();
      expect(all, isNotEmpty);
      expect(
        seen.containsAll(all),
        isTrue,
        reason: 'unreached: ${all.difference(seen)}',
      );
    }

    testWidgets('Chat / Rooms', (tester) async {
      final shell = await pump_shell(tester);
      await check(tester, shell);
    });

    testWidgets('Chat / Direct', (tester) async {
      final shell = await pump_shell(tester);
      shell.selectSubPage(ChatSubPage.direct.index);
      await check(tester, shell);
    });

    testWidgets('Contacts', (tester) async {
      final shell = await pump_shell(tester);
      shell.selectSection(AppSection.contacts);
      await check(tester, shell);
    });

    testWidgets('Garden / Explore', (tester) async {
      final shell = await pump_shell(tester);
      shell.selectSection(AppSection.garden);
      shell.selectSubPage(GardenSubPage.explore.index);
      await check(tester, shell);
    });

    testWidgets('Settings', (tester) async {
      final shell = await pump_shell(tester);
      shell.selectSection(AppSection.settings);
      await check(tester, shell);
    });
  });
}
