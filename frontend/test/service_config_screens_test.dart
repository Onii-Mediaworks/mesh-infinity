// service_config_screens_test.dart
//
// §22.54.4–§22.54.9: each protocol server configuration screen loads its
// settings, validates inline on change, disables Save with the helper line
// while a rule fails, saves through ServicesState, keeps the user's edits
// and shows the §22.51 banner when the backend refuses, and prompts before
// discarding unsaved edits.
//
// The real Rust library is not on the test host.  ServicesState and
// PeersState are subclassed so the screens talk to an in-memory store, and
// BackendBridge.open(allowMissing: true) satisfies the provider tree.

import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';

import 'package:mesh_infinity_frontend/app/app_theme.dart';
import 'package:mesh_infinity_frontend/backend/backend_bridge.dart';
import 'package:mesh_infinity_frontend/backend/models/peer_models.dart';
import 'package:mesh_infinity_frontend/backend/models/service_config_models.dart';
import 'package:mesh_infinity_frontend/core/widgets/error_banner.dart';
import 'package:mesh_infinity_frontend/features/peers/peers_state.dart';
import 'package:mesh_infinity_frontend/features/services/config/api_gateway_config_screen.dart';
import 'package:mesh_infinity_frontend/features/services/config/config_screen_shell.dart';
import 'package:mesh_infinity_frontend/features/services/config/config_validation.dart';
import 'package:mesh_infinity_frontend/features/services/config/mnfp_shares_config_screen.dart';
import 'package:mesh_infinity_frontend/features/services/config/mnrdp_server_config_screen.dart';
import 'package:mesh_infinity_frontend/features/services/config/mnsp_server_config_screen.dart';
import 'package:mesh_infinity_frontend/features/services/config/print_service_config_screen.dart';
import 'package:mesh_infinity_frontend/features/services/hosting_screen.dart';
import 'package:mesh_infinity_frontend/features/services/services_state.dart';
import 'package:mesh_infinity_frontend/shell/shell_state.dart';

/// A folder that exists on every test host.
final String existing_dir = Directory.systemTemp.path;

/// In-memory stand-in for the backend store.
class FakeServices extends ServicesState {
  FakeServices(super.bridge);

  MnrdpConfig? mnrdp = const MnrdpConfig();
  MnspConfig? mnsp = const MnspConfig();
  MnfpConfig? mnfp = const MnfpConfig();
  ApiGatewayConfig? gateway = const ApiGatewayConfig();
  PrintConfig? print_cfg = const PrintConfig();
  List<PrintQueue> queues = const [];

  /// Whether the next save is accepted.
  bool accept = true;

  /// Every config handed to a save, in order.
  final List<Object> saved = [];

  late ServiceHostFacts facts = ServiceHostFacts(
    platform: 'linux',
    hostname: 'workstation',
    vnc_available: true,
    nx_available: true,
    ard_available: false,
    default_user: 'alice',
    home: existing_dir,
    users: const ['alice'],
    shells: const ['/bin/bash', '/bin/zsh'],
  );

  @override
  String? last_error() => 'refused by fake backend';

  @override
  Future<MnrdpConfig?> fetch_mnrdp_config() async => mnrdp;
  @override
  Future<bool> save_mnrdp_config(MnrdpConfig config) async {
    saved.add(config);
    return accept;
  }

  @override
  Future<MnspConfig?> fetch_mnsp_config() async => mnsp;
  @override
  Future<bool> save_mnsp_config(MnspConfig config) async {
    saved.add(config);
    return accept;
  }

  @override
  Future<MnfpConfig?> fetch_mnfp_config() async => mnfp;
  @override
  Future<bool> save_mnfp_config(MnfpConfig config) async {
    saved.add(config);
    return accept;
  }

  @override
  Future<ApiGatewayConfig?> fetch_api_gateway_config() async => gateway;
  @override
  Future<bool> save_api_gateway_config(ApiGatewayConfig config) async {
    saved.add(config);
    return accept;
  }

  @override
  Future<PrintConfig?> fetch_print_config() async => print_cfg;
  @override
  Future<bool> save_print_config(PrintConfig config) async {
    saved.add(config);
    return accept;
  }

  @override
  Future<ServiceHostFacts> host_facts() async => facts;
  @override
  Future<List<PrintQueue>> print_queues() async => queues;
  @override
  Future<PrintQueue?> probe_print_queue(String url) async => null;
}

/// Two contacts: one above the Level 6 floors, one below.
class FakePeers extends PeersState {
  FakePeers(super.bridge);

  @override
  List<PeerModel> get peers => [
    PeerModel(id: 'a' * 64, name: 'Alice', trustLevel: TrustLevel.trusted),
    PeerModel(id: 'b' * 64, name: 'Bob', trustLevel: TrustLevel.acquaintance),
  ];
}

/// A fresh fake store, for tests that preload settings before pumping.
FakeServices fake() => FakeServices(BackendBridge.open(allowMissing: true));

/// Pump [screen] with the providers the configuration screens need.
Future<FakeServices> pump(
  WidgetTester tester,
  Widget screen, {
  FakeServices? services,
}) async {
  tester.view.physicalSize = const Size(420, 1200);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.reset);
  final store = services ?? fake();
  final bridge = BackendBridge.open(allowMissing: true);
  await tester.pumpWidget(
    MultiProvider(
      providers: [
        Provider<BackendBridge>.value(value: bridge),
        ChangeNotifierProvider<ShellState>(create: (_) => ShellState()),
        ChangeNotifierProvider<ServicesState>.value(value: store),
        ChangeNotifierProvider<PeersState>(create: (_) => FakePeers(bridge)),
      ],
      child: MaterialApp(theme: MeshTheme.light(), home: screen),
    ),
  );
  await tester.pumpAndSettle();
  return store;
}

/// The Save button at the bottom of a configuration screen.
Finder save_button() => find.widgetWithText(FilledButton, 'Save');

bool save_enabled(WidgetTester tester) =>
    tester.widget<FilledButton>(save_button()).onPressed != null;

/// A TextField by its label.
Finder field(String label) => find.byWidgetPredicate(
  (w) => w is TextField && w.decoration?.labelText == label,
);

/// Scroll the screen's list until [finder] is built and visible.  Lazily
/// built ListView children below the fold do not exist until scrolled to.
Future<void> show(WidgetTester tester, Finder finder) async {
  if (finder.evaluate().isEmpty) {
    await tester.scrollUntilVisible(
      finder,
      120,
      scrollable: find.byType(Scrollable).first,
    );
  }
  await tester.ensureVisible(finder);
  await tester.pumpAndSettle();
}

/// Tap the SwitchListTile titled [title], scrolling to it first.
Future<void> flip(WidgetTester tester, String title) async {
  final tile = find.widgetWithText(SwitchListTile, title);
  await show(tester, tile);
  await tester.tap(tile);
  await tester.pumpAndSettle();
}

/// Scroll the screen's list back to the top (the banner lives there).
Future<void> scroll_top(WidgetTester tester) async {
  await tester.drag(find.byType(Scrollable).first, const Offset(0, 3000));
  await tester.pumpAndSettle();
}

/// Ask the route to pop, as the AppBar back button or a hardware back
/// key would; a dirty screen vetoes it and shows the discard prompt.
Future<void> go_back(WidgetTester tester) async {
  await tester.state<NavigatorState>(find.byType(Navigator)).maybePop();
  await tester.pumpAndSettle();
}

/// Tap [finder] after scrolling to it.
Future<void> tap(WidgetTester tester, Finder finder) async {
  await show(tester, finder);
  await tester.tap(finder);
  await tester.pumpAndSettle();
}

MnspUserMapping alice_mapping({String local_user = 'alice'}) => MnspUserMapping(
  peer_id: 'a' * 64,
  display_name: 'Alice',
  local_user: local_user,
  allowed_shells: const ['/bin/bash'],
  working_dir: existing_dir,
);

void main() {
  group('MnrdpServerConfigScreen', () {
    testWidgets('loads defaults, names the protocol, saves', (tester) async {
      final services = await pump(tester, const MnrdpServerConfigScreen());
      expect(find.textContaining('Remote Desktop (MNRDP)'), findsOneWidget);
      await show(tester, find.text('Max simultaneous sessions: 2'));
      expect(save_enabled(tester), isTrue);
      await flip(tester, 'App gallery');
      await tester.tap(save_button());
      await tester.pumpAndSettle();
      expect(services.saved.single, const MnrdpConfig(app_gallery: false));
      expect(find.text('Remote Desktop settings saved'), findsOneWidget);
    });

    testWidgets('input floor below view floor is flagged inline', (
      tester,
    ) async {
      // A stored combination the UI could not have produced still renders
      // its rule and blocks Save until fixed.
      final services = fake()
        ..mnrdp = const MnrdpConfig(view_floor: 7, input_floor: 6);
      await pump(tester, const MnrdpServerConfigScreen(), services: services);
      expect(find.text('Must be at least the view-only level'), findsOneWidget);
      expect(save_enabled(tester), isFalse);
      expect(find.text(fixFieldsText), findsOneWidget);
    });

    testWidgets('turning every mode off blocks Save', (tester) async {
      await pump(tester, const MnrdpServerConfigScreen());
      await flip(tester, 'Full desktop');
      await flip(tester, 'App streaming');
      await flip(tester, 'App gallery');
      expect(
        find.text('Keep at least one mode on, or turn Remote Desktop off'),
        findsOneWidget,
      );
      expect(save_enabled(tester), isFalse);
    });

    testWidgets('adapters follow host facts', (tester) async {
      await pump(tester, const MnrdpServerConfigScreen());
      await show(tester, find.widgetWithText(SwitchListTile, 'VNC'));
      expect(find.widgetWithText(SwitchListTile, 'NX'), findsOneWidget);
      expect(
        find.widgetWithText(SwitchListTile, 'Apple Remote Desktop'),
        findsNothing,
      );
    });

    testWidgets('a refused save shows the banner and keeps edits', (
      tester,
    ) async {
      final services = await pump(tester, const MnrdpServerConfigScreen());
      services.accept = false;
      await flip(tester, 'VNC');
      await tester.tap(save_button());
      await tester.pumpAndSettle();
      await scroll_top(tester);
      expect(find.byType(ErrorBanner), findsOneWidget);
      expect(find.text(saveFailedText), findsOneWidget);
      expect(find.text('Retry'), findsOneWidget);
      // The edit is still there: the VNC switch stays on.
      await show(tester, find.widgetWithText(SwitchListTile, 'VNC'));
      final vnc = tester.widget<SwitchListTile>(
        find.widgetWithText(SwitchListTile, 'VNC'),
      );
      expect(vnc.value, isTrue);
      // Retry re-submits the same draft.
      services.accept = true;
      await scroll_top(tester);
      await tester.tap(find.text('Retry'));
      await tester.pumpAndSettle();
      expect(services.saved.length, 2);
      expect(services.saved.last, services.saved.first);
      await scroll_top(tester);
      expect(find.byType(ErrorBanner), findsNothing);
    });

    testWidgets('back with unsaved edits asks before discarding', (
      tester,
    ) async {
      await pump(tester, const MnrdpServerConfigScreen());
      await flip(tester, 'App gallery');
      await go_back(tester);
      expect(find.text('Discard changes?'), findsOneWidget);
      await tester.tap(find.text('Keep editing'));
      await tester.pumpAndSettle();
      expect(find.byType(MnrdpServerConfigScreen), findsOneWidget);
    });

    testWidgets('a failed load shows a retry banner, never the form', (
      tester,
    ) async {
      final services = fake()..mnrdp = null;
      await pump(tester, const MnrdpServerConfigScreen(), services: services);
      expect(find.byType(ErrorBanner), findsOneWidget);
      expect(find.byType(SwitchListTile), findsNothing);
      expect(save_enabled(tester), isFalse);
      services.mnrdp = const MnrdpConfig();
      await tester.tap(find.text('Retry'));
      await tester.pumpAndSettle();
      expect(find.byType(SwitchListTile), findsWidgets);
    });
  });

  group('MnspServerConfigScreen', () {
    testWidgets('empty grant list says nobody can connect', (tester) async {
      await pump(tester, const MnspServerConfigScreen());
      expect(find.textContaining('Remote Shell (MNSP)'), findsOneWidget);
      expect(
        find.text('No one can open a shell yet. Add a person to grant access.'),
        findsOneWidget,
      );
    });

    testWidgets('add person offers only contacts at the floor', (
      tester,
    ) async {
      final services = await pump(tester, const MnspServerConfigScreen());
      await tap(tester, find.text('Add person'));
      expect(find.text('Alice'), findsOneWidget);
      expect(find.text('Bob'), findsNothing);
      await tester.tap(find.text('Alice'));
      await tester.pumpAndSettle();
      // The person sheet opens with the host defaults.
      expect(
        tester.widget<TextField>(field('Local user account')).controller!.text,
        'alice',
      );
      expect(
        tester.widget<TextField>(field('Starting folder')).controller!.text,
        existing_dir,
      );
      await tester.tap(find.widgetWithText(FilledButton, 'Done'));
      await tester.pumpAndSettle();
      expect(find.text('Alice'), findsOneWidget);
      await tester.tap(save_button());
      await tester.pumpAndSettle();
      final saved = services.saved.single as MnspConfig;
      expect(saved.user_map.single.peer_id, 'a' * 64);
      expect(saved.user_map.single.allowed_shells, ['/bin/bash']);
      expect(saved.user_map.single.allowed_commands, isNull);
    });

    testWidgets('unknown local account is flagged and blocks Save', (
      tester,
    ) async {
      final services = fake()
        ..mnsp = MnspConfig(user_map: [alice_mapping(local_user: 'mallory')]);
      await pump(tester, const MnspServerConfigScreen(), services: services);
      expect(save_enabled(tester), isFalse);
      await tap(tester, find.text('Alice'));
      expect(find.text('No local account called mallory'), findsOneWidget);
      await tester.enterText(field('Local user account'), 'alice');
      await tester.pumpAndSettle();
      expect(find.text('No local account called mallory'), findsNothing);
      await tester.tap(find.widgetWithText(FilledButton, 'Done'));
      await tester.pumpAndSettle();
      expect(save_enabled(tester), isTrue);
    });

    testWidgets('SSH adapter reveals the port and validates it', (
      tester,
    ) async {
      await pump(tester, const MnspServerConfigScreen());
      expect(field('sshd port'), findsNothing);
      await flip(tester, 'SSH adapter');
      await show(tester, field('sshd port'));
      await tester.enterText(field('sshd port'), '0');
      await tester.pumpAndSettle();
      expect(find.text('Enter a port from 1 to 65535'), findsOneWidget);
      expect(save_enabled(tester), isFalse);
      await tester.enterText(field('sshd port'), '2222');
      await tester.pumpAndSettle();
      expect(save_enabled(tester), isTrue);
    });

    testWidgets('removing a person asks first', (tester) async {
      final services = fake()..mnsp = MnspConfig(user_map: [alice_mapping()]);
      await pump(tester, const MnspServerConfigScreen(), services: services);
      await tester.drag(find.text('Alice'), const Offset(-400, 0));
      await tester.pumpAndSettle();
      expect(find.text('Remove shell access for Alice?'), findsOneWidget);
      await tester.tap(find.text('Remove'));
      await tester.pumpAndSettle();
      expect(find.text('Alice'), findsNothing);
      await tester.tap(save_button());
      await tester.pumpAndSettle();
      expect((services.saved.single as MnspConfig).user_map, isEmpty);
    });
  });

  group('MnfpSharesConfigScreen', () {
    testWidgets('empty state and SFTP gate', (tester) async {
      await pump(tester, const MnfpSharesConfigScreen());
      expect(find.text('Nothing is shared yet.'), findsOneWidget);
      await show(tester, find.widgetWithText(SwitchListTile, 'SFTP via SSH'));
      final sftp = tester.widget<SwitchListTile>(
        find.widgetWithText(SwitchListTile, 'SFTP via SSH'),
      );
      expect(sftp.onChanged, isNull);
      expect(
        find.text('Turn on the SSH adapter in Remote Shell first'),
        findsOneWidget,
      );
    });

    testWidgets('SFTP is offered once Remote Shell has SSH on', (
      tester,
    ) async {
      final services = fake()..mnsp = const MnspConfig(ssh_adapter: true);
      await pump(tester, const MnfpSharesConfigScreen(), services: services);
      await flip(tester, 'SFTP via SSH');
      await tester.tap(save_button());
      await tester.pumpAndSettle();
      expect((services.saved.single as MnfpConfig).sftp_via_ssh, isTrue);
    });

    testWidgets('add share validates folder and name, then saves', (
      tester,
    ) async {
      final services = await pump(tester, const MnfpSharesConfigScreen());
      await tap(tester, find.text('Add share'));
      expect(find.text('Choose a folder'), findsOneWidget);
      await tester.enterText(field('Folder'), '/no/such/folder/anywhere');
      await tester.pumpAndSettle();
      expect(find.text("That folder doesn't exist"), findsOneWidget);
      await tester.enterText(field('Folder'), existing_dir);
      await tester.pumpAndSettle();
      // The name defaults to the folder's own name.
      expect(
        tester.widget<TextField>(field('Name')).controller!.text,
        folder_name(existing_dir),
      );
      await tester.enterText(field('Name'), 'Documents');
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.widgetWithText(FilledButton, 'Done'));
      await tester.tap(find.widgetWithText(FilledButton, 'Done'));
      await tester.pumpAndSettle();
      expect(find.text('Documents'), findsOneWidget);
      await tester.tap(save_button());
      await tester.pumpAndSettle();
      final saved = services.saved.single as MnfpConfig;
      expect(saved.shares.single.name, 'Documents');
      expect(saved.shares.single.root_path, existing_dir);
      expect(saved.shares.single.access, MnfpAccess.readOnly);
      expect(saved.shares.single.min_trust_level, mnfpFloor);
    });

    testWidgets('duplicate share names are refused', (tester) async {
      final services = fake()
        ..mnfp = MnfpConfig(
          shares: [MnfpShare(name: 'Documents', root_path: existing_dir)],
        );
      await pump(tester, const MnfpSharesConfigScreen(), services: services);
      await tap(tester, find.text('Add share'));
      await tester.enterText(field('Folder'), existing_dir);
      await tester.enterText(field('Name'), 'documents');
      await tester.pumpAndSettle();
      expect(
        find.text('You already have a share called documents'),
        findsOneWidget,
      );
      final done = tester.widget<FilledButton>(
        find.widgetWithText(FilledButton, 'Done'),
      );
      expect(done.onPressed, isNull);
    });

    testWidgets('stop sharing asks first', (tester) async {
      final services = fake()
        ..mnfp = MnfpConfig(
          shares: [MnfpShare(name: 'Documents', root_path: existing_dir)],
        );
      await pump(tester, const MnfpSharesConfigScreen(), services: services);
      await tap(tester, find.byTooltip('Stop sharing Documents'));
      expect(find.text('Stop sharing Documents?'), findsOneWidget);
      await tester.tap(find.text('Keep sharing'));
      await tester.pumpAndSettle();
      expect(find.text('Documents'), findsOneWidget);
    });
  });

  group('ApiGatewayConfigScreen', () {
    testWidgets('refuses a non-local upstream', (tester) async {
      await pump(tester, const ApiGatewayConfigScreen());
      expect(find.textContaining('gRPC and WebSocket'), findsOneWidget);
      expect(
        tester
            .widget<TextField>(field('Local service address'))
            .controller!
            .text,
        'http://127.0.0.1:8080',
      );
      await tester.enterText(
        field('Local service address'),
        'http://api.example.com/',
      );
      await tester.pumpAndSettle();
      expect(
        find.text('The gateway only forwards to services on this device'),
        findsOneWidget,
      );
      expect(save_enabled(tester), isFalse);
      // The machine's own hostname counts as local (host facts).
      await tester.enterText(
        field('Local service address'),
        'http://workstation:9000',
      );
      await tester.pumpAndSettle();
      expect(save_enabled(tester), isTrue);
    });

    testWidgets('methods, rate limit and prefix rules', (tester) async {
      final services = await pump(tester, const ApiGatewayConfigScreen());
      for (final method in httpMethods) {
        await tap(tester, find.widgetWithText(FilterChip, method));
      }
      expect(find.text('Allow at least one method'), findsOneWidget);
      expect(save_enabled(tester), isFalse);
      await tap(tester, find.widgetWithText(FilterChip, 'GET'));
      expect(save_enabled(tester), isTrue);

      await show(tester, field('Path prefix'));
      await tester.enterText(field('Path prefix'), 'api');
      await tester.pumpAndSettle();
      expect(find.text('The prefix must start with /'), findsOneWidget);
      await tester.enterText(field('Path prefix'), '/api/v1');
      await tester.pumpAndSettle();

      await flip(tester, 'Limit requests');
      await show(tester, field('Requests per minute per contact'));
      await tester.enterText(
        field('Requests per minute per contact'),
        '999999',
      );
      await tester.pumpAndSettle();
      expect(find.text('Enter a number from 1 to 100 000'), findsOneWidget);
      expect(save_enabled(tester), isFalse);
      await tester.enterText(field('Requests per minute per contact'), '600');
      await tester.pumpAndSettle();

      await tester.tap(save_button());
      await tester.pumpAndSettle();
      final saved = services.saved.single as ApiGatewayConfig;
      expect(saved.allowed_methods, ['GET']);
      expect(saved.path_prefix, '/api/v1');
      expect(saved.rate_limit, 600);
    });

    testWidgets('refused save keeps the typed address', (tester) async {
      final services = await pump(tester, const ApiGatewayConfigScreen());
      services.accept = false;
      await tester.enterText(
        field('Local service address'),
        'http://localhost:3000',
      );
      await tester.pumpAndSettle();
      await tester.tap(save_button());
      await tester.pumpAndSettle();
      await scroll_top(tester);
      expect(find.text(saveFailedText), findsOneWidget);
      expect(
        tester
            .widget<TextField>(field('Local service address'))
            .controller!
            .text,
        'http://localhost:3000',
      );
    });
  });

  group('PrintServiceConfigScreen', () {
    testWidgets('empty state, URL rule, then saves a printer', (tester) async {
      final services = await pump(tester, const PrintServiceConfigScreen());
      expect(find.text('No printers shared yet.'), findsOneWidget);
      await tap(tester, find.text('Share a printer'));
      // No spooler queues in the fake: the URL field is shown directly.
      expect(find.textContaining('No printer queues were found'), findsOneWidget);
      await tester.enterText(field('Queue address'), 'ipp://8.8.8.8/ipp/print');
      await tester.pumpAndSettle();
      expect(
        find.text(
          'Only printers on this device or your local network can be shared',
        ),
        findsOneWidget,
      );
      await tester.enterText(
        field('Queue address'),
        'ipp://192.168.1.20/ipp/print',
      );
      await tester.enterText(field('Name shown to contacts'), 'Office Laser');
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.widgetWithText(FilledButton, 'Done'));
      await tester.tap(find.widgetWithText(FilledButton, 'Done'));
      await tester.pumpAndSettle();
      expect(find.text('Office Laser'), findsOneWidget);
      await tester.tap(save_button());
      await tester.pumpAndSettle();
      final saved = services.saved.single as PrintConfig;
      expect(saved.printers.single.ipp_url, 'ipp://192.168.1.20/ipp/print');
      expect(saved.printers.single.min_trust_level, printFloor);
    });

    testWidgets('name longer than 64 characters is refused', (tester) async {
      await pump(tester, const PrintServiceConfigScreen());
      await tap(tester, find.text('Share a printer'));
      await tester.enterText(
        field('Queue address'),
        'ipp://127.0.0.1:631/printers/x',
      );
      await tester.enterText(field('Name shown to contacts'), 'x' * 65);
      await tester.pumpAndSettle();
      expect(find.text('Names are at most 64 characters'), findsOneWidget);
      final done = tester.widget<FilledButton>(
        find.widgetWithText(FilledButton, 'Done'),
      );
      expect(done.onPressed, isNull);
    });
  });

  group('HostingScreen', () {
    testWidgets('configure buttons only appear for enabled services', (
      tester,
    ) async {
      // With the backend unavailable every service is off, so no tile may
      // offer settings for a server that is not running.
      await pump(tester, const Scaffold(body: HostingScreen()));
      expect(find.byIcon(Icons.tune_outlined), findsNothing);
      expect(find.byType(Switch), findsWidgets);
    });
  });

  group('validation helpers mirror the backend', () {
    test('split_url and locality rules', () {
      expect(split_url('http://127.0.0.1:8080/x')!.port, 8080);
      expect(split_url('ipp://[::1]/printers/a')!.host, '::1');
      expect(split_url('http://host:0/'), isNull);
      expect(split_url('http://user@127.0.0.1/'), isNull);
      expect(split_url('nonsense'), isNull);
      expect(is_local_host('LOCALHOST', null), isTrue);
      expect(is_local_host('::1', null), isTrue);
      expect(is_local_host('box', 'Box'), isTrue);
      expect(is_local_host('10.0.0.1', null), isFalse);
      expect(is_lan_host('172.20.1.1', null), isTrue);
      expect(is_lan_host('fe80::1', null), isTrue);
      expect(is_lan_host('printer.local', null), isTrue);
      expect(is_lan_host('printers.example.com', null), isFalse);
      expect(is_lan_host('8.8.8.8', null), isFalse);
    });

    test('field rules', () {
      expect(validate_name(''), 'Enter a name');
      expect(validate_name('x' * 65), 'Names are at most 64 characters');
      expect(validate_name('ok'), isNull);
      expect(validate_path_prefix('/api/../x'), "The prefix can't contain ..");
      expect(validate_rate_limit('100000'), isNull);
      expect(validate_rate_limit('100001'), isNotNull);
      expect(validate_port('65535'), isNull);
      expect(validate_port('65536'), isNotNull);
      expect(folder_name('/home/alice/Documents/'), 'Documents');
      expect(folder_name(r'C:\Users\jon\Pictures'), 'Pictures');
    });
  });
}
