// app_connector_screen.dart
//
// AppConnectorScreen configures backend-owned per-app routing rules (§13.15,
// §22.9.4). This screen does not invent routing state locally: it reflects
// the App Connector configuration stored by Rust and lets the user edit it.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/backend_bridge.dart';
import '../../../platform/android_app_catalog_bridge.dart';
import '../../../platform/android_vpn_bridge.dart';
import '../network_state.dart';

// ---------------------------------------------------------------------------
// ConnectorMode — allowlist vs denylist selection
// ---------------------------------------------------------------------------

/// Whether the app list is an allowlist (only these apps use mesh) or
/// a denylist (all apps use mesh except these).
enum ConnectorMode {
  /// Only selected apps route through the mesh.
  allowlist,

  /// All apps route through the mesh except excluded ones.
  denylist,
}

// ---------------------------------------------------------------------------
// AppConnectorScreen
// ---------------------------------------------------------------------------

/// Configures which apps route through the mesh network.
class AppConnectorScreen extends StatefulWidget {
  const AppConnectorScreen({super.key});

  @override
  State<AppConnectorScreen> createState() => _AppConnectorScreenState();
}

class _AppConnectorScreenState extends State<AppConnectorScreen> {
  List<AndroidInstalledApp> _installedApps = const [];
  bool _loadingInstalledApps = false;

  @override
  void initState() {
    super.initState();
    _loadInstalledApps();
  }

  Future<void> _loadInstalledApps() async {
    if (!AndroidAppCatalogBridge.instance.isSupported) {
      return;
    }
    setState(() {
      _loadingInstalledApps = true;
    });
    final apps = await AndroidAppCatalogBridge.instance.listInstalledApps();
    if (!mounted) {
      return;
    }
    setState(() {
      _installedApps = apps;
      _loadingInstalledApps = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    final net = context.watch<NetworkState>();
    final tt = Theme.of(context).textTheme;
    final cs = Theme.of(context).colorScheme;
    final mode = _modeFromString(net.appConnectorMode);
    final configuredApps = net.appConnectorApps;
    final configuredRules = net.appConnectorRules;

    // VPN is "active" when the mode is anything other than "off".
    final vpnEnabled = net.isVpnActive;

    return Scaffold(
      appBar: AppBar(title: const Text('App Connector')),
      body: Column(
        children: [
          // ── VPN master toggle card ───────────────────────────────────
          // The toggle must be enabled before per-app configuration matters.
          // Shown at the top so users can see why the app list is grayed out.
          Padding(
            padding: const EdgeInsets.all(16),
            child: Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                'Mesh VPN mode',
                                style: tt.titleSmall,
                              ),
                              const SizedBox(height: 2),
                              Text(
                                'Routes selected apps through the mesh when VPN mode is active.',
                                style: tt.bodySmall?.copyWith(
                                  color: cs.onSurfaceVariant,
                                ),
                              ),
                            ],
                          ),
                        ),
                        Switch(
                          value: vpnEnabled,
                          onChanged: (v) => v
                              ? _enableVpn(context, net)
                              : _confirmDisableVpn(context, net),
                        ),
                      ],
                    ),
                    // Active indicator — shown when VPN is running.
                    if (vpnEnabled) ...[
                      const SizedBox(height: 8),
                      Row(
                        children: [
                          Container(
                            width: 8,
                            height: 8,
                            decoration: const BoxDecoration(
                              color: Color(0xFF22C55E), // secGreen
                              shape: BoxShape.circle,
                            ),
                          ),
                          const SizedBox(width: 6),
                          Text(
                            _statusSummary(net, configuredApps, mode),
                            style: tt.bodySmall?.copyWith(
                              color: const Color(0xFF22C55E),
                            ),
                          ),
                        ],
                      ),
                    ],
                  ],
                ),
              ),
            ),
          ),

          // ── VPN off — full-screen empty state ────────────────────────
          // When VPN is off, there's nothing else to configure.  Show an
          // invitation to enable it rather than a disabled-looking form.
          if (!vpnEnabled) ...[
            Expanded(
              child: Center(
                child: Padding(
                  padding: const EdgeInsets.all(32),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(
                        Icons.vpn_key_outlined,
                        size: 56,
                        color: cs.outline,
                      ),
                      const SizedBox(height: 12),
                      Text('VPN mode is off', style: tt.titleMedium),
                      const SizedBox(height: 4),
                      Text(
                        configuredApps.isEmpty
                            ? "Add at least one app rule, then enable Mesh VPN mode to turn on per-app routing."
                            : "Enable Mesh VPN mode above to turn on the app rules you've saved here.",
                        style: tt.bodyMedium?.copyWith(
                          color: cs.onSurfaceVariant,
                        ),
                        textAlign: TextAlign.center,
                      ),
                      const SizedBox(height: 16),
                      FilledButton.icon(
                        onPressed: () => _openAppDialog(context, net, configuredApps),
                        icon: const Icon(Icons.add),
                        label: Text(
                          configuredApps.isEmpty ? 'Add first rule' : 'Add another rule',
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ] else ...[
            // ── Mode selector ────────────────────────────────────────────
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('App selection mode', style: tt.labelMedium),
                  const SizedBox(height: 8),
                  SegmentedButton<ConnectorMode>(
                    segments: const [
                      ButtonSegment(
                        value: ConnectorMode.allowlist,
                        label: Text('Selected apps only'),
                        icon: Icon(Icons.checklist_outlined, size: 14),
                      ),
                      ButtonSegment(
                        value: ConnectorMode.denylist,
                        label: Text('All except excluded'),
                        icon: Icon(Icons.block_outlined, size: 14),
                      ),
                    ],
                    selected: {mode},
                    onSelectionChanged: (s) => _setMode(context, net, s.first),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    mode == ConnectorMode.allowlist
                        ? 'Only the apps you select will route through the mesh.'
                        : 'All apps will route through the mesh except those you exclude.',
                    style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
                  ),
                  const SizedBox(height: 12),
                  Card(
                    color: cs.surfaceContainerHighest,
                    elevation: 0,
                    child: Padding(
                      padding: const EdgeInsets.all(12),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text('What this changes', style: tt.titleSmall),
                          const SizedBox(height: 6),
                          Text(
                            _routingExplanation(net, mode, configuredApps.length),
                            style: tt.bodySmall?.copyWith(
                              color: cs.onSurfaceVariant,
                            ),
                          ),
                          const SizedBox(height: 8),
                          Text(
                            _manualEntryExplanation(),
                            style: tt.bodySmall?.copyWith(
                              color: cs.onSurfaceVariant,
                            ),
                          ),
                          const SizedBox(height: 8),
                          Text(
                            configuredRules.isEmpty
                                ? 'No advanced selector rules are stored yet.'
                                : '${configuredRules.length} advanced selector rule${configuredRules.length == 1 ? '' : 's'} stored in the backend.',
                            style: tt.bodySmall?.copyWith(
                              color: cs.onSurfaceVariant,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 12),
                  Align(
                    alignment: Alignment.centerLeft,
                    child: TextButton.icon(
                      onPressed: () => _openAdvancedRuleDialog(
                        context,
                        net,
                        configuredApps,
                        configuredRules,
                      ),
                      icon: const Icon(Icons.rule_folder_outlined, size: 16),
                      label: const Text('Add advanced rule'),
                    ),
                  ),
                ],
              ),
            ),

            const SizedBox(height: 8),
            const Divider(height: 1),

            // ── App list header ──────────────────────────────────────────
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
              child: Row(
                children: [
                  Expanded(
                    child: Text(
                      _listTitle(mode),
                      style: tt.titleSmall,
                    ),
                  ),
                  TextButton.icon(
                    onPressed: () => _openAppDialog(context, net, configuredApps),
                    icon: const Icon(Icons.add, size: 16),
                    label: const Text('Add'),
                  ),
                ],
              ),
            ),
            if (configuredRules.isNotEmpty)
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
                child: Card(
                  child: Column(
                    children: [
                      for (final rule in configuredRules.take(3))
                        ListTile(
                          leading: const Icon(Icons.rule_outlined),
                          title: Text(_advancedRuleTitle(rule)),
                          subtitle: Text(
                            _advancedRuleSubtitle(rule),
                            style: tt.bodySmall?.copyWith(
                              color: cs.onSurfaceVariant,
                            ),
                          ),
                          trailing: IconButton(
                            onPressed: () => _removeRule(
                              context,
                              net,
                              configuredApps,
                              configuredRules,
                              rule,
                            ),
                            icon: Icon(
                              Icons.remove_circle_outline,
                              color: cs.error,
                            ),
                          ),
                        ),
                      if (configuredRules.length > 3)
                        Padding(
                          padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
                          child: Align(
                            alignment: Alignment.centerLeft,
                            child: Text(
                              '${configuredRules.length - 3} more advanced rule${configuredRules.length - 3 == 1 ? '' : 's'} are active.',
                              style: tt.bodySmall?.copyWith(
                                color: cs.onSurfaceVariant,
                              ),
                            ),
                          ),
                        ),
                    ],
                  ),
                ),
              ),

            // ── App list or empty state ──────────────────────────────────
            Expanded(
              child: configuredApps.isEmpty
                  ? Center(
                      child: Padding(
                        padding: const EdgeInsets.all(32),
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(Icons.apps_outlined, size: 40, color: cs.outline),
                            const SizedBox(height: 8),
                            Text(
                              mode == ConnectorMode.allowlist
                                  ? 'No app rules yet. Add a package name or bundle ID to route it through the mesh.'
                                  : 'No exclusions yet. In this mode, every app would follow mesh routing.',
                              style: tt.bodyMedium?.copyWith(
                                color: cs.onSurfaceVariant,
                              ),
                              textAlign: TextAlign.center,
                            ),
                          ],
                        ),
                      ),
                    )
                  : ListView.separated(
                      itemCount: configuredApps.length,
                      separatorBuilder: (_, _) =>
                          const Divider(height: 1, indent: 72),
                      itemBuilder: (ctx, i) {
                        final app = configuredApps[i];
                        return ListTile(
                          isThreeLine: true,
                          leading: const _AppIconPlaceholder(),
                          title: Text((app['name'] as String?)?.trim().isNotEmpty == true
                              ? app['name'] as String
                              : (app['app_id'] as String? ?? 'App')),
                          subtitle: Text(
                            _appSubtitle(app, mode),
                            style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
                          ),
                          trailing: IconButton(
                            icon: Icon(
                              Icons.remove_circle_outline,
                              color: cs.error,
                            ),
                            tooltip: 'Remove',
                            onPressed: () => _removeApp(
                              context,
                              net,
                              configuredApps,
                              app['app_id'] as String? ?? '',
                            ),
                          ),
                        );
                      },
                    ),
            ),
          ],
        ],
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // VPN enable / disable
  // ---------------------------------------------------------------------------

  Future<void> _enableVpn(BuildContext context, NetworkState net) async {
    final bridge = context.read<BackendBridge>();
    if (net.appConnectorApps.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Add at least one app rule before turning on App Connector.'),
        ),
      );
      return;
    }

    final messenger = ScaffoldMessenger.of(context);
    final permissionGranted =
        await AndroidVpnBridge.instance.isPermissionGranted() ||
        await AndroidVpnBridge.instance.requestPermission();
    if (!permissionGranted) {
      if (context.mounted) {
        messenger.showSnackBar(
          const SnackBar(
            content: Text(
              'Android VPN permission is required before App Connector can route app traffic.',
            ),
          ),
        );
      }
      return;
    }

    final ok = await net.setVpnMode('policy_based');
    if (ok) {
      await _syncAndroidVpnPolicy(bridge, messenger);
    }
    if (!ok && context.mounted) {
      messenger.showSnackBar(
        const SnackBar(
          content: Text('Could not enable policy-based routing with the current backend state.'),
        ),
      );
    }
  }

  Future<void> _confirmDisableVpn(
    BuildContext context,
    NetworkState net,
  ) async {
    final bridge = context.read<BackendBridge>();
    final messenger = ScaffoldMessenger.of(context);
    final ok = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Disable Mesh VPN?'),
        content: const Text(
          'All apps will revert to their normal internet connections.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Disable'),
          ),
        ],
      ),
    );
    if (ok == true) {
      await net.setVpnMode('off');
      await _syncAndroidVpnPolicy(bridge, messenger);
    }
  }

  Future<void> _setMode(BuildContext context, NetworkState net, ConnectorMode mode) async {
    final bridge = context.read<BackendBridge>();
    final messenger = ScaffoldMessenger.of(context);
    final ok = await net.setAppConnectorConfig(
      mode: _modeToString(mode),
      apps: net.appConnectorApps,
      rules: net.appConnectorRules,
    );
    if (ok) {
      await _syncAndroidVpnPolicy(bridge, messenger);
    }
    if (!ok && context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Could not update the App Connector mode.')),
      );
    }
  }

  Future<void> _removeApp(
    BuildContext context,
    NetworkState net,
    List<Map<String, dynamic>> apps,
    String appId,
  ) async {
    final bridge = context.read<BackendBridge>();
    final messenger = ScaffoldMessenger.of(context);
    final updated = apps
        .where((app) => (app['app_id'] as String? ?? '') != appId)
        .map((app) => Map<String, dynamic>.from(app))
        .toList();
    final ok = await net.setAppConnectorConfig(
      mode: net.appConnectorMode,
      apps: updated,
      rules: net.appConnectorRules,
    );
    if (!ok && context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Could not remove that app rule.')),
      );
      return;
    }
    await _syncAndroidVpnPolicy(bridge, messenger);

    if (updated.isEmpty && net.vpnMode == 'policy_based') {
      await net.setVpnMode('off');
      await _syncAndroidVpnPolicy(bridge, messenger);
    }
  }

  Future<void> _openAppDialog(
    BuildContext context,
    NetworkState net,
    List<Map<String, dynamic>> apps,
  ) async {
    final selectedInstalledApp = await _pickInstalledApp(context, apps);
    if (!context.mounted) {
      return;
    }
    if (selectedInstalledApp != null) {
      await _saveAppRule(
        context,
        net,
        apps,
        appId: selectedInstalledApp.appId,
        name: selectedInstalledApp.label,
      );
      return;
    }
    final nameCtrl = TextEditingController();
    final appIdCtrl = TextEditingController();
    final result = await showDialog<Map<String, String>>(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Add app rule'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: nameCtrl,
              decoration: const InputDecoration(
                labelText: 'Label',
                hintText: 'Signal',
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: appIdCtrl,
              decoration: const InputDecoration(
                labelText: 'Package name or bundle ID',
                hintText: 'org.thoughtcrime.securesms',
              ),
              autocorrect: false,
              enableSuggestions: false,
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, {
              'name': nameCtrl.text.trim(),
              'app_id': appIdCtrl.text.trim(),
            }),
            child: const Text('Add'),
          ),
        ],
      ),
    );
    nameCtrl.dispose();
    appIdCtrl.dispose();
    if (!context.mounted) {
      return;
    }

    if (result == null) return;
    final appId = result['app_id']?.trim() ?? '';
    if (appId.isEmpty) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Enter a package name or bundle ID.')),
        );
      }
      return;
    }

    await _saveAppRule(
      context,
      net,
      apps,
      appId: appId,
      name: result['name']?.trim(),
    );
  }

  Future<void> _saveAppRule(
    BuildContext context,
    NetworkState net,
    List<Map<String, dynamic>> apps, {
    required String appId,
    String? name,
  }) async {
    final bridge = context.read<BackendBridge>();
    final messenger = ScaffoldMessenger.of(context);
    final normalizedAppId = appId.trim();
    final alreadyExists = apps.any(
      (app) => (app['app_id'] as String? ?? '').trim() == normalizedAppId,
    );
    if (alreadyExists) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('That app already has a rule here.')),
        );
      }
      return;
    }

    final updated = apps.map((app) => Map<String, dynamic>.from(app)).toList()
      ..add({
        'name': (name?.trim().isNotEmpty ?? false) ? name!.trim() : normalizedAppId,
        'app_id': normalizedAppId,
      });

    final ok = await net.setAppConnectorConfig(
      mode: net.appConnectorMode,
      apps: updated,
      rules: net.appConnectorRules,
    );

    if (!ok && context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Could not save that app rule.')),
      );
      return;
    }
    await _syncAndroidVpnPolicy(bridge, messenger);
  }

  Future<AndroidInstalledApp?> _pickInstalledApp(
    BuildContext context,
    List<Map<String, dynamic>> configuredApps,
  ) async {
    if (!AndroidAppCatalogBridge.instance.isSupported || _installedApps.isEmpty) {
      return null;
    }
    final configuredIds = configuredApps
        .map((app) => (app['app_id'] as String? ?? '').trim())
        .where((appId) => appId.isNotEmpty)
        .toSet();
    final availableApps = _installedApps
        .where((app) => !configuredIds.contains(app.appId))
        .toList(growable: false);
    if (availableApps.isEmpty) {
      return null;
    }
    return showDialog<AndroidInstalledApp>(
      context: context,
      builder: (_) => _InstalledAppPickerDialog(apps: availableApps),
    );
  }

  String _statusSummary(
    NetworkState net,
    List<Map<String, dynamic>> apps,
    ConnectorMode mode,
  ) {
    final status = switch (net.vpnConnectionStatus) {
      'connected' => 'VPN connected',
      'connecting' => 'VPN connecting',
      'blocked' => 'VPN blocked by kill switch',
      'disconnecting' => 'VPN disconnecting',
      _ => 'VPN active',
    };
    final ruleCount = apps.length;
    final rules = mode == ConnectorMode.allowlist
        ? '$ruleCount app rules'
        : ruleCount == 0
            ? 'no exclusions'
            : '$ruleCount exclusions';
    final advancedRuleCount = net.appConnectorRules.length;
    final advanced = advancedRuleCount == 0
        ? ''
        : ', $advancedRuleCount advanced rule${advancedRuleCount == 1 ? '' : 's'}';
    return '$status, $rules$advanced';
  }

  String _routingExplanation(
    NetworkState net,
    ConnectorMode mode,
    int appCount,
  ) {
    final appScope = switch (mode) {
      ConnectorMode.allowlist => appCount == 0
          ? 'Nothing is routed through the mesh yet.'
          : '$appCount selected app${appCount == 1 ? '' : 's'} follow your current mesh route.',
      ConnectorMode.denylist => appCount == 0
          ? 'Every app follows your current mesh route.'
          : 'All apps follow your current mesh route except $appCount exclusion${appCount == 1 ? '' : 's'}.',
    };

    final securityImpact = switch (net.vpnSecurityPosture) {
      'mesh_only' =>
        'Traffic stays inside the mesh and keeps its normal internet exit path.',
      'policy_based' =>
        'Each app follows its own rule. Some traffic can stay on the normal network while selected apps use mesh routing.',
      'exit_node' =>
        net.vpnExitNodeSeesDestinations
            ? 'Traffic leaves through an exit node. The exit node can see destinations after traffic leaves the mesh.'
            : 'Traffic leaves through an exit node with additional protection before internet egress.',
      'direct' =>
        'Traffic bypasses mesh protection and uses the normal network directly.',
      _ => 'The current route is controlled by the backend VPN mode.',
    };

    return '$appScope $securityImpact';
  }

  String _manualEntryExplanation() {
    if (AndroidAppCatalogBridge.instance.isSupported) {
      if (_loadingInstalledApps) {
        return 'Rules are stored in the backend. Installed Android apps are loading now. Manual package and selector entry is still available for anything outside the launcher-visible app list.';
      }
      if (_installedApps.isNotEmpty) {
        return 'Rules are stored in the backend. Installed Android apps can be selected directly, and manual package or selector entry is still available for advanced cases.';
      }
    }
    return 'Rules are stored in the backend. Package names, bundle IDs, and selectors are entered manually for now.';
  }

  Future<void> _removeRule(
    BuildContext context,
    NetworkState net,
    List<Map<String, dynamic>> apps,
    List<Map<String, dynamic>> rules,
    Map<String, dynamic> rule,
  ) async {
    final bridge = context.read<BackendBridge>();
    final messenger = ScaffoldMessenger.of(context);
    final updated = rules
        .where((entry) => entry.toString() != rule.toString())
        .map((entry) => Map<String, dynamic>.from(entry))
        .toList();
    final ok = await net.setAppConnectorConfig(
      mode: net.appConnectorMode,
      apps: apps,
      rules: updated,
    );
    if (!ok && context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Could not remove that advanced rule.')),
      );
      return;
    }
    await _syncAndroidVpnPolicy(bridge, messenger);
  }

  Future<void> _openAdvancedRuleDialog(
    BuildContext context,
    NetworkState net,
    List<Map<String, dynamic>> apps,
    List<Map<String, dynamic>> rules,
  ) async {
    final bridge = context.read<BackendBridge>();
    final messenger = ScaffoldMessenger.of(context);
    final appIdCtrl = TextEditingController();
    final domainCtrl = TextEditingController();
    final ipRangeCtrl = TextEditingController();
    final portCtrl = TextEditingController();
    String routeKind = 'direct_mesh';
    final result = await showDialog<Map<String, dynamic>>(
      context: context,
      builder: (_) => StatefulBuilder(
        builder: (context, setDialogState) => AlertDialog(
          title: const Text('Add advanced rule'),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                TextField(
                  controller: appIdCtrl,
                  decoration: const InputDecoration(
                    labelText: 'Package name or bundle ID',
                    hintText: 'org.thoughtcrime.securesms',
                  ),
                  autocorrect: false,
                  enableSuggestions: false,
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: domainCtrl,
                  decoration: const InputDecoration(
                    labelText: 'Domain pattern',
                    hintText: '*.example.com',
                  ),
                  autocorrect: false,
                  enableSuggestions: false,
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: ipRangeCtrl,
                  decoration: const InputDecoration(
                    labelText: 'IP range (CIDR)',
                    hintText: '10.0.0.0/8',
                  ),
                  autocorrect: false,
                  enableSuggestions: false,
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: portCtrl,
                  decoration: const InputDecoration(
                    labelText: 'Port',
                    hintText: '443',
                  ),
                  keyboardType: TextInputType.number,
                ),
                const SizedBox(height: 12),
                DropdownButtonFormField<String>(
                  initialValue: routeKind,
                  decoration: const InputDecoration(labelText: 'Route through'),
                  items: const [
                    DropdownMenuItem(
                      value: 'direct_mesh',
                      child: Text('Direct Mesh'),
                    ),
                    DropdownMenuItem(value: 'direct', child: Text('Direct')),
                    DropdownMenuItem(value: 'tor', child: Text('Tor')),
                    DropdownMenuItem(value: 'i2_p', child: Text('I2P')),
                    DropdownMenuItem(
                      value: 'mixnet_tier',
                      child: Text('Mixnet'),
                    ),
                  ],
                  onChanged: (value) {
                    setDialogState(() {
                      routeKind = value ?? routeKind;
                    });
                  },
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(context, {
                'app_selector': {
                  'app_id': appIdCtrl.text.trim(),
                  'domain_pattern': domainCtrl.text.trim(),
                  'ip_range': ipRangeCtrl.text.trim(),
                  'port': int.tryParse(portCtrl.text.trim()),
                },
                'routing_target': {'kind': routeKind},
                'priority': _nextRulePriority(rules),
                'enabled': true,
                'threat_context_min': null,
              }),
              child: const Text('Add'),
            ),
          ],
        ),
      ),
    );
    appIdCtrl.dispose();
    domainCtrl.dispose();
    ipRangeCtrl.dispose();
    portCtrl.dispose();
    if (result == null) {
      return;
    }
    final selector = Map<String, dynamic>.from(
      result['app_selector'] as Map<String, dynamic>? ?? const {},
    )..removeWhere((_, value) => value == null || (value is String && value.isEmpty));
    if (selector.isEmpty) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Add at least one selector to the rule.')),
        );
      }
      return;
    }
    final updated = rules.map((entry) => Map<String, dynamic>.from(entry)).toList()
      ..add({
        'app_selector': selector,
        'routing_target': Map<String, dynamic>.from(
          result['routing_target'] as Map<String, dynamic>,
        ),
        'priority': result['priority'],
        'enabled': true,
        'threat_context_min': null,
      });
    final ok = await net.setAppConnectorConfig(
      mode: net.appConnectorMode,
      apps: apps,
      rules: updated,
    );
    if (ok) {
      await _syncAndroidVpnPolicy(bridge, messenger);
    }
    if (!ok && context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Could not save that advanced rule.')),
      );
    }
  }

  Future<void> _syncAndroidVpnPolicy(
    BackendBridge bridge,
    ScaffoldMessengerState messenger,
  ) async {
    if (!AndroidVpnBridge.instance.isSupported) {
      return;
    }
    final policy = bridge.getAndroidVpnPolicy();
    if (policy == null) {
      return;
    }
    final applied = await AndroidVpnBridge.instance.applyPolicy(policy);
    if (!applied) {
      messenger.showSnackBar(
        const SnackBar(content: Text('Could not apply the current Android VPN policy.')),
      );
    }
  }

  int _nextRulePriority(List<Map<String, dynamic>> rules) {
    var highest = 0;
    for (final rule in rules) {
      final priority = rule['priority'] as int? ?? 0;
      if (priority >= highest) {
        highest = priority + 1;
      }
    }
    return highest.clamp(0, 255);
  }

  String _advancedRuleTitle(Map<String, dynamic> rule) {
    final selector = Map<String, dynamic>.from(
      rule['app_selector'] as Map? ?? const {},
    );
    final parts = <String>[
      if ((selector['app_id'] as String?)?.isNotEmpty == true)
        selector['app_id'] as String,
      if ((selector['domain_pattern'] as String?)?.isNotEmpty == true)
        selector['domain_pattern'] as String,
      if ((selector['ip_range'] as String?)?.isNotEmpty == true)
        selector['ip_range'] as String,
      if (selector['port'] != null) 'port ${selector['port']}',
    ];
    return parts.isEmpty ? 'Advanced rule' : parts.join(' · ');
  }

  String _advancedRuleSubtitle(Map<String, dynamic> rule) {
    final target = Map<String, dynamic>.from(
      rule['routing_target'] as Map? ?? const {},
    );
    final priority = rule['priority'] as int? ?? 0;
    return 'Route via ${_formatRoutingTarget(target)} · priority $priority';
  }

  String _formatRoutingTarget(Map<String, dynamic> target) {
    return switch (target['kind'] as String? ?? '') {
      'tor' => 'Tor',
      'i2_p' => 'I2P',
      'mixnet_tier' => 'Mixnet',
      'direct' => 'Direct',
      'exit_node' => 'Exit node',
      'infinet' => 'Infinet',
      _ => 'Direct mesh',
    };
  }

  String _listTitle(ConnectorMode mode) => switch (mode) {
        ConnectorMode.allowlist => 'Apps routed through mesh',
        ConnectorMode.denylist => 'Excluded apps',
      };

  String _appSubtitle(Map<String, dynamic> app, ConnectorMode mode) {
    final appId = app['app_id'] as String? ?? '';
    final effect = switch (mode) {
      ConnectorMode.allowlist => 'Follows your mesh route',
      ConnectorMode.denylist => 'Stays on the normal route',
    };
    return '$effect\n$appId';
  }

  ConnectorMode _modeFromString(String mode) => switch (mode) {
        'denylist' => ConnectorMode.denylist,
        _ => ConnectorMode.allowlist,
      };

  String _modeToString(ConnectorMode mode) => switch (mode) {
        ConnectorMode.allowlist => 'allowlist',
        ConnectorMode.denylist => 'denylist',
      };
}

// ---------------------------------------------------------------------------
// _AppIconPlaceholder — shown when no icon is available
// ---------------------------------------------------------------------------

/// Placeholder when app icon can't be loaded (platform channel not wired yet).
class _AppIconPlaceholder extends StatelessWidget {
  const _AppIconPlaceholder();

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 40,
      height: 40,
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Icon(
        Icons.apps_outlined,
        size: 24,
        color: Theme.of(context).colorScheme.onSurfaceVariant,
      ),
    );
  }
}

class _InstalledAppPickerDialog extends StatefulWidget {
  const _InstalledAppPickerDialog({required this.apps});

  final List<AndroidInstalledApp> apps;

  @override
  State<_InstalledAppPickerDialog> createState() => _InstalledAppPickerDialogState();
}

class _InstalledAppPickerDialogState extends State<_InstalledAppPickerDialog> {
  String _query = '';

  @override
  Widget build(BuildContext context) {
    final filteredApps = widget.apps.where((app) {
      if (_query.isEmpty) {
        return true;
      }
      final query = _query.toLowerCase();
      return app.label.toLowerCase().contains(query) ||
          app.appId.toLowerCase().contains(query);
    }).toList(growable: false);
    return AlertDialog(
      title: const Text('Pick installed app'),
      content: SizedBox(
        width: 480,
        height: 420,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              decoration: const InputDecoration(
                prefixIcon: Icon(Icons.search),
                labelText: 'Search apps',
              ),
              onChanged: (value) {
                setState(() {
                  _query = value.trim();
                });
              },
            ),
            const SizedBox(height: 12),
            Expanded(
              child: filteredApps.isEmpty
                  ? const Center(
                      child: Text('No installed apps match that search.'),
                    )
                  : ListView.separated(
                      itemCount: filteredApps.length,
                      separatorBuilder: (_, _) => const Divider(height: 1),
                      itemBuilder: (context, index) {
                        final app = filteredApps[index];
                        return ListTile(
                          leading: const _AppIconPlaceholder(),
                          title: Text(app.label),
                          subtitle: Text(app.appId),
                          trailing: app.isSystemApp
                              ? const Icon(Icons.shield_outlined, size: 18)
                              : null,
                          onTap: () => Navigator.pop(context, app),
                        );
                      },
                    ),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('Manual entry'),
        ),
      ],
    );
  }
}
