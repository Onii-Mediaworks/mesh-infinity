import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/backend_bridge.dart';

/// Notification preferences screen (§14).
///
/// Reads and writes NotificationConfig via mi_get_notification_config /
/// mi_set_notification_config.  Four tiers:
///   1 = MeshTunnel (no third-party exposure)
///   2 = UnifiedPush (push server sees timing)
///   3 = SilentPush  (platform vendor sees timing)
///   4 = RichPush    (platform vendor sees timing + content)
class NotificationScreen extends StatefulWidget {
  const NotificationScreen({super.key});

  @override
  State<NotificationScreen> createState() => _NotificationScreenState();
}

class _NotificationScreenState extends State<NotificationScreen> {
  bool _loading = true;
  bool _saving  = false;

  bool   _enabled            = true;
  int    _tier               = 1;       // 1–4
  bool   _cloudPingEnabled   = false;
  bool   _showPreviews       = true;
  bool   _soundEnabled       = true;
  bool   _vibrationEnabled   = true;
  bool   _suppressedByThreat = false;

  final _urlController = TextEditingController();

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _urlController.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    final bridge = context.read<BackendBridge>();
    final cfg = bridge.getNotificationConfig();
    if (cfg != null && mounted) {
      setState(() {
        _enabled            = cfg['enabled']            as bool?   ?? true;
        _tier               = (cfg['tier']              as int?)   ?? 1;
        _cloudPingEnabled   = cfg['cloudPingEnabled']   as bool?   ?? false;
        _showPreviews       = cfg['showPreviews']       as bool?   ?? true;
        _soundEnabled       = cfg['soundEnabled']       as bool?   ?? true;
        _vibrationEnabled   = cfg['vibrationEnabled']   as bool?   ?? true;
        _suppressedByThreat = cfg['suppressedByThreat'] as bool?   ?? false;
        _urlController.text = (cfg['pushServerUrl']     as String? ?? '');
        _loading = false;
      });
    } else {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _save() async {
    setState(() => _saving = true);
    final bridge = context.read<BackendBridge>();
    final ok = bridge.setNotificationConfig({
      'enabled':       _enabled,
      'tier':          _cloudPingEnabled ? _tier.clamp(2, 4) : 1,
      'pushServerUrl': _cloudPingEnabled ? _urlController.text.trim() : '',
      'showPreviews':  _showPreviews,
    });
    if (!mounted) return;
    setState(() => _saving = false);
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Text(ok ? 'Notification settings saved' : 'Failed to save settings'),
    ));
    if (ok) await _load();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs    = theme.colorScheme;

    if (_loading) {
      return Scaffold(
        appBar: AppBar(title: const Text('Notifications')),
        body: const Center(child: CircularProgressIndicator()),
      );
    }

    return Scaffold(
      appBar: AppBar(
        title: const Text('Notifications'),
        actions: [
          if (_saving)
            const Padding(
              padding: EdgeInsets.all(14),
              child: SizedBox(
                width: 20, height: 20,
                child: CircularProgressIndicator(strokeWidth: 2),
              ),
            )
          else
            TextButton(onPressed: _save, child: const Text('Save')),
        ],
      ),
      body: ListView(
        children: [
          // ── Master toggle ────────────────────────────────────────────
          SwitchListTile(
            secondary: const Icon(Icons.notifications_outlined),
            title: const Text('Enable notifications'),
            subtitle: const Text('Receive alerts for messages, calls, and events'),
            value: _enabled,
            onChanged: (v) => setState(() => _enabled = v),
          ),

          const Divider(),

          // ── Mesh-native (Tier 1) ────────────────────────────────────
          _sectionHeader('Mesh-Native (Tier 1)', theme),
          const Padding(
            padding: EdgeInsets.symmetric(horizontal: 16),
            child: Text(
              'Delivered directly over the encrypted mesh channel. No third '
              'party involved. This is the primary and default mechanism.',
              style: TextStyle(fontSize: 13),
            ),
          ),
          const SizedBox(height: 4),
          SwitchListTile(
            secondary: const Icon(Icons.preview_outlined),
            title: const Text('Show message previews'),
            subtitle: const Text('Display sender and text in notifications'),
            value: _showPreviews,
            onChanged: _enabled ? (v) => setState(() => _showPreviews = v) : null,
          ),
          SwitchListTile(
            secondary: const Icon(Icons.volume_up_outlined),
            title: const Text('Sound'),
            value: _soundEnabled,
            onChanged: _enabled ? (v) => setState(() => _soundEnabled = v) : null,
          ),
          SwitchListTile(
            secondary: const Icon(Icons.vibration_outlined),
            title: const Text('Vibration'),
            value: _vibrationEnabled,
            onChanged: _enabled ? (v) => setState(() => _vibrationEnabled = v) : null,
          ),

          const Divider(),

          // ── Cloud wake signal ────────────────────────────────────────
          _sectionHeader('Cloud Wake Signal (Optional)', theme),
          const Padding(
            padding: EdgeInsets.symmetric(horizontal: 16),
            child: Text(
              'A cloud push can wake the app when a mesh message is waiting. '
              'The payload contains zero message content — only a wake signal '
              'and priority level. The actual content always travels over the '
              'encrypted mesh channel.',
              style: TextStyle(fontSize: 13),
            ),
          ),
          const SizedBox(height: 8),
          SwitchListTile(
            secondary: const Icon(Icons.cloud_outlined),
            title: const Text('Enable cloud ping'),
            subtitle: const Text('Use APNs / FCM / UnifiedPush as a wake signal'),
            value: _cloudPingEnabled,
            onChanged: _enabled
                ? (v) => setState(() {
                      _cloudPingEnabled = v;
                      if (v && _tier < 2) _tier = 2;
                    })
                : null,
          ),

          if (_cloudPingEnabled) ...[
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
              child: DropdownButtonFormField<int>(
                initialValue: _tier.clamp(2, 4),
                decoration: const InputDecoration(
                  labelText: 'Notification tier',
                  border: OutlineInputBorder(),
                ),
                items: const [
                  DropdownMenuItem(
                    value: 2,
                    child: Text('Tier 2 — UnifiedPush (server sees timing)'),
                  ),
                  DropdownMenuItem(
                    value: 3,
                    child: Text('Tier 3 — Silent push (platform sees timing)'),
                  ),
                  DropdownMenuItem(
                    value: 4,
                    child: Text('Tier 4 — Rich push (platform sees timing + content)'),
                  ),
                ],
                onChanged: (v) {
                  if (v != null) setState(() => _tier = v);
                },
              ),
            ),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
              child: TextField(
                controller: _urlController,
                decoration: const InputDecoration(
                  labelText: 'Self-hosted push server URL',
                  hintText: 'https://ntfy.example.com',
                  helperText:
                      'Leave empty to use platform default (APNs/FCM)',
                  border: OutlineInputBorder(),
                ),
              ),
            ),
            const Padding(
              padding: EdgeInsets.fromLTRB(16, 0, 16, 8),
              child: Card(
                child: Padding(
                  padding: EdgeInsets.all(12),
                  child: Row(
                    children: [
                      Icon(Icons.info_outline, size: 20),
                      SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          'Using a self-hosted server (e.g. ntfy.sh) eliminates '
                          'dependence on Google/Apple notification infrastructure.',
                          style: TextStyle(fontSize: 12),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ],

          // Threat-context suppression warning
          if (_suppressedByThreat)
            Padding(
              padding: const EdgeInsets.all(16),
              child: Card(
                color: cs.errorContainer,
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Row(
                    children: [
                      Icon(Icons.warning_amber_rounded,
                          color: cs.onErrorContainer),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          'Cloud wake signal is suppressed because threat level '
                          'is Elevated or Critical (§14.7). Tier 1 mesh '
                          'delivery remains active.',
                          style: TextStyle(
                              fontSize: 12, color: cs.onErrorContainer),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),

          const Divider(),

          // ── Priority reference ───────────────────────────────────────
          _sectionHeader('Priority Levels', theme),
          const ListTile(
            leading: Icon(Icons.priority_high, color: Colors.red),
            title: Text('Urgent'),
            subtitle:
                Text('Calls, pairing requests — immediate delivery, no jitter'),
          ),
          const ListTile(
            leading: Icon(Icons.arrow_upward, color: Colors.orange),
            title: Text('High'),
            subtitle: Text(
                'Direct messages from trusted peers — up to 10 s jitter'),
          ),
          const ListTile(
            leading: Icon(Icons.remove, color: Colors.blue),
            title: Text('Normal'),
            subtitle: Text(
                'Group messages, file transfer offers — up to 60 s jitter'),
          ),
          const ListTile(
            leading: Icon(Icons.arrow_downward, color: Colors.grey),
            title: Text('Low'),
            subtitle: Text(
                'Presence updates, network map — always batched (5 min)'),
          ),
          const SizedBox(height: 32),
        ],
      ),
    );
  }

  Widget _sectionHeader(String text, ThemeData theme) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
      child: Text(
        text,
        style: theme.textTheme.titleSmall?.copyWith(
          color: theme.colorScheme.primary,
          fontWeight: FontWeight.bold,
        ),
      ),
    );
  }
}
