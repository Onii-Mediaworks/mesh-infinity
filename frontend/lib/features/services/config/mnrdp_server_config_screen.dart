// mnrdp_server_config_screen.dart
//
// MnrdpServerConfigScreen — Remote Desktop (MNRDP) server settings
// (SPEC §22.54.5).
//
// WHAT THE USER SETS
// ------------------
//   Who can connect   — the view-only floor (never below Level 5) and the
//                       input / app-streaming floor (never below Level 6,
//                       and never below the view-only floor).
//   What is offered   — full desktop, app streaming, app gallery; at least
//                       one stays on.
//   Adapters          — VNC / NX / Apple Remote Desktop bridges, drawn only
//                       where the platform has them (host facts).
//   Limits            — simultaneous sessions, 1–8.
//
// Validation runs on every change (§22.54.4); the Save button is disabled
// with a helper line while any rule fails.  The backend applies the same
// rules again on save.
//
// Reached from: Services → Hosting → Remote Desktop → Configure.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/models/service_config_models.dart';
import '../services_state.dart';
import 'config_screen_shell.dart';
import 'trust_floor_selector.dart';

/// Edits [MnrdpConfig] (§22.54.5).
class MnrdpServerConfigScreen extends StatefulWidget {
  const MnrdpServerConfigScreen({super.key});

  @override
  State<MnrdpServerConfigScreen> createState() =>
      _MnrdpServerConfigScreenState();
}

class _MnrdpServerConfigScreenState extends State<MnrdpServerConfigScreen> {
  /// What the backend holds; the "clean" baseline for the dirty check.
  MnrdpConfig _loaded = const MnrdpConfig();

  /// The user's working copy.
  MnrdpConfig _draft = const MnrdpConfig();

  /// Adapter availability for this platform.
  ServiceHostFacts _facts = const ServiceHostFacts();

  bool _loading = true;
  String? _load_error;
  bool _saving = false;
  String? _save_error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  /// Fetch the settings and host facts.
  Future<void> _load() async {
    setState(() {
      _loading = true;
      _load_error = null;
    });
    final state = context.read<ServicesState>();
    final cfg = await state.fetch_mnrdp_config();
    final facts = await state.host_facts();
    if (!mounted) return;
    setState(() {
      _loading = false;
      if (cfg == null) {
        _load_error = "Couldn't load service settings. Try again.";
      } else {
        _loaded = cfg;
        _draft = cfg;
        _facts = facts;
      }
    });
  }

  /// Push the draft to the backend; keep edits on refusal (§22.54.4).
  Future<void> _save() async {
    setState(() {
      _saving = true;
      _save_error = null;
    });
    final state = context.read<ServicesState>();
    final ok = await state.save_mnrdp_config(_draft);
    if (!mounted) return;
    setState(() {
      _saving = false;
      if (ok) {
        _loaded = _draft;
      } else {
        _save_error = saveFailedText;
      }
    });
    if (ok) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Remote Desktop settings saved')),
      );
    }
  }

  void _update(MnrdpConfig next) => setState(() => _draft = next);

  /// §22.54.5: input floor must be at least the view-only floor.
  String? get _input_floor_error => _draft.input_floor < _draft.view_floor
      ? 'Must be at least the view-only level'
      : null;

  /// §22.54.5: keep at least one mode on.
  String? get _modes_error => _draft.any_mode
      ? null
      : 'Keep at least one mode on, or turn Remote Desktop off';

  bool get _valid =>
      _input_floor_error == null &&
      _modes_error == null &&
      _draft.max_sessions >= 1 &&
      _draft.max_sessions <= mnrdpMaxSessions;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final text = Theme.of(context).textTheme;

    return ConfigScreenShell(
      title: 'Remote Desktop',
      loading: _loading,
      load_error: _load_error,
      on_retry_load: _load,
      dirty: _draft != _loaded,
      valid: _valid,
      saving: _saving,
      save_error: _save_error,
      on_save: _save,
      children: [
        Padding(
          padding: const EdgeInsets.only(bottom: 12),
          child: Text(
            'Remote Desktop (MNRDP) lets trusted contacts see your screen '
            'or use individual apps on this device.',
            style: text.bodyMedium?.copyWith(color: cs.onSurfaceVariant),
          ),
        ),
        ConfigGroup(
          title: 'Who can connect',
          children: [
            TrustFloorSelector(
              minimum: mnrdpViewFloor,
              value: _draft.view_floor,
              label: 'View-only floor',
              protocol: 'Remote Desktop',
              on_changed: (level) => _update(_draft.copyWith(view_floor: level)),
            ),
            const SizedBox(height: 16),
            TrustFloorSelector(
              minimum: mnrdpInputFloor,
              value: _draft.input_floor,
              label: 'Input and app streaming floor',
              protocol: 'Remote Desktop',
              error: _input_floor_error,
              on_changed: (level) =>
                  _update(_draft.copyWith(input_floor: level)),
            ),
          ],
        ),
        ConfigGroup(
          title: 'What is offered',
          children: [
            SwitchListTile(
              title: const Text('Full desktop'),
              subtitle: const Text('Your whole screen, as one window.'),
              value: _draft.full_desktop,
              onChanged: (v) => _update(_draft.copyWith(full_desktop: v)),
            ),
            SwitchListTile(
              title: const Text('App streaming'),
              subtitle: const Text(
                'Single apps appear as windows on the contact\'s desktop.',
              ),
              value: _draft.app_stream,
              onChanged: (v) => _update(_draft.copyWith(app_stream: v)),
            ),
            SwitchListTile(
              title: const Text('App gallery'),
              subtitle: const Text('Contacts pick an app from a list first.'),
              value: _draft.app_gallery,
              onChanged: (v) => _update(_draft.copyWith(app_gallery: v)),
            ),
            if (_modes_error != null) InlineError(_modes_error!),
          ],
        ),
        if (_facts.vnc_available || _facts.nx_available || _facts.ard_available)
          ConfigGroup(
            title: 'Adapters',
            children: [
              if (_facts.vnc_available) ...[
                SwitchListTile(
                  title: const Text('VNC'),
                  value: _draft.vnc_adapter,
                  onChanged: (v) => _update(_draft.copyWith(vnc_adapter: v)),
                ),
                const HelperLine(
                  'Lets existing VNC clients reach this computer through the mesh.',
                ),
              ],
              if (_facts.nx_available) ...[
                SwitchListTile(
                  title: const Text('NX'),
                  value: _draft.nx_adapter,
                  onChanged: (v) => _update(_draft.copyWith(nx_adapter: v)),
                ),
                const HelperLine(
                  'Lets existing NX clients reach this computer through the mesh.',
                ),
              ],
              if (_facts.ard_available) ...[
                SwitchListTile(
                  title: const Text('Apple Remote Desktop'),
                  value: _draft.ard_adapter,
                  onChanged: (v) => _update(_draft.copyWith(ard_adapter: v)),
                ),
                const HelperLine(
                  'Lets existing Apple Remote Desktop clients reach this computer through the mesh.',
                ),
              ],
            ],
          ),
        ConfigGroup(
          title: 'Limits',
          children: [
            Text(
              'Max simultaneous sessions: ${_draft.max_sessions}',
              style: text.bodyMedium,
            ),
            Semantics(
              label: 'Max simultaneous sessions',
              value: '${_draft.max_sessions}',
              child: Slider(
                min: 1,
                max: mnrdpMaxSessions.toDouble(),
                divisions: mnrdpMaxSessions - 1,
                value: _draft.max_sessions
                    .clamp(1, mnrdpMaxSessions)
                    .toDouble(),
                label: '${_draft.max_sessions}',
                onChanged: (v) =>
                    _update(_draft.copyWith(max_sessions: v.round())),
              ),
            ),
          ],
        ),
      ],
    );
  }
}
