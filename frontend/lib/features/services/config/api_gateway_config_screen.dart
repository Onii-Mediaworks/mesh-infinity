// api_gateway_config_screen.dart
//
// ApiGatewayConfigScreen — API Gateway settings (SPEC §22.54.8).
//
// WHAT THE USER SETS
// ------------------
//   Upstream        — the local service address.  Only `http(s)://` to a
//                     host on this device is accepted, so the gateway can
//                     never be turned into an open proxy.
//   Who can connect — trust floor, never below Level 5.
//   Authentication  — what the upstream receives to identify a contact.
//   Limits          — optional per-contact rate limit, allowed methods
//                     (at least one), optional path prefix.
//
// gRPC and WebSocket services share this configuration (§20.5.2, §20.5.3),
// which the intro line states.
//
// Reached from: Services → Hosting → API Gateway → Configure.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../../../backend/models/service_config_models.dart';
import '../services_state.dart';
import 'config_screen_shell.dart';
import 'config_validation.dart';
import 'trust_floor_selector.dart';

/// Edits [ApiGatewayConfig] (§22.54.8).
class ApiGatewayConfigScreen extends StatefulWidget {
  const ApiGatewayConfigScreen({super.key});

  @override
  State<ApiGatewayConfigScreen> createState() => _ApiGatewayConfigScreenState();
}

class _ApiGatewayConfigScreenState extends State<ApiGatewayConfigScreen> {
  ApiGatewayConfig _loaded = const ApiGatewayConfig();
  ApiGatewayConfig _draft = const ApiGatewayConfig();
  ServiceHostFacts _facts = const ServiceHostFacts();

  /// Text controllers for the free-text fields; the draft is derived from
  /// them on every change so validation stays in one place.
  final _upstream = TextEditingController();
  final _rate = TextEditingController();
  final _prefix = TextEditingController();

  /// Whether the rate limit switch is on; the number lives in [_rate].
  bool _limit_on = false;

  bool _loading = true;
  String? _load_error;
  bool _saving = false;
  String? _save_error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _upstream.dispose();
    _rate.dispose();
    _prefix.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _load_error = null;
    });
    final state = context.read<ServicesState>();
    final cfg = await state.fetch_api_gateway_config();
    final facts = await state.host_facts();
    if (!mounted) return;
    setState(() {
      _loading = false;
      if (cfg == null) {
        _load_error = "Couldn't load service settings. Try again.";
        return;
      }
      _loaded = cfg;
      _draft = cfg;
      _facts = facts;
      _upstream.text = cfg.upstream_url;
      _limit_on = cfg.rate_limit != null;
      _rate.text = cfg.rate_limit?.toString() ?? '';
      _prefix.text = cfg.path_prefix ?? '';
    });
  }

  Future<void> _save() async {
    setState(() {
      _saving = true;
      _save_error = null;
    });
    final ok = await context.read<ServicesState>().save_api_gateway_config(
      _draft,
    );
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
        const SnackBar(content: Text('API Gateway settings saved')),
      );
    }
  }

  void _update(ApiGatewayConfig next) => setState(() => _draft = next);

  /// Rebuild the rate-limit part of the draft from the switch and field.
  void _sync_rate() {
    final parsed = int.tryParse(_rate.text.trim());
    // While the text is invalid the draft keeps a sentinel 0 so the dirty
    // check and validation both see "limit on, value not acceptable".
    _update(_draft.copyWith(rate_limit: _limit_on ? (parsed ?? 0) : null));
  }

  String? get _upstream_error =>
      validate_upstream_url(_draft.upstream_url, _facts.hostname);

  String? get _rate_error => _limit_on ? validate_rate_limit(_rate.text) : null;

  String? get _methods_error => _draft.effective_methods.isEmpty
      ? 'Allow at least one method'
      : null;

  String? get _prefix_error => validate_path_prefix(_draft.path_prefix ?? '');

  bool get _valid =>
      _upstream_error == null &&
      _rate_error == null &&
      _methods_error == null &&
      _prefix_error == null;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final text = Theme.of(context).textTheme;

    return ConfigScreenShell(
      title: 'API Gateway',
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
            'The API Gateway lets contacts reach a web service running on '
            'this device. The same settings apply to HTTP, gRPC and '
            'WebSocket services.',
            style: text.bodyMedium?.copyWith(color: cs.onSurfaceVariant),
          ),
        ),
        ConfigGroup(
          title: 'Upstream',
          children: [
            TextField(
              controller: _upstream,
              style: mono_style(context),
              keyboardType: TextInputType.url,
              autocorrect: false,
              decoration: InputDecoration(
                labelText: 'Local service address',
                errorText: _upstream_error,
                helperText: 'Example: http://127.0.0.1:8080',
              ),
              onChanged: (v) => _update(_draft.copyWith(upstream_url: v)),
            ),
          ],
        ),
        ConfigGroup(
          title: 'Who can connect',
          children: [
            TrustFloorSelector(
              minimum: apiGatewayFloor,
              value: _draft.min_trust_level,
              protocol: 'The API Gateway',
              on_changed: (level) =>
                  _update(_draft.copyWith(min_trust_level: level)),
            ),
          ],
        ),
        ConfigGroup(
          title: 'Authentication',
          children: [
            RadioGroup<ApiAuthMode>(
              groupValue: _draft.auth_mode,
              onChanged: (v) {
                if (v != null) _update(_draft.copyWith(auth_mode: v));
              },
              child: Column(
                children: [
                  for (final mode in ApiAuthMode.values)
                    RadioListTile<ApiAuthMode>(
                      value: mode,
                      title: Text(mode.label),
                      subtitle: Text(mode.helper),
                    ),
                ],
              ),
            ),
          ],
        ),
        ConfigGroup(
          title: 'Limits',
          children: [
            SwitchListTile(
              title: const Text('Limit requests'),
              subtitle: const Text('Requests per minute, per contact.'),
              value: _limit_on,
              onChanged: (v) {
                _limit_on = v;
                _sync_rate();
              },
            ),
            if (_limit_on)
              TextField(
                controller: _rate,
                keyboardType: TextInputType.number,
                inputFormatters: [FilteringTextInputFormatter.digitsOnly],
                decoration: InputDecoration(
                  labelText: 'Requests per minute per contact',
                  errorText: _rate_error,
                ),
                onChanged: (_) => _sync_rate(),
              ),
            const SizedBox(height: 12),
            Text('Allowed methods', style: text.bodyMedium),
            const SizedBox(height: 6),
            Wrap(
              spacing: 8,
              runSpacing: 4,
              children: [
                for (final method in httpMethods)
                  FilterChip(
                    label: Text(method),
                    selected: _draft.effective_methods.contains(method),
                    onSelected: (on) {
                      final next = [..._draft.effective_methods];
                      if (on) {
                        if (!next.contains(method)) next.add(method);
                      } else {
                        next.remove(method);
                      }
                      // Keep the canonical order so "all selected" compares
                      // equal to the default regardless of click order.
                      next.sort(
                        (a, b) => httpMethods
                            .indexOf(a)
                            .compareTo(httpMethods.indexOf(b)),
                      );
                      _update(
                        _draft.copyWith(
                          allowed_methods: next.length == httpMethods.length
                              ? null
                              : next,
                        ),
                      );
                    },
                  ),
              ],
            ),
            if (_methods_error != null) InlineError(_methods_error!),
            const SizedBox(height: 12),
            TextField(
              controller: _prefix,
              style: mono_style(context),
              autocorrect: false,
              decoration: InputDecoration(
                labelText: 'Path prefix',
                helperText: 'Leave empty to forward every path.',
                errorText: _prefix_error,
              ),
              onChanged: (v) => _update(
                _draft.copyWith(path_prefix: v.isEmpty ? null : v),
              ),
            ),
          ],
        ),
      ],
    );
  }
}
