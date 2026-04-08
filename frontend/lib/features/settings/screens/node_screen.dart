// node_screen.dart
//
// NodeScreen — mesh node mode, clearnet TCP port, and pairing code display.
//
// WHAT THIS SCREEN CONFIGURES:
// ----------------------------
// A "node" in the mesh network is any device running Mesh Infinity.  Each
// node can participate in the mesh in one of three ways (the node mode):
//
//   Client (0) — connects to the mesh but does NOT route traffic for other
//                nodes.  Good for low-power or metered-data devices.  Traffic
//                from this node leaves via a nearby relay.
//
//   Server (1) — forwards packets for other nodes.  Requires stable, always-on
//                connectivity (e.g. a VPS, a desktop that is rarely suspended).
//                Increases routing resilience for the whole mesh.
//
//   Dual (2)   — full participant: routes for others AND originates/receives its
//                own messages.  The preferred mode for desktop machines with
//                reliable connectivity.
//
// CLEARNET PORT:
// --------------
// The "clearnet" transport is a plain TCP socket used when other encrypted
// overlay transports (Tor, I2P) are unavailable or when the operator allows
// direct internet connections.  The port must be in the ephemeral range
// (1024–65535) to avoid needing root / admin rights on most systems.
// Default port: 7234.
//
// PAIRING CODE:
// -------------
// A short alphanumeric string used to bootstrap contact pairing (§10.1).
// Displayed here so power users can copy it when they don't have a QR scanner
// available.  If none is set yet, the backend generates one on the first peer
// pairing attempt.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../../../backend/backend_bridge.dart';
import '../settings_state.dart';

// ---------------------------------------------------------------------------
// NodeScreen
// ---------------------------------------------------------------------------

/// Settings screen for node mode, clearnet port, and pairing code.
///
/// Changes are applied only when the user taps Save — not live — so the
/// user can edit multiple fields before committing.
class NodeScreen extends StatefulWidget {
  const NodeScreen({super.key});

  @override
  State<NodeScreen> createState() => _NodeScreenState();
}

class _NodeScreenState extends State<NodeScreen> {
  // Current node mode selection (0 = Client, 1 = Server, 2 = Dual).
  // Seeded from SettingsState in initState so the radio group starts on the
  // user's existing choice rather than a default.
  int _nodeMode = 0;

  // Controller for the clearnet TCP port text field.
  // We use a controller (instead of a raw String) so we can pre-fill it
  // from the current settings and read it back on Save.
  final _portController = TextEditingController();

  // True while the backend Save calls are in flight.
  // Causes the Save button to be replaced by a circular progress indicator.
  bool _saving = false;

  @override
  void initState() {
    super.initState();
    // Seed both fields from the most recently loaded settings snapshot.
    // context.read is appropriate here (not watch) because we only need the
    // current value once during initialisation, not ongoing reactivity.
    final s = context.read<SettingsState>().settings;
    if (s != null) {
      _nodeMode = s.nodeMode;
      _portController.text = s.clearnetPort.toString();
    }
  }

  @override
  void dispose() {
    // TextEditingController holds a reference to an underlying native text
    // engine resource.  Disposing it here prevents a memory leak.
    _portController.dispose();
    super.dispose();
  }

  // ---------------------------------------------------------------------------
  // Save handler
  // ---------------------------------------------------------------------------

  /// Validate inputs then call the backend to persist the new node mode and port.
  ///
  /// Two separate bridge calls are made (setNodeMode / setClearnetPort).
  /// If either fails we show an error snackbar and do NOT reload settings,
  /// leaving the on-screen values unchanged so the user can retry.
  Future<void> _save() async {
    // Validate the port before sending it to the backend.
    // int.tryParse returns null for non-numeric input; the range check below
    // enforces 1024–65535 (unprivileged port range).
    final port = int.tryParse(_portController.text.trim());
    if (port == null || port < 1024 || port > 65535) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Port must be between 1024 and 65535')),
      );
      return;
    }

    // Show the in-app-bar spinner while the calls are in flight.
    setState(() => _saving = true);

    final bridge = context.read<BackendBridge>();

    // Apply both settings.  The backend validates them independently —
    // modeOk and portOk can differ if e.g. the port conflicts with another
    // service that is already running.
    final modeOk = bridge.setNodeMode(_nodeMode);
    final portOk = bridge.setClearnetPort(port);

    if (mounted) {
      setState(() => _saving = false);
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
        content: Text(
          (modeOk && portOk) ? 'Node settings saved' : 'Failed to save settings',
        ),
      ));
    }

    // Only reload settings state when both calls succeeded.
    // Reloading on partial failure would overwrite the user's edits with the
    // stale stored values, which is confusing.
    if (modeOk && portOk && mounted) {
      await context.read<SettingsState>().loadAll();
    }
  }

  // ---------------------------------------------------------------------------
  // Build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    // context.watch rebuilds this widget whenever SettingsState notifies.
    // This keeps the pairing code section in sync if another screen changes it.
    final settings = context.watch<SettingsState>();
    final s = settings.settings;
    final theme = Theme.of(context);
    final cs = theme.colorScheme;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Node'),
        actions: [
          // Replace the Save button with a spinner while saving to prevent
          // the user from triggering a second save before the first finishes.
          if (_saving)
            const Padding(
              padding: EdgeInsets.all(14),
              child: SizedBox(
                width: 20,
                height: 20,
                child: CircularProgressIndicator(strokeWidth: 2),
              ),
            )
          else
            TextButton(onPressed: _save, child: const Text('Save')),
        ],
      ),
      body: ListView(
        children: [
          // ── Node mode ───────────────────────────────────────────────────────
          // Three radio options.  RadioGroup is a Material 3 widget that ties
          // groupValue and onChanged so only one option is selected at a time.
          const _SectionHeader('Node mode'),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
            child: Text(
              'Controls how this device participates in the mesh network.',
              style: theme.textTheme.bodySmall?.copyWith(
                color: cs.onSurfaceVariant,
              ),
            ),
          ),
          RadioGroup<int>(
            groupValue: _nodeMode,
            onChanged: (v) {
              // v can be null if the user clicks the already-selected option;
              // we guard to avoid a no-op setState call.
              if (v != null) setState(() => _nodeMode = v);
            },
            child: const Column(
              children: [
                RadioListTile<int>(
                  secondary: Icon(Icons.device_hub_outlined),
                  title: Text('Client'),
                  subtitle: Text(
                    'Connects to the mesh but does not route traffic for others',
                  ),
                  value: 0,
                ),
                RadioListTile<int>(
                  secondary: Icon(Icons.router_outlined),
                  title: Text('Server'),
                  subtitle: Text(
                    'Routes traffic for other nodes; requires stable connectivity',
                  ),
                  value: 1,
                ),
                RadioListTile<int>(
                  secondary: Icon(Icons.hub_outlined),
                  title: Text('Dual'),
                  subtitle: Text(
                    'Full participant — routes traffic and originates messages',
                  ),
                  value: 2,
                ),
              ],
            ),
          ),
          const Divider(height: 1),

          // ── Clearnet transport ──────────────────────────────────────────────
          // The clearnet port is where other nodes can reach this device directly
          // over the internet (TCP).  Ports below 1024 require admin privileges
          // and are rejected.  FilteringTextInputFormatter.digitsOnly prevents
          // the user from entering non-numeric characters.
          const _SectionHeader('Clearnet transport'),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 4, 16, 16),
            child: TextField(
              controller: _portController,
              keyboardType: TextInputType.number,
              // digitsOnly prevents letters, punctuation, and symbols from
              // being entered, reducing the chance of a validation error on Save.
              inputFormatters: [FilteringTextInputFormatter.digitsOnly],
              decoration: const InputDecoration(
                labelText: 'TCP listen port',
                hintText: '7234',
                helperText: 'Port range 1024–65535. Default: 7234.',
              ),
            ),
          ),
          const Divider(height: 1),

          // ── Pairing code ────────────────────────────────────────────────────
          // The pairing code is a short alphanumeric token the backend generates
          // on first peer pairing.  Showing it here lets the user copy it for
          // out-of-band sharing (e.g. paste into a Signal message) instead of
          // always needing to scan a QR code.
          const _SectionHeader('Pairing'),
          // Only render the copy tile if a pairing code exists.
          // isNotEmpty check guards against an empty string returned by Rust
          // before any pairing has happened.
          if (s != null && (s.pairingCode?.isNotEmpty ?? false))
            ListTile(
              leading: const Icon(Icons.qr_code_2_outlined),
              title: const Text('Pairing code'),
              subtitle: Text(s.pairingCode!),
              trailing: IconButton(
                icon: const Icon(Icons.copy_outlined),
                tooltip: 'Copy pairing code',
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: s.pairingCode!));
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Pairing code copied')),
                  );
                },
              ),
            )
          else
            // No pairing code yet — explain why rather than showing an empty
            // section.  This avoids user confusion ("is something broken?").
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
              child: Text(
                'No pairing code configured. The backend will generate one '
                'on first peer pairing.',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: cs.onSurfaceVariant,
                ),
              ),
            ),
          const SizedBox(height: 24),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _SectionHeader — coloured section label used throughout this screen
// ---------------------------------------------------------------------------

/// A small all-caps labelled section divider matching the settings design
/// language across all settings sub-screens.
class _SectionHeader extends StatelessWidget {
  const _SectionHeader(this.title);

  /// The label text, rendered in the theme's primary colour.
  final String title;

  @override
  Widget build(BuildContext context) {
    return Padding(
      // Top padding separates sections visually; bottom padding keeps the
      // label close to the content it describes.
      padding: const EdgeInsets.fromLTRB(16, 20, 16, 6),
      child: Text(
        title,
        style: Theme.of(context).textTheme.labelMedium?.copyWith(
              color: Theme.of(context).colorScheme.primary,
              fontWeight: FontWeight.w700,
              letterSpacing: 0.8, // slight tracking makes label-style text more legible
            ),
      ),
    );
  }
}
