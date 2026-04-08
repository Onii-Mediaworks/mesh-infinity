// security_screen.dart
//
// SecurityScreen — hub for threat context, PIN, emergency erase, and advanced
// security features (§22.10).
//
// WHAT IS THREAT CONTEXT?
// -----------------------
// Mesh Infinity supports four operational threat levels (0–3).  When the user
// raises the threat level, the backend automatically applies stricter transport
// and metadata rules without the user having to configure each individually:
//
//   0 — Normal   : Standard operation.  No extra restrictions.
//   1 — Elevated : Disables cloud wake signals.  Reduces metadata exposure.
//   2 — High     : Forces Tor / I2P only.  Suppresses all third-party services.
//   3 — Critical : Maximum isolation.  All clearnet transports disabled.
//
// The SecurityStatusBar (shown above all screens) reflects the active level
// so the user always knows their current posture.
//
// SUB-SCREENS REACHABLE FROM HERE:
//   PinScreen               — §22.10.x  app lock PIN configuration
//   EmergencyEraseScreen    — §22.10.11 duress PIN, wrong-PIN wipe, remote wipe
//   PotentialExtremesScreen — §22.10.4  advanced features with risk disclosures
//   KnownLimitationsScreen  — §22.10.5  honest list of what we cannot protect
//   IdentityScreen          — cryptographic keys and pairing payload

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/backend_bridge.dart';
import '../../../app/app_theme.dart';
import '../settings_state.dart';
import 'identity_screen.dart';
import 'pin_screen.dart';
import 'emergency_erase_screen.dart';
import 'potential_extremes_screen.dart';
import 'known_limitations_screen.dart';

/// Hub screen for all security-related settings.
///
/// Loads the current threat level from the backend in [initState] so the
/// radio group starts on the user's existing selection.
class SecurityScreen extends StatefulWidget {
  const SecurityScreen({super.key});

  @override
  State<SecurityScreen> createState() => _SecurityScreenState();
}

class _SecurityScreenState extends State<SecurityScreen> {
  // The currently active threat level (0–3).  Loaded from the backend in
  // initState; updated immediately when the user selects a new radio option
  // (optimistic UI — we apply locally before the backend confirms).
  int _threatLevel = 0;

  // True only during the initial backend fetch.  Replaced by the loading
  // indicator below; the full screen is shown once loading completes.
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  /// Fetch the current threat level from the backend synchronously.
  ///
  /// Synchronous because [BackendBridge.getThreatContext] is a fast FFI call
  /// that does not block the event loop.  We still need setState to trigger
  /// a rebuild once we have the value.
  void _load() {
    final bridge = context.read<BackendBridge>();
    final level = bridge.getThreatContext();
    setState(() {
      _threatLevel = level;
      _loading = false;
    });
  }

  /// Apply a new threat level by calling the backend and updating local state.
  ///
  /// The UI updates optimistically (radio immediately moves) before awaiting
  /// the backend result.  If the backend rejects the call the state is not
  /// reverted — a production implementation would handle this case.
  Future<void> _setThreatLevel(int level) async {
    final bridge = context.read<BackendBridge>();
    final ok = bridge.setThreatContext(level);
    // Only update local state if the backend accepted the change.
    if (ok && mounted) setState(() => _threatLevel = level);
  }

  // ---------------------------------------------------------------------------
  // Build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;

    // Show a minimal loading screen while the initial fetch is in flight.
    // This is brief (~1 frame) but prevents the radio group from flickering
    // from level 0 to the real value.
    if (_loading) {
      return Scaffold(
        appBar: AppBar(title: const Text('Security')),
        body: const Center(child: CircularProgressIndicator()),
      );
    }

    return Scaffold(
      appBar: AppBar(title: const Text('Security')),
      body: ListView(
        children: [
          // ── Threat context ────────────────────────────────────────────────
          // Four radio tiles, each colour-coded to convey severity at a glance.
          // Selecting a higher level immediately applies stricter rules in the
          // backend without requiring a separate Save action.
          const _SectionHeader('Threat context'),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
            child: Text(
              'Set the current operational threat level. Higher levels apply '
              'stricter transport and metadata controls automatically.',
              style: theme.textTheme.bodySmall?.copyWith(
                color: cs.onSurfaceVariant,
              ),
            ),
          ),
          RadioGroup<int>(
            groupValue: _threatLevel,
            onChanged: (v) {
              // v is null only if the already-selected option was tapped again;
              // guard to avoid a no-op state update.
              if (v != null) _setThreatLevel(v);
            },
            child: Column(
              // Generates four radio tiles for levels 0–3, each using the
              // threat-level-specific colour and description string.
              children: List.generate(4, (i) {
                final color = _threatColor(i);
                return RadioListTile<int>(
                  secondary: Icon(Icons.shield_outlined, color: color),
                  title: Text(
                    _threatLabel(i),
                    style: TextStyle(color: color, fontWeight: FontWeight.w600),
                  ),
                  subtitle: Text(_threatDescription(i)),
                  value: i,
                );
              }),
            ),
          ),
          const Divider(height: 1),

          // ── App lock ──────────────────────────────────────────────────────
          // A PIN is optional but recommended on shared or mobile devices.
          // It protects against casual access without affecting the mesh
          // identity itself (§22.10.x).  The PIN sub-screen adapts its
          // mode based on whether a PIN is already set (change vs. setup).
          const _SectionHeader('App lock'),
          // Consumer rebuilds only this tile when SettingsState changes,
          // keeping the subtitle ("PIN enabled" / "No PIN set") accurate
          // after the user sets or removes a PIN in the sub-screen.
          Consumer<SettingsState>(
            builder: (context, settings, _) => ListTile(
              leading: const Icon(Icons.pin_outlined),
              title: const Text('App PIN'),
              subtitle: Text(
                settings.pinEnabled ? 'PIN enabled — tap to change' : 'No PIN set',
              ),
              trailing: const Icon(Icons.chevron_right),
              onTap: () => Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (_) => PinScreen(
                    // Open in change mode if a PIN is already configured;
                    // otherwise open in setup mode so the user creates one.
                    mode: settings.pinEnabled
                        ? PinScreenMode.change
                        : PinScreenMode.setup,
                  ),
                ),
              ),
            ),
          ),
          const Divider(height: 1),

          // ── Emergency ─────────────────────────────────────────────────────
          // EmergencyEraseScreen groups all data-destruction triggers:
          //   - Duress PIN (looks like normal unlock but silently wipes)
          //   - Wrong-PIN wipe threshold
          //   - Remote wipe via a trusted contact
          //   - Manual immediate erase
          // Grouping these in a sub-screen keeps the main security list clean
          // and prevents accidental activation (§22.10.11).
          const _SectionHeader('Emergency'),
          ListTile(
            leading: Icon(Icons.emergency_outlined, color: cs.error),
            title: Text(
              'Emergency erase',
              style: TextStyle(color: cs.error),
            ),
            subtitle: const Text('Configure and activate data destruction'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const EmergencyEraseScreen()),
            ),
          ),
          const Divider(height: 1),

          // ── Advanced ──────────────────────────────────────────────────────
          // Two informational screens the spec requires to be reachable from
          // the Security section (§22.10.4, §22.10.5).
          // PotentialExtremesScreen: features with real tradeoffs.
          // KnownLimitationsScreen: honest list of what Mesh Infinity cannot do.
          const _SectionHeader('Advanced'),
          ListTile(
            leading: const Icon(Icons.warning_amber_outlined),
            title: const Text('Potential extremes'),
            subtitle: const Text('Advanced features with explicit risk disclosures'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const PotentialExtremesScreen()),
            ),
          ),
          ListTile(
            leading: const Icon(Icons.info_outline),
            title: const Text('Known limitations'),
            subtitle: const Text('What Mesh Infinity cannot protect against'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const KnownLimitationsScreen()),
            ),
          ),
          const Divider(height: 1),

          // ── Cryptographic identity ─────────────────────────────────────────
          // IdentityScreen exposes the raw cryptographic keys, peer ID, and
          // pairing payload.  It is an advanced screen — most users never need
          // to visit it.  It is placed here (under Security) because the keys
          // are a security artifact, not a routine settings item.
          const _SectionHeader('Cryptographic identity'),
          ListTile(
            leading: const Icon(Icons.fingerprint_outlined),
            title: const Text('Advanced identity'),
            subtitle: const Text('Cryptographic keys and pairing payload'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const IdentityScreen()),
            ),
          ),
          const SizedBox(height: 24),
        ],
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // Threat level metadata helpers
  // ---------------------------------------------------------------------------

  /// Human-readable name for each threat level (0–3).
  String _threatLabel(int level) => switch (level) {
    0 => 'Normal',
    1 => 'Elevated',
    2 => 'High',
    3 => 'Critical',
    _ => 'Unknown',
  };

  /// One-sentence description of what each threat level enforces.
  String _threatDescription(int level) => switch (level) {
    0 => 'Standard operational profile. No extra restrictions.',
    1 => 'Reduces metadata exposure. Disables cloud wake signals.',
    2 => 'Forces Tor/I2P only. Suppresses all third-party services.',
    3 => 'Maximum isolation. All clearnet transports disabled.',
    _ => '',
  };

  /// Accent colour for each threat level — green → amber → red → purple
  /// maps intuitively from "safe" to "danger" to "maximum caution".
  Color _threatColor(int level) => switch (level) {
    0 => MeshTheme.brand,       // Normal: brand blue — standard operating colour
    1 => MeshTheme.secAmber,    // Elevated: amber — caution
    2 => MeshTheme.secRed,      // High: red — serious threat
    3 => MeshTheme.secPurple,   // Critical: purple — beyond normal threat scale
    _ => Colors.grey,
  };
}

// ---------------------------------------------------------------------------
// _SectionHeader — coloured section label
// ---------------------------------------------------------------------------

/// Small all-caps section label matching the settings design language.
class _SectionHeader extends StatelessWidget {
  const _SectionHeader(this.title);

  final String title;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 20, 16, 6),
      child: Text(
        title,
        style: Theme.of(context).textTheme.labelMedium?.copyWith(
              color: Theme.of(context).colorScheme.primary,
              fontWeight: FontWeight.w700,
              letterSpacing: 0.8,
            ),
      ),
    );
  }
}
