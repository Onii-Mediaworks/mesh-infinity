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

// ---------------------------------------------------------------------------
// SecurityScreen — threat context, PIN, emergency erase, and advanced identity.
//
// Sub-screens reachable from here (§22.10):
//   PinScreen             — §22.10.x  app lock PIN configuration
//   EmergencyEraseScreen  — §22.10.11 emergency data destruction triggers
//   PotentialExtremesScreen — §22.10.4 advanced features with risk disclosures
//   KnownLimitationsScreen  — §22.10.5 honest list of what we can't protect
//   IdentityScreen        — cryptographic keys and pairing payload
// ---------------------------------------------------------------------------

class SecurityScreen extends StatefulWidget {
  const SecurityScreen({super.key});

  @override
  State<SecurityScreen> createState() => _SecurityScreenState();
}

class _SecurityScreenState extends State<SecurityScreen> {
  int _threatLevel = 0;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  void _load() {
    final bridge = context.read<BackendBridge>();
    final level = bridge.getThreatContext();
    setState(() {
      _threatLevel = level;
      _loading = false;
    });
  }

  Future<void> _setThreatLevel(int level) async {
    final bridge = context.read<BackendBridge>();
    final ok = bridge.setThreatContext(level);
    if (ok && mounted) setState(() => _threatLevel = level);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;

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
          // ── Threat context ──────────────────────────────────────────
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
              if (v != null) _setThreatLevel(v);
            },
            child: Column(
              children: List.generate(4, (i) {
                final color = _threatColor(i);
                return RadioListTile<int>(
                  secondary: Icon(Icons.shield_outlined, color: color),
                  title: Text(
                    _threatLabel(i),
                    style:
                        TextStyle(color: color, fontWeight: FontWeight.w600),
                  ),
                  subtitle: Text(_threatDescription(i)),
                  value: i,
                );
              }),
            ),
          ),
          const Divider(height: 1),

          // ── App lock ────────────────────────────────────────────────
          // PIN protects the app from casual access without affecting the
          // mesh identity itself.  Configuring a PIN is optional but
          // recommended on shared or mobile devices (§22.10.x).
          const _SectionHeader('App lock'),
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
                    mode: settings.pinEnabled
                        ? PinScreenMode.change
                        : PinScreenMode.setup,
                  ),
                ),
              ),
            ),
          ),
          const Divider(height: 1),

          // ── Emergency ───────────────────────────────────────────────
          // EmergencyEraseScreen lets the user configure duress PIN,
          // wrong-PIN wipe threshold, remote trigger, and manual erase.
          // Replaces the old one-tap kill-switch with a richer flow (§22.10.11).
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

          // ── Advanced ────────────────────────────────────────────────
          // Two informational/advanced screens the spec requires to be
          // reachable from the Security section (§22.10.4, §22.10.5).
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

          // ── Cryptographic identity ──────────────────────────────────
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

  String _threatLabel(int level) => switch (level) {
    0 => 'Normal',
    1 => 'Elevated',
    2 => 'High',
    3 => 'Critical',
    _ => 'Unknown',
  };

  String _threatDescription(int level) => switch (level) {
    0 => 'Standard operational profile. No extra restrictions.',
    1 => 'Reduces metadata exposure. Disables cloud wake signals.',
    2 => 'Forces Tor/I2P only. Suppresses all third-party services.',
    3 => 'Maximum isolation. All clearnet transports disabled.',
    _ => '',
  };

  Color _threatColor(int level) => switch (level) {
    0 => MeshTheme.brand,
    1 => MeshTheme.secAmber,
    2 => MeshTheme.secRed,
    3 => MeshTheme.secPurple,
    _ => Colors.grey,
  };
}

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
