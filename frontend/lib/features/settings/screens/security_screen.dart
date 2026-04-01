import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/backend_bridge.dart';
import '../../../app/app_theme.dart';
import 'identity_screen.dart';
import 'killswitch_screen.dart';

// ---------------------------------------------------------------------------
// SecurityScreen — threat context, emergency erase, and advanced identity.
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

          // ── Emergency ───────────────────────────────────────────────
          const _SectionHeader('Emergency'),
          ListTile(
            leading: Icon(Icons.warning_amber_rounded, color: cs.error),
            title: Text(
              'Emergency data destruction',
              style: TextStyle(color: cs.error),
            ),
            subtitle: const Text('Permanently destroy all local data'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const KillswitchScreen()),
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
