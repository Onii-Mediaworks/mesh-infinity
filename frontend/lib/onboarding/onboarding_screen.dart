import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../backend/backend_bridge.dart';
import '../backend/models/settings_models.dart';

class OnboardingScreen extends StatefulWidget {
  const OnboardingScreen({super.key, required this.onComplete});

  final VoidCallback onComplete;

  @override
  State<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends State<OnboardingScreen> {
  LocalIdentitySummary? _identity;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _init();
  }

  void _init() {
    final bridge = context.read<BackendBridge>();
    // Identity is auto-created on first mesh_init if absent.
    // Fetch it so we can display the peer ID / pairing QR.
    final id = bridge.fetchLocalIdentity();
    if (mounted) {
      setState(() {
        _identity = id;
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 420),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const SizedBox(height: 24),
                  Icon(Icons.hub_rounded, size: 72, color: cs.primary),
                  const SizedBox(height: 16),
                  Text(
                    'Mesh Infinity',
                    style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Decentralised, encrypted peer-to-peer messaging.',
                    textAlign: TextAlign.center,
                    style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                      color: cs.onSurfaceVariant,
                    ),
                  ),
                  const SizedBox(height: 40),
                  if (_loading)
                    const CircularProgressIndicator()
                  else ...[
                    _IdentityCard(identity: _identity),
                    const SizedBox(height: 32),
                    FilledButton.icon(
                      onPressed: widget.onComplete,
                      icon: const Icon(Icons.arrow_forward_rounded),
                      label: const Text('Get Started'),
                      style: FilledButton.styleFrom(
                        minimumSize: const Size(double.infinity, 52),
                      ),
                    ),
                  ],
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _IdentityCard extends StatelessWidget {
  const _IdentityCard({required this.identity});

  final LocalIdentitySummary? identity;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final peerId = identity?.peerId ?? '';

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          children: [
            Text(
              'Your Identity',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 16),
            if (peerId.isNotEmpty) ...[
              Container(
                decoration: BoxDecoration(
                  color: Colors.white,
                  borderRadius: BorderRadius.circular(12),
                ),
                padding: const EdgeInsets.all(8),
                child: QrImageView(
                  data: peerId,
                  version: QrVersions.auto,
                  size: 180,
                  eyeStyle: QrEyeStyle(
                    eyeShape: QrEyeShape.square,
                    color: cs.primary,
                  ),
                ),
              ),
              const SizedBox(height: 16),
              Text(
                'Peer ID',
                style: Theme.of(context).textTheme.labelSmall?.copyWith(
                  color: cs.onSurfaceVariant,
                ),
              ),
              const SizedBox(height: 4),
              SelectableText(
                _formatPeerId(peerId),
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  fontFamily: 'monospace',
                ),
                textAlign: TextAlign.center,
              ),
            ] else ...[
              Icon(Icons.warning_amber_rounded, color: cs.error),
              const SizedBox(height: 8),
              Text(
                'Identity not yet available.\nThe backend may still be initialising.',
                textAlign: TextAlign.center,
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ],
          ],
        ),
      ),
    );
  }

  String _formatPeerId(String id) {
    if (id.length <= 16) return id;
    final buf = StringBuffer();
    for (var i = 0; i < id.length; i += 8) {
      if (i > 0) buf.write(' ');
      buf.write(id.substring(i, (i + 8).clamp(0, id.length)));
    }
    return buf.toString();
  }
}
