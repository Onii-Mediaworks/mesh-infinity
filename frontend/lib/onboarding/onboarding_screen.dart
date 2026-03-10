import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../backend/backend_bridge.dart';

enum _Step { choice, importBackup, publicProfile, privateProfile }

class OnboardingScreen extends StatefulWidget {
  const OnboardingScreen({super.key, required this.onComplete});

  final VoidCallback onComplete;

  @override
  State<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends State<OnboardingScreen> {
  _Step _step = _Step.choice;
  bool _busy = false;
  String? _error;

  // Public profile
  final _pubName = TextEditingController();
  bool _identityPublic = false; // "don't show my identity publicly" is pre-checked

  // Private profile
  final _privName = TextEditingController();
  final _privBio = TextEditingController();

  // Import
  final _phrase = TextEditingController();

  @override
  void dispose() {
    _pubName.dispose();
    _privName.dispose();
    _privBio.dispose();
    _phrase.dispose();
    super.dispose();
  }

  Future<void> _createIdentity() async {
    final bridge = context.read<BackendBridge>();
    setState(() {
      _busy = true;
      _error = null;
    });
    final ok = bridge.createIdentity();
    if (!mounted) return;
    if (ok) {
      setState(() {
        _busy = false;
        _step = _Step.publicProfile;
      });
    } else {
      setState(() {
        _busy = false;
        _error = bridge.getLastError() ?? 'Failed to create identity.';
      });
    }
  }

  Future<void> _importBackup() async {
    // The field expects the passphrase on the first line and the backup JSON
    // (the EncryptedBackup payload) on the remaining lines.
    final text = _phrase.text.trim();
    if (text.isEmpty) {
      setState(() => _error = 'Please enter your passphrase and backup data.');
      return;
    }
    final newlineIdx = text.indexOf('\n');
    final passphrase =
        newlineIdx >= 0 ? text.substring(0, newlineIdx).trim() : text;
    final backupJson =
        newlineIdx >= 0 ? text.substring(newlineIdx + 1).trim() : '';
    if (backupJson.isEmpty) {
      setState(() => _error =
          'Paste your passphrase on the first line and the backup JSON below it.');
      return;
    }
    final bridge = context.read<BackendBridge>();
    setState(() {
      _busy = true;
      _error = null;
    });
    final ok = bridge.importIdentity(backupJson: backupJson, passphrase: passphrase);
    if (!mounted) return;
    if (ok) {
      setState(() {
        _busy = false;
        _step = _Step.publicProfile;
      });
    } else {
      setState(() {
        _busy = false;
        _error = bridge.getLastError() ??
            'Import failed. Check your passphrase and backup data.';
      });
    }
  }

  void _finishProfiles() {
    final bridge = context.read<BackendBridge>();
    final pubName = _pubName.text.trim();
    final privName = _privName.text.trim();
    final bio = _privBio.text.trim();
    bridge.setPublicProfile(
      displayName: pubName.isEmpty ? null : pubName,
      isPublic: _identityPublic,
    );
    bridge.setPrivateProfile(
      displayName: privName.isEmpty ? null : privName,
      bio: bio.isEmpty ? null : bio,
    );
    widget.onComplete();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 420),
              child: AnimatedSwitcher(
                duration: const Duration(milliseconds: 250),
                transitionBuilder: (child, anim) => FadeTransition(
                  opacity: anim,
                  child: child,
                ),
                child: _buildStep(),
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildStep() {
    switch (_step) {
      case _Step.choice:
        return _ChoiceStep(
          key: const ValueKey(_Step.choice),
          busy: _busy,
          error: _error,
          onCreateNew: _createIdentity,
          onImport: () => setState(() {
            _step = _Step.importBackup;
            _error = null;
          }),
        );
      case _Step.importBackup:
        return _ImportStep(
          key: const ValueKey(_Step.importBackup),
          controller: _phrase,
          busy: _busy,
          error: _error,
          onImport: _importBackup,
          onBack: () => setState(() {
            _step = _Step.choice;
            _error = null;
          }),
        );
      case _Step.publicProfile:
        return _PublicProfileStep(
          key: const ValueKey(_Step.publicProfile),
          controller: _pubName,
          isPublic: _identityPublic,
          onPublicChanged: (v) => setState(() => _identityPublic = v),
          onNext: () => setState(() => _step = _Step.privateProfile),
        );
      case _Step.privateProfile:
        return _PrivateProfileStep(
          key: const ValueKey(_Step.privateProfile),
          nameController: _privName,
          bioController: _privBio,
          onBack: () => setState(() => _step = _Step.publicProfile),
          onDone: _finishProfiles,
        );
    }
  }
}

// ---------------------------------------------------------------------------
// Shared header
// ---------------------------------------------------------------------------

class _Header extends StatelessWidget {
  const _Header({required this.title, this.subtitle});

  final String title;
  final String? subtitle;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Column(
      children: [
        const SizedBox(height: 16),
        const _Logo(size: 64),
        const SizedBox(height: 16),
        Text(
          'Mesh Infinity',
          style: Theme.of(context).textTheme.headlineMedium?.copyWith(
            fontWeight: FontWeight.bold,
          ),
        ),
        const SizedBox(height: 8),
        Text(
          title,
          style: Theme.of(context).textTheme.titleMedium,
        ),
        if (subtitle != null) ...[
          const SizedBox(height: 4),
          Text(
            subtitle!,
            textAlign: TextAlign.center,
            style: Theme.of(context).textTheme.bodySmall?.copyWith(
              color: cs.onSurfaceVariant,
            ),
          ),
        ],
        const SizedBox(height: 32),
      ],
    );
  }
}

class _Logo extends StatelessWidget {
  const _Logo({required this.size});

  final double size;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Image.asset(
      '../assets/logo.png',
      width: size,
      height: size,
      errorBuilder: (context, error, stackTrace) =>
          Icon(Icons.hub_rounded, size: size, color: cs.primary),
    );
  }
}

// ---------------------------------------------------------------------------
// Step: choice
// ---------------------------------------------------------------------------

class _ChoiceStep extends StatelessWidget {
  const _ChoiceStep({
    super.key,
    required this.busy,
    required this.error,
    required this.onCreateNew,
    required this.onImport,
  });

  final bool busy;
  final String? error;
  final VoidCallback onCreateNew;
  final VoidCallback onImport;

  @override
  Widget build(BuildContext context) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        const _Header(
          title: 'Welcome',
          subtitle: 'Decentralised, encrypted peer-to-peer messaging.',
        ),
        if (error != null) ...[
          _ErrorBanner(error!),
          const SizedBox(height: 16),
        ],
        FilledButton.icon(
          onPressed: busy ? null : onCreateNew,
          icon: busy
              ? const SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Icon(Icons.person_add_rounded),
          label: const Text('Create New Identity'),
          style: FilledButton.styleFrom(
            minimumSize: const Size(double.infinity, 52),
          ),
        ),
        const SizedBox(height: 12),
        OutlinedButton.icon(
          onPressed: busy ? null : onImport,
          icon: const Icon(Icons.download_rounded),
          label: const Text('Import Backup'),
          style: OutlinedButton.styleFrom(
            minimumSize: const Size(double.infinity, 52),
          ),
        ),
        const SizedBox(height: 8),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// Step: import backup
// ---------------------------------------------------------------------------

class _ImportStep extends StatelessWidget {
  const _ImportStep({
    super.key,
    required this.controller,
    required this.busy,
    required this.error,
    required this.onImport,
    required this.onBack,
  });

  final TextEditingController controller;
  final bool busy;
  final String? error;
  final VoidCallback onImport;
  final VoidCallback onBack;

  @override
  Widget build(BuildContext context) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const _Header(
          title: 'Import Backup',
          subtitle:
              'Paste your passphrase on the first line, then your backup JSON below it.',
        ),
        if (error != null) ...[
          _ErrorBanner(error!),
          const SizedBox(height: 16),
        ],
        TextField(
          controller: controller,
          enabled: !busy,
          minLines: 3,
          maxLines: 6,
          decoration: const InputDecoration(
            labelText: 'Backup phrase',
            hintText: 'passphrase\n{"version":1,"salt":...}',
            border: OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 20),
        FilledButton(
          onPressed: busy ? null : onImport,
          style: FilledButton.styleFrom(minimumSize: const Size(double.infinity, 52)),
          child: busy
              ? const SizedBox(
                  width: 20,
                  height: 20,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Text('Import'),
        ),
        const SizedBox(height: 12),
        TextButton(
          onPressed: busy ? null : onBack,
          child: const Text('Back'),
        ),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// Step: public profile
// ---------------------------------------------------------------------------

class _PublicProfileStep extends StatelessWidget {
  const _PublicProfileStep({
    super.key,
    required this.controller,
    required this.isPublic,
    required this.onPublicChanged,
    required this.onNext,
  });

  final TextEditingController controller;
  final bool isPublic;
  final ValueChanged<bool> onPublicChanged;
  final VoidCallback onNext;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const _Header(
          title: 'Public Profile',
          subtitle:
              'This information may be visible to peers who discover you.',
        ),
        TextField(
          controller: controller,
          decoration: const InputDecoration(
            labelText: 'Display name (optional)',
            hintText: 'e.g. Alice',
            border: OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 8),
        Card(
          margin: EdgeInsets.zero,
          child: CheckboxListTile(
            value: !isPublic,
            onChanged: (v) => onPublicChanged(!(v ?? true)),
            title: const Text("Don't show my identity publicly"),
            subtitle: Text(
              'Your peer ID will only be shared with contacts you add.',
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                color: cs.onSurfaceVariant,
              ),
            ),
            controlAffinity: ListTileControlAffinity.leading,
            contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
          ),
        ),
        const SizedBox(height: 24),
        FilledButton(
          onPressed: onNext,
          style: FilledButton.styleFrom(minimumSize: const Size(double.infinity, 52)),
          child: const Text('Next'),
        ),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// Step: private profile
// ---------------------------------------------------------------------------

class _PrivateProfileStep extends StatelessWidget {
  const _PrivateProfileStep({
    super.key,
    required this.nameController,
    required this.bioController,
    required this.onBack,
    required this.onDone,
  });

  final TextEditingController nameController;
  final TextEditingController bioController;
  final VoidCallback onBack;
  final VoidCallback onDone;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const _Header(
          title: 'Private Profile',
          subtitle: 'Stored only on this device. Never shared with peers.',
        ),
        TextField(
          controller: nameController,
          decoration: const InputDecoration(
            labelText: 'Your name (optional)',
            hintText: 'e.g. Alice Smith',
            border: OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 16),
        TextField(
          controller: bioController,
          minLines: 3,
          maxLines: 6,
          decoration: const InputDecoration(
            labelText: 'About me (optional)',
            hintText: 'Notes for yourself…',
            border: OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 8),
        Text(
          'You can update this at any time in Settings.',
          style: Theme.of(context).textTheme.bodySmall?.copyWith(
            color: cs.onSurfaceVariant,
          ),
        ),
        const SizedBox(height: 24),
        FilledButton.icon(
          onPressed: onDone,
          icon: const Icon(Icons.arrow_forward_rounded),
          label: const Text('Get Started'),
          style: FilledButton.styleFrom(minimumSize: const Size(double.infinity, 52)),
        ),
        const SizedBox(height: 12),
        TextButton(
          onPressed: onBack,
          child: const Text('Back'),
        ),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// Shared error banner
// ---------------------------------------------------------------------------

class _ErrorBanner extends StatelessWidget {
  const _ErrorBanner(this.message);

  final String message;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      decoration: BoxDecoration(
        color: cs.errorContainer,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        children: [
          Icon(Icons.warning_amber_rounded, color: cs.onErrorContainer, size: 20),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              message,
              style: TextStyle(color: cs.onErrorContainer),
            ),
          ),
        ],
      ),
    );
  }
}
