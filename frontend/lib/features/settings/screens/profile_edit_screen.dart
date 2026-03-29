import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/backend_bridge.dart';
import '../settings_state.dart';

/// Screen for editing public and private profile fields after onboarding.
class ProfileEditScreen extends StatefulWidget {
  const ProfileEditScreen({super.key});

  @override
  State<ProfileEditScreen> createState() => _ProfileEditScreenState();
}

class _ProfileEditScreenState extends State<ProfileEditScreen> {
  final _formKey = GlobalKey<FormState>();

  final _pubNameCtl = TextEditingController();
  final _pubBioCtl = TextEditingController();
  bool _identityIsPublic = false;

  final _privNameCtl = TextEditingController();
  final _privBioCtl = TextEditingController();

  bool _busy = false;

  @override
  void initState() {
    super.initState();
    // Pre-fill with existing identity name if available.
    final identity = context.read<SettingsState>().identity;
    if (identity?.name != null) {
      _pubNameCtl.text = identity!.name!;
    }
  }

  @override
  void dispose() {
    _pubNameCtl.dispose();
    _pubBioCtl.dispose();
    _privNameCtl.dispose();
    _privBioCtl.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    if (!_formKey.currentState!.validate()) return;

    setState(() => _busy = true);

    final bridge = context.read<BackendBridge>();

    final pubOk = bridge.setPublicProfile(
      displayName: _pubNameCtl.text.trim().isEmpty
          ? null
          : _pubNameCtl.text.trim(),
      isPublic: _identityIsPublic,
    );

    final privOk = bridge.setPrivateProfile(
      displayName: _privNameCtl.text.trim().isEmpty
          ? null
          : _privNameCtl.text.trim(),
      bio: _privBioCtl.text.trim().isEmpty ? null : _privBioCtl.text.trim(),
    );

    // Refresh settings state so identity screen picks up changes.
    await context.read<SettingsState>().loadAll();

    if (!mounted) return;
    setState(() => _busy = false);

    final messenger = ScaffoldMessenger.of(context);
    if (pubOk && privOk) {
      messenger.showSnackBar(
        const SnackBar(content: Text('Profile saved')),
      );
      Navigator.pop(context);
    } else {
      messenger.showSnackBar(
        const SnackBar(content: Text('Failed to save profile')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    return Scaffold(
      appBar: AppBar(title: const Text('Edit Profile')),
      body: Form(
        key: _formKey,
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            // -- Public Profile --
            _SectionHeader(
              title: 'Public Profile',
              subtitle: 'Visible to peers you communicate with',
              color: cs.primary,
            ),
            const SizedBox(height: 8),
            TextFormField(
              controller: _pubNameCtl,
              decoration: const InputDecoration(
                labelText: 'Display name',
                prefixIcon: Icon(Icons.person_outline),
              ),
              textInputAction: TextInputAction.next,
            ),
            const SizedBox(height: 12),
            TextFormField(
              controller: _pubBioCtl,
              decoration: const InputDecoration(
                labelText: 'Bio',
                prefixIcon: Icon(Icons.short_text),
              ),
              maxLines: 3,
              minLines: 1,
              textInputAction: TextInputAction.next,
            ),
            const SizedBox(height: 8),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              title: const Text('Make identity discoverable'),
              subtitle: const Text(
                'When enabled, unknown peers on the mesh can find you by name.',
              ),
              value: _identityIsPublic,
              onChanged: (v) => setState(() => _identityIsPublic = v),
            ),

            const Divider(height: 32),

            // -- Private Profile --
            _SectionHeader(
              title: 'Private Profile',
              subtitle: 'Stored on this device only, never shared',
              color: cs.secondary,
            ),
            const SizedBox(height: 8),
            TextFormField(
              controller: _privNameCtl,
              decoration: const InputDecoration(
                labelText: 'Private display name',
                prefixIcon: Icon(Icons.lock_outline),
              ),
              textInputAction: TextInputAction.next,
            ),
            const SizedBox(height: 12),
            TextFormField(
              controller: _privBioCtl,
              decoration: const InputDecoration(
                labelText: 'Private bio',
                prefixIcon: Icon(Icons.note_outlined),
              ),
              maxLines: 3,
              minLines: 1,
              textInputAction: TextInputAction.done,
            ),

            const SizedBox(height: 24),

            FilledButton.icon(
              onPressed: _busy ? null : _save,
              icon: _busy
                  ? const SizedBox(
                      width: 18,
                      height: 18,
                      child: CircularProgressIndicator(
                        strokeWidth: 2,
                        color: Colors.white,
                      ),
                    )
                  : const Icon(Icons.save_outlined),
              label: Text(_busy ? 'Saving...' : 'Save Profile'),
            ),
          ],
        ),
      ),
    );
  }
}

class _SectionHeader extends StatelessWidget {
  const _SectionHeader({
    required this.title,
    required this.subtitle,
    required this.color,
  });

  final String title;
  final String subtitle;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          title,
          style: Theme.of(context).textTheme.titleMedium?.copyWith(
                color: color,
                fontWeight: FontWeight.bold,
              ),
        ),
        const SizedBox(height: 2),
        Text(
          subtitle,
          style: Theme.of(context).textTheme.bodySmall?.copyWith(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
        ),
      ],
    );
  }
}
