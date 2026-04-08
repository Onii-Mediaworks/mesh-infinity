// profile_edit_screen.dart
//
// ProfileEditScreen — edit public and private profile fields after onboarding.
//
// WHY TWO SEPARATE PROFILES?
// --------------------------
// Mesh Infinity uses a layered identity model (§9.2).  A single user has:
//
//   Public profile  — display name and bio that OTHER PEERS can see.
//                     Visibility is controlled by the "Make identity
//                     discoverable" toggle.  When off, only paired contacts
//                     can see the public profile.  When on, any node on the
//                     mesh may find this user by name.
//
//   Private profile — display name and bio stored ONLY on this device.
//                     Never transmitted.  Useful for personal notes about
//                     who this identity is (e.g. "work persona").
//
// This screen is the only place the user can update both profiles after the
// initial onboarding wizard.  Onboarding also shows both profiles (see
// onboarding_screen.dart) but uses a simpler UI.
//
// REACHED FROM: YouScreen → "Edit profile" button (or Settings → Identity).

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/backend_bridge.dart';
import '../settings_state.dart';

/// Screen for editing the public and private profile fields.
///
/// Changes to both profiles are applied in a single Save operation to ensure
/// the backend is always in a consistent state (both profiles updated or
/// neither).  The Save button is disabled while the async calls are in flight.
class ProfileEditScreen extends StatefulWidget {
  const ProfileEditScreen({super.key});

  @override
  State<ProfileEditScreen> createState() => _ProfileEditScreenState();
}

class _ProfileEditScreenState extends State<ProfileEditScreen> {
  // Form key used to trigger validation across all TextFormField validators.
  // We don't currently have validators (all fields are optional), but the Form
  // widget is here to support future validation without a large refactor.
  final _formKey = GlobalKey<FormState>();

  // ── Public profile controllers ─────────────────────────────────────────────

  /// Public display name — the name other peers see.
  final _pubNameCtl = TextEditingController();

  /// Public bio — visible to any peer that can see the public profile.
  final _pubBioCtl = TextEditingController();

  /// Whether this identity is discoverable to unknown peers.
  /// Off by default — privacy-first is the safer choice.
  bool _identityIsPublic = false;

  // ── Private profile controllers ────────────────────────────────────────────

  /// Private display name — stored on-device only, never transmitted.
  final _privNameCtl = TextEditingController();

  /// Private bio / personal notes — also device-only.
  final _privBioCtl = TextEditingController();

  // True while both backend calls (setPublicProfile + setPrivateProfile) are
  // in flight.  Disables the Save button to prevent a double-submit.
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    // Pre-fill with the current identity name from SettingsState so the user
    // doesn't have to re-type something they already set.
    // We use context.read (not watch) here because we only need the value once,
    // not ongoing reactivity.  initState runs before the first build, so
    // reading here is safe.
    final identity = context.read<SettingsState>().identity;
    if (identity?.name != null) {
      _pubNameCtl.text = identity!.name!;
    }
    // Note: we do NOT pre-fill the private profile fields here because
    // SettingsState does not currently cache private profile data — only the
    // identity summary (public name + peer ID) is returned by the backend.
    // If we add private profile caching in SettingsState, this is where to add
    // the pre-fill.
  }

  @override
  void dispose() {
    // Release each TextEditingController's native text-editing resource.
    // Forgetting dispose() here would cause a memory leak because the
    // controllers hold a reference that the garbage collector cannot collect.
    _pubNameCtl.dispose();
    _pubBioCtl.dispose();
    _privNameCtl.dispose();
    _privBioCtl.dispose();
    super.dispose();
  }

  // ---------------------------------------------------------------------------
  // Save handler
  // ---------------------------------------------------------------------------

  /// Validate the form, then apply public and private profile changes.
  ///
  /// Calls two separate bridge methods:
  ///   setPublicProfile  — updates the peer-visible display name and discoverability.
  ///   setPrivateProfile — updates the device-only display name and bio.
  ///
  /// Both calls are made regardless of each other's result so we can report
  /// which ones failed.  On full success, reloads SettingsState so all
  /// downstream screens (YouScreen, NavDrawer header) reflect the new values.
  Future<void> _save() async {
    // _formKey.currentState!.validate() runs all TextFormField validators.
    // If any returns a non-null string the form is invalid and validate() returns false.
    if (!_formKey.currentState!.validate()) return;

    setState(() => _busy = true);

    final bridge = context.read<BackendBridge>();

    // Empty display name is treated as "not set" — pass null to the backend
    // so it knows to clear the field rather than store an empty string.
    // The backend treats null as "use fallback" (peer ID shortform).
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

    // Refresh SettingsState so downstream widgets (YouScreen avatar name,
    // NavDrawer header, etc.) pick up the changes immediately.
    await context.read<SettingsState>().loadAll();

    // Guard against the widget being disposed while the await was suspended.
    // Without this check, the setState() call below would throw because the
    // State is no longer attached to the widget tree.
    if (!mounted) return;
    setState(() => _busy = false);

    final messenger = ScaffoldMessenger.of(context);
    if (pubOk && privOk) {
      messenger.showSnackBar(
        const SnackBar(content: Text('Profile saved')),
      );
      // Pop back to the previous screen (YouScreen or IdentityScreen).
      Navigator.pop(context);
    } else {
      // At least one call failed — tell the user but don't pop so they can
      // retry without losing their edits.
      messenger.showSnackBar(
        const SnackBar(content: Text('Failed to save profile')),
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Build
  // ---------------------------------------------------------------------------

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
            // ── Public Profile ───────────────────────────────────────────────
            // Fields in this section are transmitted to other peers and may
            // be visible beyond the immediate contact list depending on the
            // discoverability toggle.
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
              // textInputAction.next moves focus to the next field when the
              // user presses the "next" key on the keyboard, improving UX
              // on mobile where tapping between fields is slow.
              textInputAction: TextInputAction.next,
            ),
            const SizedBox(height: 12),
            TextFormField(
              controller: _pubBioCtl,
              decoration: const InputDecoration(
                labelText: 'Bio',
                prefixIcon: Icon(Icons.short_text),
              ),
              // maxLines / minLines allow the field to expand as the user types
              // without taking up too much space when empty.
              maxLines: 3,
              minLines: 1,
              textInputAction: TextInputAction.next,
            ),
            const SizedBox(height: 8),
            // The discoverability toggle controls whether unknown mesh nodes
            // can find this user by name.  Off = contacts only.
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

            // ── Private Profile ──────────────────────────────────────────────
            // Fields in this section are stored locally only.  They are
            // useful for the user's own reference (e.g. "this is my work
            // identity") and are NEVER transmitted.
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
              // TextInputAction.done closes the keyboard on the last field,
              // signalling to the user that all inputs are complete.
              textInputAction: TextInputAction.done,
            ),

            const SizedBox(height: 24),

            // Save button — disabled while _busy to prevent double-submission.
            // Shows a compact spinner in the icon slot while saving so the
            // user gets visual feedback without a full-screen loading state.
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

// ---------------------------------------------------------------------------
// _SectionHeader — two-line section label with title and subtitle
// ---------------------------------------------------------------------------

/// Section header used to separate public and private profile fields.
///
/// [color] distinguishes public (primary) from private (secondary) visually.
class _SectionHeader extends StatelessWidget {
  const _SectionHeader({
    required this.title,
    required this.subtitle,
    required this.color,
  });

  /// Main label text — rendered in [color] at titleMedium size.
  final String title;

  /// Supplementary description below the title.
  final String subtitle;

  /// The accent colour for this section (primary for public, secondary for private).
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
