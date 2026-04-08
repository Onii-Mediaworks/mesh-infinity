// create_group_screen.dart
//
// CreateGroupScreen lets the user create a new group room ("garden") with
// a name, optional description, and a networkType (visibility / join policy).
//
// WHAT IS networkType?
// --------------------
// networkType controls who can discover and join the group:
//
//   Private (0) — Invitation only.  The group is completely hidden from
//                 the mesh discovery layer.  Outsiders cannot even tell it
//                 exists.
//   Closed  (1) — Invitation only.  The group name is visible on the mesh
//                 but only invited members can join.
//   Open    (2) — Anyone can request to join; an admin approves requests.
//   Public  (3) — Anyone on the mesh can join without approval.
//
// WHY INTEGER VALUES?
// -------------------
// The backend expects an integer (0–3) for the networkType field, not a
// string.  Using named constants in a static list keeps the values readable
// in code while still sending the right integer to Rust.
//
// FLOW
// ----
//   1. User fills in name (required), description (optional), networkType.
//   2. Taps "Create Group" → _create() validates the form.
//   3. _create() calls bridge.createGroup() → Rust creates the group and a
//      linked room, returning a map containing the new roomId.
//   4. loadRooms() is called so the new group appears in the Garden list.
//   5. The screen pops with the new roomId so the caller can navigate there.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/backend_bridge.dart';
// BackendBridge — gateway to Rust; specifically createGroup() is used here.
import '../messaging_state.dart';
// MessagingState — we call loadRooms() after creation so the new group
// appears in the room list without a manual pull-to-refresh.

/// Screen for creating a new group room (§8.7).
///
/// Pops with the new room's ID (a String) on success, or null if the user
/// cancelled without creating.
class CreateGroupScreen extends StatefulWidget {
  const CreateGroupScreen({super.key});

  @override
  State<CreateGroupScreen> createState() => _CreateGroupScreenState();
}

class _CreateGroupScreenState extends State<CreateGroupScreen> {
  // ---------------------------------------------------------------------------
  // Form state
  // ---------------------------------------------------------------------------

  /// GlobalKey lets us call _formKey.currentState!.validate() from _create()
  /// to trigger inline validation on all TextFormFields at once.
  final _formKey = GlobalKey<FormState>();

  /// Controller for the group name field.
  final _nameCtrl = TextEditingController();

  /// Controller for the optional description field.
  final _descCtrl = TextEditingController();

  /// Currently selected networkType.  Defaults to Private (0) — the most
  /// restrictive setting, following a "safe by default" UX principle.
  int _networkType = 0; // 0=Private, 1=Closed, 2=Open, 3=Public

  /// True while the backend createGroup() call is in flight.
  /// Disables the Create button to prevent double-submission.
  bool _creating = false;

  /// The four networkType options shown in the radio group.
  /// Each entry has a value (the integer the backend expects), a label
  /// (shown as the radio tile title), and a hint (shown as the subtitle
  /// to explain what the policy means in plain language).
  static const _networkTypes = [
    (value: 0, label: 'Private',  hint: 'Invitation only, profile hidden'),
    (value: 1, label: 'Closed',   hint: 'Invitation only, name visible'),
    (value: 2, label: 'Open',     hint: 'Join with approval'),
    (value: 3, label: 'Public',   hint: 'Anyone can join'),
  ];

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  @override
  void dispose() {
    // Always dispose TextEditingControllers to free platform text-input
    // resources (especially important on Android/iOS where the OS maintains
    // an IME connection as long as the controller is alive).
    _nameCtrl.dispose();
    _descCtrl.dispose();
    super.dispose();
  }

  // ---------------------------------------------------------------------------
  // Create action
  // ---------------------------------------------------------------------------

  /// Validates the form, calls the backend to create the group, and navigates.
  ///
  /// The [_creating] flag is set before the backend call and cleared after,
  /// disabling the Create button to prevent a double-tap from creating
  /// two identical groups.
  ///
  /// On success:
  ///   1. loadRooms() updates the room list in MessagingState.
  ///   2. The screen pops with the new roomId so the caller (GardenScreen
  ///      or CreateRoomScreen) can navigate directly to the new group thread.
  ///
  /// On failure:
  ///   A SnackBar is shown and the form remains visible so the user can retry.
  Future<void> _create() async {
    // Form.validate() triggers validators on all TextFormFields.
    // Returns false if any field fails validation.
    if (!_formKey.currentState!.validate()) return;

    setState(() => _creating = true);

    final bridge = context.read<BackendBridge>();
    final result = bridge.createGroup(
      name: _nameCtrl.text.trim(),
      description: _descCtrl.text.trim(),
      networkType: _networkType,
    );

    setState(() => _creating = false);

    // Guard: user could navigate away while the backend call was in progress.
    if (!mounted) return;

    if (result == null) {
      // Backend returned null — creation failed (e.g. name conflict, storage
      // error).  Keep the form open so the user can adjust and retry.
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Failed to create group')),
      );
      return;
    }

    // Success: refresh the room list so the new group appears in GardenScreen.
    await context.read<MessagingState>().loadRooms();

    if (mounted) {
      // Pop with the roomId so the caller can navigate to the new group thread.
      Navigator.pop(context, result['roomId'] as String?);
    }
  }

  // ---------------------------------------------------------------------------
  // Build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    return Scaffold(
      appBar: AppBar(title: const Text('New Group')),
      body: Form(
        key: _formKey,
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            // Group avatar placeholder — a generic group icon in a large circle.
            // Avatar customisation (photo upload) is a future feature.
            Center(
              child: CircleAvatar(
                radius: 40,
                backgroundColor: cs.primaryContainer,
                child: Icon(Icons.group_outlined, size: 40, color: cs.onPrimaryContainer),
              ),
            ),
            const SizedBox(height: 24),

            // Name field — required, max 64 characters.
            // counterText: '' suppresses the default "0/64" character counter
            // that Flutter shows by default for maxLength fields.
            TextFormField(
              controller: _nameCtrl,
              decoration: const InputDecoration(
                labelText: 'Group name *',
                border: OutlineInputBorder(),
                counterText: '',
              ),
              maxLength: 64,
              // Auto-capitalise the first letter of the name for ergonomics.
              textCapitalization: TextCapitalization.sentences,
              validator: (v) {
                if (v == null || v.trim().isEmpty) return 'Name is required';
                if (v.trim().length > 64) return 'Max 64 characters';
                return null;
              },
            ),
            const SizedBox(height: 16),

            // Description field — optional, max 256 characters.
            TextFormField(
              controller: _descCtrl,
              decoration: const InputDecoration(
                labelText: 'Description (optional)',
                border: OutlineInputBorder(),
                counterText: '',
              ),
              maxLength: 256,
              maxLines: 3, // Tall enough to show ~2 sentences at once.
            ),
            const SizedBox(height: 24),

            // Network-type selector — radio group for the four join policies.
            Text('Visibility', style: Theme.of(context).textTheme.titleSmall),
            const SizedBox(height: 8),
            RadioGroup<int>(
              groupValue: _networkType,
              onChanged: (v) => setState(() => _networkType = v!),
              child: Column(
                children: _networkTypes.map((t) => RadioListTile<int>(
                  value: t.value,
                  title: Text(t.label),
                  subtitle: Text(t.hint),
                  contentPadding: EdgeInsets.zero,
                )).toList(),
              ),
            ),

            const SizedBox(height: 32),

            // Create button — shows a spinner while _creating is true.
            // onPressed is null (disabled) during creation to prevent
            // double-submit.
            FilledButton.icon(
              onPressed: _creating ? null : _create,
              icon: _creating
                  ? const SizedBox(
                      width: 16,
                      height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.check),
              label: const Text('Create Group'),
            ),
          ],
        ),
      ),
    );
  }
}
