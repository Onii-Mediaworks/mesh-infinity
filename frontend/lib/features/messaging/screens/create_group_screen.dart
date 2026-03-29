import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/backend_bridge.dart';
import '../messaging_state.dart';

/// Screen for creating a new group (§8.7).
///
/// The user sets a name, optional description, and visibility/join policy.
/// On success the backend creates the group + a linked room, and we navigate
/// to that room's thread.
class CreateGroupScreen extends StatefulWidget {
  const CreateGroupScreen({super.key});

  @override
  State<CreateGroupScreen> createState() => _CreateGroupScreenState();
}

class _CreateGroupScreenState extends State<CreateGroupScreen> {
  final _formKey = GlobalKey<FormState>();
  final _nameCtrl = TextEditingController();
  final _descCtrl = TextEditingController();
  int _networkType = 0; // 0=Private, 1=Closed, 2=Open, 3=Public
  bool _creating = false;

  static const _networkTypes = [
    (value: 0, label: 'Private',  hint: 'Invitation only, profile hidden'),
    (value: 1, label: 'Closed',   hint: 'Invitation only, name visible'),
    (value: 2, label: 'Open',     hint: 'Join with approval'),
    (value: 3, label: 'Public',   hint: 'Anyone can join'),
  ];

  @override
  void dispose() {
    _nameCtrl.dispose();
    _descCtrl.dispose();
    super.dispose();
  }

  Future<void> _create() async {
    if (!_formKey.currentState!.validate()) return;
    setState(() => _creating = true);

    final bridge = context.read<BackendBridge>();
    final result = bridge.createGroup(
      name: _nameCtrl.text.trim(),
      description: _descCtrl.text.trim(),
      networkType: _networkType,
    );

    setState(() => _creating = false);

    if (!mounted) return;

    if (result == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Failed to create group')),
      );
      return;
    }

    // Reload rooms so the new group room appears.
    await context.read<MessagingState>().loadRooms();

    if (mounted) {
      // Return the roomId to the caller so it can navigate to the thread.
      Navigator.pop(context, result['roomId'] as String?);
    }
  }

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
            // Group avatar placeholder
            Center(
              child: CircleAvatar(
                radius: 40,
                backgroundColor: cs.primaryContainer,
                child: Icon(Icons.group_outlined, size: 40, color: cs.onPrimaryContainer),
              ),
            ),
            const SizedBox(height: 24),

            // Name field
            TextFormField(
              controller: _nameCtrl,
              decoration: const InputDecoration(
                labelText: 'Group name *',
                border: OutlineInputBorder(),
                counterText: '',
              ),
              maxLength: 64,
              textCapitalization: TextCapitalization.sentences,
              validator: (v) {
                if (v == null || v.trim().isEmpty) return 'Name is required';
                if (v.trim().length > 64) return 'Max 64 characters';
                return null;
              },
            ),
            const SizedBox(height: 16),

            // Description field
            TextFormField(
              controller: _descCtrl,
              decoration: const InputDecoration(
                labelText: 'Description (optional)',
                border: OutlineInputBorder(),
                counterText: '',
              ),
              maxLength: 256,
              maxLines: 3,
            ),
            const SizedBox(height: 24),

            // Network type selector
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
