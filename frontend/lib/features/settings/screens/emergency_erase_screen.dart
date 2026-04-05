// emergency_erase_screen.dart
//
// EmergencyEraseScreen — configure and activate emergency data destruction (§22.10.11).
//
// WHAT EMERGENCY ERASE DOES:
// ---------------------------
// Emergency erase immediately and permanently deletes:
//   - The identity key pair (Layer 1 + Layer 2 keys)
//   - All message history
//   - All cached contacts, sessions, and routing state
//   - All app data on this device
//
// It also broadcasts a "self-disavowed" signal to trusted contacts so they
// know not to trust further messages from this device (§3.9.2).
//
// TRIGGERS (configured on this screen):
//   1. Auto-wipe on wrong PIN — erase after N consecutive failures.
//   2. Remote trigger — a Level-8 (InnerCircle) contact can trigger erase
//      remotely if you're unreachable.
//   3. Manual activation — the "Erase now" button at the bottom with
//      a two-step confirmation dialog.
//
// DESIGN PHILOSOPHY:
// ------------------
// This is a serious screen.  It uses error colour (not amber) for the manual
// erase button because this action is irreversible.  Everything else uses
// muted/neutral styling — the configuration steps are routine safety hygiene,
// not alarming.  The spec requires non-alarmist framing (§22.22).
//
// Reached from: Settings → Security → Emergency erase.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/backend_bridge.dart';
import '../settings_state.dart';
// ---------------------------------------------------------------------------
// EmergencyEraseScreen
// ---------------------------------------------------------------------------

/// Allows configuration of emergency erase triggers and manual activation.
class EmergencyEraseScreen extends StatelessWidget {
  const EmergencyEraseScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final settings = context.watch<SettingsState>();
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    return Scaffold(
      appBar: AppBar(title: const Text('Emergency Erase')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // ---------------------------------------------------------------------------
          // Explanation card
          // ---------------------------------------------------------------------------
          // Tells the user what the erase covers before they see any toggles.
          // Clear scope description prevents surprises (§22.22 plain language).
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Icon(Icons.emergency_outlined, size: 20, color: cs.error),
                      const SizedBox(width: 8),
                      Text('What this does', style: tt.titleSmall),
                    ],
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Emergency erase immediately deletes your identity, keys, '
                    'and all message history. It also broadcasts a '
                    '"self-disavowed" signal to your contacts so they know not '
                    'to trust further messages from this device.\n\n'
                    'Configure a trigger now — you want this ready before you '
                    'need it.',
                    style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
                  ),
                ],
              ),
            ),
          ),

          const SizedBox(height: 16),

          // ---------------------------------------------------------------------------
          // Duress PIN status
          // ---------------------------------------------------------------------------
          const _SectionHeader('Duress PIN'),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
            child: Text(
              'A duress PIN looks like a normal unlock, but it immediately '
              'wipes your current local identity and opens a fresh account. '
              'Use a PIN you can remember under pressure.',
              style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
            ),
          ),
          ListTile(
            leading: Icon(
              settings.duressPinConfigured
                  ? Icons.lock_reset_outlined
                  : Icons.password_outlined,
            ),
            title: Text(
              settings.duressPinConfigured
                  ? 'Duress PIN is configured'
                  : 'No duress PIN configured',
            ),
            subtitle: const Text(
              'Entering it at unlock destroys the current account on this device.',
            ),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
            child: Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                FilledButton.tonal(
                  onPressed: () => _showDuressPinDialog(
                    context,
                    mode: settings.duressPinConfigured
                        ? _DuressPinDialogMode.change
                        : _DuressPinDialogMode.set,
                  ),
                  child: Text(
                    settings.duressPinConfigured ? 'Change duress PIN' : 'Set duress PIN',
                  ),
                ),
                if (settings.duressPinConfigured)
                  OutlinedButton(
                    onPressed: () => _showDuressPinDialog(
                      context,
                      mode: _DuressPinDialogMode.remove,
                    ),
                    child: const Text('Remove duress PIN'),
                  ),
              ],
            ),
          ),

          const Divider(height: 1),
          const SizedBox(height: 8),

          // ---------------------------------------------------------------------------
          // Auto-wipe on wrong PIN
          // ---------------------------------------------------------------------------
          const _SectionHeader('Auto-wipe on wrong PIN'),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
            child: Text(
              'Automatically erase after too many wrong PIN attempts. '
              'Disabled by default.',
              style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
            ),
          ),
          SwitchListTile(
            title: const Text('Enable wrong-PIN wipe'),
            value: settings.wrongPinWipeEnabled,
            onChanged: (value) =>
                _updateSecurityConfig(context, {'wrongPinWipeEnabled': value}),
          ),
          // Threshold dropdown — only shown when wrong-PIN wipe is enabled.
          if (settings.wrongPinWipeEnabled)
            ListTile(
              title: const Text('Wipe after'),
              trailing: DropdownButton<int>(
                value: settings.wrongPinWipeThreshold,
                items: [3, 5, 10]
                    .map(
                      (n) => DropdownMenuItem(
                        value: n,
                        child: Text('$n attempts'),
                      ),
                    )
                    .toList(),
                onChanged: (value) {
                  if (value == null) return;
                  _updateSecurityConfig(context, {
                    'wrongPinWipeThreshold': value,
                  });
                },
              ),
            ),

          const Divider(height: 1),
          const SizedBox(height: 8),

          // ---------------------------------------------------------------------------
          // Remote trigger
          // ---------------------------------------------------------------------------
          // A Level-8 trusted contact can trigger erase if they believe you're
          // unreachable.  Only works if both parties have configured it.
          const _SectionHeader('Remote trigger'),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
            child: Text(
              'A trusted contact with InnerCircle (Level 8) status can trigger '
              "an erase remotely if you're unreachable.",
              style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
            ),
          ),
          SwitchListTile(
            title: const Text('Allow remote erase'),
            subtitle: const Text(
              'Only trusted peers you explicitly authorize should be able to trigger this.',
            ),
            value: settings.remoteWipeEnabled,
            onChanged: (value) =>
                _updateSecurityConfig(context, {'remoteWipeEnabled': value}),
          ),

          const SizedBox(height: 32),

          // ---------------------------------------------------------------------------
          // Manual activation
          // ---------------------------------------------------------------------------
          // Full-width outlined button in error colour.  Two-step confirmation
          // (this button → AlertDialog) prevents accidental activation.
          OutlinedButton.icon(
            onPressed: () => _confirmManualErase(context),
            icon: const Icon(Icons.delete_forever_outlined),
            label: const Text('Erase now'),
            style: OutlinedButton.styleFrom(
              foregroundColor: cs.error,
              minimumSize: const Size(double.infinity, 52),
            ),
          ),

          const SizedBox(height: 16),
        ],
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // Manual erase confirmation dialog
  // ---------------------------------------------------------------------------

  /// Shows a two-step confirmation before triggering manual erase.
  ///
  /// The first tap opens the dialog; the second tap (confirm) is the point of
  /// no return.  A dismissable barrierDismissible is set to false so the user
  /// must make an explicit choice (Erase vs Cancel).
  void _confirmManualErase(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    showDialog<void>(
      context: context,
      barrierDismissible: false, // force an explicit button tap
      builder: (_) => AlertDialog(
        title: Row(
          children: [
            Icon(Icons.warning_rounded, color: cs.error),
            const SizedBox(width: 8),
            const Text('Erase everything?'),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'This will immediately and permanently delete:',
              style: tt.bodySmall,
            ),
            const SizedBox(height: 8),
            Text(
              '• Your identity and all cryptographic keys\n'
              '• All messages and conversation history\n'
              '• All contacts and trust records\n'
              '• All sessions and routing state\n\n'
              'This cannot be undone.',
              style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
            ),
          ],
        ),
        actions: [
          // Cancel — safe path, clearly labelled.
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          // Erase — destructive, uses error colour.
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: cs.error),
            onPressed: () {
              Navigator.pop(context);
              final bridge = context.read<BackendBridge>();
              final ok = bridge.emergencyErase();
              if (ok) {
                Navigator.of(context).popUntil((route) => route.isFirst);
                return;
              }
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Emergency erase failed.')),
              );
            },
            child: const Text('Erase'),
          ),
        ],
      ),
    );
  }

  Future<void> _updateSecurityConfig(
    BuildContext context,
    Map<String, dynamic> config,
  ) async {
    final ok = await context.read<SettingsState>().updateSecurityConfig(config);
    if (!context.mounted || ok) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Failed to update security setting.')),
    );
  }

  Future<void> _showDuressPinDialog(
    BuildContext context, {
    required _DuressPinDialogMode mode,
  }) async {
    final bridge = context.read<BackendBridge>();
    final settings = context.read<SettingsState>();
    final currentController = TextEditingController();
    final newController = TextEditingController();
    final confirmController = TextEditingController();
    final removeController = TextEditingController();
    final title = switch (mode) {
      _DuressPinDialogMode.set => 'Set duress PIN',
      _DuressPinDialogMode.change => 'Change duress PIN',
      _DuressPinDialogMode.remove => 'Remove duress PIN',
    };

    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: Text(title),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (mode == _DuressPinDialogMode.change)
              TextField(
                controller: currentController,
                obscureText: true,
                keyboardType: TextInputType.number,
                decoration: const InputDecoration(labelText: 'Current duress PIN'),
              ),
            if (mode != _DuressPinDialogMode.remove) ...[
              TextField(
                controller: newController,
                obscureText: true,
                keyboardType: TextInputType.number,
                decoration: InputDecoration(
                  labelText: mode == _DuressPinDialogMode.set ? 'New duress PIN' : 'Replacement duress PIN',
                ),
              ),
              TextField(
                controller: confirmController,
                obscureText: true,
                keyboardType: TextInputType.number,
                decoration: const InputDecoration(labelText: 'Confirm duress PIN'),
              ),
            ],
            if (mode == _DuressPinDialogMode.remove)
              TextField(
                controller: removeController,
                obscureText: true,
                keyboardType: TextInputType.number,
                decoration: const InputDecoration(labelText: 'Current duress PIN'),
              ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(dialogContext, true),
            child: Text(
              switch (mode) {
                _DuressPinDialogMode.set => 'Save',
                _DuressPinDialogMode.change => 'Change',
                _DuressPinDialogMode.remove => 'Remove',
              },
            ),
          ),
        ],
      ),
    );

    if (confirmed != true) {
      return;
    }
    if (!context.mounted) {
      return;
    }

    bool ok = false;
    if (mode == _DuressPinDialogMode.remove) {
      ok = bridge.removeDuressPin(removeController.text.trim());
    } else {
      final newPin = newController.text.trim();
      final confirmPin = confirmController.text.trim();
      if (newPin != confirmPin) {
        _showMessage(context, 'Duress PINs do not match.');
        return;
      }
      ok = mode == _DuressPinDialogMode.set
          ? bridge.setDuressPin(newPin)
          : bridge.changeDuressPin(currentController.text.trim(), newPin);
    }

    if (!ok) {
      _showMessage(
        context,
        bridge.getLastError() ?? 'Unable to update duress PIN.',
      );
      return;
    }

    await settings.loadAll();
    if (!context.mounted) {
      return;
    }
    _showMessage(
      context,
      switch (mode) {
        _DuressPinDialogMode.set => 'Duress PIN saved.',
        _DuressPinDialogMode.change => 'Duress PIN changed.',
        _DuressPinDialogMode.remove => 'Duress PIN removed.',
      },
    );
  }

  void _showMessage(BuildContext context, String message) {
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(message)));
  }
}

enum _DuressPinDialogMode { set, change, remove }

// ---------------------------------------------------------------------------
// _SectionHeader — muted section label above groups of ListTiles
// ---------------------------------------------------------------------------

/// Small bold section header matching the visual style from SettingsScreen.
class _SectionHeader extends StatelessWidget {
  const _SectionHeader(this.title);

  final String title;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
      child: Text(
        title,
        style: Theme.of(context).textTheme.labelMedium?.copyWith(
          color: Theme.of(context).colorScheme.primary,
          fontWeight: FontWeight.w600,
        ),
      ),
    );
  }
}
