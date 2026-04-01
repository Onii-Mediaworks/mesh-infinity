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
//   1. Duress PIN — a second PIN that looks like a normal unlock but silently
//      erases everything.  The UI looks exactly the same as a normal unlock.
//   2. Auto-wipe on wrong PIN — erase after N consecutive failures.
//   3. Remote trigger — a Level-8 (InnerCircle) contact can trigger erase
//      remotely if you're unreachable.
//   4. Manual activation — the "Erase now" button at the bottom with
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

import '../settings_state.dart';
import 'pin_screen.dart'; // PinScreen + PinScreenMode

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
                      Icon(
                        Icons.emergency_outlined,
                        size: 20,
                        color: cs.error,
                      ),
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
                    style: tt.bodySmall?.copyWith(
                      color: cs.onSurfaceVariant,
                    ),
                  ),
                ],
              ),
            ),
          ),

          const SizedBox(height: 16),

          // ---------------------------------------------------------------------------
          // Duress PIN section
          // ---------------------------------------------------------------------------
          // A second PIN that looks identical to the normal unlock PIN.
          // The backend detects it and triggers erase without any visible change
          // in the UI (§3.10 duress unlock invariant).
          _SectionHeader('Duress PIN'),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
            child: Text(
              'A second PIN that looks like a normal unlock but silently erases '
              'everything. An observer cannot tell the difference.',
              style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
            ),
          ),
          ListTile(
            leading: const Icon(Icons.pin_outlined),
            title: Text(
              settings.duressPinConfigured
                  ? 'Duress PIN configured'
                  : 'Set duress PIN',
            ),
            subtitle: Text(
              settings.duressPinConfigured ? 'Tap to change' : 'Tap to configure',
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => Navigator.push(
              context,
              MaterialPageRoute(
                builder: (_) => const PinScreen(mode: PinScreenMode.setupDuress),
              ),
            ),
          ),
          // Test button — lets the user verify the duress PIN works without
          // actually triggering any erase.  Only shown when duress PIN is set.
          if (settings.duressPinConfigured)
            ListTile(
              leading: const Icon(Icons.science_outlined),
              title: const Text('Test duress PIN'),
              subtitle: const Text(
                'Verify your duress PIN works without erasing anything.',
              ),
              trailing: const Icon(Icons.chevron_right),
              onTap: () => Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (_) => const PinScreen(mode: PinScreenMode.testDuress),
                ),
              ),
            ),

          const Divider(height: 1),
          const SizedBox(height: 8),

          // ---------------------------------------------------------------------------
          // Auto-wipe on wrong PIN
          // ---------------------------------------------------------------------------
          _SectionHeader('Auto-wipe on wrong PIN'),
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
            // Stub — backend wiring pending.
            onChanged: (_) => _stubNotImplemented(context),
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
                onChanged: (_) => _stubNotImplemented(context),
              ),
            ),

          const Divider(height: 1),
          const SizedBox(height: 8),

          // ---------------------------------------------------------------------------
          // Remote trigger
          // ---------------------------------------------------------------------------
          // A Level-8 trusted contact can trigger erase if they believe you're
          // unreachable.  Only works if both parties have configured it.
          _SectionHeader('Remote trigger'),
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
            subtitle: Text(
              settings.remoteWipeEnabled
                  ? 'No Inner Circle contacts authorised yet'
                  : 'Off',
            ),
            value: settings.remoteWipeEnabled,
            onChanged: (_) => _stubNotImplemented(context),
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
              // TODO(backend/security): call bridge.emergencyErase() here.
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(
                  content: Text('Emergency erase not yet available.'),
                ),
              );
            },
            child: const Text('Erase'),
          ),
        ],
      ),
    );
  }

  void _stubNotImplemented(BuildContext context) {
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Feature pending backend implementation.'),
        duration: Duration(seconds: 2),
      ),
    );
  }
}

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
