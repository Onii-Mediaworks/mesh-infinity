// killswitch_screen.dart
//
// KillswitchScreen — manual emergency data destruction (§3.9).
//
// WHAT THIS DOES:
// ---------------
// Triggering the killswitch calls BackendBridge.emergencyErase(), which:
//   1. Overwrites identity.key with random bytes, permanently orphaning
//      identity.dat (the encrypted vault). The key cannot be recovered.
//   2. Deletes all vault files (messages, contacts, routing state, sessions).
//   3. Returns true on completion so the UI can navigate to root and let
//      the onboarding flow restart as if the app was freshly installed.
//
// TWO-STEP CONFIRMATION:
// ----------------------
// Step 1: The user checks an acknowledgement checkbox. This guards against
//   accidental taps and ensures the user has read what will be destroyed.
//   The Destroy button is disabled until the checkbox is checked.
// Step 2: A confirmation dialog requires the user to type "DELETE" exactly.
//   This second barrier ensures the user understands this is irreversible
//   even under time pressure (e.g. duress).
//
// DIFFERENCE FROM EmergencyEraseScreen:
// --------------------------------------
// EmergencyEraseScreen (Settings → Emergency Erase) configures automatic
// triggers: duress PIN, wrong-PIN wipe threshold, remote trigger.
// This screen (KillswitchScreen) is the manual immediate-activation flow.
// Both ultimately call emergencyErase() on the backend.
//
// Reached from: Settings → Emergency Data Destruction.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/backend_bridge.dart';

/// Emergency data destruction screen (§3.9).
///
/// Calls [BackendBridge.emergencyErase] which performs a standard killswitch
/// erase: overwrites identity.key with random bytes (permanently orphaning
/// identity.dat), then deletes all vault files. After destruction the app
/// navigates back to root so the onboarding flow restarts.
class KillswitchScreen extends StatefulWidget {
  const KillswitchScreen({super.key});

  @override
  State<KillswitchScreen> createState() => _KillswitchScreenState();
}

class _KillswitchScreenState extends State<KillswitchScreen> {
  /// Whether the user has checked "I understand this is irreversible".
  ///
  /// The Destroy button is disabled while this is false — prevents accidental
  /// activation from a single mis-tap.
  bool _acknowledged = false;

  /// True while the emergencyErase() call is in flight.
  ///
  /// Disables the button and shows a spinner to prevent double-triggering.
  bool _busy = false;

  Future<void> _onDestroy() async {
    // Second confirmation step: require the user to type "DELETE" in a dialog.
    // barrierDismissible=false forces an explicit Cancel or Destroy choice —
    // the user cannot dismiss by tapping outside the dialog.
    final confirmed = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => _ConfirmDeleteDialog(),
    );

    // User cancelled or the widget unmounted while the dialog was open.
    if (confirmed != true || !mounted) return;

    setState(() => _busy = true);

    final bridge = context.read<BackendBridge>();
    final ok = bridge.emergencyErase();

    if (!mounted) return;

    if (ok) {
      // Navigate to the root route and clear the navigation stack so the
      // onboarding flow renders as if the app was freshly installed.
      Navigator.of(context).popUntil((route) => route.isFirst);
    } else {
      // Erase failed — leave _busy=false so the button is re-enabled and the
      // user can try again (or investigate via the debug screen).
      setState(() => _busy = false);
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Failed to destroy data')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Emergency Data Destruction'),
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // ── Warning banner ──────────────────────────────────────────────
          // Error-container colour signals maximum severity — this is the most
          // destructive action in the entire app.
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: cs.errorContainer,
              borderRadius: BorderRadius.circular(12),
            ),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Icon(Icons.warning_amber_rounded,
                    color: cs.onErrorContainer, size: 28),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    'This action is IRREVERSIBLE. All data on this device will '
                    'be permanently destroyed and cannot be recovered.',
                    style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                          color: cs.onErrorContainer,
                          fontWeight: FontWeight.w600,
                        ),
                  ),
                ),
              ],
            ),
          ),

          const SizedBox(height: 24),

          Text(
            'The following will be permanently destroyed:',
            style: Theme.of(context).textTheme.titleSmall,
          ),
          const SizedBox(height: 12),

          // ── Destruction scope ──────────────────────────────────────────
          // Explicit list of what gets erased so the user has informed consent
          // before hitting the final confirmation dialog.
          const _DestroyItem(
            icon: Icons.key_off_outlined,
            label: 'Identity keys',
            description: 'Your cryptographic key pair will be overwritten',
          ),
          const _DestroyItem(
            icon: Icons.map_outlined,
            label: 'Network map',
            description: 'All known peer routes and relay data',
          ),
          const _DestroyItem(
            icon: Icons.chat_bubble_outline,
            label: 'Message history',
            description: 'All conversations and messages',
          ),
          const _DestroyItem(
            icon: Icons.person_off_outlined,
            label: 'Profile data',
            description: 'Public and private profile information',
          ),
          const _DestroyItem(
            icon: Icons.cached_outlined,
            label: 'All cached data',
            description: 'Temporary files, session tokens, and local state',
          ),

          const SizedBox(height: 24),

          // ── Acknowledgement checkbox ────────────────────────────────────
          // First of two required user actions before destruction is allowed.
          // Checking this enables the Destroy button; unchecking it disables it.
          CheckboxListTile(
            contentPadding: EdgeInsets.zero,
            controlAffinity: ListTileControlAffinity.leading,
            title: const Text('I understand this is irreversible'),
            value: _acknowledged,
            onChanged: (v) => setState(() => _acknowledged = v ?? false),
          ),

          const SizedBox(height: 16),

          // ── Destroy button ─────────────────────────────────────────────
          // Gated by both _acknowledged (checkbox) and !_busy (in-flight guard).
          // Error background colour reinforces the severity of this action.
          FilledButton.icon(
            onPressed: (_acknowledged && !_busy) ? _onDestroy : null,
            style: FilledButton.styleFrom(
              backgroundColor: cs.error,
              foregroundColor: cs.onError,
              minimumSize: const Size.fromHeight(52),
            ),
            // Show a spinner while the erase is in progress so the user knows
            // the app hasn't frozen — the FFI call can take up to ~500 ms for
            // secure overwrite passes.
            icon: _busy
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(
                      strokeWidth: 2,
                      color: Colors.white,
                    ),
                  )
                : const Icon(Icons.delete_forever_outlined),
            label: Text(_busy ? 'Destroying...' : 'DESTROY ALL DATA'),
          ),
        ],
      ),
    );
  }
}

/// A single bullet-point item describing one category of data that will be
/// destroyed, shown before the user can activate the killswitch.
class _DestroyItem extends StatelessWidget {
  const _DestroyItem({
    required this.icon,
    required this.label,
    required this.description,
  });

  final IconData icon;
  final String label;
  final String description;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          // Error-colour icon reinforces that each item will be permanently lost.
          Icon(icon, size: 20, color: Theme.of(context).colorScheme.error),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(label,
                    style: Theme.of(context)
                        .textTheme
                        .bodyMedium
                        ?.copyWith(fontWeight: FontWeight.w600)),
                Text(description,
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
                        )),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

/// Second-step confirmation dialog that requires the user to type "DELETE".
///
/// Typing-to-confirm is intentionally harder than a tap — it breaks any
/// accidental muscle-memory tap path and ensures the user is consciously
/// acting under no duress (a forced tap would still require typing).
class _ConfirmDeleteDialog extends StatefulWidget {
  @override
  State<_ConfirmDeleteDialog> createState() => _ConfirmDeleteDialogState();
}

class _ConfirmDeleteDialogState extends State<_ConfirmDeleteDialog> {
  /// Holds the user's typed text.
  final _ctl = TextEditingController();

  /// True only when the typed text is exactly "DELETE" (case-insensitive).
  ///
  /// The Destroy button is disabled until this returns true.
  bool get _isValid => _ctl.text.trim().toUpperCase() == 'DELETE';

  @override
  void dispose() {
    _ctl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    return AlertDialog(
      title: const Text('Final Confirmation'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Text('Type DELETE to confirm data destruction.'),
          const SizedBox(height: 12),
          TextField(
            controller: _ctl,
            autofocus: true,
            decoration: const InputDecoration(
              hintText: 'DELETE',
            ),
            // Rebuild on each keystroke so the Destroy button enables/disables
            // as soon as the text matches "DELETE".
            onChanged: (_) => setState(() {}),
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context, false),
          child: const Text('Cancel'),
        ),
        FilledButton(
          // Disable the button until typing is correct — prevents blind tapping.
          onPressed: _isValid ? () => Navigator.pop(context, true) : null,
          style: FilledButton.styleFrom(
            backgroundColor: cs.error,
            foregroundColor: cs.onError,
          ),
          child: const Text('Destroy'),
        ),
      ],
    );
  }
}
