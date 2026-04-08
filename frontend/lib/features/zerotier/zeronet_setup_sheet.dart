// zeronet_setup_sheet.dart
//
// ZeroNetSetupSheet — a bottom sheet for adding a new ZeroNet instance.
//
// FORM FIELDS
// ------------
//   Label          — user-chosen display name (e.g. "Home Lab", "Work VPN").
//   Controller     — segmented picker: ZeroTier Central vs Self-hosted.
//   Controller URL — text field (shown only when Self-hosted is selected).
//   API Key        — secret; obscured with password masking.
//   Network IDs    — zero or more 16-hex-char network IDs to join immediately.
//                    Added via a text field + "Add" button; shown as removable
//                    InputChips below the field.
//
// ADVANCED WARNING
// -----------------
// If the user already has at least one ZeroNet instance configured,
// AdvancedWarningDialog is shown before the sheet opens.  The caller (hub
// screen) is responsible for checking ZeroTierState.zeronets.length and
// calling showAdvancedWarningDialog first; the sheet itself also checks on
// submission as a belt-and-braces guard.
//
// SUBMISSION
// -----------
// "Add ZeroNet" validates the form (label required, API key required,
// at least one network ID) then calls ZeroTierState.addInstance().  On
// success the sheet closes.  On failure the error is shown inline.
//
// Spec ref: §5.23 ZeroTier overlay — instance enrolment.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'zerotier_state.dart';
// ZeroTierState — the state notifier; addInstance() is called on submit.

import 'widgets/advanced_warning_dialog.dart';
// showAdvancedWarningDialog — shown when adding a 2nd+ instance.

// ---------------------------------------------------------------------------
// ZeroNetSetupSheet
// ---------------------------------------------------------------------------

/// Modal bottom sheet for adding a new ZeroNet instance.
///
/// Open with [showZeroNetSetupSheet] rather than pushing directly, so the
/// caller gets a properly configured [showModalBottomSheet] call with
/// `isScrollControlled: true` (required for forms with text fields, otherwise
/// the keyboard overlaps the sheet).
class ZeroNetSetupSheet extends StatefulWidget {
  /// Creates a [ZeroNetSetupSheet].
  const ZeroNetSetupSheet({super.key});

  @override
  State<ZeroNetSetupSheet> createState() => _ZeroNetSetupSheetState();
}

class _ZeroNetSetupSheetState extends State<ZeroNetSetupSheet> {
  // ---------------------------------------------------------------------------
  // Form field controllers
  // ---------------------------------------------------------------------------

  /// User-chosen label for this instance (e.g. "Home Lab").
  final _labelCtrl = TextEditingController();

  /// API key from ZeroTier Central or the self-hosted controller admin panel.
  /// Treated as a secret; the text field is obscured.
  final _apiKeyCtrl = TextEditingController();

  /// URL of a self-hosted ZeroTier controller (e.g. "https://zt.example.com").
  /// Only visible and required when [_controllerType] is [_ControllerType.selfHosted].
  final _controllerUrlCtrl = TextEditingController();

  /// Text field for entering a single network ID before adding it to the list.
  final _networkIdCtrl = TextEditingController();

  // ---------------------------------------------------------------------------
  // Local UI state
  // ---------------------------------------------------------------------------

  /// Which controller backend the user has selected.
  _ControllerType _controllerType = _ControllerType.central;

  /// Network IDs staged for joining during setup.
  ///
  /// Validated 16-hex-char strings accumulate here as the user adds them.
  /// Shown as removable InputChips below the network ID field.
  final List<String> _pendingNetworks = [];

  /// True while the "Add ZeroNet" submission is in flight.
  bool _submitting = false;

  /// Error string from the most recent failed validation or bridge call.
  String? _error;

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  @override
  void dispose() {
    _labelCtrl.dispose();
    _apiKeyCtrl.dispose();
    _controllerUrlCtrl.dispose();
    _networkIdCtrl.dispose();
    super.dispose();
  }

  // ---------------------------------------------------------------------------
  // _addNetwork
  // ---------------------------------------------------------------------------

  /// Validates and stages a network ID in [_pendingNetworks].
  ///
  /// ZeroTier network IDs are exactly 16 hexadecimal characters.  Rejects
  /// duplicates and obviously invalid values before they reach the backend.
  void _addNetwork() {
    final id = _networkIdCtrl.text.trim();

    if (id.isEmpty) return;

    // Validate: must be exactly 16 hex characters (0-9, a-f, A-F).
    if (!RegExp(r'^[0-9a-fA-F]{16}$').hasMatch(id)) {
      setState(() {
        _error = 'Network ID must be exactly 16 hex characters '
            '(e.g. 8056c2e21c000001)';
      });
      return;
    }

    // Guard duplicates — adding the same ID twice is a no-op but confusing.
    if (_pendingNetworks.contains(id)) {
      setState(() => _error = 'That network ID is already in the list');
      return;
    }

    setState(() {
      _pendingNetworks.add(id);
      _networkIdCtrl.clear();
      _error = null;
    });
  }

  // ---------------------------------------------------------------------------
  // _submit
  // ---------------------------------------------------------------------------

  /// Validates the form and calls ZeroTierState.addInstance().
  ///
  /// Shows the advanced warning dialog if this is not the first instance,
  /// as a final belt-and-braces check (the caller should already have shown
  /// it, but this guards against callers that skip that step).
  Future<void> _submit() async {
    // Validate label.
    final label = _labelCtrl.text.trim();
    if (label.isEmpty) {
      setState(() => _error = 'A label is required');
      return;
    }

    // Validate API key.
    final apiKey = _apiKeyCtrl.text.trim();
    if (apiKey.isEmpty) {
      setState(() => _error = 'An API key is required');
      return;
    }

    // Validate controller URL when self-hosted is selected.
    if (_controllerType == _ControllerType.selfHosted) {
      final url = _controllerUrlCtrl.text.trim();
      if (url.isEmpty) {
        setState(() => _error = 'Controller URL is required for self-hosted');
        return;
      }
      // Basic URL format check — full validation happens on the backend.
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        setState(() => _error = 'Controller URL must start with http:// or https://');
        return;
      }
    }

    // At least one network ID is required — a ZeroTier client with no
    // networks joined has nothing to do.
    if (_pendingNetworks.isEmpty) {
      setState(() => _error = 'Add at least one network ID to join');
      return;
    }

    final state = context.read<ZeroTierState>();

    // Belt-and-braces advanced warning: show if this won't be the first
    // instance.  The hub screen should already have shown it, but we guard
    // here in case the sheet is opened from another entry point.
    if (state.zeronets.isNotEmpty) {
      final confirmed = await showAdvancedWarningDialog(
        context,
        existingCount: state.zeronets.length,
      );
      if (!confirmed) return; // User cancelled — abort without error message.
    }

    setState(() {
      _submitting = true;
      _error = null;
    });

    // Build the controller URL.  Empty string tells the backend to use
    // ZeroTier Central (my.zerotier.com).
    final controllerUrl = _controllerType == _ControllerType.selfHosted
        ? _controllerUrlCtrl.text.trim()
        : '';

    // addInstance returns null on success, or a human-readable error string.
    final err = await state.addInstance(
      label,
      apiKey,
      controllerUrl,
      List.from(_pendingNetworks),
    );

    if (!mounted) return;

    if (err != null) {
      // Show the error inline and let the user correct it.
      setState(() {
        _error = err;
        _submitting = false;
      });
    } else {
      // Success — close the sheet.
      Navigator.of(context).pop();
    }
  }

  // ---------------------------------------------------------------------------
  // build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    // isScrollControlled must be true in the showModalBottomSheet call (see
    // showZeroNetSetupSheet below) so the sheet expands above the keyboard.
    // Here we use a DraggableScrollableSheet pattern via SingleChildScrollView
    // + viewInsets padding to ensure the keyboard never obscures the form.
    return Padding(
      // Bottom inset pushes the form above the keyboard.
      padding: EdgeInsets.only(
        bottom: MediaQuery.of(context).viewInsets.bottom,
      ),
      child: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(24, 8, 24, 32),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          mainAxisSize: MainAxisSize.min,
          children: [
            // ---- Sheet title -----------------------------------------------
            Text('Add ZeroNet Instance', style: tt.titleMedium),
            const SizedBox(height: 4),
            Text(
              'Connect Mesh Infinity to a ZeroTier network. '
              'No separate app needed.',
              style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
            ),
            const SizedBox(height: 20),

            // ---- Label field -----------------------------------------------
            TextField(
              controller: _labelCtrl,
              decoration: const InputDecoration(
                labelText: 'Label',
                hintText: 'e.g. Home Lab',
                border: OutlineInputBorder(),
                prefixIcon: Icon(Icons.label_outline),
              ),
              textCapitalization: TextCapitalization.words,
            ),
            const SizedBox(height: 16),

            // ---- Controller type picker ------------------------------------
            Text('Controller', style: tt.labelLarge),
            const SizedBox(height: 8),
            SegmentedButton<_ControllerType>(
              segments: const [
                ButtonSegment(
                  value: _ControllerType.central,
                  label: Text('ZeroTier Central'),
                  icon: Icon(Icons.cloud_outlined),
                ),
                ButtonSegment(
                  value: _ControllerType.selfHosted,
                  label: Text('Self-hosted'),
                  icon: Icon(Icons.dns_outlined),
                ),
              ],
              selected: {_controllerType},
              onSelectionChanged: (s) =>
                  setState(() => _controllerType = s.first),
            ),
            const SizedBox(height: 16),

            // ---- Controller URL (self-hosted only) -------------------------
            if (_controllerType == _ControllerType.selfHosted) ...[
              TextField(
                controller: _controllerUrlCtrl,
                decoration: const InputDecoration(
                  labelText: 'Controller URL',
                  hintText: 'https://zt.example.com',
                  border: OutlineInputBorder(),
                  prefixIcon: Icon(Icons.link_outlined),
                ),
                keyboardType: TextInputType.url,
                autocorrect: false,
              ),
              const SizedBox(height: 16),
            ],

            // ---- API key field ---------------------------------------------
            Text('API Key', style: tt.labelLarge),
            const SizedBox(height: 4),
            // Context-sensitive hint tells the user where to find the key.
            Text(
              _controllerType == _ControllerType.central
                  ? 'Generate at my.zerotier.com → Account → API Access Tokens'
                  : 'Generate in your self-hosted controller admin panel',
              style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: _apiKeyCtrl,
              decoration: const InputDecoration(
                labelText: 'API Key',
                hintText: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
                border: OutlineInputBorder(),
                prefixIcon: Icon(Icons.key_outlined),
              ),
              // Obscure the key — it is a long-lived secret.
              obscureText: true,
              autocorrect: false,
            ),
            const SizedBox(height: 20),

            // ---- Network IDs -----------------------------------------------
            Text('Networks to Join', style: tt.labelLarge),
            const SizedBox(height: 4),
            Text(
              'Add one or more 16-character ZeroTier network IDs. '
              'Private networks require admin approval after joining.',
              style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
            ),
            const SizedBox(height: 8),
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Expanded(
                  child: TextField(
                    controller: _networkIdCtrl,
                    decoration: const InputDecoration(
                      labelText: 'Network ID',
                      hintText: '8056c2e21c000001',
                      border: OutlineInputBorder(),
                      prefixIcon: Icon(Icons.lan_outlined),
                    ),
                    maxLength: 16,
                    autocorrect: false,
                    onSubmitted: (_) => _addNetwork(),
                  ),
                ),
                const SizedBox(width: 8),
                Padding(
                  // Align button with text field top, accounting for label.
                  padding: const EdgeInsets.only(top: 4),
                  child: FilledButton.tonal(
                    onPressed: _addNetwork,
                    child: const Text('Add'),
                  ),
                ),
              ],
            ),

            // ---- Pending network chips ------------------------------------
            if (_pendingNetworks.isNotEmpty) ...[
              const SizedBox(height: 8),
              Wrap(
                spacing: 8,
                runSpacing: 4,
                children: [
                  for (final id in _pendingNetworks)
                    InputChip(
                      // Monospace label so the 16-char ID is readable.
                      label: Text(
                        id,
                        style: const TextStyle(fontFamily: 'monospace'),
                      ),
                      // X button removes the ID from the pending list.
                      onDeleted: () =>
                          setState(() => _pendingNetworks.remove(id)),
                    ),
                ],
              ),
            ],

            // ---- Error banner ---------------------------------------------
            if (_error != null) ...[
              const SizedBox(height: 12),
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: cs.errorContainer,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Row(
                  children: [
                    Icon(Icons.error_outline,
                        size: 16, color: cs.onErrorContainer),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        _error!,
                        style: tt.bodySmall
                            ?.copyWith(color: cs.onErrorContainer),
                      ),
                    ),
                  ],
                ),
              ),
            ],

            const SizedBox(height: 24),

            // ---- Submit button --------------------------------------------
            FilledButton.icon(
              onPressed: _submitting ? null : _submit,
              icon: _submitting
                  ? const SizedBox(
                      width: 16,
                      height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.add_link),
              label: const Text('Add ZeroNet'),
              style: FilledButton.styleFrom(
                minimumSize: const Size(double.infinity, 48),
              ),
            ),

            const SizedBox(height: 12),

            // ---- Privacy footnote ----------------------------------------
            Text(
              'ZeroTier anonymization score: 0.3 (vendor coordination server) '
              '· Self-hosted: 0.5. '
              'Private networks expose your Node ID to the network admin.',
              style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _ControllerType (private enum)
// ---------------------------------------------------------------------------

/// Which ZeroTier controller backend the user is connecting to.
enum _ControllerType {
  /// ZeroTier Central SaaS (my.zerotier.com) — hosted, easy to set up.
  central,

  /// Self-hosted ZeroTier controller — full sovereignty, requires a server.
  selfHosted,
}

// ---------------------------------------------------------------------------
// showZeroNetSetupSheet
// ---------------------------------------------------------------------------

/// Opens the [ZeroNetSetupSheet] as a modal bottom sheet.
///
/// The caller should check [ZeroTierState.zeronets.isNotEmpty] and call
/// [showAdvancedWarningDialog] first if the user already has at least one
/// instance — the sheet also checks internally as a guard.
///
/// Uses `isScrollControlled: true` so the sheet resizes above the keyboard
/// when text fields receive focus.
Future<void> showZeroNetSetupSheet(BuildContext context) {
  return showModalBottomSheet<void>(
    context: context,
    // isScrollControlled: true is REQUIRED for sheets containing text fields.
    // Without it, Flutter clips the sheet at half-screen height and the
    // keyboard overlaps the focused field.
    isScrollControlled: true,
    // useSafeArea: true prevents the sheet from drawing under the home
    // indicator on iOS / navigation bar on Android.
    useSafeArea: true,
    builder: (_) => const ZeroNetSetupSheet(),
  );
}
