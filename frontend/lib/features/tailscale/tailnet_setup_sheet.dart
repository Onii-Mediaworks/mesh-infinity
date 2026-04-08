// tailnet_setup_sheet.dart
//
// TailnetSetupSheet — a modal bottom sheet for enrolling a new Tailscale
// tailnet instance.
//
// WHAT THIS SHEET DOES
// --------------------
// This sheet collects the information needed to enrol a new tailnet:
//
//   Label        — user-chosen name, e.g. "Work" or "Home VPN".  Stored by
//                  the backend alongside the instance so users can tell their
//                  tailnets apart in the hub list.
//
//   Controller   — which control plane to use: vendor Tailscale
//                  (controlplane.tailscale.com) or a self-hosted Headscale
//                  server.  Presented as a SegmentedButton.
//
//   Headscale URL — the URL of the Headscale server (conditional on controller
//                  selection).  Only shown when Headscale is selected.
//
//   Auth method  — OAuth (interactive browser flow) or pre-auth key
//                  (headless enrolment).  Presented as a SwitchListTile.
//
//   Auth key     — the pre-auth key string (conditional on auth method).
//                  Only shown when "Use auth key" is toggled on.
//
// ADVANCED WARNING
// ----------------
// If the user already has at least one tailnet configured, adding another is
// considered an advanced operation.  Before calling TailscaleState.addInstance
// the sheet shows AdvancedWarningDialog.  If the user cancels the dialog, the
// enrolment is aborted.
//
// HOW TO SHOW THIS SHEET
// ----------------------
// Use the showTailnetSetupSheet() convenience function:
//
//   await showTailnetSetupSheet(context);
//
// The function returns after the sheet is dismissed (either by completing
// enrolment or by the user swiping it away).
//
// DESIGN
// ------
// Uses a DraggableScrollableSheet so the sheet can expand to accommodate the
// keyboard when a text field is focused, without the fields being hidden
// behind the soft keyboard.  The sheet is not full-screen; the scrim behind
// it provides visual context that the hub is still underneath.

import 'package:flutter/material.dart';
// DraggableScrollableSheet, BottomSheet, Form, TextFormField, SegmentedButton.

import 'package:provider/provider.dart';
// context.read<TailscaleState>() — fire-and-forget write calls.
// context.watch<TailscaleState>() — read loading state for spinner.

import 'tailscale_state.dart';
// TailscaleState — mediates addInstance() and exposes loading/error state.

import 'widgets/advanced_warning_dialog.dart';
// showAdvancedWarningDialog — shown before adding a second tailnet.

// ---------------------------------------------------------------------------
// showTailnetSetupSheet — public convenience function
// ---------------------------------------------------------------------------

/// Show the tailnet setup bottom sheet and wait for it to be dismissed.
///
/// Call this from TailscaleHubScreen's add button or FAB.
///
/// [context] must be the BuildContext of an ancestor with both a Navigator and
/// a TailscaleState provider (i.e. anywhere inside the main app shell).
Future<void> showTailnetSetupSheet(BuildContext context) {
  return showModalBottomSheet<void>(
    context: context,
    // isScrollControlled: true allows the sheet to resize when the keyboard
    // appears, preventing text fields from being obscured.
    isScrollControlled: true,
    // useSafeArea: true keeps the sheet above the home indicator on iOS.
    useSafeArea: true,
    // Shape gives the sheet rounded top corners — standard Material 3 style.
    shape: const RoundedRectangleBorder(
      borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
    ),
    builder: (_) => const _TailnetSetupSheet(),
  );
}

// ---------------------------------------------------------------------------
// _TailnetSetupSheet — internal StatefulWidget
// ---------------------------------------------------------------------------

/// The content of the tailnet setup bottom sheet.
///
/// Private — consumers use [showTailnetSetupSheet].
class _TailnetSetupSheet extends StatefulWidget {
  const _TailnetSetupSheet();

  @override
  State<_TailnetSetupSheet> createState() => _TailnetSetupSheetState();
}

class _TailnetSetupSheetState extends State<_TailnetSetupSheet> {
  // -------------------------------------------------------------------------
  // Form key and controllers
  // -------------------------------------------------------------------------

  /// Key used to validate the form before submission.
  final _formKey = GlobalKey<FormState>();

  /// Controller for the label field — the user-chosen tailnet name.
  final _labelCtrl = TextEditingController();

  /// Controller for the Headscale server URL field.
  ///
  /// Only used when [_controllerType] is [_ControllerType.headscale].
  final _headscaleUrlCtrl = TextEditingController();

  /// Controller for the pre-auth key field.
  ///
  /// Only used when [_useAuthKey] is true.
  final _authKeyCtrl = TextEditingController();

  // -------------------------------------------------------------------------
  // Form state
  // -------------------------------------------------------------------------

  /// Which control server to use for this tailnet instance.
  _ControllerType _controllerType = _ControllerType.tailscaleVendor;

  /// When true, enrol using a pre-auth key instead of the OAuth browser flow.
  ///
  /// Pre-auth keys are suitable for headless / server nodes where a browser
  /// is not available.  They are generated in the Tailscale admin panel.
  bool _useAuthKey = false;

  /// True while the add operation is in flight (bridge call + reload).
  ///
  /// Disables the submit button to prevent double-submission.
  bool _submitting = false;

  /// Human-readable error from the last failed submission attempt, or null.
  String? _errorMessage;

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  @override
  void dispose() {
    // Always dispose TextEditingControllers to avoid memory leaks.
    _labelCtrl.dispose();
    _headscaleUrlCtrl.dispose();
    _authKeyCtrl.dispose();
    super.dispose();
  }

  // -------------------------------------------------------------------------
  // _submit — main enrolment logic
  // -------------------------------------------------------------------------

  /// Validate the form, show the advanced warning if needed, then enrol.
  ///
  /// The sequence is:
  ///   1. Validate the form fields.
  ///   2. If ≥1 tailnet already exists, show AdvancedWarningDialog.
  ///      Abort if the user cancels.
  ///   3. Call TailscaleState.addInstance() to create the backend row.
  ///   4. If auth key mode: call TailscaleState.connectAuthKey().
  ///      If OAuth mode: call TailscaleState.beginOAuth().
  ///   5. Dismiss the sheet on success.
  Future<void> _submit() async {
    // Step 1: validate.
    if (!(_formKey.currentState?.validate() ?? false)) return;

    final state = context.read<TailscaleState>();

    // Step 2: advanced warning when a second (or more) tailnet is being added.
    if (state.tailnets.isNotEmpty) {
      final confirmed = await showAdvancedWarningDialog(context);
      // If the user tapped "Cancel" or dismissed, abort silently.
      if (!confirmed) return;
    }

    setState(() {
      _submitting = true;
      _errorMessage = null;
    });

    try {
      // Resolve the control URL.  Empty string = vendor Tailscale.
      final controlUrl = _controllerType == _ControllerType.headscale
          ? _headscaleUrlCtrl.text.trim()
          : '';

      // Step 3: create the backend row and get the new instance ID.
      final newId = await state.addInstance(_labelCtrl.text.trim(), controlUrl);

      if (newId == null) {
        // addInstance() already set state.lastError — surface it here too.
        setState(() {
          _errorMessage = state.lastError ?? 'Failed to create tailnet';
        });
        return;
      }

      // Step 4: start the authentication flow.
      bool ok;
      if (_useAuthKey) {
        // Pre-auth key enrolment — synchronous, no browser needed.
        ok = await state.connectAuthKey(
          newId,
          _authKeyCtrl.text.trim(),
          controlUrl,
        );
      } else {
        // OAuth flow — opens the system browser.  The sheet can be dismissed
        // immediately; the backend will fire TailscaleOAuthCompleteEvent when
        // done.
        ok = await state.beginOAuth(newId, controlUrl);
      }

      if (!ok) {
        setState(() {
          _errorMessage = state.lastError ?? 'Authentication failed';
        });
        return;
      }

      // Step 5: success — dismiss the sheet.
      if (mounted) Navigator.of(context).pop();
    } finally {
      if (mounted) setState(() => _submitting = false);
    }
  }

  // -------------------------------------------------------------------------
  // build
  // -------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;
    // Watch for loading state driven by TailscaleState so the button spinner
    // also activates during bridge calls initiated outside the sheet.
    final loading = context.watch<TailscaleState>().loading;
    final busy = _submitting || loading;

    return Padding(
      // viewInsets.bottom accounts for the soft keyboard height so the form
      // content scrolls above the keyboard rather than being hidden behind it.
      padding: EdgeInsets.only(
        bottom: MediaQuery.viewInsetsOf(context).bottom,
      ),
      child: SingleChildScrollView(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(20, 12, 20, 28),
          child: Form(
            key: _formKey,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                // Sheet drag handle — visual affordance for the modal sheet.
                Center(
                  child: Container(
                    width: 36,
                    height: 4,
                    decoration: BoxDecoration(
                      color: cs.outlineVariant,
                      borderRadius: BorderRadius.circular(2),
                    ),
                  ),
                ),
                const SizedBox(height: 16),

                // Sheet title.
                Text('Add Tailnet', style: tt.titleLarge),
                const SizedBox(height: 4),
                Text(
                  'Connect Mesh Infinity to an existing tailnet.',
                  style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
                ),
                const SizedBox(height: 24),

                // --- Label field ---
                // Required.  The label is how the user identifies this
                // instance in the hub list (e.g. "Work", "Home").
                TextFormField(
                  controller: _labelCtrl,
                  decoration: const InputDecoration(
                    labelText: 'Label',
                    hintText: 'e.g. Work, Home, Personal',
                    border: OutlineInputBorder(),
                    prefixIcon: Icon(Icons.label_outline),
                  ),
                  textInputAction: TextInputAction.next,
                  autocorrect: false,
                  validator: (v) =>
                      (v == null || v.trim().isEmpty) ? 'Label is required' : null,
                ),
                const SizedBox(height: 20),

                // --- Controller type ---
                Text('Controller', style: tt.labelLarge),
                const SizedBox(height: 8),
                SegmentedButton<_ControllerType>(
                  segments: const [
                    ButtonSegment(
                      value: _ControllerType.tailscaleVendor,
                      label: Text('Tailscale'),
                      icon: Icon(Icons.cloud_outlined),
                    ),
                    ButtonSegment(
                      value: _ControllerType.headscale,
                      label: Text('Headscale'),
                      icon: Icon(Icons.dns_outlined),
                    ),
                  ],
                  selected: {_controllerType},
                  onSelectionChanged: (s) =>
                      setState(() => _controllerType = s.first),
                ),

                // Headscale URL — conditional on controller selection.
                if (_controllerType == _ControllerType.headscale) ...[
                  const SizedBox(height: 16),
                  TextFormField(
                    controller: _headscaleUrlCtrl,
                    decoration: const InputDecoration(
                      labelText: 'Headscale server URL',
                      hintText: 'https://headscale.example.com',
                      border: OutlineInputBorder(),
                      prefixIcon: Icon(Icons.link_outlined),
                    ),
                    keyboardType: TextInputType.url,
                    autocorrect: false,
                    textInputAction: TextInputAction.next,
                    validator: (v) {
                      // Only validate when Headscale is selected.
                      if (_controllerType != _ControllerType.headscale) {
                        return null;
                      }
                      if (v == null || v.trim().isEmpty) {
                        return 'Headscale URL is required';
                      }
                      if (!v.trim().startsWith('http')) {
                        return 'URL must start with http:// or https://';
                      }
                      return null;
                    },
                  ),
                ],
                const SizedBox(height: 20),

                // --- Authentication method ---
                Text('Authentication', style: tt.labelLarge),
                const SizedBox(height: 4),
                SwitchListTile(
                  contentPadding: EdgeInsets.zero,
                  title: const Text('Use auth key'),
                  subtitle: const Text(
                    'For headless nodes (servers, CI). '
                    'Generate the key in the Tailscale / Headscale admin panel.',
                  ),
                  value: _useAuthKey,
                  onChanged: (v) => setState(() => _useAuthKey = v),
                ),

                // Auth key field — conditional on _useAuthKey.
                if (_useAuthKey) ...[
                  const SizedBox(height: 8),
                  TextFormField(
                    controller: _authKeyCtrl,
                    decoration: const InputDecoration(
                      labelText: 'Auth key',
                      hintText: 'tskey-auth-...',
                      border: OutlineInputBorder(),
                      prefixIcon: Icon(Icons.key_outlined),
                    ),
                    obscureText: true,
                    autocorrect: false,
                    textInputAction: TextInputAction.done,
                    onFieldSubmitted: (_) => busy ? null : _submit(),
                    validator: (v) {
                      if (!_useAuthKey) return null;
                      if (v == null || v.trim().isEmpty) {
                        return 'Auth key is required';
                      }
                      return null;
                    },
                  ),
                ] else ...[
                  // OAuth info box — shown when interactive login is selected.
                  const SizedBox(height: 8),
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: cs.surfaceContainerHighest,
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: cs.outlineVariant),
                    ),
                    child: Row(
                      children: [
                        Icon(Icons.info_outline,
                            size: 16, color: cs.onSurfaceVariant),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            'Tapping "Add Tailnet" will open a browser window '
                            'to sign in with '
                            '${_controllerType == _ControllerType.headscale ? "Headscale" : "Tailscale"}.',
                            style: tt.bodySmall
                                ?.copyWith(color: cs.onSurfaceVariant),
                          ),
                        ),
                      ],
                    ),
                  ),
                ],

                // Error message — shown when the last submission failed.
                if (_errorMessage != null) ...[
                  const SizedBox(height: 14),
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
                            _errorMessage!,
                            style: TextStyle(
                                fontSize: 13, color: cs.onErrorContainer),
                          ),
                        ),
                      ],
                    ),
                  ),
                ],

                const SizedBox(height: 24),

                // Submit button.
                FilledButton.icon(
                  onPressed: busy ? null : _submit,
                  icon: busy
                      ? const SizedBox(
                          width: 16,
                          height: 16,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : Icon(_useAuthKey
                          ? Icons.link_outlined
                          : Icons.login_outlined),
                  label: Text(_useAuthKey ? 'Enrol with key' : 'Add Tailnet'),
                  style: FilledButton.styleFrom(
                    minimumSize: const Size(double.infinity, 48),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _ControllerType — private enum
// ---------------------------------------------------------------------------

/// Which Tailscale control server to use for the new instance.
enum _ControllerType {
  /// Tailscale Inc's vendor control plane (controlplane.tailscale.com).
  ///
  /// No URL configuration needed — the backend uses the default endpoint.
  tailscaleVendor,

  /// A self-hosted Headscale server.
  ///
  /// Requires the user to enter the server URL in [_headscaleUrlCtrl].
  headscale,
}
