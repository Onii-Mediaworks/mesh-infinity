// config_screen_shell.dart
//
// ConfigScreenShell — the §22.54.4 "common layout" every protocol server
// configuration screen shares, so the five screens differ only in their
// fields.
//
// WHAT IT PROVIDES
// ----------------
//   * AppBar with the service name and a back button.
//   * Card-level skeleton (§22.50) while the first load is pending, and an
//     ErrorBanner with Retry when that load failed.
//   * The body ListView wrapped in PrimaryFocus so a keyboard or pad user
//     lands on the first control (§22.36 rule 2).
//   * A single filled Save button pinned at the bottom inside SafeArea,
//     disabled with "Fix the highlighted fields to save" while any field
//     is invalid, and showing a spinner while a save is in flight.
//   * The §22.51 save-failure banner ("Couldn't save service settings. Try
//     again.", Retry = yes) above the fields, leaving the edits in place.
//   * "Discard changes?" (Keep editing / Discard) on back while dirty.
//
// Section cards are built with [ConfigGroup] so every screen has the same
// title weight, padding and spacing.

import 'package:flutter/material.dart';

import '../../../core/widgets/error_banner.dart';
import '../../../core/widgets/shimmer.dart';
import '../../../shell/primary_focus.dart';

/// §22.51 fallback string for a refused save.
const String saveFailedText = "Couldn't save service settings. Try again.";

/// Helper shown under a disabled Save button (§22.54.4).
const String fixFieldsText = 'Fix the highlighted fields to save';

/// Common scaffold for the protocol server configuration screens.
class ConfigScreenShell extends StatelessWidget {
  const ConfigScreenShell({
    super.key,
    required this.title,
    required this.loading,
    required this.load_error,
    required this.on_retry_load,
    required this.dirty,
    required this.valid,
    required this.saving,
    required this.save_error,
    required this.on_save,
    required this.children,
  });

  /// AppBar title: the service's plain-language name.
  final String title;

  /// True until the first load completes.
  final bool loading;

  /// Message when the load failed; null otherwise.
  final String? load_error;

  /// Re-runs the load after a failure.
  final VoidCallback on_retry_load;

  /// True when the draft differs from what was loaded.
  final bool dirty;

  /// True when every field passes its rule.
  final bool valid;

  /// True while a save is in flight.
  final bool saving;

  /// Message when the last save was refused; null otherwise.
  final String? save_error;

  /// Saves the draft.
  final VoidCallback on_save;

  /// The field groups.
  final List<Widget> children;

  /// Ask whether to drop unsaved edits; true means leave the screen.
  Future<bool> _confirm_discard(BuildContext context) async {
    final leave = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Discard changes?'),
        content: const Text('Your edits to these settings have not been saved.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Keep editing'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Discard'),
          ),
        ],
      ),
    );
    return leave ?? false;
  }

  @override
  Widget build(BuildContext context) {
    final text = Theme.of(context).textTheme;
    final cs = Theme.of(context).colorScheme;

    final Widget body;
    if (loading) {
      // Card-level skeleton: four blocks the height of a short group card.
      body = const ShimmerList(count: 4, height: 96);
    } else if (load_error != null) {
      body = ListView(
        padding: const EdgeInsets.symmetric(vertical: 12),
        children: [ErrorBanner(message: load_error!, onRetry: on_retry_load)],
      );
    } else {
      body = PrimaryFocus(
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            if (save_error != null)
              Padding(
                padding: const EdgeInsets.only(bottom: 12),
                child: ErrorBanner(message: save_error!, onRetry: on_save),
              ),
            ...children,
            const SizedBox(height: 16),
          ],
        ),
      );
    }

    final can_save = !loading && load_error == null && valid && !saving;

    return PopScope(
      // A dirty draft vetoes the pop so the prompt can run first.
      canPop: !dirty,
      onPopInvokedWithResult: (did_pop, _) async {
        if (did_pop) return;
        final leave = await _confirm_discard(context);
        if (leave && context.mounted) Navigator.of(context).pop();
      },
      child: Scaffold(
        appBar: AppBar(title: Text(title)),
        body: body,
        bottomNavigationBar: SafeArea(
          child: Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 12),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                if (!valid && !loading)
                  Padding(
                    padding: const EdgeInsets.only(bottom: 6),
                    child: Text(
                      fixFieldsText,
                      style: text.bodySmall?.copyWith(color: cs.error),
                    ),
                  ),
                SizedBox(
                  width: double.infinity,
                  // 48dp minimum touch target (§22.34).
                  height: 48,
                  child: Semantics(
                    button: true,
                    label: 'Save $title settings',
                    child: FilledButton(
                      onPressed: can_save ? on_save : null,
                      child: saving
                          ? const SizedBox(
                              width: 20,
                              height: 20,
                              child: CircularProgressIndicator(strokeWidth: 2),
                            )
                          : const Text('Save'),
                    ),
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

/// One titled Card group of fields.
class ConfigGroup extends StatelessWidget {
  const ConfigGroup({super.key, required this.title, required this.children});

  /// Group title, e.g. "Who can connect".
  final String title;

  /// The group's fields.
  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    final text = Theme.of(context).textTheme;
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 14, 16, 12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(title, style: text.titleSmall),
            const SizedBox(height: 10),
            ...children,
          ],
        ),
      ),
    );
  }
}

/// A short explanatory line under a control (§22.22 plain language).
class HelperLine extends StatelessWidget {
  const HelperLine(this.text, {super.key});

  final String text;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.only(left: 16, right: 16, bottom: 6),
      child: Text(
        text,
        style: theme.textTheme.bodySmall?.copyWith(
          color: theme.colorScheme.onSurfaceVariant,
        ),
      ),
    );
  }
}

/// An inline rule violation shown under a group (§22.51 inline rule).
class InlineError extends StatelessWidget {
  const InlineError(this.text, {super.key});

  final String text;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.only(left: 16, right: 16, top: 4),
      child: Text(
        text,
        style: theme.textTheme.bodySmall?.copyWith(
          color: theme.colorScheme.error,
        ),
      ),
    );
  }
}

/// Monospace text style for paths, URLs and IDs (§22.54.4: never paraphrased).
TextStyle mono_style(BuildContext context) =>
    Theme.of(context).textTheme.bodyMedium!.copyWith(fontFamily: 'monospace');
