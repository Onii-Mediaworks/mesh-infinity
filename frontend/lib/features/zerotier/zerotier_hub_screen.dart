// zerotier_hub_screen.dart
//
// ZeroTierHubScreen — the top-level management screen for all ZeroNet
// instances configured in Mesh Infinity.
//
// WHAT IS A "ZERONET INSTANCE"?
// ------------------------------
// Mesh Infinity supports running multiple simultaneous ZeroTier clients, each
// with its own API key, controller, and set of joined networks.  Each such
// client is called a "ZeroNet instance".  A typical user has one; power users
// (e.g. separate home, work, and community networks) may have several.
//
// This screen is the hub — the list view of all configured instances with
// quick-action menus and navigation to per-instance detail screens.
//
// SCREEN STRUCTURE
// -----------------
//   AppBar
//     Title: "ZeroTier"
//     Actions: add-instance button (IconButton)
//
//   Body (one of):
//     • Empty state (no instances configured) — centered illustration + call
//       to action with an "Add ZeroNet" button.
//     • ListView of ZeroNetListTile — one per instance, sorted as returned
//       by the backend.
//
//   Error banner (conditional) — shown below the AppBar when ZeroTierState
//   has a non-null lastError.  Tapping clears it.
//
// ADDING A SECOND INSTANCE
// -------------------------
// If the user tries to add a second instance when one already exists, an
// advanced warning dialog (showAdvancedWarningDialog) is shown first.
// The dialog explains resource implications and IP conflict risks.  Only on
// confirmation does the setup sheet open.
//
// The first-instance path skips the warning and opens the sheet directly —
// it is the normal, encouraged workflow.
//
// WHY CHECK IN THE HUB RATHER THAN ONLY IN THE SHEET?
// ---------------------------------------------------
// The hub check lets us stop the user before they even open the sheet,
// which feels more intentional than showing the warning mid-form.  The sheet
// has a belt-and-braces check too, in case it is ever opened from a different
// call site.
//
// Spec ref: §5.23 ZeroTier overlay — multi-instance management.

import 'package:flutter/material.dart';
// Material widgets: Scaffold, AppBar, ListView, IconButton, FloatingActionButton,
// Center, Column, Icon, Text, FilledButton, SnackBar.

import 'package:provider/provider.dart';
// Provider: context.watch / context.read for consuming ZeroTierState.

import 'models/zeronet_instance.dart';
// ZeroNetInstance — the model passed to ZeroNetListTile.

import 'zerotier_state.dart';
// ZeroTierState — ChangeNotifier providing the instance list and mutations.

import 'zeronet_setup_sheet.dart';
// showZeroNetSetupSheet — opens the modal bottom sheet for adding an instance.

import 'widgets/advanced_warning_dialog.dart';
// showAdvancedWarningDialog — shown before adding a 2nd+ instance.

import 'widgets/zeronet_list_tile.dart';
// ZeroNetListTile — renders one instance row in the list.

// ---------------------------------------------------------------------------
// ZeroTierHubScreen
// ---------------------------------------------------------------------------

/// Top-level hub screen listing all ZeroNet instances managed by Mesh Infinity.
///
/// Provided via the navigation shell (e.g. from shell_state.dart routing).
/// Consumes [ZeroTierState] via Provider; rebuilds automatically on changes.
///
/// Spec ref: §5.23 ZeroTier overlay — instance management hub.
class ZeroTierHubScreen extends StatelessWidget {
  /// Creates a [ZeroTierHubScreen].
  const ZeroTierHubScreen({super.key});

  // ---------------------------------------------------------------------------
  // _openAddSheet
  // ---------------------------------------------------------------------------

  /// Opens the ZeroNet setup sheet, preceded by an advanced warning dialog if
  /// this is not the first instance.
  ///
  /// The advanced warning dialog informs the user about resource implications
  /// and IP conflict risks of running multiple ZeroTier clients simultaneously.
  /// For the first instance the dialog is skipped — it is the encouraged path.
  ///
  /// Returns without opening the sheet if the user dismisses the warning.
  Future<void> _openAddSheet(BuildContext context, ZeroTierState state) async {
    // Show the warning only when at least one instance already exists.
    // Adding the first instance is straightforward and should not be gated.
    if (state.zeronets.isNotEmpty) {
      // showAdvancedWarningDialog returns true if the user pressed
      // "I understand, continue", false if they cancelled or dismissed.
      final confirmed = await showAdvancedWarningDialog(
        context,
        existingCount: state.zeronets.length,
      );

      // If the user cancelled (or tapped outside the dialog), abort.
      if (!confirmed) return;
    }

    // Guard: if the widget is no longer in the tree after the await, bail out.
    // This can happen if the screen was popped while the dialog was open.
    if (!context.mounted) return;

    // Open the modal bottom sheet for collecting setup parameters.
    // showZeroNetSetupSheet handles isScrollControlled and useSafeArea.
    await showZeroNetSetupSheet(context);
  }

  // ---------------------------------------------------------------------------
  // build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    // Watch ZeroTierState so the hub rebuilds whenever the instance list or
    // error state changes (e.g. after addInstance, removeInstance, loadAll).
    final state = context.watch<ZeroTierState>();

    return Scaffold(
      // ---- AppBar -----------------------------------------------------------
      appBar: AppBar(
        title: const Text('ZeroTier'),

        // Actions: a single add button in the top-right corner.
        // Using an IconButton here (rather than a FAB) keeps the UI
        // consistent with other hub screens in the app.
        actions: [
          // The add button is always present regardless of instance count.
          // An empty list shows it too — there's nothing to disable it.
          IconButton(
            icon: const Icon(Icons.add),
            tooltip: 'Add ZeroNet instance',
            onPressed: () => _openAddSheet(context, state),
          ),
        ],
      ),

      // ---- Body -------------------------------------------------------------
      body: Column(
        children: [
          // ---- Error banner (conditional) -----------------------------------
          // Shown when ZeroTierState.lastError is non-null.  Covers the full
          // width above the list so it is hard to miss.
          if (state.lastError != null)
            _ErrorBanner(
              message: state.lastError!,
              onDismiss: state.clearError,
            ),

          // ---- Loading indicator (conditional) ------------------------------
          // A thin progress bar at the top while an async operation is in flight.
          // Does not block the list — existing instances remain visible and
          // tappable during a refresh.
          if (state.loading)
            const LinearProgressIndicator(minHeight: 2),

          // ---- Main content (empty state or instance list) -----------------
          Expanded(
            child: state.zeronets.isEmpty
                // Empty state: no instances configured yet.
                ? _EmptyState(onAdd: () => _openAddSheet(context, state))
                // Instance list: one tile per ZeroNet instance.
                : _InstanceList(state: state),
          ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _InstanceList (private)
// ---------------------------------------------------------------------------

/// Scrollable list of all configured ZeroNet instances.
///
/// Extracted from [ZeroTierHubScreen.build] to keep the build method readable.
/// Passes priority and callback props down to [ZeroNetListTile].
class _InstanceList extends StatelessWidget {
  /// The current ZeroTierState — source of the instance list and priority ID.
  final ZeroTierState state;

  const _InstanceList({required this.state});

  @override
  Widget build(BuildContext context) {
    // The list is unordered (backend order is preserved) but sorted so that
    // the priority instance appears first.  This makes the priority instance
    // easy to find without requiring the user to know the label.
    final sorted = _sortedInstances(state.zeronets, state.priorityZeronetId);

    return ListView.separated(
      // Standard list padding: 8 dp top/bottom, 0 left/right so tiles use
      // their own horizontal padding (ListTile uses 16 dp by default).
      padding: const EdgeInsets.symmetric(vertical: 8),
      itemCount: sorted.length,
      // Divider between tiles: the default Divider height (1 px) with indent
      // matching the ListTile content start (72 dp = leading + gap).
      separatorBuilder: (_, _) => const Divider(
        height: 1,
        indent: 72,
        endIndent: 16,
      ),
      itemBuilder: (context, index) {
        final instance = sorted[index];
        final isPriority = instance.id == state.priorityZeronetId;

        return ZeroNetListTile(
          instance: instance,
          isPriority: isPriority,
        );
      },
    );
  }

  // ---------------------------------------------------------------------------
  // _sortedInstances
  // ---------------------------------------------------------------------------

  /// Returns [instances] with the priority instance moved to the front.
  ///
  /// All other instances retain their original relative order (as returned by
  /// the backend).  This is a stable sort in O(n) time — acceptable since
  /// the number of instances is expected to be 1–5 in practice.
  List<ZeroNetInstance> _sortedInstances(
    List<ZeroNetInstance> instances,
    String? priorityId,
  ) {
    if (priorityId == null) {
      // No priority set — use backend order unchanged.
      return instances;
    }

    // Build the sorted list: priority instance first, then all others.
    final result = <ZeroNetInstance>[];
    ZeroNetInstance? priority;

    for (final instance in instances) {
      if (instance.id == priorityId) {
        // Save the priority instance for front-insertion after the loop.
        priority = instance;
      } else {
        result.add(instance);
      }
    }

    // Prepend the priority instance (or fall back to original order if not found).
    if (priority != null) result.insert(0, priority);
    return result;
  }
}

// ---------------------------------------------------------------------------
// _EmptyState (private)
// ---------------------------------------------------------------------------

/// Centered empty-state view shown when no ZeroNet instances are configured.
///
/// Includes a brief explanation of what ZeroTier is and an "Add ZeroNet"
/// button as the primary call to action.
class _EmptyState extends StatelessWidget {
  /// Called when the user taps "Add ZeroNet".
  final VoidCallback onAdd;

  const _EmptyState({required this.onAdd});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    return Center(
      // Horizontal padding prevents text running edge-to-edge on wide screens.
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 40),
        child: Column(
          // Vertically centre the content within the remaining screen area.
          mainAxisSize: MainAxisSize.min,
          children: [
            // ---- Illustration icon -----------------------------------------
            // A large network/VPN icon signals "this is about connectivity"
            // without needing localised alt-text.
            Icon(
              Icons.lan_outlined,
              size: 72,
              // Low opacity so the icon reads as decorative rather than
              // interactive — the primary action is the button below.
              color: cs.onSurfaceVariant.withValues(alpha: 0.4),
            ),
            const SizedBox(height: 20),

            // ---- Primary label --------------------------------------------
            Text(
              'No zeronets configured',
              style: tt.titleMedium?.copyWith(color: cs.onSurface),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 8),

            // ---- Secondary explanation ------------------------------------
            // Brief explanation of ZeroTier for users who are not familiar
            // with the product — avoids an opaque empty screen.
            Text(
              'ZeroTier creates encrypted virtual networks between your '
              'devices and peers, without port-forwarding or a central server. '
              'Add a ZeroNet instance to get started.',
              style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 28),

            // ---- Primary call to action -----------------------------------
            // FilledButton is the highest-emphasis button style — appropriate
            // for the only action available in an empty-state screen.
            FilledButton.icon(
              onPressed: onAdd,
              icon: const Icon(Icons.add),
              label: const Text('Add ZeroNet'),
            ),
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _ErrorBanner (private)
// ---------------------------------------------------------------------------

/// A dismissible error banner displayed above the instance list.
///
/// Shows [message] in an error-coloured container.  Tapping the close icon
/// calls [onDismiss], which should clear [ZeroTierState.lastError].
class _ErrorBanner extends StatelessWidget {
  /// The error message to display.
  final String message;

  /// Called when the user taps the dismiss button.
  final VoidCallback onDismiss;

  const _ErrorBanner({required this.message, required this.onDismiss});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    return Container(
      // Full-width banner with error-container background.
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
      color: cs.errorContainer,
      child: Row(
        children: [
          // Warning icon — draws the eye to the error region.
          Icon(Icons.error_outline, size: 16, color: cs.onErrorContainer),
          const SizedBox(width: 8),

          // Error message: expands to fill available width so long messages
          // wrap onto multiple lines rather than overflowing.
          Expanded(
            child: Text(
              message,
              style: tt.bodySmall?.copyWith(color: cs.onErrorContainer),
            ),
          ),

          // Dismiss button: clears the error from ZeroTierState.
          IconButton(
            icon: Icon(Icons.close, size: 16, color: cs.onErrorContainer),
            tooltip: 'Dismiss',
            onPressed: onDismiss,
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(),
          ),
        ],
      ),
    );
  }
}
