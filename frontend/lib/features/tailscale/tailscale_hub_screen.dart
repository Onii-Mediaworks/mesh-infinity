// tailscale_hub_screen.dart
//
// TailscaleHubScreen — the top-level screen for the multi-instance Tailscale
// feature in Mesh Infinity.
//
// WHAT THIS SCREEN IS
// --------------------
// This is the entry point into the Tailscale section of the app.  It shows
// a list of all tailnet instances the user has configured, along with their
// connection status, and gives access to:
//
//   - Adding a new tailnet (via TailnetSetupSheet)
//   - Viewing/managing a tailnet (by tapping a list tile → TailnetDetailScreen)
//   - Removing a tailnet (via the popup menu in TailnetListTile)
//
// MULTI-INSTANCE CONTEXT
// -----------------------
// Running multiple tailnets simultaneously is an "advanced" feature (§5.22).
// Most users will have one tailnet.  The UI is designed to be approachable
// for single-tailnet users (prominent "Add your first tailnet" CTA when empty)
// while still being fully functional for power users with multiple tailnets.
//
// Before adding a second (or subsequent) tailnet, the user is shown
// AdvancedWarningDialog explaining routing conflict risks and the priority
// mechanism.  This warning is shown in _openAddSheet() rather than in
// TailnetSetupSheet itself, so TailnetListTile's "Add" action and the
// TailscaleHubScreen FAB both get the same gate.
//
// NAVIGATION
// ----------
// TailscaleHubScreen is pushed onto the navigator stack from the nav drawer
// or the Services section.  It is NOT a tab inside AppShell's bottom nav —
// it is a dedicated "full screen" navigation destination.
//
// EMPTY STATE
// -----------
// When tailnets is empty:
//   - Full-screen centered empty state with icon, headline, and "Add your
//     first tailnet" FilledButton.
//   - No FAB (no list to complement).
//
// Non-empty state:
//   - ListView of TailnetListTile widgets.
//   - FAB in the bottom-right corner for adding further tailnets.
//   - The priority tailnet (if any) is highlighted via PriorityBadge inside
//     the tile — no separate header row needed for one or two tailnets.
//
// ERROR HANDLING
// --------------
// TailscaleState.lastError is shown as a top-of-list error container that
// dismisses when the user taps the close icon.  Individual tile actions
// (remove, disconnect) surface errors through the same mechanism.
//
// Spec reference: §5.22 (multi-instance Tailscale overlay)

import 'package:flutter/material.dart';
// Scaffold, AppBar, ListView, FloatingActionButton, Center, FilledButton, etc.

import 'package:provider/provider.dart';
// context.watch<TailscaleState>() — rebuild on state changes.
// context.read<TailscaleState>() — fire-and-forget write operations.

import 'tailscale_state.dart';
// TailscaleState — the ChangeNotifier that owns all tailnet list data.

import 'models/tailnet_instance.dart';
// TailnetInstance — the data model; needed for the remove confirmation dialog.

import 'tailnet_setup_sheet.dart';
// showTailnetSetupSheet — convenience function to display the add-tailnet sheet.

import 'widgets/tailnet_list_tile.dart';
// TailnetListTile — renders one row in the hub list.

import 'widgets/advanced_warning_dialog.dart';
// showAdvancedWarningDialog — shown before adding a second tailnet.

// ---------------------------------------------------------------------------
// TailscaleHubScreen
// ---------------------------------------------------------------------------

/// The top-level screen for managing multiple Tailscale instances ("tailnets").
///
/// Lists all configured tailnets, provides navigation to [TailnetDetailScreen]
/// for each one, and offers add/remove actions.
///
/// Spec reference: §5.22 (multi-instance Tailscale overlay management hub)
class TailscaleHubScreen extends StatelessWidget {
  /// Creates the [TailscaleHubScreen].
  const TailscaleHubScreen({super.key});

  @override
  Widget build(BuildContext context) {
    // Watch TailscaleState so the list rebuilds whenever instances are added,
    // removed, or change status (e.g. "connecting" → "connected").
    final state = context.watch<TailscaleState>();
    final tailnets = state.tailnets;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Tailscale'),
        // The trailing add button mirrors the FAB — both open the same sheet.
        // Having both gives users two obvious paths to the primary action,
        // which is especially useful when the list is short and the FAB might
        // be out of immediate view.
        actions: [
          IconButton(
            icon: const Icon(Icons.add),
            tooltip: 'Add tailnet',
            onPressed: () => _openAddSheet(context, state),
          ),
        ],
      ),

      body: tailnets.isEmpty
          // ----------------------------------------------------------------
          // Empty state — no tailnets configured yet
          // ----------------------------------------------------------------
          ? _EmptyState(onAdd: () => _openAddSheet(context, state))
          // ----------------------------------------------------------------
          // Non-empty state — list of tailnet tiles
          // ----------------------------------------------------------------
          : _TailnetList(state: state, tailnets: tailnets),

      // FAB is only shown when there is already at least one tailnet.
      // In the empty state the full-screen CTA button serves the same purpose
      // without the visual duplication of having two "add" affordances.
      floatingActionButton: tailnets.isNotEmpty
          ? FloatingActionButton(
              // The star icon on the FAB matches the add icon in the AppBar
              // to make the relationship clear — both do the same thing.
              onPressed: () => _openAddSheet(context, state),
              tooltip: 'Add tailnet',
              child: const Icon(Icons.add),
            )
          : null,
    );
  }

  // -------------------------------------------------------------------------
  // _openAddSheet — gate for the add-tailnet flow
  // -------------------------------------------------------------------------

  /// Open the [TailnetSetupSheet], preceded by [showAdvancedWarningDialog] if
  /// the user already has one or more tailnets configured.
  ///
  /// The warning dialog explains routing conflicts and the priority mechanism
  /// so the user enters the sheet with informed expectations.
  ///
  /// If the user cancels the warning dialog, the sheet is NOT shown — this
  /// prevents accidental addition of a second tailnet by users who clicked
  /// "Add" by mistake.
  Future<void> _openAddSheet(
    BuildContext context,
    TailscaleState state,
  ) async {
    if (state.tailnets.isNotEmpty) {
      // Show the advanced-feature warning before allowing the second+ tailnet.
      // If the user cancels ("Cancel" button or back-gesture), abort here.
      final confirmed = await showAdvancedWarningDialog(context);
      if (!confirmed) return;
    }

    // Guard: context may no longer be mounted after the await above (unlikely
    // but possible if the screen was popped while the dialog was open).
    if (!context.mounted) return;

    // Show the setup sheet.  Await its completion so _openAddSheet itself
    // completes after the sheet is dismissed.  The caller does not need to
    // do anything after this returns — TailscaleState.loadAll() is called
    // inside the sheet on success, which triggers a rebuild.
    await showTailnetSetupSheet(context);
  }
}

// ---------------------------------------------------------------------------
// _EmptyState — private widget for the "no tailnets" case
// ---------------------------------------------------------------------------

/// Centered empty state shown when no tailnets have been configured.
///
/// Provides a prominent icon, explanatory text, and a [FilledButton] CTA.
class _EmptyState extends StatelessWidget {
  const _EmptyState({required this.onAdd});

  /// Called when the user taps "Add your first tailnet".
  final VoidCallback onAdd;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    return Center(
      child: Padding(
        // Horizontal padding ensures the content does not run to the screen
        // edge on wide screens or landscape orientation.
        padding: const EdgeInsets.symmetric(horizontal: 40),
        child: Column(
          // shrink-wrap so the column sits in the true vertical centre.
          mainAxisSize: MainAxisSize.min,
          children: [
            // Decorative icon — large enough to register as an illustration
            // without being overwhelming.
            Icon(
              Icons.lan_outlined,
              size: 72,
              color: cs.onSurfaceVariant.withValues(alpha: 0.4),
            ),
            const SizedBox(height: 24),

            // Headline — tells the user clearly what this screen is for.
            Text(
              'No tailnets configured',
              style: tt.headlineSmall?.copyWith(color: cs.onSurface),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 12),

            // Body text — explains the value proposition in one sentence.
            // We deliberately keep this short; advanced details are in the
            // setup sheet and the AdvancedWarningDialog.
            Text(
              'Connect Mesh Infinity to a Tailscale or Headscale tailnet to '
              'access peers, exit nodes, and overlay routing.',
              style: tt.bodyMedium?.copyWith(color: cs.onSurfaceVariant),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 32),

            // Primary CTA.  FilledButton is the highest-emphasis button style
            // in Material 3 — appropriate here since adding a tailnet is the
            // only action available in the empty state.
            FilledButton.icon(
              onPressed: onAdd,
              icon: const Icon(Icons.add),
              label: const Text('Add your first tailnet'),
            ),
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _TailnetList — private widget for the non-empty list case
// ---------------------------------------------------------------------------

/// Scrollable list of [TailnetListTile] widgets, one per tailnet instance.
///
/// Also renders the error banner (if any) and a loading indicator (if a
/// bridge call is in flight) above the list content.
class _TailnetList extends StatelessWidget {
  const _TailnetList({
    required this.state,
    required this.tailnets,
  });

  /// The TailscaleState to read loading/error from.
  final TailscaleState state;

  /// The snapshot of the current tailnet list.  Passed from the parent so
  /// this widget does not need to call context.watch again.
  final List<TailnetInstance> tailnets;

  @override
  Widget build(BuildContext context) {
    return ListView.builder(
      // Bottom padding reserves space for the FAB so the last tile is never
      // hidden behind it.
      padding: const EdgeInsets.only(bottom: 96),
      itemCount: tailnets.length
          // Extra items for the error banner and the loading indicator.
          + (state.lastError != null ? 1 : 0)
          + (state.loading ? 1 : 0),
      itemBuilder: (context, index) {
        // Item ordering from top of list:
        //   [0] Error banner (if lastError != null)
        //   [1] Loading indicator (if loading)
        //   [remaining] TailnetListTile for each instance

        int offset = 0;

        // Error banner — shown at position 0 when an error exists.
        if (state.lastError != null) {
          if (index == 0) {
            return _ErrorBanner(
              message: state.lastError!,
              onDismiss: state.clearError,
            );
          }
          offset++;
        }

        // Loading indicator — shown just below the error banner (or at top).
        if (state.loading) {
          if (index == offset) {
            return const Padding(
              padding: EdgeInsets.symmetric(vertical: 8),
              child: LinearProgressIndicator(),
            );
          }
          offset++;
        }

        // Tailnet tile — one per instance.
        final tileIndex = index - offset;
        final instance = tailnets[tileIndex];
        final isPriority = state.priorityTailnetId == instance.id ||
            // Fallback: show the priority badge on the computed priority
            // instance even when no explicit id has been set.
            (state.priorityTailnetId == null &&
                state.priorityInstance?.id == instance.id);

        return TailnetListTile(
          instance: instance,
          isPriority: isPriority,
          totalInstances: tailnets.length,
          // The removal confirmation is handled here in the parent so the
          // tile stays stateless.  The parent owns the dialog lifecycle.
          onRemoveRequest: () => _confirmRemove(context, instance),
        );
      },
    );
  }

  // -------------------------------------------------------------------------
  // _confirmRemove — confirmation dialog for tile remove action
  // -------------------------------------------------------------------------

  /// Show a confirmation dialog and remove the instance if confirmed.
  ///
  /// Removing a tailnet deletes its stored credentials from the backend
  /// keystore — this is irreversible, so we require explicit confirmation.
  Future<void> _confirmRemove(
    BuildContext context,
    TailnetInstance instance,
  ) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Remove tailnet?'),
        content: Text(
          'This will permanently remove "${instance.label}" and delete its '
          'stored credentials. You will need to re-enrol to reconnect to this '
          'tailnet.',
        ),
        actions: [
          // Cancel — do nothing.
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('Cancel'),
          ),
          // Confirm — destructive action, styled in error colour.
          FilledButton(
            style: FilledButton.styleFrom(
              backgroundColor: Theme.of(ctx).colorScheme.error,
              foregroundColor: Theme.of(ctx).colorScheme.onError,
            ),
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('Remove'),
          ),
        ],
      ),
    );

    if (confirmed == true && context.mounted) {
      // Delegate the actual removal to TailscaleState.
      // loadAll() is called internally by removeInstance() so the list
      // rebuilds without any additional work here.
      await context.read<TailscaleState>().removeInstance(instance.id);
    }
  }
}

// ---------------------------------------------------------------------------
// _ErrorBanner — private inline error display
// ---------------------------------------------------------------------------

/// Inline error container shown at the top of the list when
/// [TailscaleState.lastError] is non-null.
///
/// Styled consistently with the error containers in TailnetDetailScreen
/// and TailnetSetupSheet — same padding, same decoration, same dismiss icon.
class _ErrorBanner extends StatelessWidget {
  const _ErrorBanner({
    required this.message,
    required this.onDismiss,
  });

  /// The error message to display.
  final String message;

  /// Called when the user taps the close icon.
  final VoidCallback onDismiss;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    return Padding(
      // Horizontal padding aligns the banner with the list tiles below it.
      padding: const EdgeInsets.fromLTRB(12, 12, 12, 4),
      child: Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: cs.errorContainer,
          borderRadius: BorderRadius.circular(8),
        ),
        child: Row(
          children: [
            // Warning icon — clearly identifies this as an error message.
            Icon(Icons.error_outline, size: 16, color: cs.onErrorContainer),
            const SizedBox(width: 8),
            // Error text — expands to fill available width; wraps if long.
            Expanded(
              child: Text(
                message,
                style: TextStyle(fontSize: 13, color: cs.onErrorContainer),
              ),
            ),
            // Dismiss button — clears the error in TailscaleState so the
            // banner disappears without requiring a full reload.
            IconButton(
              icon: Icon(Icons.close, size: 16, color: cs.onErrorContainer),
              padding: EdgeInsets.zero,
              constraints: const BoxConstraints(),
              onPressed: onDismiss,
            ),
          ],
        ),
      ),
    );
  }
}
