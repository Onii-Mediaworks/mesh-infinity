// explore_screen.dart
//
// GardenExploreScreen is sub-page 2 of the Garden section.
// It shows a discoverable list of public, open, and closed gardens on the
// local mesh so users can browse and join communities.
//
// WHAT IS "DISCOVERING" A GARDEN?
// --------------------------------
// The backend's discoverGardens() call returns gardens that are broadcasting
// their existence on the mesh (via the service-discovery layer).  Gardens
// with networkType == 'private' do not broadcast and will never appear here —
// they can only be joined via a direct invitation.
//
// NETWORKTYPE VALUES
// ------------------
// Each garden has a networkType string that controls visibility and join policy:
//   public  — anyone can join without approval.
//   open    — anyone can join; membership is visible.
//   closed  — invitation only; name is visible to the mesh.
//   private — invitation only; completely hidden from discovery.
//   joined  — synthetic value set by the backend when the local node is
//             already a member, used to show a "Joined" tick instead of a
//             Join button.
//
// GARDEN GNOME (§22.12.5 #20)
// ----------------------------
// On approximately 1-in-5 calendar days, a small GardenGnomeWidget appears
// below the EmptyState on the "no gardens found" screen.  This is a design
// flourish defined in §22.12.5 #20.  It never replaces the empty state;
// it only appears beneath it.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../backend/backend_bridge.dart';
// BackendBridge — all Rust FFI calls, including discoverGardens() and joinGarden().
import '../../core/widgets/empty_state.dart';
// EmptyState — shared zero-data placeholder shown when no gardens are found.
import '../../app/app_theme.dart';
// MeshTheme — brand colour used by the garden avatar tile.
import '../../core/widgets/focus_ring.dart';
import '../../core/widgets/load_gate.dart';
// FocusRing — shell focus ring around the Join button (§22.36 rule 3).
import '../../shell/primary_focus.dart';
// PrimaryFocus — declares where key/pad focus lands on open (§22.36).
import '../tidbits/widgets/garden_gnome.dart'; // §22.12.5 #20 Garden Gnome

// GardenGnomeWidget — the §22.12.5 design-flourish widget.

/// Discoverable-garden browser screen.
///
/// Loaded from sub-page index 2 of the Garden section shell.
/// On initial mount, calls discoverGardens() to populate the list.
/// Pull-to-refresh repeats the discovery call.
class GardenExploreScreen extends StatefulWidget {
  const GardenExploreScreen({super.key});
  @override
  State<GardenExploreScreen> createState() => _GardenExploreScreenState();
}

class _GardenExploreScreenState extends State<GardenExploreScreen> {
  // ---------------------------------------------------------------------------
  // State fields
  // ---------------------------------------------------------------------------

  /// The list of discovered gardens returned by the backend.
  /// Starts empty; populated by _load().
  List<Map<String, dynamic>> _gardens = const [];

  /// True while _load() is running — shows a full-screen spinner.
  bool _loading = true;

  // Failure text from the last discovery, or null (§22.51).  A failed load
  // shows the ErrorBanner, never "No gardens found".
  String? _error;

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  @override
  void initState() {
    super.initState();
    // Start discovery immediately so the list is populated on first render.
    _load();
  }

  // ---------------------------------------------------------------------------
  // Data loading
  // ---------------------------------------------------------------------------

  /// Calls discoverGardens() on the backend and updates the list.
  ///
  /// The [mounted] guard before setState prevents a "setState after dispose"
  /// error if the user navigates away while the call is in flight.
  Future<void> _load() async {
    final bridge = context.read<BackendBridge>();

    // discoverGardens() queries the local mesh discovery layer (synchronous
    // FFI call today — returns cached results from Rust's service registry).
    List<Map<String, dynamic>>? gardens;
    String? error;
    try {
      gardens = bridge.discoverGardens();
    } on Object catch (_) {
      // Report the failure instead of showing the empty state.
      final reason = bridge.getLastError();
      error = (reason == null || reason.isEmpty)
          ? "Couldn't load gardens. Check your mesh connection."
          : reason;
    }

    if (mounted) {
      setState(() {
        if (gardens != null) _gardens = gardens;
        _error = error;
        _loading = false;
      });
    }
  }

  // ---------------------------------------------------------------------------
  // Actions
  // ---------------------------------------------------------------------------

  /// Attempts to join the given garden.
  ///
  /// [garden] is the map from _gardens with at least an 'id' and 'name' key.
  /// An empty gardenId means the backend returned a malformed record — we
  /// bail out silently rather than sending a join request for an empty ID.
  ///
  /// On success, _load() is called so the tile updates to show "Joined".
  /// On failure, the backend's last-error string is shown in a SnackBar.
  Future<void> _joinGarden(Map<String, dynamic> garden) async {
    final bridge = context.read<BackendBridge>();
    final gardenId = garden['id'] as String? ?? '';

    // Guard against a malformed entry — empty ID would cause a Rust panic.
    if (gardenId.isEmpty) {
      return;
    }

    final ok = bridge.joinGarden(gardenId);

    if (!mounted) {
      return;
    }

    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          ok
              // Use the garden name for the success message.
              ? 'Joined ${garden['name'] as String? ?? 'garden'}'
              // Show the backend's last-error string so the user knows WHY it failed
              // (e.g. "garden is closed — invitation required").
              : (bridge.getLastError() ?? 'Could not join that garden.'),
        ),
      ),
    );

    if (ok) {
      // Reload so the "Join" button on the tile changes to a "Joined" tick.
      await _load();
    }
  }

  // ---------------------------------------------------------------------------
  // Build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    // LoadGate (§22.50 / §22.51): shimmer while loading, ErrorBanner after a
    // failed load, and the empty state only after a successful empty load.
    return LoadGate(
      loading: _loading,
      error: _error,
      is_empty: _gardens.isEmpty,
      on_retry: _load,
      shimmer_count: 4,
      shimmer_height: 72,
      // Empty state + optional Garden Gnome easter-egg (§22.12.5 #20).
      // The Gnome is rendered below the EmptyState — it never replaces it.
      // GardenGnomeWidget uses its own internal random seed to decide whether
      // to show itself on any given calendar day (~1-in-5 chance).
      empty: const Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          EmptyState(
            icon: Icons.explore_outlined,
            title: 'No gardens found',
            body: 'Discoverable public or open gardens will appear here.',
          ),
          GardenGnomeWidget(),
        ],
      ),
      child: _gardens_list(),
    );
  }

  /// Scrollable list of discoverable gardens.
  ///
  /// PrimaryFocus (§22.36 rule 2): the first row's Join button is the
  /// primary action, since the rows themselves are not tappable.
  Widget _gardens_list() {
    return PrimaryFocus(
      child: RefreshIndicator(
        onRefresh: _load,
        child: ListView.builder(
          padding: const EdgeInsets.symmetric(vertical: 4),
          itemCount: _gardens.length,
          itemBuilder: (context, i) => _GardenTile(
            garden: _gardens[i],
            // Close over the current index so the callback always references
            // the correct garden even if the list is rebuilt between taps.
            onJoin: () => _joinGarden(_gardens[i]),
          ),
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _GardenTile — one row in the explore list
// ---------------------------------------------------------------------------

/// Displays a garden's name, member count, description, and networkType badge.
///
/// Shows either a "Join" button (if not yet a member) or a green check icon
/// (if already joined) in the trailing position.
///
/// Stateful only to own a non-focusable node for the ListTile: the row has
/// no tap action, so it must not be a Tab stop — focus goes straight to the
/// Join button (§22.36 rule 2).
class _GardenTile extends StatefulWidget {
  const _GardenTile({required this.garden, required this.onJoin});

  /// The raw garden map from discoverGardens().
  final Map<String, dynamic> garden;

  /// Called when the user taps the Join button.
  final VoidCallback onJoin;

  @override
  State<_GardenTile> createState() => _GardenTileState();
}

class _GardenTileState extends State<_GardenTile> {
  /// Keeps the row itself out of traversal; the Join button is the control.
  final FocusNode _row_focus = FocusNode(
    canRequestFocus: false,
    skipTraversal: true,
    debugLabel: 'garden_row',
  );

  @override
  void dispose() {
    _row_focus.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final garden = widget.garden;
    final theme = Theme.of(context);
    final cs = theme.colorScheme;

    // Parse with null-safe casts — backend maps use dynamic values.
    final name = garden['name'] as String? ?? 'Unnamed garden';
    final description = garden['description'] as String? ?? '';
    final memberCount = (garden['memberCount'] as num?)?.toInt() ?? 0;
    final networkType = garden['networkType'] as String? ?? 'public';

    // The backend sets joined == true when the local node is already a member.
    final joined = garden['joined'] == true;

    return ListTile(
      focusNode: _row_focus,
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),

      // Garden avatar — rounded square with brand-tinted background.
      leading: ClipRRect(
        borderRadius: BorderRadius.circular(12),
        child: Container(
          width: 48,
          height: 48,
          color: MeshTheme.brand.withValues(alpha: 0.12),
          child: const Icon(Icons.groups_outlined, color: MeshTheme.brand),
        ),
      ),

      // Title row: name + networkType badge on the right of the name.
      title: Row(
        children: [
          Expanded(
            child: Text(
              name,
              style: theme.textTheme.titleSmall,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
          ),
          // Badge shows public/open/closed/private/joined — see _NetworkTypeBadge.
          _NetworkTypeBadge(type: networkType),
        ],
      ),

      // Subtitle row: member count + description snippet.
      subtitle: Row(
        children: [
          Icon(Icons.people_outline, size: 14, color: cs.onSurfaceVariant),
          const SizedBox(width: 4),
          Text(
            '$memberCount member${memberCount == 1 ? '' : 's'}',
            style: theme.textTheme.bodySmall?.copyWith(
              color: cs.onSurfaceVariant,
            ),
          ),
          // Description is optional — only render it if the backend provided one.
          if (description.isNotEmpty) ...[
            const SizedBox(width: 8),
            Expanded(
              child: Text(
                description,
                style: theme.textTheme.bodySmall?.copyWith(
                  color: cs.onSurfaceVariant,
                ),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
              ),
            ),
          ],
        ],
      ),

      // Trailing: check icon for already-joined gardens; Join button otherwise.
      // Showing a check (not the join button) prevents accidental re-join
      // attempts and gives clear feedback about membership status.
      // The Join button carries the shell focus ring (§22.36 rule 3); 20 dp
      // matches the M3 outlined-button pill.
      trailing: joined
          ? Icon(Icons.check_circle_outline, color: cs.primary)
          : FocusRing(
              radius: 20,
              child: OutlinedButton(
                onPressed: widget.onJoin,
                child: const Text('Join'),
              ),
            ),
    );
  }
}

// ---------------------------------------------------------------------------
// _NetworkTypeBadge — neutral chip showing the garden's join policy
// ---------------------------------------------------------------------------

/// A neutral outlined chip naming a garden's networkType (§22.6.1, CMR-025).
///
/// It deliberately carries no security colour: green, amber and purple are
/// reserved for verified / LoSec / compromised states, and a private garden
/// must not wear the same colour as a compromised contact. Meaning comes
/// from the icon and the label, drawn in `onSurfaceVariant`.
class _NetworkTypeBadge extends StatelessWidget {
  const _NetworkTypeBadge({required this.type});

  /// The raw networkType string from the backend.
  final String type;

  @override
  Widget build(BuildContext context) {
    // One neutral role for icon, text and outline; the theme supplies the
    // contrast-safe value for light and dark.
    final color = Theme.of(context).colorScheme.onSurfaceVariant;
    return Semantics(
      // Screen readers get the policy by name, not "chip".
      label: '${_label()} garden',
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(4),
          border: Border.all(color: color.withValues(alpha: 0.5)),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Icon first so the policy is readable at a glance without
            // relying on colour (§22.34).
            Icon(_icon(), size: 12, color: color),
            const SizedBox(width: 3),
            Text(
              _label(),
              style: TextStyle(
                fontSize: 10,
                color: color,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
      ),
    );
  }

  /// One icon per join policy, so the chip never depends on colour.
  IconData _icon() => switch (type) {
    'joined' => Icons.check_circle_outline,
    'public' => Icons.public,
    'open' => Icons.lock_open_outlined,
    'closed' => Icons.lock_outline,
    'private' => Icons.visibility_off_outlined,
    _ => Icons.help_outline, // Unknown type — say so rather than guess.
  };

  /// Returns the human-readable label for the given networkType.
  String _label() => switch (type) {
    'joined' => 'Joined',
    'public' => 'Public',
    'open' => 'Open',
    'closed' => 'Closed',
    'private' => 'Private',
    _ => type, // Pass through unknown types verbatim.
  };
}
