// tidbit_registry.dart
//
// ignore_for_file: unused_import
import 'package:flutter/widgets.dart'; // BuildContext, Overlay, OverlayEntry
//
// Central registry for all Playful Tidbits (§22.12).
//
// WHAT IS A PLAYFUL TIDBIT?
// -------------------------
// A Playful Tidbit is a small, optional, hidden amusement inside Mesh
// Infinity — an easter egg, a tiny game, a whimsical animation.  They are
// never intrusive, never block serious tasks, and are intentionally difficult
// to stumble across by accident (§22.12.1).
//
// The spec explicitly allows tens of thousands of tidbits over the lifetime
// of the product.  Each one should be around a dozen lines of implementation.
// The spec's 100-item catalogue is a starting point, not a ceiling.
//
// HOW THE REGISTRY WORKS:
// -----------------------
// 1. Each tidbit is described by a [TidbitDef] — id, spec reference, mode,
//    and a [show] callback that does the actual presentation work.
// 2. Feature code calls [TidbitRegistry.instance.register(def)] at startup
//    to add tidbits to the registry (see tidbits_catalogue.dart).
// 3. UI code calls [TidbitRegistry.instance.show('id', context)] when a
//    trigger condition is met (e.g. after a tap count, at a certain time).
//
// ADDING A NEW TIDBIT:
// --------------------
// 1. Open catalogue/local_tidbits.dart (or create a new catalogue file).
// 2. Add a registration call inside the existing init function (~10 lines).
// 3. Add a trigger site in the relevant UI widget (~3 lines).
// That's it.  No new infrastructure needed.

/// Delivery and social context for a [TidbitDef].
///
/// Mirrors the Rust enum at §22.12.2:
///   LocalOnly        — runs entirely on one device
///   FriendShared     — uses an existing trusted relationship
///   GardenShared     — usable within a Garden context
///   PracticalUtility — playful but also operationally useful
enum TidbitMode {
  // The tidbit needs no network access and no other participants.
  // Safe to run in fully offline / air-gapped mode.
  localOnly,

  // The tidbit is more fun with friends and uses Mesh Infinity's own
  // friend / contact system (never a new identity concept).
  friendShared,

  // The tidbit integrates with a Garden channel or topic.
  gardenShared,

  // The tidbit is playful but also teaches something about the network:
  // latency, connectivity, proximity, trust progress, etc.
  practicalUtility,
}

// ---------------------------------------------------------------------------
// TidbitDef — one registered playful tidbit
// ---------------------------------------------------------------------------

/// Describes a single Playful Tidbit.
///
/// The [show] function receives a [BuildContext] and is responsible for
/// presenting the tidbit — showing an overlay, a dialog, navigating, or
/// triggering a side effect.  It may be a no-op if the tidbit is not yet
/// implemented (set [implemented] = false to suppress the trigger call).
class TidbitDef {
  // All fields are required.  The registry checks [implemented] before calling
  // [show], so stub entries are safe to leave in the catalogue.
  const TidbitDef({
    required this.id,
    required this.specRef,
    required this.mode,
    required this.show,
    this.implemented = true,
  });

  // Unique string identifier used to call this tidbit from UI code.
  // Naming convention: lowercase_with_underscores, matching the spec name.
  // Example: 'copy_confetti', 'tiny_pong', 'garden_gnome'.
  final String id;

  // Spec reference for audit trail.  Example: '§22.12.5 #7'.
  // If this is a new tidbit not in the original 100, use '§22.12.5 (new)'.
  final String specRef;

  // Delivery context — what kind of social/network access this tidbit needs.
  final TidbitMode mode;

  // The presentation callback.  Called with a BuildContext that is safe to
  // use for Navigator, Overlay, showDialog, etc.
  // Constraint: must NEVER block serious user flows (§22.12.3).
  final void Function(BuildContext context) show;

  // Set to false for tidbits that are registered in the catalogue but whose
  // visual/interactive implementation is not yet written.  A stub entry is
  // better than no entry — it reserves the ID and documents the intent.
  final bool implemented;
}

// ---------------------------------------------------------------------------
// TidbitRegistry — singleton store for all registered tidbits
// ---------------------------------------------------------------------------

/// Singleton registry.  All registered [TidbitDef]s live here.
///
/// Access pattern:
///   // In catalogue init code:
///   TidbitRegistry.instance.register(TidbitDef(...));
///
///   // In UI trigger code:
///   TidbitRegistry.instance.show('copy_confetti', context);
class TidbitRegistry {
  // ---------------------------------------------------------------------------
  // Singleton plumbing
  // ---------------------------------------------------------------------------

  // Factory constructor always returns the same instance.
  // Using a named private constructor prevents accidental external construction.
  static final TidbitRegistry instance = TidbitRegistry._();
  TidbitRegistry._();

  // The actual store: string ID → TidbitDef.
  // Using a Map gives O(1) lookup — important if we eventually have thousands.
  final Map<String, TidbitDef> _defs = {};

  // ---------------------------------------------------------------------------
  // Registration
  // ---------------------------------------------------------------------------

  /// Register a [TidbitDef].  If a def with the same [id] already exists it
  /// is replaced (last-write-wins; useful for hot reload during development).
  void register(TidbitDef def) {
    _defs[def.id] = def;
  }

  /// Register a list of defs at once — convenience for catalogue init.
  void registerAll(Iterable<TidbitDef> defs) {
    for (final d in defs) {
      _defs[d.id] = d;
    }
  }

  // ---------------------------------------------------------------------------
  // Triggering
  // ---------------------------------------------------------------------------

  /// Show the tidbit with [id], using [context] for overlay/dialog/navigation.
  ///
  /// Silently does nothing if:
  ///  - the [id] is not registered (safe to call from UI without null checks)
  ///  - [TidbitDef.implemented] is false (stub entry)
  void show(String id, BuildContext context) {
    final def = _defs[id];
    if (def == null || !def.implemented) return;
    def.show(context);
  }

  // ---------------------------------------------------------------------------
  // Inspection (for debug menu / testing)
  // ---------------------------------------------------------------------------

  /// All registered tidbit IDs.  Useful for the debug screen and unit tests.
  List<String> get allIds => List.unmodifiable(_defs.keys);

  /// Count of registered tidbits (includes stubs).
  int get count => _defs.length;

  /// Count of fully implemented tidbits.
  int get implementedCount =>
      _defs.values.where((d) => d.implemented).length;
}
