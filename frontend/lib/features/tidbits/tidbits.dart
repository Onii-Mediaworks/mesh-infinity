// tidbits.dart
//
// Playful Tidbits — top-level init + barrel export (§22.12).
//
// USAGE:
// ------
// 1. Call initTidbits() once at app startup (from app.dart initState).
// 2. Import this barrel file anywhere you need tidbit widgets or the registry:
//      import '../features/tidbits/tidbits.dart';
//
// ARCHITECTURE SUMMARY:
// ---------------------
// TidbitRegistry  — singleton store; register + show by string ID.
// TidbitDef       — data class for one tidbit (id, specRef, mode, show fn).
// TidbitMode      — enum: localOnly / friendShared / gardenShared / practicalUtility.
// TapTrigger      — transparent tap-count wrapper widget.
// ConfettiBurst   — particle confetti overlay (showConfettiBurst helper).
// SnowfallLayer   — ambient winter snow background layer.
// GardenGnomeWidget — rare gnome in empty Garden states.
// HaikuGenerator  — deterministic haiku from a string.
// initLocalTidbits / registerHaikuForPeer — catalogue registration.

// Direct imports needed here because this file defines initTidbits(), which
// calls into the catalogue and registry.  Re-exports below expose these to
// consumers of the barrel.
import 'tidbit_registry.dart';
import 'catalogue/local_tidbits.dart';

export 'tidbit_registry.dart';
export 'haiku_generator.dart';
export 'widgets/tap_trigger.dart';
export 'widgets/confetti_burst.dart';
export 'widgets/snowfall_layer.dart';
export 'widgets/garden_gnome.dart';
export 'catalogue/local_tidbits.dart' show initLocalTidbits, registerHaikuForPeer;

// ---------------------------------------------------------------------------
// initTidbits — call once from app.dart
// ---------------------------------------------------------------------------

/// Initialises the [TidbitRegistry] with all known tidbits.
///
/// Safe to call multiple times (idempotent — last-write-wins per ID).
/// Must be called before the first frame so that tidbit IDs are available
/// when the widget tree builds.
void initTidbits() {
  // Register all local-only tidbits (the main catalogue).
  // Friends/Garden tidbits will get their own init functions when implemented.
  initLocalTidbits(TidbitRegistry.instance);
}
