import 'package:flutter/widgets.dart';

/// Reduced-motion helpers (SPEC §22.1.7, §22.34).
///
/// The platform reports the user's "remove animations" preference through
/// `MediaQuery.disableAnimations`.  The spec says to respect it
/// unconditionally: every duration becomes zero and every looping or pulsing
/// indicator is replaced by a static equivalent.  Screens never read
/// MediaQuery for this themselves; they call the two functions below so the
/// rule lives in exactly one place.

/// True when the user asked the platform to remove animations.
///
/// Uses the `maybe` lookup so widgets built outside a MediaQuery (some
/// overlay and test hosts) fall back to "animations allowed" instead of
/// throwing.
bool reduced_motion(BuildContext context) {
  return MediaQuery.maybeDisableAnimationsOf(context) ?? false;
}

/// Returns [normal], or [Duration.zero] when reduced motion is on.
///
/// Wrap every `AnimationController`, `AnimatedXxx`, `animateTo` and route
/// transition duration in this call.
Duration motion_duration(BuildContext context, Duration normal) {
  return reduced_motion(context) ? Duration.zero : normal;
}
