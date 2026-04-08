import 'dart:async';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'calls_state.dart';
import '../peers/peers_state.dart';

// ---------------------------------------------------------------------------
// CallOverlay
//
// A full-screen overlay that appears on top of the app shell whenever a call
// is in any non-idle phase:
//   - outgoingRinging → "Calling…" with hang-up button
//   - incomingRinging → peer name + Accept / Decline
//   - connected       → timer + mute / hang-up
//
// This widget is inserted at the Navigator level in app.dart so it covers
// every screen without disturbing the existing navigation stack.
//
// HOW IT WORKS:
// CallOverlay wraps the entire app shell (widget.child).  When CallsState
// reports a non-idle phase, a _CallScreen is stacked on top of the child
// using a Stack widget.  When the call returns to idle, the Stack collapses
// back to just the child — no navigation push/pop involved.
// ---------------------------------------------------------------------------

/// Wraps [child] with a call overlay layer that automatically appears and
/// disappears as [CallsState] transitions between call phases.
///
/// The overlay uses [Consumer<CallsState>] to rebuild only when call state
/// changes, avoiding unnecessary redraws of the underlying app shell.
class CallOverlay extends StatefulWidget {
  const CallOverlay({super.key, required this.child});

  /// The underlying app shell widget to display beneath the call overlay.
  final Widget child;

  @override
  State<CallOverlay> createState() => _CallOverlayState();
}

class _CallOverlayState extends State<CallOverlay> {
  /// Periodic timer that drives the call duration display once per second.
  /// Stored as a field so it can be cancelled on dispose.
  Timer? _ticker;

  @override
  void initState() {
    super.initState();
    // Drive the call duration display with a 1-second ticker.
    // CallsState.tick() computes elapsed seconds from a stored DateTime, so
    // it is idempotent — calling it when no call is active is a no-op.
    // We tick here (in the UI layer) rather than inside CallsState because
    // the timer is a UI concern: it only needs to run while this widget is
    // mounted, and it avoids CallsState needing to manage its own timer.
    _ticker = Timer.periodic(const Duration(seconds: 1), (_) {
      context.read<CallsState>().tick();
    });
  }

  @override
  void dispose() {
    // Cancel the timer to prevent it from firing after the widget is removed
    // from the tree, which would call context.read() on an unmounted context.
    _ticker?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    // Consumer<CallsState> subscribes this builder to call phase changes.
    // When the phase is idle, we return the child directly — no Stack
    // overhead — so there is zero rendering cost during normal use.
    return Consumer<CallsState>(
      builder: (context, calls, _) {
        if (calls.phase == CallPhase.idle) return widget.child;

        // Non-idle: stack the call screen on top of the app shell so the
        // user can still see (but not interact with) the underlying UI.
        return Stack(
          children: [
            widget.child,
            _CallScreen(calls: calls),
          ],
        );
      },
    );
  }
}

// ---------------------------------------------------------------------------
// _CallScreen — the actual overlay content
// ---------------------------------------------------------------------------

/// The full-screen call UI rendered on top of the app shell during a call.
///
/// Renders one of three layouts depending on [CallsState.phase]:
///   - [CallPhase.outgoingRinging]: peer avatar + "Calling…" + hang-up button.
///   - [CallPhase.incomingRinging]: peer avatar + "Incoming call" + Accept/Decline.
///   - [CallPhase.connected]:        peer avatar + elapsed timer + hang-up button.
class _CallScreen extends StatelessWidget {
  const _CallScreen({required this.calls});
  final CallsState calls;

  /// Resolves the remote peer's display name from [PeersState].
  ///
  /// Falls back to a truncated peer ID prefix if the peer is not in the
  /// local contact list or if PeersState is not available.
  ///
  /// WHY the try/catch: PeersState may not be in scope if the widget tree
  /// is being torn down during a hot restart or when tests do not provide
  /// the provider.  The overlay must remain stable in all conditions.
  String _peerName(BuildContext context) {
    if (calls.remotePeerId == null) return 'Unknown';
    try {
      final peers = context.read<PeersState>();
      final peer = peers.peers
          .where((p) => p.id == calls.remotePeerId)
          .firstOrNull;
      // Fall back to the first 8 characters of the hex peer ID if the peer
      // is not found in the local contact list (e.g. unknown caller).
      return peer?.name ?? calls.remotePeerId!.substring(0, 8);
    } catch (_) {
      // PeersState not available — use the raw peer ID prefix.
      // Error is swallowed because this is a display-only fallback; the user
      // will see a truncated peer ID, which is better than a crash.
      return calls.remotePeerId!.substring(0, 8);
    }
  }

  /// Formats [secs] as "MM:SS" for the connected-call timer display.
  ///
  /// padLeft(2, '0') zero-pads single-digit minutes and seconds so the
  /// display width stays constant (e.g. "02:07" not "2:7").
  String _formatDuration(int secs) {
    final m = secs ~/ 60;
    final s = secs % 60;
    return '${m.toString().padLeft(2, '0')}:${s.toString().padLeft(2, '0')}';
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final name = _peerName(context);

    return Material(
      // Semi-transparent surface tint covers the app shell without fully
      // hiding it — alpha 230/255 ≈ 90% opaque, giving the user a sense of
      // the app still being "alive" beneath the call.
      color: cs.surfaceContainerHighest.withAlpha(230),
      child: SafeArea(
        // SafeArea ensures content stays clear of notches and home-bar areas.
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 48),
          child: Column(
            // spaceBetween pushes the header group to the top and the action
            // buttons to the bottom, giving the layout visual balance.
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              // ── Header ──────────────────────────────────────────────────
              Column(
                children: [
                  // Contact avatar — shows the first letter of the peer name
                  // in a large circle.  Will be replaced by MaskAvatar when
                  // avatar data is wired through PeerModel (§22.4.3).
                  CircleAvatar(
                    radius: 48,
                    backgroundColor: cs.primaryContainer,
                    child: Text(
                      // Guard against an empty name string to avoid an
                      // index-out-of-range error on name[0].
                      name.isNotEmpty ? name[0].toUpperCase() : '?',
                      style: TextStyle(
                        fontSize: 40,
                        fontWeight: FontWeight.bold,
                        color: cs.onPrimaryContainer,
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),
                  Text(name,
                      style: Theme.of(context).textTheme.headlineSmall),
                  const SizedBox(height: 8),
                  // Status label: "Calling…", "Incoming call", "Voice call", etc.
                  Text(
                    _statusLabel(),
                    style: Theme.of(context)
                        .textTheme
                        .bodyMedium
                        ?.copyWith(color: cs.onSurfaceVariant),
                  ),
                  // Duration timer is only shown once the call is connected.
                  if (calls.phase == CallPhase.connected) ...[
                    const SizedBox(height: 4),
                    Text(
                      _formatDuration(calls.durationSecs),
                      style: Theme.of(context)
                          .textTheme
                          .bodySmall
                          ?.copyWith(color: cs.onSurfaceVariant),
                    ),
                  ],
                ],
              ),

              // ── Action buttons ───────────────────────────────────────────
              // Which buttons are shown depends entirely on the call phase.
              // See _buildButtons() for details.
              _buildButtons(context, cs),
            ],
          ),
        ),
      ),
    );
  }

  /// Returns the human-readable status label for the current [CallPhase].
  String _statusLabel() {
    return switch (calls.phase) {
      CallPhase.outgoingRinging => 'Calling…',
      // Distinguish video vs audio for the incoming label so the user knows
      // what they are about to accept.
      CallPhase.incomingRinging =>
          calls.isVideo ? 'Incoming video call' : 'Incoming call',
      CallPhase.connected => calls.isVideo ? 'Video call' : 'Voice call',
      // idle is unreachable here because CallOverlay hides _CallScreen when
      // phase == idle, but the switch must be exhaustive.
      CallPhase.idle => '',
    };
  }

  /// Builds the action button row for the current [CallPhase].
  ///
  /// - incomingRinging: Decline (red) + Accept (green) side by side.
  /// - outgoingRinging / connected: single Hang Up (red) centred.
  /// - idle: empty — should never be reached (see _statusLabel note above).
  Widget _buildButtons(BuildContext context, ColorScheme cs) {
    switch (calls.phase) {
      case CallPhase.incomingRinging:
        return Row(
          mainAxisAlignment: MainAxisAlignment.spaceEvenly,
          children: [
            _CircleButton(
              icon: Icons.call_end,
              color: cs.error,
              label: 'Decline',
              onPressed: () => context.read<CallsState>().declineCall(),
            ),
            _CircleButton(
              icon: Icons.call,
              // Green is universal for "accept call" — not themed because
              // the semantic must override colour-scheme variations.
              color: Colors.green,
              label: 'Accept',
              onPressed: () => context.read<CallsState>().acceptCall(),
            ),
          ],
        );

      // During outgoing ringing and while connected, the only action the
      // user can take is to hang up.
      case CallPhase.outgoingRinging:
      case CallPhase.connected:
        return Center(
          child: _CircleButton(
            icon: Icons.call_end,
            color: cs.error,
            label: 'Hang up',
            onPressed: () => context.read<CallsState>().hangUp(),
          ),
        );

      case CallPhase.idle:
        // Idle should never be visible — CallOverlay hides this widget.
        return const SizedBox.shrink();
    }
  }
}

/// A large circular FAB-style button with an icon and a text label below it.
///
/// Used in the call overlay for Accept / Decline / Hang Up actions.
/// The large tap target (56px FAB) is intentional for a high-stress interaction
/// where precise tapping may be difficult.
class _CircleButton extends StatelessWidget {
  const _CircleButton({
    required this.icon,
    required this.color,
    required this.label,
    required this.onPressed,
  });

  final IconData icon;
  final Color color;
  final String label;
  final VoidCallback onPressed;

  @override
  Widget build(BuildContext context) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        FloatingActionButton(
          // heroTag must be unique across all FABs visible simultaneously.
          // Using [label] (e.g. "Accept", "Decline") guarantees uniqueness
          // since the two concurrent buttons always have different labels.
          heroTag: label,
          backgroundColor: color,
          onPressed: onPressed,
          // White icon contrasts against any coloured background (red/green).
          child: Icon(icon, color: Colors.white),
        ),
        const SizedBox(height: 8),
        Text(label, style: Theme.of(context).textTheme.labelSmall),
      ],
    );
  }
}
