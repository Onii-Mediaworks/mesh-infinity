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
// ---------------------------------------------------------------------------

class CallOverlay extends StatefulWidget {
  const CallOverlay({super.key, required this.child});

  final Widget child;

  @override
  State<CallOverlay> createState() => _CallOverlayState();
}

class _CallOverlayState extends State<CallOverlay> {
  Timer? _ticker;

  @override
  void initState() {
    super.initState();
    // Tick every second to update call duration display.
    _ticker = Timer.periodic(const Duration(seconds: 1), (_) {
      context.read<CallsState>().tick();
    });
  }

  @override
  void dispose() {
    _ticker?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Consumer<CallsState>(
      builder: (context, calls, _) {
        if (calls.phase == CallPhase.idle) return widget.child;

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

class _CallScreen extends StatelessWidget {
  const _CallScreen({required this.calls});
  final CallsState calls;

  String _peerName(BuildContext context) {
    if (calls.remotePeerId == null) return 'Unknown';
    try {
      final peers = context.read<PeersState>();
      final peer = peers.peers
          .where((p) => p.id == calls.remotePeerId)
          .firstOrNull;
      return peer?.name ?? calls.remotePeerId!.substring(0, 8);
    } catch (_) {
      return calls.remotePeerId!.substring(0, 8);
    }
  }

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
      color: cs.surfaceContainerHighest.withAlpha(230),
      child: SafeArea(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 48),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              // ── Header ──────────────────────────────────────────────────
              Column(
                children: [
                  CircleAvatar(
                    radius: 48,
                    backgroundColor: cs.primaryContainer,
                    child: Text(
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
                  Text(
                    _statusLabel(),
                    style: Theme.of(context)
                        .textTheme
                        .bodyMedium
                        ?.copyWith(color: cs.onSurfaceVariant),
                  ),
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
              _buildButtons(context, cs),
            ],
          ),
        ),
      ),
    );
  }

  String _statusLabel() {
    return switch (calls.phase) {
      CallPhase.outgoingRinging => 'Calling…',
      CallPhase.incomingRinging =>
          calls.isVideo ? 'Incoming video call' : 'Incoming call',
      CallPhase.connected => calls.isVideo ? 'Video call' : 'Voice call',
      CallPhase.idle => '',
    };
  }

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
              color: Colors.green,
              label: 'Accept',
              onPressed: () => context.read<CallsState>().acceptCall(),
            ),
          ],
        );

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
        return const SizedBox.shrink();
    }
  }
}

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
          heroTag: label,
          backgroundColor: color,
          onPressed: onPressed,
          child: Icon(icon, color: Colors.white),
        ),
        const SizedBox(height: 8),
        Text(label, style: Theme.of(context).textTheme.labelSmall),
      ],
    );
  }
}
