import 'package:flutter/material.dart';

/// Inline error display for non-fatal, recoverable errors within a screen.
///
/// Never use a full-screen error state for recoverable errors — always use
/// this widget instead (§22.4.8).  The banner is rendered inside the normal
/// screen layout (e.g. at the top of a list) so the user can still see and
/// interact with whatever content is available.
///
/// If [onRetry] is provided, a "Retry" button appears at the trailing edge.
/// Omit it for errors where a retry makes no sense (e.g. a permissions error
/// that requires the user to go to system settings).
class ErrorBanner extends StatelessWidget {
  const ErrorBanner({super.key, required this.message, this.onRetry});

  /// Human-readable description of what went wrong.
  final String message;

  /// Optional callback invoked when the user taps "Retry".
  /// Null hides the button — use when the user cannot directly trigger a fix.
  final VoidCallback? onRetry;

  @override
  Widget build(BuildContext context) {
    // Cache the color scheme once — it is referenced multiple times below.
    final cs = Theme.of(context).colorScheme;
    return Padding(
      // Horizontal padding keeps the banner from touching the screen edges.
      // Vertical padding creates a small gap between this and adjacent widgets.
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        decoration: BoxDecoration(
          // errorContainer is the M3 semantic colour for error backgrounds —
          // it is a soft tint of the error colour, readable without being
          // alarming.
          color: cs.errorContainer,
          borderRadius: BorderRadius.circular(8),
        ),
        child: Row(
          children: [
            // Warning icon reinforces the error semantic for users who rely
            // on colour and for accessibility (screen readers announce
            // the icon's semantic label alongside the message text).
            Icon(
              Icons.warning_amber_rounded,
              size: 18,
              // onErrorContainer ensures the icon is legible on the tinted
              // errorContainer background in both light and dark modes.
              color: cs.onErrorContainer,
            ),
            const SizedBox(width: 8),
            // Expanded lets the message text take up all remaining horizontal
            // space, pushing the Retry button to the far right.
            Expanded(
              child: Text(
                message,
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  color: cs.onErrorContainer,
                ),
              ),
            ),
            // Retry button — only rendered when the caller provides a callback,
            // meaning the action is meaningful (e.g. re-fetching a resource).
            if (onRetry != null)
              TextButton(
                onPressed: onRetry,
                style: TextButton.styleFrom(
                  // Match the text/icon colour to onErrorContainer so the
                  // button remains legible on the error background.
                  foregroundColor: cs.onErrorContainer,
                  // Reduce side padding so the button fits comfortably next
                  // to a long message string on narrow screens.
                  padding: const EdgeInsets.symmetric(horizontal: 8),
                ),
                child: const Text('Retry'),
              ),
          ],
        ),
      ),
    );
  }
}
