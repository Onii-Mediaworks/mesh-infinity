import 'package:flutter/material.dart';

import 'error_banner.dart';
import 'shimmer.dart';

/// Chooses between shimmer, error banner, empty state and content for a list
/// screen (SPEC §22.49 / §22.50 / §22.51).
///
/// The rule it enforces in one place: an [EmptyState] is only truthful when a
/// load finished successfully and found nothing.  So while a load is in
/// flight the list shows shimmer tiles, and after a failed load it shows the
/// inline `ErrorBanner` -- never the "nothing here yet" copy.
///
/// Order of precedence when the list has no rows:
///   1. [loading]  -> [ShimmerList]
///   2. [error]    -> [ErrorBanner] (retry button only if [on_retry] is set)
///   3. otherwise  -> [empty]
/// When rows exist they are always shown, with the banner above them if a
/// refresh failed, so stale data is never hidden by a transient error.
class LoadGate extends StatelessWidget {
  const LoadGate({
    super.key,
    required this.loading,
    required this.error,
    required this.is_empty,
    required this.empty,
    required this.child,
    required this.shimmer_count,
    required this.shimmer_height,
    this.on_retry,
  });

  /// True while a load is in flight.
  final bool loading;

  /// Failure message from the last load, or null when it succeeded.
  final String? error;

  /// True when the loaded data has no rows.
  final bool is_empty;

  /// The §22.49 empty state, shown only after a successful empty load.
  final Widget empty;

  /// The populated content.
  final Widget child;

  /// Number of placeholder tiles (§22.50 table).
  final int shimmer_count;

  /// Height of each placeholder tile (§22.50 table).
  final double shimmer_height;

  /// Retry callback; null where §22.51 says pull-to-refresh is the retry.
  final VoidCallback? on_retry;

  @override
  Widget build(BuildContext context) {
    final message = error;

    if (is_empty) {
      if (loading) {
        return ShimmerList(count: shimmer_count, height: shimmer_height);
      }
      if (message != null) {
        // A scrollable host keeps pull-to-refresh usable for retry.
        return ListView(
          physics: const AlwaysScrollableScrollPhysics(),
          children: [ErrorBanner(message: message, onRetry: on_retry)],
        );
      }
      return empty;
    }

    if (message == null) return child;
    return Column(
      children: [
        ErrorBanner(message: message, onRetry: on_retry),
        Expanded(child: child),
      ],
    );
  }
}
