import 'package:flutter/material.dart';

import '../../app/app_theme.dart';

/// Show a shared service detail sheet for both discovered and configured
/// services.
///
/// The sheet is deliberately descriptive rather than editable. The services
/// area still lacks dedicated per-service config screens for most protocols,
/// so this centralizes the useful metadata we do have without inventing fake
/// controls.
Future<void> show_service_details_sheet({
  required BuildContext context,
  required IconData icon,
  required String name,
  required String description,
  String? address,
  String? path,
  String? hostName,
  int? minTrustLevel,
  List<String> allowedTransports = const [],
  String? statusLabel,
  Widget? footer,
}) {
  return showModalBottomSheet<void>(
    context: context,
    isScrollControlled: true,
    showDragHandle: true,
    builder: (sheetContext) {
      final theme = Theme.of(sheetContext);
      final colorScheme = theme.colorScheme;
      final trimmedDescription = description.trim();
      final visibleAddress = (address ?? '').trim();
      final visiblePath = (path ?? '').trim();
      final visibleHost = (hostName ?? '').trim();

      return SafeArea(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(20, 8, 20, 24),
          child: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Container(
                      width: 44,
                      height: 44,
                      decoration: BoxDecoration(
                        color: MeshTheme.brand.withValues(alpha: 0.12),
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: Icon(icon, color: MeshTheme.brand),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text(name, style: theme.textTheme.titleLarge),
                    ),
                  ],
                ),
                if (trimmedDescription.isNotEmpty) ...[
                  const SizedBox(height: 12),
                  Text(
                    trimmedDescription,
                    style: theme.textTheme.bodyMedium?.copyWith(
                      color: colorScheme.onSurfaceVariant,
                    ),
                  ),
                ],
                const SizedBox(height: 20),
                if (statusLabel != null && statusLabel.trim().isNotEmpty)
                  _DetailRow(label: 'Status', value: statusLabel.trim()),
                if (visibleHost.isNotEmpty)
                  _DetailRow(label: 'Host', value: visibleHost),
                if (minTrustLevel != null)
                  _DetailRow(
                    label: 'Trust',
                    value: 'Level $minTrustLevel or higher',
                  ),
                if (allowedTransports.isNotEmpty)
                  _DetailRow(
                    label: 'Transport',
                    value: allowedTransports.join(', '),
                  ),
                if (visibleAddress.isNotEmpty)
                  _DetailRow(
                    label: 'Address',
                    value: visibleAddress,
                    monospace: true,
                  ),
                if (visiblePath.isNotEmpty)
                  _DetailRow(
                    label: 'Path',
                    value: visiblePath,
                    monospace: true,
                  ),
                if (footer != null) ...[const SizedBox(height: 20), footer],
              ],
            ),
          ),
        ),
      );
    },
  );
}

class _DetailRow extends StatelessWidget {
  const _DetailRow({
    required this.label,
    required this.value,
    this.monospace = false,
  });

  final String label;
  final String value;
  final bool monospace;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 88,
            child: Text(
              label,
              style: theme.textTheme.bodySmall?.copyWith(
                color: colorScheme.onSurfaceVariant,
              ),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: theme.textTheme.bodyMedium?.copyWith(
                fontFamily: monospace ? 'monospace' : null,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
