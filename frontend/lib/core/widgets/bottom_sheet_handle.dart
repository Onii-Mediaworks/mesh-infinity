import 'package:flutter/material.dart';

/// Standardised drag handle for bottom sheets built outside of
/// [showModalBottomSheet] (§22.4.6).
///
/// For sheets opened via [showModalBottomSheet], the handle is provided
/// automatically by [BottomSheetThemeData.showDragHandle: true] in
/// [MeshTheme] — do not add this widget to those sheets manually.
class BottomSheetHandle extends StatelessWidget {
  const BottomSheetHandle({super.key});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(top: 12, bottom: 4),
      child: Center(
        child: Container(
          width: 32,
          height: 4,
          decoration: BoxDecoration(
            color: Theme.of(context)
                .colorScheme
                .onSurfaceVariant
                .withValues(alpha: 0.3),
            borderRadius: BorderRadius.circular(2),
          ),
        ),
      ),
    );
  }
}
