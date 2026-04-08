import 'package:flutter/material.dart';

/// Standardised drag handle for bottom sheets built outside of
/// [showModalBottomSheet] (§22.4.6).
///
/// For sheets opened via [showModalBottomSheet], the handle is provided
/// automatically by [BottomSheetThemeData.showDragHandle: true] in
/// [MeshTheme] — do not add this widget to those sheets manually.
///
/// The handle renders as a short, rounded pill centred at the top of the
/// sheet.  The dimensions (32×4) and colours match the Material 3 spec for
/// bottom sheet drag handles so the affordance is immediately recognisable.
class BottomSheetHandle extends StatelessWidget {
  const BottomSheetHandle({super.key});

  @override
  Widget build(BuildContext context) {
    return Padding(
      // Top padding separates the handle from the top edge of the sheet.
      // Bottom padding gives breathing room before the sheet content begins.
      padding: const EdgeInsets.only(top: 12, bottom: 4),
      child: Center(
        child: Container(
          // 32×4 matches the M3 drag handle specification.
          width: 32,
          height: 4,
          decoration: BoxDecoration(
            // onSurfaceVariant at 30% opacity is the M3-recommended colour for
            // drag handles — it is visible on both light and dark surfaces
            // without being distracting or high-contrast.
            color: Theme.of(context)
                .colorScheme
                .onSurfaceVariant
                .withValues(alpha: 0.3),
            // Circular radius on a 4px-tall pill gives fully rounded ends.
            borderRadius: BorderRadius.circular(2),
          ),
        ),
      ),
    );
  }
}
