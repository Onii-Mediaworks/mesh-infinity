import 'package:flutter/material.dart';

/// A styled section divider label used to group related items within a list
/// or settings screen.
///
/// The title is rendered in UPPERCASE so it reads as a label rather than
/// content — a common pattern in mobile settings screens and contact lists
/// (e.g. iOS Contacts groups items under "A", "B", ... section headers).
///
/// Colours use [ColorScheme.primary] to give the label a light accent
/// without making it compete visually with content below it.
///
/// Example:
/// ```dart
/// SectionHeader('Trusted contacts')
/// // renders: "TRUSTED CONTACTS" in branded label style
/// ```
class SectionHeader extends StatelessWidget {
  const SectionHeader(this.title, {super.key});

  /// The label text to display.  Will be converted to uppercase automatically.
  final String title;

  @override
  Widget build(BuildContext context) {
    return Padding(
      // Top padding (20px) creates clear visual separation from the previous
      // section's last item.  Bottom padding (6px) keeps the header close
      // to the items it labels.
      padding: const EdgeInsets.fromLTRB(16, 20, 16, 6),
      child: Text(
        // toUpperCase() enforces the label convention regardless of how
        // the caller passes the string — "Contacts" and "CONTACTS" render
        // identically.
        title.toUpperCase(),
        style: Theme.of(context).textTheme.labelMedium?.copyWith(
          // Primary colour gives the header a branded accent.
          color: Theme.of(context).colorScheme.primary,
          // w700 makes the label legible at the small labelMedium size.
          fontWeight: FontWeight.w700,
        ),
      ),
    );
  }
}
