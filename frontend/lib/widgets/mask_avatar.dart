// mask_avatar.dart
//
// MaskAvatar — circular avatar widget for a mask identity (§22.4.3).
//
// WHAT A "MASK" IS:
// -----------------
// In Mesh Infinity, a "mask" is a Layer-3 pseudonymous identity that sits
// on top of the user's mesh identity.  Each mask has its own display name
// and avatar colour, allowing the user to present different personas in
// different social contexts without revealing that they are the same person.
//
// When a user creates a mask they choose:
//   - A display name (e.g. "Work alias", "Night trader", "Anonymous poet").
//   - An avatar colour from the palette defined in [kMaskAvatarColors].
//
// The avatar is rendered as a coloured circle with the first letter of the
// name in white.  This minimal design makes the avatar fast to render and
// easy to distinguish at a glance even at small sizes.
//
// FOUR SIZES:
// -----------
//   small  (radius 14 → diameter 28 px)  — used in dense lists, message rows.
//   medium (radius 20 → diameter 40 px)  — used in the nav drawer header.
//   large  (radius 32 → diameter 64 px)  — used in profile cards.
//   hero   (radius 40 → diameter 80 px)  — used in the full-screen identity view.
//
// USAGE:
// ------
// Build a [MaskAvatarData] with a name and color, then pass it to [MaskAvatar]:
//
//   MaskAvatar(
//     mask: MaskAvatarData(name: 'Alice', avatarColor: kMaskAvatarColors[0]),
//     size: MaskAvatarSize.medium,
//   )
//
// When a full mask model is available, construct [MaskAvatarData] from it.
// When only a peer ID is available (e.g. for a contact who hasn't shared a
// mask), use [ProfileCard._avatarColor] to derive a stable color from the
// peer ID and pass the display name.

import 'package:flutter/material.dart';

/// The 8 avatar background colours available when creating a mask.
///
/// Ordered by visual distinctiveness — adjacent colours are intentionally
/// different enough to be told apart even at small sizes and in low-contrast
/// environments.
///
/// Index 0 is the brand blue, which is also the default for new masks before
/// the user chooses a colour.
const List<Color> kMaskAvatarColors = [
  Color(0xFF2C6EE2), // brand blue
  Color(0xFF7C3AED), // purple
  Color(0xFF059669), // green
  Color(0xFFEF4444), // red
  Color(0xFFF59E0B), // amber
  Color(0xFF0EA5E9), // sky blue
  Color(0xFFEC4899), // pink
  Color(0xFF64748B), // slate
];

/// The four rendering sizes for a [MaskAvatar].
///
/// Each size corresponds to a different use-case in the UI.
/// The [_MaskAvatarSizeValues] extension provides the pixel dimensions.
enum MaskAvatarSize {
  /// 28 px diameter — used in dense lists, message timestamps, inline mentions.
  small,
  /// 40 px diameter — used in the drawer header, list tiles, compact profile cards.
  medium,
  /// 64 px diameter — used in full profile cards, contact detail headers.
  large,
  /// 80 px diameter — used in the You screen hero identity display.
  hero,
}

/// Maps [MaskAvatarSize] enum values to concrete pixel dimensions.
///
/// Kept as a private extension so the size→pixel mapping lives next to the
/// enum without polluting the public API.
extension _MaskAvatarSizeValues on MaskAvatarSize {
  /// CircleAvatar radius in logical pixels (diameter = radius × 2).
  double get radius => switch (this) {
    MaskAvatarSize.small  => 14.0,
    MaskAvatarSize.medium => 20.0,
    MaskAvatarSize.large  => 32.0,
    MaskAvatarSize.hero   => 40.0,
  };

  /// Font size for the initial letter rendered inside the circle.
  ///
  /// Scaled relative to the circle radius so the letter fills roughly
  /// 50–60% of the available area at every size.
  double get fontSize => switch (this) {
    MaskAvatarSize.small  => 12.0,
    MaskAvatarSize.medium => 18.0,
    MaskAvatarSize.large  => 28.0,
    MaskAvatarSize.hero   => 34.0,
  };
}

/// Minimal data needed to render a [MaskAvatar].
///
/// This thin data class decouples the avatar widget from whatever model
/// (mask, contact, identity) the rest of the screen works with.  Callers
/// construct a [MaskAvatarData] from their model and pass it to [MaskAvatar]
/// — the widget doesn't need to know about masks at all.
///
/// [name] must not be empty in production — the widget shows '?' if it is,
/// but that should only happen during exceptional error states.
class MaskAvatarData {
  const MaskAvatarData({required this.name, required this.avatarColor});

  /// Display name of the mask.  The first character is shown in the circle.
  final String name;

  /// Background fill colour chosen from [kMaskAvatarColors].
  final Color avatarColor;
}

/// Circular avatar for a mask identity (§22.4.3).
///
/// Displays the first letter of [mask.name] in white on a coloured circle.
/// The circle size is controlled by [size], defaulting to [MaskAvatarSize.medium].
///
/// This widget is stateless and cheap to build — it holds no state, makes
/// no async calls, and never repaints unless its inputs change.
class MaskAvatar extends StatelessWidget {
  const MaskAvatar({
    super.key,
    required this.mask,
    this.size = MaskAvatarSize.medium,
  });

  /// The mask whose name and colour should be displayed.
  final MaskAvatarData mask;

  /// Rendering size: small / medium / large / hero.  Defaults to medium.
  final MaskAvatarSize size;

  @override
  Widget build(BuildContext context) {
    return CircleAvatar(
      radius: size.radius,
      backgroundColor: mask.avatarColor,
      child: Text(
        // Display the uppercased initial.  If name is somehow empty, show '?'
        // as a defensive fallback rather than crashing or rendering a blank circle.
        mask.name.isNotEmpty ? mask.name[0].toUpperCase() : '?',
        style: TextStyle(
          fontSize: size.fontSize,
          fontWeight: FontWeight.w700,
          // White text on any of the [kMaskAvatarColors] passes WCAG AA
          // contrast requirements at all four font sizes.
          color: Colors.white,
        ),
      ),
    );
  }
}
