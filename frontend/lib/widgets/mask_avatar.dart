import 'package:flutter/material.dart';

/// The 8 avatar background colors a user can pick when creating a mask.
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

enum MaskAvatarSize { small, medium, large, hero }

extension _MaskAvatarSizeValues on MaskAvatarSize {
  double get radius => switch (this) {
    MaskAvatarSize.small  => 14.0,
    MaskAvatarSize.medium => 20.0,
    MaskAvatarSize.large  => 32.0,
    MaskAvatarSize.hero   => 40.0,
  };

  double get fontSize => switch (this) {
    MaskAvatarSize.small  => 12.0,
    MaskAvatarSize.medium => 18.0,
    MaskAvatarSize.large  => 28.0,
    MaskAvatarSize.hero   => 34.0,
  };
}

/// Minimal mask data needed to render an avatar.
///
/// Backed by full mask models when they exist. For now accepts bare name
/// and color so screens that know only the identity can still render.
class MaskAvatarData {
  const MaskAvatarData({required this.name, required this.avatarColor});

  final String name;
  final Color avatarColor;
}

/// Circular avatar for a mask identity per §22.4.3.
///
/// Shows the first letter of the mask name on a colored background.
/// Four sizes: small (28px), medium (40px), large (64px), hero (80px).
class MaskAvatar extends StatelessWidget {
  const MaskAvatar({
    super.key,
    required this.mask,
    this.size = MaskAvatarSize.medium,
  });

  final MaskAvatarData mask;
  final MaskAvatarSize size;

  @override
  Widget build(BuildContext context) {
    return CircleAvatar(
      radius: size.radius,
      backgroundColor: mask.avatarColor,
      child: Text(
        mask.name.isNotEmpty ? mask.name[0].toUpperCase() : '?',
        style: TextStyle(
          fontSize: size.fontSize,
          fontWeight: FontWeight.w700,
          color: Colors.white,
        ),
      ),
    );
  }
}
