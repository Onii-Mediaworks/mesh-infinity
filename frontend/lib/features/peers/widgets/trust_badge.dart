import 'package:flutter/material.dart';

import '../../../backend/models/peer_models.dart';

class TrustBadge extends StatelessWidget {
  const TrustBadge({super.key, required this.level, this.compact = false});

  final TrustLevel level;
  final bool compact;

  @override
  Widget build(BuildContext context) {
    final (color, icon) = switch (level) {
      TrustLevel.untrusted => (Colors.red, Icons.block_outlined),
      TrustLevel.caution => (Colors.orange, Icons.warning_amber_outlined),
      TrustLevel.trusted => (Colors.green, Icons.verified_outlined),
      TrustLevel.highlyTrusted => (Colors.blue, Icons.shield_outlined),
    };

    if (compact) {
      return Icon(icon, size: 16, color: color);
    }

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withValues(alpha: 0.4)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 14, color: color),
          const SizedBox(width: 4),
          Text(
            level.label,
            style: TextStyle(fontSize: 12, color: color, fontWeight: FontWeight.w600),
          ),
        ],
      ),
    );
  }
}
