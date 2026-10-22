// mask_intro_card.dart
//
// First-use explanation of the word "mask" (§22.11, CMR-024).
//
// Onboarding never uses the word (§22.42.3), so the first screen that does
// (the You section, or the MaskSwitcherSheet) must define it once.  The same
// text stays re-readable from Help and from the `?` icon on the Identity &
// Masks screen (§22.10.2) through [MaskIntroScreen].

import 'package:flutter/material.dart';

import '../../app/app_theme.dart';
import '../../app/ui_prefs.dart';

/// Per-device flag recording that the card was dismissed.
String get mask_intro_flag => 'mask_intro_seen';

/// Card title, shared by the card, the Help tile and the screen.
String get mask_intro_title => "What's a mask?";

/// Card body.  "Mask" is the one name; "face" appears only in this definition.
String get mask_intro_body =>
    'A mask is a separate face you show different groups of people. '
    'Your first one is the identity you just created.';

/// Draws [MaskIntroCard] until the user dismisses it, then nothing.
///
/// Both surfaces (You section, MaskSwitcherSheet) wrap their card slot in
/// this gate, so dismissing on one hides it on the other too.
class MaskIntroGate extends StatefulWidget {
  const MaskIntroGate({super.key});

  @override
  State<MaskIntroGate> createState() => _MaskIntroGateState();
}

class _MaskIntroGateState extends State<MaskIntroGate> {
  // Null until the flag file has been read, so a seen card never flashes.
  bool? _seen;

  @override
  void initState() {
    super.initState();
    UiPrefs.instance.load().then((_) {
      if (mounted) {
        setState(() => _seen = UiPrefs.instance.flag(mask_intro_flag));
      }
    });
  }

  // Hide at once; persisting happens in the background.
  void _dismiss() {
    setState(() => _seen = true);
    UiPrefs.instance.set_flag(mask_intro_flag);
  }

  @override
  Widget build(BuildContext context) {
    if (_seen != false) return const SizedBox.shrink();
    return MaskIntroCard(on_dismiss: _dismiss);
  }
}

/// The "What's a mask?" card.  Without [on_dismiss] it has no button, which is
/// how the Help screen shows the same text read-only.
class MaskIntroCard extends StatelessWidget {
  const MaskIntroCard({super.key, this.on_dismiss});

  /// Called by "Got it"; null hides the button.
  final VoidCallback? on_dismiss;

  @override
  Widget build(BuildContext context) {
    final tt = Theme.of(context).textTheme;
    return Card(
      margin: const EdgeInsets.only(bottom: 16),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                // Icon foreground: per-theme brand token (§22.1.1, CMR-019).
                Icon(
                  Icons.theater_comedy_outlined,
                  color: MeshColors.of(context).brand_fg,
                ),
                const SizedBox(width: 8),
                Text(mask_intro_title, style: tt.titleSmall),
              ],
            ),
            const SizedBox(height: 8),
            Text(mask_intro_body, style: tt.bodyMedium),
            if (on_dismiss != null)
              Align(
                alignment: Alignment.centerRight,
                child: TextButton(
                  onPressed: on_dismiss,
                  child: const Text('Got it'),
                ),
              ),
          ],
        ),
      ),
    );
  }
}

/// Read-only page for Help and the Identity & Masks `?` icon.
class MaskIntroScreen extends StatelessWidget {
  const MaskIntroScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(mask_intro_title)),
      body: const Padding(
        padding: EdgeInsets.all(16),
        child: Align(
          alignment: Alignment.topCenter,
          child: MaskIntroCard(),
        ),
      ),
    );
  }
}
