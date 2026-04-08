// appearance_screen.dart
//
// AppearanceScreen — light / dark / system theme selection.
//
// ARCHITECTURE:
// -------------
// The selected [ThemeMode] lives in [SettingsState] and is persisted to the
// backend so it survives restarts.  The Material3 [RadioGroup] wrapper ensures
// only one option is selected at a time; [RadioListTile] values are passed by
// the enum directly rather than by index to be refactor-safe.
//
// The three modes map to Flutter's ThemeMode enum:
//   ThemeMode.system  — follow the OS light/dark setting (default)
//   ThemeMode.light   — always use the light theme
//   ThemeMode.dark    — always use the dark theme
//
// Reached from: Settings → Appearance.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../settings_state.dart';

/// Lets the user choose between system, light, and dark themes.
///
/// Uses a [RadioGroup] around the [ListView] so that all three [RadioListTile]
/// widgets share a single group value and a single [onChanged] callback — this
/// is the correct M3 pattern for exclusive radio selection inside a list.
class AppearanceScreen extends StatelessWidget {
  const AppearanceScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final settings = context.watch<SettingsState>();

    // Current theme mode — drives which radio button is checked.
    final current = settings.themeMode;

    return Scaffold(
      appBar: AppBar(title: const Text('Appearance')),
      body: RadioGroup<ThemeMode>(
        // groupValue is the currently active selection; matched against each
        // RadioListTile's value to determine which is checked.
        groupValue: current,
        onChanged: (mode) {
          // mode is nullable because RadioGroup can emit null when nothing is
          // selected — guard against that before persisting.
          if (mode != null) context.read<SettingsState>().setThemeMode(mode);
        },
        child: ListView(
          children: const [
            RadioListTile<ThemeMode>(
              secondary: Icon(Icons.brightness_auto_outlined),
              title: Text('System default'),
              subtitle: Text('Follow the device light/dark setting'),
              value: ThemeMode.system,
            ),
            RadioListTile<ThemeMode>(
              secondary: Icon(Icons.light_mode_outlined),
              title: Text('Light'),
              subtitle: Text('Always use the light theme'),
              value: ThemeMode.light,
            ),
            RadioListTile<ThemeMode>(
              secondary: Icon(Icons.dark_mode_outlined),
              title: Text('Dark'),
              subtitle: Text('Always use the dark theme'),
              value: ThemeMode.dark,
            ),
          ],
        ),
      ),
    );
  }
}
