import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../settings_state.dart';

// ---------------------------------------------------------------------------
// AppearanceScreen — light / dark / system theme selection.
// ---------------------------------------------------------------------------

class AppearanceScreen extends StatelessWidget {
  const AppearanceScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final settings = context.watch<SettingsState>();
    final current = settings.themeMode;

    return Scaffold(
      appBar: AppBar(title: const Text('Appearance')),
      body: RadioGroup<ThemeMode>(
        groupValue: current,
        onChanged: (mode) {
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
