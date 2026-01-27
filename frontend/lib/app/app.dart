import 'package:flutter/material.dart';

import '../screens/shell/signal_shell.dart';

class NetInfinityApp extends StatelessWidget {
  const NetInfinityApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'NetInfinity',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF2C6EE2)),
        useMaterial3: true,
        scaffoldBackgroundColor: const Color(0xFFF7F8FA),
      ),
      home: const SignalShell(),
    );
  }
}
