// Spike S1, Flutter host: the same screen as the Compose host, so the shared
// instrumented test drives both. Each element carries a Semantics identifier,
// which Flutter exposes on Android as the accessibility node's resource id,
// the same ids the Compose host exposes from its test tags.
//
// The confinement happens before Dart starts: Application.onCreate in the
// `:ui` process locks the process down (common module, UiSession). Dart
// reaches the core only through the host's method channel, which forwards
// to UiSession's protocol socket.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// The host's channel: `status` (the run's mode, lockdown result and
/// probes) and `request` (one message to the core, its reply back).
const MethodChannel _core = MethodChannel('mesh_ui_spike/core');

void main() => runApp(const SpikeApp());

class SpikeApp extends StatelessWidget {
  const SpikeApp({super.key});

  @override
  Widget build(BuildContext context) =>
      const MaterialApp(home: Scaffold(body: SafeArea(child: SpikeScreen())));
}

class SpikeScreen extends StatefulWidget {
  const SpikeScreen({super.key});

  @override
  State<SpikeScreen> createState() => _SpikeScreenState();
}

class _SpikeScreenState extends State<SpikeScreen> {
  final TextEditingController _input = TextEditingController();
  String _status = 'starting';
  String _reply = '';

  @override
  void initState() {
    super.initState();
    _load_status();
  }

  /// Shows what the host reports about this process's confinement.
  Future<void> _load_status() async {
    final status = await _core.invokeMethod<String>('status');
    if (mounted) setState(() => _status = status ?? 'no status');
  }

  /// Sends the field's text to the core and shows the reply.
  Future<void> _send() async {
    final reply = await _core.invokeMethod<String>('request', 'echo ${_input.text}');
    if (mounted) setState(() => _reply = reply ?? 'no reply');
  }

  @override
  void dispose() {
    _input.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Semantics(identifier: 'status', child: Text(_status)),
            Row(children: [
              Expanded(
                child: Semantics(
                  identifier: 'input',
                  child: TextField(
                    controller: _input,
                    decoration: const InputDecoration(labelText: 'message'),
                  ),
                ),
              ),
              Semantics(
                identifier: 'send',
                child: ElevatedButton(onPressed: _send, child: const Text('send')),
              ),
            ]),
            Semantics(identifier: 'reply', child: Text(_reply)),
            Expanded(
              child: Semantics(
                identifier: 'list',
                child: ListView.builder(
                  itemCount: 3000,
                  itemBuilder: (context, index) => Padding(
                    padding: const EdgeInsets.symmetric(vertical: 6),
                    child: Text('row $index: a message preview long enough to wrap onto a '
                        'second line on a phone screen'),
                  ),
                ),
              ),
            ),
          ],
        ),
      );
}
