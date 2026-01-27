import 'package:flutter/material.dart';

class ComposerBar extends StatelessWidget {
  const ComposerBar({
    super.key,
    required this.controller,
    required this.padding,
    required this.onAdd,
    required this.onSend,
    required this.enabled,
  });

  final TextEditingController controller;
  final double padding;
  final VoidCallback onAdd;
  final ValueChanged<String> onSend;
  final bool enabled;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: EdgeInsets.all(padding),
      child: Row(
        children: [
          IconButton(
            onPressed: enabled ? onAdd : null,
            icon: const Icon(Icons.add_circle_outline),
          ),
          Expanded(
            child: TextField(
              controller: controller,
              enabled: enabled,
              decoration: InputDecoration(
                hintText: enabled ? 'Message' : 'Create a conversation to start messaging',
                filled: true,
                fillColor: const Color(0xFFF2F4F7),
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(24),
                  borderSide: BorderSide.none,
                ),
              ),
              onSubmitted: enabled ? onSend : null,
            ),
          ),
          const SizedBox(width: 12),
          FilledButton(
            onPressed: enabled ? () => onSend(controller.text) : null,
            child: const Text('Send'),
          ),
        ],
      ),
    );
  }
}
