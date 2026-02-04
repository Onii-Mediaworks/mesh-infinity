import 'package:flutter/material.dart';

class ComposerBar extends StatelessWidget {
  const ComposerBar({
    super.key,
    required this.controller,
    required this.onAdd,
    required this.onSend,
    required this.enabled,
    this.focusNode,
  });

  final TextEditingController controller;
  final VoidCallback onAdd;
  final ValueChanged<String> onSend;
  final bool enabled;
  final FocusNode? focusNode;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color: cs.surface,
        border: Border(top: BorderSide(color: cs.outline.withValues(alpha: 0.2))),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          IconButton(
            onPressed: enabled ? onAdd : null,
            icon: const Icon(Icons.add_circle_outline),
            iconSize: 24,
          ),
          Expanded(
            child: TextField(
              controller: controller,
              enabled: enabled,
              focusNode: focusNode,
              decoration: InputDecoration(
                hintText: enabled ? 'Message' : 'Select a conversation',
                filled: true,
                fillColor: cs.surfaceContainerHighest,
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(24),
                  borderSide: BorderSide.none,
                ),
                focusedBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(24),
                  borderSide: BorderSide.none,
                ),
                contentPadding: const EdgeInsets.symmetric(horizontal: 18, vertical: 10),
              ),
              onSubmitted: enabled ? onSend : null,
            ),
          ),
          const SizedBox(width: 8),
          AnimatedOpacity(
            opacity: enabled ? 1.0 : 0.4,
            duration: const Duration(milliseconds: 200),
            child: FilledButton(
              onPressed: enabled ? () => onSend(controller.text) : null,
              style: FilledButton.styleFrom(
                padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 10),
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
              ),
              child: const Text('Send'),
            ),
          ),
        ],
      ),
    );
  }
}
