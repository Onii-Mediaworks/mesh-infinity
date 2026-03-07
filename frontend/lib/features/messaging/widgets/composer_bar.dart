import 'package:flutter/material.dart';

class ComposerBar extends StatefulWidget {
  const ComposerBar({super.key, required this.onSend, this.onAttach});

  final ValueChanged<String> onSend;
  final VoidCallback? onAttach;

  @override
  State<ComposerBar> createState() => _ComposerBarState();
}

class _ComposerBarState extends State<ComposerBar> {
  final _controller = TextEditingController();
  bool _hasText = false;

  @override
  void initState() {
    super.initState();
    _controller.addListener(() {
      final has = _controller.text.trim().isNotEmpty;
      if (has != _hasText) setState(() => _hasText = has);
    });
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _send() {
    final text = _controller.text.trim();
    if (text.isEmpty) return;
    widget.onSend(text);
    _controller.clear();
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return SafeArea(
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
        decoration: BoxDecoration(
          color: cs.surface,
          border: Border(top: BorderSide(color: cs.outlineVariant)),
        ),
        child: Row(
          children: [
            if (widget.onAttach != null)
              IconButton(
                onPressed: widget.onAttach,
                icon: const Icon(Icons.attach_file_rounded),
                tooltip: 'Attach file',
              ),
            Expanded(
              child: TextField(
                controller: _controller,
                maxLines: 4,
                minLines: 1,
                textCapitalization: TextCapitalization.sentences,
                decoration: InputDecoration(
                  hintText: 'Message',
                  contentPadding:
                      const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                  isDense: true,
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(24),
                    borderSide: BorderSide.none,
                  ),
                ),
                onSubmitted: (_) => _send(),
              ),
            ),
            const SizedBox(width: 4),
            AnimatedContainer(
              duration: const Duration(milliseconds: 150),
              child: _hasText
                  ? IconButton.filled(
                      onPressed: _send,
                      icon: const Icon(Icons.send_rounded),
                      tooltip: 'Send',
                    )
                  : IconButton(
                      onPressed: null,
                      icon: Icon(Icons.send_rounded, color: cs.outline),
                    ),
            ),
          ],
        ),
      ),
    );
  }
}
