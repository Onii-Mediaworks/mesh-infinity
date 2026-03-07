import 'package:flutter/material.dart';

class TransportToggleRow extends StatelessWidget {
  const TransportToggleRow({
    super.key,
    required this.icon,
    required this.label,
    required this.description,
    required this.value,
    required this.onChanged,
    this.enabled = true,
  });

  final IconData icon;
  final String label;
  final String description;
  final bool value;
  final ValueChanged<bool> onChanged;
  final bool enabled;

  @override
  Widget build(BuildContext context) {
    return SwitchListTile(
      secondary: Icon(icon),
      title: Text(label),
      subtitle: Text(description, style: Theme.of(context).textTheme.bodySmall),
      value: value,
      onChanged: enabled ? onChanged : null,
    );
  }
}
