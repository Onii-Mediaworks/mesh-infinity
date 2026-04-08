import 'package:flutter/material.dart';

/// TransportToggleRow — a standardised SwitchListTile for transport settings.
///
/// Used wherever a single transport can be toggled on or off (e.g. Tor,
/// Clearnet, Bluetooth, mDNS).  Provides a consistent look across all
/// transport rows without duplicating switch-tile boilerplate.
///
/// The [enabled] flag allows the caller to gray out the toggle when the
/// underlying feature is unavailable (e.g. Bluetooth on a device that has no
/// Bluetooth hardware, or a transport that requires a dependency to be enabled
/// first).  When [enabled] is false the switch is rendered but not interactive.
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

  /// Icon displayed to the left of the tile as a visual identifier.
  final IconData icon;

  /// Short name of the transport, e.g. "Tor" or "Clearnet".
  final String label;

  /// One-line explanation of what this transport does and its trade-offs.
  final String description;

  /// The current on/off state of this transport.
  final bool value;

  /// Called with the new value when the user flips the switch.
  final ValueChanged<bool> onChanged;

  /// Whether the switch is interactive.  Set to false when the transport
  /// cannot be toggled in the current context (e.g. missing hardware or
  /// a conflicting dependency is not satisfied).
  final bool enabled;

  @override
  Widget build(BuildContext context) {
    return SwitchListTile(
      secondary: Icon(icon),
      title: Text(label),
      subtitle: Text(description, style: Theme.of(context).textTheme.bodySmall),
      value: value,
      // Passing null to onChanged disables the switch and grays it out.
      // This is the standard Flutter pattern for a disabled interactive widget.
      onChanged: enabled ? onChanged : null,
    );
  }
}
