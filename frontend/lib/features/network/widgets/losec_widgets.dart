import 'package:flutter/material.dart';

/// Full-screen terror warning modal for direct LoSec (0-hop) connections.
///
/// Spec section 6.7: "When direct mode is available and the user selects it,
/// a full-screen modal is displayed before the connection is established."
///
/// Returns `true` if the user confirmed, `false` if cancelled.
Future<bool> showDirectConnectionWarning(BuildContext context) async {
  final result = await showDialog<bool>(
    context: context,
    barrierDismissible: false,
    builder: (ctx) => const _DirectConnectionWarningDialog(),
  );
  return result ?? false;
}

class _DirectConnectionWarningDialog extends StatefulWidget {
  const _DirectConnectionWarningDialog();

  @override
  State<_DirectConnectionWarningDialog> createState() =>
      _DirectConnectionWarningDialogState();
}

class _DirectConnectionWarningDialogState
    extends State<_DirectConnectionWarningDialog> {
  bool _understood = false;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Dialog.fullscreen(
      child: Scaffold(
        backgroundColor: theme.colorScheme.errorContainer,
        appBar: AppBar(
          backgroundColor: theme.colorScheme.error,
          foregroundColor: theme.colorScheme.onError,
          title: const Text('SEVERE PRIVACY RISK'),
          automaticallyImplyLeading: false,
        ),
        body: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(
                Icons.warning_amber_rounded,
                size: 64,
                color: theme.colorScheme.error,
              ),
              const SizedBox(height: 16),
              Text(
                'DIRECT CONNECTION',
                style: theme.textTheme.headlineMedium?.copyWith(
                  color: theme.colorScheme.onErrorContainer,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 16),
              Text(
                'A direct connection exposes your network location to the '
                'remote peer and to any observer on your network path. '
                'There is no relay, no anonymization, and no protection '
                'against traffic analysis. Your IP address will be visible '
                'to the other party.',
                style: theme.textTheme.bodyLarge?.copyWith(
                  color: theme.colorScheme.onErrorContainer,
                ),
              ),
              const SizedBox(height: 16),
              Text(
                'This mode should only be used when both parties are fully '
                'trusted and network privacy is not a concern (e.g., a '
                'local home network with no threat model).',
                style: theme.textTheme.bodyLarge?.copyWith(
                  color: theme.colorScheme.onErrorContainer,
                ),
              ),
              const Spacer(),
              CheckboxListTile(
                value: _understood,
                onChanged: (v) => setState(() => _understood = v ?? false),
                title: Text(
                  'I understand the risks',
                  style: TextStyle(
                    color: theme.colorScheme.onErrorContainer,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                activeColor: theme.colorScheme.error,
                controlAffinity: ListTileControlAffinity.leading,
              ),
              const SizedBox(height: 16),
              Row(
                children: [
                  Expanded(
                    child: OutlinedButton(
                      onPressed: () => Navigator.of(context).pop(false),
                      child: const Text('Cancel'),
                    ),
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: FilledButton(
                      onPressed: _understood
                          ? () => Navigator.of(context).pop(true)
                          : null,
                      style: FilledButton.styleFrom(
                        backgroundColor: theme.colorScheme.error,
                        foregroundColor: theme.colorScheme.onError,
                      ),
                      child: const Text('I understand \u2014 connect directly'),
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}

/// Persistent red banner for active direct (0-hop) LoSec connections.
///
/// Spec: "During the connection, a persistent red banner is displayed:
/// 'Direct connection \u2014 no anonymization.'"
class DirectConnectionBanner extends StatelessWidget {
  const DirectConnectionBanner({super.key});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return MaterialBanner(
      backgroundColor: theme.colorScheme.error,
      content: Text(
        'Direct connection \u2014 no anonymization',
        style: TextStyle(
          color: theme.colorScheme.onError,
          fontWeight: FontWeight.bold,
        ),
      ),
      leading: Icon(Icons.warning, color: theme.colorScheme.onError),
      actions: const [SizedBox.shrink()],
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
    );
  }
}

/// Persistent amber banner for active 1-2 hop LoSec connections.
///
/// Spec: "For 1\u20132 hop LoSec (not direct), a persistent amber indicator is
/// displayed during the connection: 'Low-security mode active \u2014 your network
/// location may be visible to relay nodes.'"
class LoSecBanner extends StatelessWidget {
  const LoSecBanner({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialBanner(
      backgroundColor: Colors.amber.shade800,
      content: const Text(
        'Low-security mode active \u2014 your network location may be '
        'visible to relay nodes',
        style: TextStyle(
          color: Colors.white,
          fontWeight: FontWeight.bold,
        ),
      ),
      leading: const Icon(Icons.shield_outlined, color: Colors.white),
      actions: const [SizedBox.shrink()],
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
    );
  }
}

/// Confirmation dialog for requesting LoSec (1-2 hop) mode.
///
/// Returns `true` if accepted, `false` if declined.
Future<bool> showLoSecRequestDialog(BuildContext context) async {
  final result = await showDialog<bool>(
    context: context,
    builder: (ctx) => AlertDialog(
      icon: Icon(Icons.shield_outlined, color: Colors.amber.shade800),
      title: const Text('Request Low-Security Mode?'),
      content: const Text(
        'Low-security mode routes through 1\u20132 relay hops instead of '
        'the full anonymizing path. This improves bandwidth and latency '
        'but weakens sender anonymity and traffic analysis resistance.\n\n'
        'The remote peer must also accept this request.',
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(ctx).pop(false),
          child: const Text('Cancel'),
        ),
        FilledButton(
          onPressed: () => Navigator.of(ctx).pop(true),
          style: FilledButton.styleFrom(
            backgroundColor: Colors.amber.shade800,
          ),
          child: const Text('Request LoSec'),
        ),
      ],
    ),
  );
  return result ?? false;
}
