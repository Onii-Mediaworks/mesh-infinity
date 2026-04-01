import 'package:flutter/material.dart';

import '../peers/screens/pair_peer_screen.dart';

// Requests screen — shows incoming pairing requests.
// Backend pending-request list not yet implemented; shows the pairing UI.
class RequestsScreen extends StatelessWidget {
  const RequestsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.person_add_outlined,
                size: 56, color: Theme.of(context).colorScheme.outline),
            const SizedBox(height: 16),
            Text(
              'No pending requests',
              style: Theme.of(context).textTheme.titleMedium?.copyWith(
                    color: Theme.of(context).colorScheme.outline,
                  ),
            ),
            const SizedBox(height: 8),
            FilledButton.tonal(
              onPressed: () => Navigator.push(
                context,
                MaterialPageRoute(builder: (_) => const PairPeerScreen()),
              ),
              child: const Text('Pair a new contact'),
            ),
          ],
        ),
      ),
    );
  }
}
