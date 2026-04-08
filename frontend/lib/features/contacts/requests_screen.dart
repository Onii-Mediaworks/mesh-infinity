import 'package:flutter/material.dart';

import 'screens/pair_contact_screen.dart';

/// The "Requests" sub-page of the Contacts section.
///
/// Displays incoming contact pairing requests — messages from peers who want
/// to be added to the user's contact list but have not yet been approved.
///
/// CURRENT STATUS:
/// The backend pending-request queue (§10.1.1 message request queue) is not
/// yet wired to this screen.  Until that integration is complete, this screen
/// shows a static "No pending requests" placeholder and offers a shortcut
/// button to the pairing flow so the user can initiate pairing manually.
///
/// When the backend integration arrives, this screen will display a list of
/// [ContactRequestTile] rows, each with Accept / Decline buttons.
class RequestsScreen extends StatelessWidget {
  const RequestsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // person_add icon communicates "contact request" rather than
            // "no contacts" — distinct from the AllContacts empty state.
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
            // Shortcut: while the request queue is not yet implemented, offer
            // direct access to the manual pairing flow so the user is not
            // stranded on an empty screen.
            FilledButton.tonal(
              onPressed: () => Navigator.push(
                context,
                MaterialPageRoute(builder: (_) => const PairContactScreen()),
              ),
              child: const Text('Pair a new contact'),
            ),
          ],
        ),
      ),
    );
  }
}
