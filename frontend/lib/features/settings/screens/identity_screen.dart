// identity_screen.dart
//
// IdentityScreen — shows the user's primary identity QR code, peer ID, and
// public key with copy actions.
//
// QR PAIRING PAYLOAD:
// -------------------
// The QR code encodes a pairing payload JSON string, not just the peer ID.
// The payload includes:
//   - The peer's public key
//   - Transport hints (known addresses, preferred relay IDs)
//   - A short-lived nonce for replay prevention
//
// Encoding the full payload means the person scanning the QR code gets
// everything they need to establish an encrypted session without any
// additional back-channel communication.
//
// The payload is loaded from the backend on initState via getPairingPayload().
// It is nullable because: (a) the backend may not be ready yet on cold start,
// (b) the identity vault may not be unlocked.  In either case the QR falls back
// to encoding just the peer ID, which allows pairing but requires an extra
// round-trip to negotiate transport details.
//
// REFRESH:
// --------
// The AppBar refresh button reloads the pairing payload. The payload contains
// a time-limited nonce, so refreshing generates a fresh nonce and makes the
// previous QR code un-scannable (the backend will reject replayed nonces).
//
// DISPLAY NAME:
// -------------
// identity.name is nullable: the user may not have set a display name during
// onboarding. When present it is shown in a card below the keys.
//
// Reached from: Settings → Identity (or the Identity & Masks sub-screen).

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../../../backend/backend_bridge.dart';
import '../settings_state.dart';
import 'profile_edit_screen.dart';

/// Shows the user's own identity QR, peer ID, public key, and display name.
///
/// The pairing payload is loaded from the backend on startup and can be
/// refreshed via the AppBar button to rotate the embedded nonce.
class IdentityScreen extends StatefulWidget {
  const IdentityScreen({super.key});

  @override
  State<IdentityScreen> createState() => _IdentityScreenState();
}

class _IdentityScreenState extends State<IdentityScreen> {
  /// Full pairing payload JSON — loaded from the backend and encoded in the QR.
  ///
  /// Nullable because the backend may not be ready (vault locked, cold start)
  /// when this screen is first shown. Falls back to just the peer ID in that
  /// case so the QR is still scannable (reduced functionality only).
  String? _pairingPayload;

  @override
  void initState() {
    super.initState();
    _loadPairingPayload();
  }

  /// Fetches a fresh pairing payload from the backend.
  ///
  /// Each call generates a new time-limited nonce, invalidating previous QR
  /// codes. The user can also trigger this via the AppBar refresh button.
  void _loadPairingPayload() {
    final bridge = context.read<BackendBridge>();
    setState(() {
      _pairingPayload = bridge.getPairingPayload();
    });
  }

  /// Copies [value] to the clipboard and shows a confirmation snackbar.
  ///
  /// [label] appears in the snackbar text, e.g. "Peer ID copied".
  void _copy(BuildContext context, String value, String label) {
    Clipboard.setData(ClipboardData(text: value));
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('$label copied')),
    );
  }

  @override
  Widget build(BuildContext context) {
    final identity = context.watch<SettingsState>().identity;
    final cs = Theme.of(context).colorScheme;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Identity'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh_outlined),
            tooltip: 'Refresh QR Code',
            // Regenerates the pairing payload nonce so the current QR code
            // becomes invalid and a new one is displayed.
            onPressed: _loadPairingPayload,
          ),
          IconButton(
            icon: const Icon(Icons.edit_outlined),
            tooltip: 'Edit Profile',
            onPressed: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const ProfileEditScreen()),
            ),
          ),
        ],
      ),
      // Show a message when identity isn't loaded yet — this can happen on
      // first launch before onboarding completes or while the vault is locked.
      body: identity == null
          ? const Center(child: Text('Identity not available'))
          : ListView(
              padding: const EdgeInsets.all(16),
              children: [
                // ── QR code card ───────────────────────────────────────────
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(20),
                    child: Column(
                      children: [
                        Container(
                          decoration: BoxDecoration(
                            // White background ensures QR contrast regardless
                            // of the current app theme colour.
                            color: Colors.white,
                            borderRadius: BorderRadius.circular(12),
                          ),
                          padding: const EdgeInsets.all(8),
                          child: QrImageView(
                            // Prefer the full pairing payload so the scanner
                            // gets transport hints + keys. Falls back to the
                            // peer ID if the payload isn't available yet.
                            data: _pairingPayload ?? identity.peerId,
                            version: QrVersions.auto,
                            size: 200,
                            eyeStyle: QrEyeStyle(
                              // Square eyes match the Mesh Infinity design
                              // language (sharp corners, minimal rounding).
                              eyeShape: QrEyeShape.square,
                              color: cs.primary,
                            ),
                          ),
                        ),
                        const SizedBox(height: 12),
                        Text(
                          'Share your QR code for others to pair with you',
                          style: Theme.of(context).textTheme.bodySmall?.copyWith(
                            color: cs.onSurfaceVariant,
                          ),
                          textAlign: TextAlign.center,
                        ),
                      ],
                    ),
                  ),
                ),

                const SizedBox(height: 12),

                // ── Key cards ──────────────────────────────────────────────
                // Peer ID — the unique identifier for this node on the mesh.
                _KeyCard(
                  label: 'Peer ID',
                  value: identity.peerId,
                  onCopy: () => _copy(context, identity.peerId, 'Peer ID'),
                ),
                const SizedBox(height: 8),

                // Public key — the Ed25519/X25519 public key of this identity.
                // Shown so the user can verify their key out-of-band with
                // trusted contacts.
                _KeyCard(
                  label: 'Public Key',
                  value: identity.publicKey,
                  onCopy: () => _copy(context, identity.publicKey, 'Public key'),
                ),

                // Display name — only shown when the user set one during
                // onboarding or via the edit profile flow. Not all identities
                // have a display name (anonymous masks don't).
                if (identity.name != null) ...[
                  const SizedBox(height: 8),
                  Card(
                    child: ListTile(
                      title: const Text('Display Name'),
                      subtitle: Text(identity.name!),
                      leading: const Icon(Icons.person_outline),
                    ),
                  ),
                ],
              ],
            ),
    );
  }
}

/// A tappable card that shows a cryptographic key string with a copy button.
///
/// The whole card is an InkWell so users can tap anywhere (not just the small
/// copy icon) to copy — more ergonomic on small screens.
/// [SelectableText] allows manual selection for partial comparison over voice.
class _KeyCard extends StatelessWidget {
  const _KeyCard({
    required this.label,
    required this.value,
    required this.onCopy,
  });

  /// Display label for the key type, e.g. "Peer ID" or "Public Key".
  final String label;

  /// The full key string to display and copy.
  final String value;

  /// Called when the card or copy icon is tapped.
  final VoidCallback onCopy;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: InkWell(
        // Tap anywhere on the card copies the value — matches the copy icon
        // tap target for consistency.
        borderRadius: BorderRadius.circular(16),
        onTap: onCopy,
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Text(label, style: Theme.of(context).textTheme.titleSmall),
                  const Spacer(),
                  // Compact icon button for power users who expect the icon.
                  IconButton(
                    icon: const Icon(Icons.copy_outlined, size: 18),
                    tooltip: 'Copy',
                    onPressed: onCopy,
                    visualDensity: VisualDensity.compact,
                  ),
                ],
              ),
              const SizedBox(height: 8),
              // SelectableText allows the user to highlight a segment manually
              // for side-by-side comparison (e.g. verifying a key over a call).
              SelectableText(
                value,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
