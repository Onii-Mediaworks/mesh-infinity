// pair_contact_screen.dart
//
// This file implements PairContactScreen — the "Add Contact" flow (§22.8.3).
//
// WHAT IS PAIRING?
// ----------------
// Pairing is the act of exchanging cryptographic identities with another
// Mesh Infinity user so that:
//   1. Each side can verify the other's messages (signature verification).
//   2. Each side can encrypt messages specifically for the other (X25519 key
//      exchange, used to derive the Double Ratchet session key).
//   3. The contact appears in each other's contact list at a default trust
//      level (Level 2 — "Vouched"), which can be promoted later.
//
// WHY FOUR / FIVE TABS?
// ---------------------
// There is no single universal "pairing channel".  Different situations call
// for different methods:
//   - QR: easiest in person; point cameras at each other's screens.
//   - Pairing code: a short human-readable code shown in the app; works
//     over voice, SMS, or any text channel.
//   - Link: a full URI (meshinfinity://pair?...) shareable over any medium.
//   - Key import: paste the full public-key block for maximum security
//     (no channel to trust — you verify the raw keys out-of-band).
//
// Each tab is a separate stateless widget so the pairing logic stays in the
// parent [_PairContactScreenState] and the tabs only render UI.
//
// PREFILL PEER ID
// ---------------
// [prefillPeerId] is an optional parameter set when arriving from
// ProfilePreviewScreen (§22.8.4).  If present, the QR/Code tabs are
// pre-populated so the user just has to confirm rather than type.
//
// SPEC REFERENCE: §22.8.3

import 'package:flutter/material.dart';
// HapticFeedback for success/failure vibrations on pairing result.
import 'package:flutter/services.dart';
// Provider — context.read to access PeersState and BackendBridge.
import 'package:provider/provider.dart';

// BackendBridge — fetches the local identity and settings for the link/key
// tabs so the user can share their own pairing information.
import '../../../backend/backend_bridge.dart';
// LocalIdentitySummary + SettingsModel — used to build the sharable link
// and public-key block in the Link and Key tabs.
import '../../../backend/models/settings_models.dart';
// PeersState — pairPeer() calls Rust to initiate the pairing handshake.
import '../../peers/peers_state.dart';
// QrPairingWidget — the camera viewfinder that decodes QR codes.
// Lives in peers/widgets/ as it may be reused by other pairing surfaces.
import '../../peers/widgets/qr_pairing_widget.dart';

// ---------------------------------------------------------------------------
// PairContactScreen (§22.8.3)
// ---------------------------------------------------------------------------

/// The "Add Contact" screen — a tabbed interface offering four pairing methods:
/// QR Scan, Pairing Code, Link, and Key Import.
///
/// Opened from:
///   - Contacts section AppBar add-contact icon button.
///   - ProfilePreviewScreen "Pair" action button (sets [prefillPeerId]).
///   - AllContactsScreen FAB.
///
/// On successful pairing, pops the route with `true` so the caller can
/// trigger a contact-list refresh.
class PairContactScreen extends StatefulWidget {
  const PairContactScreen({
    super.key,
    // Optional peer ID to pre-populate the pairing code field.
    // Set by ProfilePreviewScreen when the user taps "Pair" on a known peer.
    this.prefillPeerId,
  });

  /// If set, the code/QR tabs are pre-filled with this peer ID so the user
  /// can confirm the pairing with a single tap.
  final String? prefillPeerId;

  @override
  State<PairContactScreen> createState() => _PairContactScreenState();
}

class _PairContactScreenState extends State<PairContactScreen>
    with SingleTickerProviderStateMixin {
  // ---------------------------------------------------------------------------
  // State fields
  // ---------------------------------------------------------------------------

  /// Controls the TabBar / TabBarView synchronisation.
  /// Length 4 — QR, Code, Link, Key tabs.
  late final TabController _tabs = TabController(length: 4, vsync: this);

  /// Text input controller for the Pairing Code tab.
  final _codeController = TextEditingController();

  /// Text input controller for the Link Import section.
  final _linkImportController = TextEditingController();

  /// Text input controller for the Key Import section.
  final _keyImportController = TextEditingController();

  /// True while a pairing attempt is in progress — shows a full-screen
  /// CircularProgressIndicator so the user knows to wait.
  bool _pairing = false;

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  @override
  void initState() {
    super.initState();

    // If a prefill peer ID was provided (e.g. from ProfilePreviewScreen),
    // pre-populate the code field so the user only needs to tap Pair.
    if (widget.prefillPeerId != null) {
      _codeController.text = widget.prefillPeerId!;
    }
  }

  @override
  void dispose() {
    // Always dispose of TabController — it holds animation resources.
    _tabs.dispose();
    // Always dispose TextEditingControllers — they hold platform input state.
    _codeController.dispose();
    _linkImportController.dispose();
    _keyImportController.dispose();
    super.dispose();
  }

  // ---------------------------------------------------------------------------
  // Pairing logic
  // ---------------------------------------------------------------------------

  /// Initiates pairing with the given [code] (peer ID or pairing token).
  ///
  /// Sets [_pairing] to true immediately so the UI shows a progress indicator,
  /// then calls [PeersState.pairPeer] which proxies to the Rust backend.
  ///
  /// On success: pops the route with `true` so the caller can refresh.
  /// On failure: shows a SnackBar and re-enables the UI.
  Future<void> _pair(String code) async {
    // Empty/whitespace input — do nothing rather than sending a blank request.
    if (code.trim().isEmpty) return;

    // Show progress indicator while the backend processes the pairing request.
    setState(() => _pairing = true);

    // pairPeer() calls mi_pair_peer() in Rust which initiates the key exchange.
    final ok = await context.read<PeersState>().pairPeer(code.trim());

    // Guard: the user may have navigated away while pairing was in flight.
    if (!mounted) return;

    if (ok) {
      // Haptic success confirmation — provides tactile feedback for the
      // positive outcome without the user needing to read the screen.
      HapticFeedback.mediumImpact();
      // Pop with `true` to signal the caller that pairing succeeded.
      Navigator.pop(context, true);
    } else {
      // Re-enable the UI so the user can try a different code.
      setState(() => _pairing = false);
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Pairing failed. Check the code and try again.'),
        ),
      );
    }
  }

  /// Parses a deep-link URL and extracts the pairing token, then calls [_pair].
  ///
  /// Expected format: `meshinfinity://pair?v=1&peer_id=<hex>&token=<code>`
  /// Any other format is rejected with a user-visible error message.
  Future<void> _importLink(String linkText) async {
    final text = linkText.trim();
    if (text.isEmpty) return;

    // Uri.tryParse returns null if the string is not a valid URI.
    final uri = Uri.tryParse(text);
    if (uri == null || uri.scheme != 'meshinfinity' || uri.host != 'pair') {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Invalid link. Expected meshinfinity://pair?... format.'),
        ),
      );
      return;
    }

    // Extract the required query parameters.
    final peerId = uri.queryParameters['peer_id'];
    final token = uri.queryParameters['token'];

    if (peerId == null || peerId.isEmpty || token == null || token.isEmpty) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Link is missing required peer_id or token.'),
        ),
      );
      return;
    }

    // Use the token as the pairing code — the Rust backend uses it to
    // authenticate the pairing request during the key exchange handshake.
    await _pair(token);
  }

  /// Parses a public-key block (PEM-like format) and extracts the peer ID.
  ///
  /// Key block format:
  /// ```
  /// --- BEGIN MESH INFINITY PUBLIC KEY ---
  /// Peer-ID: <hex>
  /// Ed25519: <base64>
  /// X25519: <base64>
  /// --- END MESH INFINITY PUBLIC KEY ---
  /// ```
  Future<void> _importKey(String keyText) async {
    final text = keyText.trim();
    if (text.isEmpty) return;

    // Validate that the block has the expected delimiters.
    if (!text.contains('--- BEGIN MESH INFINITY PUBLIC KEY ---') ||
        !text.contains('--- END MESH INFINITY PUBLIC KEY ---')) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Invalid key block. Check the format and try again.'),
        ),
      );
      return;
    }

    // Extract the Peer-ID line using a regex.
    // The regex `\s*` matches optional spaces between "Peer-ID:" and the value.
    final peerIdMatch = RegExp(r'Peer-ID:\s*([0-9a-fA-F]+)').firstMatch(text);
    if (peerIdMatch == null) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Could not find Peer-ID in key block.')),
      );
      return;
    }

    // group(1) returns the first capture group — the hex peer ID.
    final peerId = peerIdMatch.group(1)!;
    await _pair(peerId);
  }

  // ---------------------------------------------------------------------------
  // Build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Add Contact'),
        // CloseButton pops the route without a result (cancelled).
        // Using CloseButton rather than BackButton signals this is a modal
        // flow, matching M3 guidelines for action flows.
        leading: const CloseButton(),
        bottom: TabBar(
          controller: _tabs,
          // isScrollable: false — four tabs fits comfortably on all screens.
          tabs: const [
            Tab(icon: Icon(Icons.qr_code_scanner), text: 'QR Code'),
            Tab(icon: Icon(Icons.keyboard_outlined), text: 'Code'),
            Tab(icon: Icon(Icons.link_outlined), text: 'Link'),
            Tab(icon: Icon(Icons.key_outlined), text: 'Key'),
          ],
        ),
      ),
      // While pairing is in progress show a full-screen spinner so the user
      // cannot tap other buttons and trigger a second concurrent pairing attempt.
      body: _pairing
          ? const Center(child: CircularProgressIndicator())
          : TabBarView(
              controller: _tabs,
              children: [
                // Tab 0: QR scanner — uses the device camera.
                _ScanTab(onScanned: _pair),
                // Tab 1: Manual code entry or pre-filled from prefillPeerId.
                _CodeTab(controller: _codeController, onPair: _pair),
                // Tab 2: Share/import deep links.
                _LinkTab(
                  controller: _linkImportController,
                  onImportLink: _importLink,
                ),
                // Tab 3: Share/import full public-key blocks.
                _KeyTab(
                  controller: _keyImportController,
                  onImportKey: _importKey,
                ),
              ],
            ),
    );
  }
}

// ---------------------------------------------------------------------------
// _ScanTab — QR code scanner tab
// ---------------------------------------------------------------------------

/// Shows the device camera via [QrPairingWidget] to scan a peer's QR code.
///
/// When a QR code is successfully decoded, [onScanned] is called with the
/// decoded string (the peer's pairing token or peer ID).
class _ScanTab extends StatelessWidget {
  const _ScanTab({required this.onScanned});

  /// Called with the decoded QR string when a code is scanned.
  final ValueChanged<String> onScanned;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(24),
      child: Column(
        children: [
          // QrPairingWidget wraps mobile_scanner with the correct permissions
          // handling and UI chrome (targeting reticle, etc.).
          Expanded(child: QrPairingWidget(onScanned: onScanned)),
          const SizedBox(height: 16),
          Text(
            'Point the camera at your contact\'s QR code',
            style: Theme.of(context).textTheme.bodySmall?.copyWith(
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _CodeTab — manual pairing code entry
// ---------------------------------------------------------------------------

/// Text field + Pair button for entering a pairing code manually.
///
/// Also used when [prefillPeerId] is set — the controller is pre-populated
/// and the user just taps Pair.
class _CodeTab extends StatelessWidget {
  const _CodeTab({required this.controller, required this.onPair});

  /// Controller pre-populated when arriving from ProfilePreviewScreen.
  final TextEditingController controller;

  /// Called with the text field content when the user submits or taps Pair.
  final ValueChanged<String> onPair;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          TextField(
            controller: controller,
            autofocus: true,
            decoration: const InputDecoration(
              labelText: 'Pairing code',
              hintText: 'Paste or type the contact\'s pairing code',
            ),
            // Allow submitting via keyboard action key.
            onSubmitted: onPair,
          ),
          const SizedBox(height: 24),
          FilledButton(
            onPressed: () => onPair(controller.text),
            child: const Text('Pair'),
          ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _LinkTab — share / import meshinfinity:// deep links
// ---------------------------------------------------------------------------

/// Displays the user's own sharable pairing link (for sending to a peer)
/// and a text field to paste a peer's link for import.
class _LinkTab extends StatelessWidget {
  const _LinkTab({required this.controller, required this.onImportLink});

  final TextEditingController controller;
  final ValueChanged<String> onImportLink;

  @override
  Widget build(BuildContext context) {
    // Read BackendBridge directly — we only need to fetch identity once,
    // not subscribe to changes (it never changes during this screen's lifecycle).
    final bridge = context.read<BackendBridge>();

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Upper section: share the user's own link.
          Text(
            'Share your pairing link',
            style: Theme.of(context).textTheme.titleSmall,
          ),
          const SizedBox(height: 12),
          _PairingLinkDisplay(bridge: bridge),
          const SizedBox(height: 32),
          const Divider(),
          const SizedBox(height: 24),
          // Lower section: import a peer's link.
          Text(
            'Import a contact\'s link',
            style: Theme.of(context).textTheme.titleSmall,
          ),
          const SizedBox(height: 12),
          TextField(
            controller: controller,
            maxLines: 2,
            decoration: const InputDecoration(
              labelText: 'Pairing link',
              hintText: 'Paste meshinfinity://pair?... link here',
            ),
            onSubmitted: onImportLink,
          ),
          const SizedBox(height: 16),
          FilledButton.icon(
            onPressed: () => onImportLink(controller.text),
            icon: const Icon(Icons.download_outlined),
            label: const Text('Import Link'),
          ),
        ],
      ),
    );
  }
}

/// Fetches the local identity and builds a shareable pairing link to display.
///
/// The link format is: `meshinfinity://pair?v=1&peer_id=<hex>&token=<code>`
/// This is a custom URI scheme — not HTTP — so it opens the Mesh Infinity app
/// on the recipient's device when tapped.
class _PairingLinkDisplay extends StatelessWidget {
  const _PairingLinkDisplay({required this.bridge});

  final BackendBridge bridge;

  /// Builds the full pairing URI from the local identity and settings.
  ///
  /// [identity] provides the peer ID and optional display name.
  /// [settings] provides the pairing code (a short human-readable token
  /// generated by Rust); falls back to the raw peer ID if not set.
  String _buildLink(LocalIdentitySummary identity, SettingsModel? settings) {
    final peerId = identity.peerId;
    // pairingCode is a short token set in Settings that the peer submits.
    // Falls back to peerId itself if not configured.
    final token = settings?.pairingCode ?? peerId;
    final params = <String, String>{
      'v': '1',          // Link format version — allows future schema changes.
      'peer_id': peerId, // The sender's cryptographic peer ID.
      'token': token,    // The authentication token the peer submits to pair.
    };
    // Include the display name so the recipient sees who is pairing with them.
    if (identity.name != null && identity.name!.isNotEmpty) {
      params['name'] = identity.name!;
    }
    final uri = Uri(
      scheme: 'meshinfinity',
      host: 'pair',
      queryParameters: params,
    );
    return uri.toString();
  }

  @override
  Widget build(BuildContext context) {
    final identity = bridge.fetchLocalIdentity();
    if (identity == null) {
      // Identity is not available — should not happen after onboarding.
      return const Text('Identity not available.');
    }

    final settings = bridge.fetchSettings();
    final link = _buildLink(identity, settings);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // Display the link in a monospace container for easy reading.
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: Theme.of(context).colorScheme.surfaceContainerHighest,
            borderRadius: BorderRadius.circular(8),
          ),
          child: SelectableText(
            link,
            style: Theme.of(context).textTheme.bodySmall?.copyWith(
              fontFamily: 'monospace',
            ),
          ),
        ),
        const SizedBox(height: 12),
        FilledButton.tonalIcon(
          onPressed: () {
            Clipboard.setData(ClipboardData(text: link));
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(content: Text('Pairing link copied.')),
            );
          },
          icon: const Icon(Icons.copy),
          label: const Text('Copy Link'),
        ),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// _KeyTab — share / import raw public-key blocks
// ---------------------------------------------------------------------------

/// Displays the user's own public-key block and a field to paste a peer's
/// key for import.
///
/// Key import is the highest-security pairing method: the user verifies
/// the raw Ed25519/X25519 keys out-of-band (e.g. by reading them over a
/// phone call or via a signed email) before pasting, which eliminates any
/// dependency on a potentially-compromised transport channel.
class _KeyTab extends StatelessWidget {
  const _KeyTab({required this.controller, required this.onImportKey});

  final TextEditingController controller;
  final ValueChanged<String> onImportKey;

  @override
  Widget build(BuildContext context) {
    final bridge = context.read<BackendBridge>();

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Upper section: export the user's own public key.
          Text(
            'Your public key',
            style: Theme.of(context).textTheme.titleSmall,
          ),
          const SizedBox(height: 12),
          _PublicKeyDisplay(bridge: bridge),
          const SizedBox(height: 32),
          const Divider(),
          const SizedBox(height: 24),
          // Lower section: paste a peer's key for import.
          Text(
            'Import a contact\'s key',
            style: Theme.of(context).textTheme.titleSmall,
          ),
          const SizedBox(height: 12),
          TextField(
            controller: controller,
            maxLines: 6,
            decoration: const InputDecoration(
              labelText: 'Public key block',
              hintText: 'Paste the full key block from --- BEGIN to --- END',
              // alignLabelWithHint keeps the floating label aligned to the
              // top of the multi-line field rather than the vertical centre.
              alignLabelWithHint: true,
            ),
          ),
          const SizedBox(height: 16),
          FilledButton.icon(
            onPressed: () => onImportKey(controller.text),
            icon: const Icon(Icons.download_outlined),
            label: const Text('Import Key'),
          ),
        ],
      ),
    );
  }
}

/// Fetches and displays the local node's public-key block for sharing.
///
/// The block format wraps the Ed25519 signing key and X25519 encryption key
/// in a human-readable PEM-like structure alongside the peer ID.
class _PublicKeyDisplay extends StatelessWidget {
  const _PublicKeyDisplay({required this.bridge});

  final BackendBridge bridge;

  /// Builds the ASCII key block string from [identity].
  ///
  /// The publicKey field from the backend may encode both keys as
  /// `ed25519:<base64>:x25519:<base64>`, or just a single key.
  /// We split on ':' and handle both cases.
  String _buildKeyBlock(LocalIdentitySummary identity) {
    final buf = StringBuffer()
      ..writeln('--- BEGIN MESH INFINITY PUBLIC KEY ---')
      ..writeln('Peer-ID: ${identity.peerId}');

    // The publicKey field may contain both Ed25519 and X25519 keys
    // separated by a colon, or a single key.
    final parts = identity.publicKey.split(':');
    if (parts.length >= 2) {
      buf
        ..writeln('Ed25519: ${parts[0]}')
        ..writeln('X25519: ${parts[1]}');
    } else {
      // Single key — display as Ed25519 with a note about derivation.
      buf
        ..writeln('Ed25519: ${identity.publicKey}')
        ..writeln('X25519: <derived from Ed25519>');
    }

    buf.write('--- END MESH INFINITY PUBLIC KEY ---');
    return buf.toString();
  }

  @override
  Widget build(BuildContext context) {
    final identity = bridge.fetchLocalIdentity();
    if (identity == null) {
      return const Text('Identity not available.');
    }

    final keyBlock = _buildKeyBlock(identity);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // Monospace container — key material should always be displayed in a
        // fixed-width font so it is easy to compare character-by-character.
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: Theme.of(context).colorScheme.surfaceContainerHighest,
            borderRadius: BorderRadius.circular(8),
          ),
          child: SelectableText(
            keyBlock,
            style: Theme.of(context).textTheme.bodySmall?.copyWith(
              fontFamily: 'monospace',
              // Relaxed line height makes multi-line key blocks easier to read.
              height: 1.6,
            ),
          ),
        ),
        const SizedBox(height: 12),
        FilledButton.tonalIcon(
          onPressed: () {
            Clipboard.setData(ClipboardData(text: keyBlock));
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(content: Text('Public key copied.')),
            );
          },
          icon: const Icon(Icons.copy),
          label: const Text('Copy Key'),
        ),
      ],
    );
  }
}
