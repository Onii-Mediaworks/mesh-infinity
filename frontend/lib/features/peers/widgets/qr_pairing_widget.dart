// qr_pairing_widget.dart
//
// QrPairingWidget — live QR scanner for the contact pairing flow.
//
// HOW PAIRING WORKS (§10.1):
// ---------------------------
// When two users want to become contacts they each generate a pairing payload
// (public key + transport hints) and encode it in a QR code.  One party scans
// the other's code; the backend verifies the payload, derives a shared session
// key, and registers the new peer.
//
// This widget owns the camera scanner.  It fires [onScanned] exactly once —
// the one-shot deduplication (_scanned flag) prevents duplicate calls if the
// scanner detects the same code in multiple consecutive frames, which the
// mobile_scanner library can do before the camera feed is paused.
//
// The parent (PairContactScreen) is responsible for passing the scanned code
// to PeersState.pairPeer() and handling success/failure feedback.

import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

/// A full-area live QR scanner that calls [onScanned] with the raw QR value
/// exactly once per widget lifetime.
///
/// The widget clips to a rounded rectangle so it fits inside card or dialog
/// containers without sharp corners breaking the visual design.
///
/// Dispose semantics: the [MobileScannerController] is disposed when this
/// widget is removed from the tree, freeing the camera resource.
class QrPairingWidget extends StatefulWidget {
  const QrPairingWidget({super.key, required this.onScanned});

  /// Called with the raw string value of the first QR code detected.
  ///
  /// This callback fires at most once per widget instance — subsequent
  /// detections are silently ignored by the [_scanned] gate.
  final ValueChanged<String> onScanned;

  @override
  State<QrPairingWidget> createState() => _QrPairingWidgetState();
}

class _QrPairingWidgetState extends State<QrPairingWidget> {
  /// Controls the underlying camera stream. Must be disposed when the widget
  /// is removed to release the camera hardware.
  final _controller = MobileScannerController();

  /// Guards against duplicate [onScanned] calls.
  ///
  /// The camera decoder can emit multiple detection events for the same code
  /// within a single video frame or across sequential frames before the camera
  /// has time to pause. This flag ensures only the first valid detection is
  /// forwarded — subsequent ones are dropped.
  bool _scanned = false;

  @override
  void dispose() {
    // Release the camera session. Failing to do this leaks the camera resource
    // and can prevent other apps from using the camera until the OS reclaims it.
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return ClipRRect(
      // Rounded corners so the scanner fills a card-style container cleanly
      // without visually jarring square corners inside a rounded parent.
      borderRadius: BorderRadius.circular(16),
      child: MobileScanner(
        controller: _controller,
        onDetect: (capture) {
          // Drop all events after the first successful scan. This is a
          // one-shot widget — the parent will dispose it once it has the code.
          if (_scanned) return;

          // Extract the raw string value from the first barcode in the capture.
          // rawValue can be null if the library decoded a binary-only payload,
          // or empty if the QR code was blank; both are invalid pairing codes.
          final code = capture.barcodes.firstOrNull?.rawValue;
          if (code != null && code.isNotEmpty) {
            _scanned = true;
            widget.onScanned(code);
          }
        },
      ),
    );
  }
}
