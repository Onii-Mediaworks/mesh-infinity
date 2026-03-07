import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

class QrPairingWidget extends StatefulWidget {
  const QrPairingWidget({super.key, required this.onScanned});

  final ValueChanged<String> onScanned;

  @override
  State<QrPairingWidget> createState() => _QrPairingWidgetState();
}

class _QrPairingWidgetState extends State<QrPairingWidget> {
  final _controller = MobileScannerController();
  bool _scanned = false;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return ClipRRect(
      borderRadius: BorderRadius.circular(16),
      child: MobileScanner(
        controller: _controller,
        onDetect: (capture) {
          if (_scanned) return;
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
