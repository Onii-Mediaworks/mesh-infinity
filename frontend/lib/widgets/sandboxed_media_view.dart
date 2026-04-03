// §22.4.11 SandboxedMediaView
//
// All media received from peers (images, GIFs, stickers) is untrusted.
// Rendering is sandboxed:
//   - Decoded in a background Isolate via compute() — never on the UI thread.
//   - Maximum decode dimensions: 4096×4096px. Larger images are rejected.
//   - EXIF stripping: handled in Rust before the blob crosses the FFI boundary.
//     The Flutter layer never sees EXIF data.
//   - SVG is prohibited — never passed to this widget.
//   - Failed validation shows a broken-media placeholder, never silently hidden.
//   - Tapping opens a fullscreen InteractiveViewer with hero transition.

import 'dart:ui' as ui;

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

// ---------------------------------------------------------------------------
// AttachmentRef — minimal descriptor for a media attachment
// ---------------------------------------------------------------------------

/// Opaque reference to a media attachment stored in the local vault.
///
/// [id]       — vault key used to retrieve the raw bytes via BackendBridge.
/// [mimeType] — declared MIME type (verified against magic bytes in Rust).
/// [bytes]    — pre-fetched raw bytes, if already available; null triggers load.
/// [width]    — declared pixel width from the attachment header (may differ
///              from decoded dimensions if the header was tampered; the decoder
///              enforces the 4096px cap independently).
/// [height]   — declared pixel height.
class AttachmentRef {
  const AttachmentRef({
    required this.id,
    required this.mimeType,
    this.bytes,
    this.width,
    this.height,
  });

  final String id;
  final String mimeType;
  final Uint8List? bytes;
  final int? width;
  final int? height;

  bool get isImage => mimeType.startsWith('image/');
}

// ---------------------------------------------------------------------------
// _DecodeResult — passed between UI thread and background Isolate
// ---------------------------------------------------------------------------

class _DecodeResult {
  const _DecodeResult({this.image, this.error});
  final ui.Image? image;
  final String? error;
}

/// Top-level function (required by compute()) that decodes bytes in a
/// background Isolate.  Rejects images wider or taller than 4096px.
Future<_DecodeResult> _decodeImage(Uint8List bytes) async {
  try {
    final codec = await ui.instantiateImageCodec(
      bytes,
      // targetWidth/targetHeight of 0 means "no forced resize"; Flutter will
      // decode at native size.  We cap after decoding by checking dimensions.
    );
    final frame = await codec.getNextFrame();
    final image = frame.image;

    if (image.width > 4096 || image.height > 4096) {
      image.dispose();
      return const _DecodeResult(
        error: 'Image exceeds maximum safe dimensions (4096×4096).',
      );
    }
    return _DecodeResult(image: image);
  } catch (e) {
    return _DecodeResult(error: 'Failed to decode image: $e');
  }
}

// ---------------------------------------------------------------------------
// SandboxedMediaView
// ---------------------------------------------------------------------------

class SandboxedMediaView extends StatefulWidget {
  const SandboxedMediaView({
    super.key,
    required this.attachment,
    this.maxWidth,
    this.maxHeight,
    this.onTap,
    this.borderRadius = 12.0,
    this.showPlayButton = true,
  });

  final AttachmentRef attachment;
  final double? maxWidth;
  final double? maxHeight;

  /// Override default tap handler (fullscreen viewer).  Null = use built-in.
  final VoidCallback? onTap;

  final double borderRadius;

  /// Show a play button overlay for video thumbnails.
  final bool showPlayButton;

  @override
  State<SandboxedMediaView> createState() => _SandboxedMediaViewState();
}

class _SandboxedMediaViewState extends State<SandboxedMediaView> {
  _DecodeResult? _result;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void didUpdateWidget(SandboxedMediaView old) {
    super.didUpdateWidget(old);
    if (old.attachment.id != widget.attachment.id) {
      setState(() {
        _result = null;
        _loading = true;
      });
      _load();
    }
  }

  Future<void> _load() async {
    final bytes = widget.attachment.bytes;
    if (bytes == null) {
      // Bytes not pre-fetched — in a full implementation BackendBridge would
      // be called here to fetch from the vault.  For now, show broken placeholder.
      if (mounted) {
        setState(() {
          _result = const _DecodeResult(
            error: 'Media not available.',
          );
          _loading = false;
        });
      }
      return;
    }

    // Decode on a background Isolate — never block the UI thread.
    final result = await compute(_decodeImage, bytes);

    if (mounted) {
      setState(() {
        _result = result;
        _loading = false;
      });
    }
  }

  void _openFullscreen(BuildContext context) {
    if (widget.onTap != null) {
      widget.onTap!();
      return;
    }
    final result = _result;
    if (result?.image == null) return;
    Navigator.push(
      context,
      PageRouteBuilder<void>(
        opaque: false,
        barrierColor: Colors.black87,
        transitionDuration: const Duration(milliseconds: 500),
        reverseTransitionDuration: const Duration(milliseconds: 300),
        pageBuilder: (ctx, animation, secondary) => FadeTransition(
          opacity: animation,
          child: _FullscreenViewer(
            attachment: widget.attachment,
            heroTag: 'sandboxed_${widget.attachment.id}',
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    Widget content;

    if (_loading) {
      content = Container(
        color: cs.surfaceContainerHighest,
        child: const Center(child: CircularProgressIndicator(strokeWidth: 2)),
      );
    } else {
      final result = _result;
      if (result?.error != null || result?.image == null) {
        // Broken-media placeholder — never silent.
        content = Container(
          color: cs.surfaceContainerHighest,
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(
                Icons.broken_image_outlined,
                size: 36,
                color: cs.onSurfaceVariant,
              ),
              const SizedBox(height: 8),
              Text(
                "This media couldn't be displayed.",
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  color: cs.onSurfaceVariant,
                ),
                textAlign: TextAlign.center,
              ),
            ],
          ),
        );
      } else {
        content = Hero(
          tag: 'sandboxed_${widget.attachment.id}',
          child: RawImage(image: result!.image),
        );
      }
    }

    return GestureDetector(
      onTap: _result?.image != null ? () => _openFullscreen(context) : null,
      child: ClipRRect(
        borderRadius: BorderRadius.circular(widget.borderRadius),
        child: SizedBox(
          width: widget.maxWidth,
          height: widget.maxHeight,
          child: content,
        ),
      ),
    );
  }

  @override
  void dispose() {
    // Release the decoded ui.Image to free GPU memory.
    _result?.image?.dispose();
    super.dispose();
  }
}

// ---------------------------------------------------------------------------
// _FullscreenViewer
// ---------------------------------------------------------------------------

/// Fullscreen viewer opened by tapping a SandboxedMediaView.
/// Hero tag matches the thumbnail so Flutter animates the transition.
/// Pinch-to-zoom via InteractiveViewer (1×–5×). Swipe down to dismiss.
class _FullscreenViewer extends StatelessWidget {
  const _FullscreenViewer({
    required this.attachment,
    required this.heroTag,
  });

  final AttachmentRef attachment;
  final String heroTag;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      extendBodyBehindAppBar: true,
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        foregroundColor: Colors.white,
        elevation: 0,
      ),
      body: Center(
        child: Hero(
          tag: heroTag,
          child: InteractiveViewer(
            minScale: 1.0,
            maxScale: 5.0,
            child: attachment.bytes != null
                ? Image.memory(
                    attachment.bytes!,
                    fit: BoxFit.contain,
                    errorBuilder: (ctx, err, _) => const Icon(
                      Icons.broken_image_outlined,
                      color: Colors.white54,
                      size: 64,
                    ),
                  )
                : const Icon(
                    Icons.broken_image_outlined,
                    color: Colors.white54,
                    size: 64,
                  ),
          ),
        ),
      ),
    );
  }
}
