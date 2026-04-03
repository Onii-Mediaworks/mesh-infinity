// =============================================================================
// event_bus.dart
//
// This file implements the background event-polling loop that bridges
// real-time notifications from the Rust backend into Flutter's reactive UI.
//
// THE PROBLEM THIS SOLVES
// The Rust backend is event-driven: when a new message arrives, when a peer
// comes online, when a file transfer completes — these things happen
// asynchronously inside Rust's own threads.  Flutter's UI thread ("the main
// isolate") needs to know about these events so it can update the screen.
//
// We solve this with a polling loop:
//   1. A background Dart Isolate runs a tight loop calling mi_poll_events().
//   2. Rust's mi_poll_events() drains its internal event queue and returns
//      the events as a JSON string.
//   3. The background isolate sends the JSON string to the main isolate via a
//      message port.
//   4. The main isolate parses the JSON and adds typed BackendEvent objects to
//      a Dart Stream.
//   5. Feature-level state objects (MessagingState, PeersState, etc.) listen
//      to that Stream and update their data, causing the UI to rebuild.
//
// WHAT IS A DART ISOLATE?
// Dart is single-threaded by design — all UI code runs on a single thread
// called "the main isolate".  This keeps UI code simple and avoids a whole
// class of concurrency bugs.
//
// However, you CAN run work on a separate thread by spawning a new Isolate.
// Isolates are like threads but with one key difference: they share NO memory.
// Each isolate has its own heap, its own variables, its own stack.  They
// communicate ONLY by sending messages through "ports" (like pipes).
//
// This isolation is why we can't just pass the BackendBridge object to the
// background isolate — Dart forbids sharing objects across isolate boundaries.
// Instead we pass primitive values (integers, strings) and reconstruct what
// we need inside the new isolate.
//
// WHAT IS A STREAM?
// A Dart Stream is like an asynchronous list — it produces values over time.
// Any piece of code can "listen" to a stream and receive each value as it
// arrives.  Here, the stream produces BackendEvent objects, and all the
// state/provider classes subscribe to it.
// =============================================================================

import 'dart:async';    // StreamController, Stream — asynchronous event streams
import 'dart:convert';  // jsonDecode — parse JSON strings into Dart objects
import 'dart:ffi';      // DynamicLibrary, Pointer, Void, Utf8, etc.
import 'dart:io';       // Platform, sleep — OS detection and thread sleeping
import 'dart:isolate';  // Isolate, ReceivePort, SendPort — inter-isolate messaging

import 'package:ffi/ffi.dart'; // Utf8 type alias and helpers
import 'package:flutter/foundation.dart' show debugPrint;

import 'event_models.dart'; // BackendEvent and its subclasses

// =============================================================================
// EventBus
//
// A singleton (there is only ever ONE instance) that owns the background
// isolate and the broadcast stream.
//
// Usage:
//   EventBus.instance.start(bridge.contextAddress); // call once at app start
//   EventBus.instance.stream.listen((event) { ... }); // subscribe anywhere
//   EventBus.instance.stop(); // call when the app is closing
// =============================================================================

class EventBus {
  // Private constructor prevents external instantiation.
  // The `._()` naming convention is idiomatic Dart for private named constructors.
  EventBus._();

  /// The single global instance — created eagerly when the class is first used.
  static final EventBus instance = EventBus._();

  // ---------------------------------------------------------------------------
  // The broadcast stream
  //
  // StreamController is the "write end" — we add events to it.
  // stream is the "read end" — listeners subscribe to it.
  //
  // `.broadcast()` allows MULTIPLE listeners at the same time.  Without this,
  // only one listener could subscribe before causing an error.  Since many
  // state objects (MessagingState, PeersState, NetworkState, etc.) all need to
  // listen simultaneously, broadcast mode is essential.
  // ---------------------------------------------------------------------------
  final StreamController<BackendEvent> _controller =
      StreamController<BackendEvent>.broadcast();

  /// Public stream that any code in the app can listen to.
  /// Subscribe with: EventBus.instance.stream.listen((event) { ... });
  Stream<BackendEvent> get stream => _controller.stream;

  // ---------------------------------------------------------------------------
  // Isolate management
  // ---------------------------------------------------------------------------

  // A reference to the background isolate so we can kill it on shutdown.
  Isolate? _isolate;

  // The port on which the MAIN isolate receives messages from the background.
  // Closing this port effectively signals that we no longer want messages.
  ReceivePort? _receivePort;

  // Ports for monitoring isolate errors and exit.
  ReceivePort? _errorPort;
  ReceivePort? _exitPort;

  // The context address is stored so we can restart the isolate if it dies.
  int? _contextAddress;

  // Whether stop() was called intentionally (suppresses auto-restart).
  bool _stopped = false;

  // Native (non-GC) flag shared with the background isolate.  Setting it to 1
  // signals the poll loop to exit cleanly between FFI calls, so we do not call
  // mesh_destroy() while an mi_poll_events() call is still executing in the
  // background isolate.  calloc() allocates outside the Dart GC heap, so the
  // pointer is readable by both isolates as a plain integer address.
  final Pointer<Int32> _stopFlag = calloc<Int32>();

  // Timestamps of recent restarts for rate-limiting.  If more than
  // _maxRestartsInWindow restarts happen within _restartWindow, we stop
  // retrying to avoid a rapid crash loop.
  final List<DateTime> _restartTimestamps = [];
  static const int _maxRestartsInWindow = 5;
  static const Duration _restartWindow = Duration(seconds: 60);
  static const Duration _restartDelay = Duration(seconds: 2);

  // ---------------------------------------------------------------------------
  // start()
  //
  // Launch the background polling isolate.  Call this once when the app
  // starts and the Rust backend is confirmed available.
  //
  // contextAddress — the raw integer memory address of the Rust context pointer.
  //   We cannot send a Pointer<Void> across the isolate boundary (isolates
  //   share no memory), but a plain integer is fine.  The background isolate
  //   reconstructs the pointer from the integer using Pointer.fromAddress().
  // ---------------------------------------------------------------------------
  void start(int contextAddress) {
    _contextAddress = contextAddress;
    _stopped = false;
    _stopFlag.value = 0; // Arm the cooperative-stop flag for the new isolate.
    _spawnIsolate();
  }

  // ---------------------------------------------------------------------------
  // _spawnIsolate()
  //
  // Internal helper that creates the background isolate with error and exit
  // monitoring.  Extracted from start() so that the restart logic can reuse it.
  // ---------------------------------------------------------------------------
  void _spawnIsolate() {
    // Clean up any previous ports (relevant on restart).
    _receivePort?.close();
    _errorPort?.close();
    _exitPort?.close();

    // Create a port that will receive messages FROM the background isolate.
    _receivePort = ReceivePort();

    // Register our message handler.  Every time the background isolate sends
    // a message, _onMessage() will be called on the main isolate's thread.
    _receivePort!.listen(_onMessage);

    // Port for receiving uncaught errors from the background isolate.
    // Errors arrive as a two-element list: [errorDescription, stackTrace].
    _errorPort = ReceivePort();
    _errorPort!.listen((dynamic error) {
      // Log the error but do not restart here — the onExit handler fires
      // after the error when the isolate actually terminates.
      debugPrint('[EventBus] Background isolate error: $error');
    });

    // Port for detecting when the background isolate terminates.
    // The message is null when the isolate exits.
    _exitPort = ReceivePort();
    _exitPort!.listen((_) {
      _onIsolateExit();
    });

    // Spawn the background isolate.
    //
    // errorsAreFatal: true — if the poll loop throws an unhandled exception the
    // isolate terminates, which triggers _exitPort so we can restart it.
    // The old behaviour (errorsAreFatal: false) silently swallowed errors and
    // left the UI permanently stale.
    //
    // onError / onExit — receive ports that let us detect crashes and exits.
    Isolate.spawn(
      _pollLoop,
      _PollMessage(
        sendPort: _receivePort!.sendPort,
        contextAddress: _contextAddress!,
        stopFlagAddress: _stopFlag.address,
      ),
      errorsAreFatal: true,
      onError: _errorPort!.sendPort,
      onExit: _exitPort!.sendPort,
    ).then((isolate) => _isolate = isolate);
  }

  // ---------------------------------------------------------------------------
  // _onIsolateExit()
  //
  // Called when the background isolate terminates (crash or kill).
  // If the exit was not intentional (i.e. stop() was not called), attempt an
  // automatic restart after a short delay.
  //
  // Rate-limiting: if the isolate has restarted more than 5 times within the
  // last 60 seconds, stop retrying — something is fundamentally broken and
  // rapid restarts would just waste resources.
  // ---------------------------------------------------------------------------
  void _onIsolateExit() {
    _isolate = null;

    // Intentional shutdown — do nothing.
    if (_stopped) return;

    // Prune restart timestamps outside the window.
    final now = DateTime.now();
    _restartTimestamps.removeWhere(
      (t) => now.difference(t) > _restartWindow,
    );

    if (_restartTimestamps.length >= _maxRestartsInWindow) {
      debugPrint(
        '[EventBus] Isolate restarted $_maxRestartsInWindow times in '
        '${_restartWindow.inSeconds}s — giving up. UI events will not update.',
      );
      return;
    }

    _restartTimestamps.add(now);
    debugPrint(
      '[EventBus] Background isolate exited unexpectedly. '
      'Restarting in ${_restartDelay.inSeconds}s '
      '(${_restartTimestamps.length}/$_maxRestartsInWindow)...',
    );

    // Delay before restarting to avoid a tight crash loop.
    Future<void>.delayed(_restartDelay, () {
      // Re-check — stop() may have been called during the delay.
      if (!_stopped && _contextAddress != null) {
        _spawnIsolate();
      }
    });
  }

  // ---------------------------------------------------------------------------
  // stop()
  //
  // Signal the background isolate to exit cleanly, wait for confirmation,
  // then clean up resources.  Returns a Future so the caller can await it
  // before calling mesh_destroy() — guaranteeing the isolate is not inside
  // an mi_poll_events() FFI call when the Rust context is freed (C3).
  //
  // Shutdown sequence:
  //   1. Set the cooperative stop flag (native memory readable by the isolate).
  //      The poll loop checks this flag at the top of each iteration and
  //      immediately after each FFI call, so it will exit within one polling
  //      cycle (≤ 200 ms) without entering another FFI call.
  //   2. Register a one-shot listener on _exitPort and await its completion
  //      with a 500 ms timeout (belt-and-suspenders if the isolate hangs).
  //   3. Force-kill the isolate — no-op if it already exited cleanly.
  //   4. Close all ports and null out references.
  // ---------------------------------------------------------------------------
  Future<void> stop() async {
    _stopped = true;

    // Step 1 — signal cooperative exit.
    _stopFlag.value = 1;

    // Step 2 — wait for the isolate to confirm it has exited.
    if (_isolate != null) {
      final exitCompleter = Completer<void>();

      // Re-create _exitPort so we get a clean one-shot notification.
      _exitPort?.close();
      _exitPort = ReceivePort();
      _exitPort!.listen((_) {
        if (!exitCompleter.isCompleted) exitCompleter.complete();
      });
      _isolate!.addOnExitListener(_exitPort!.sendPort);

      // Step 3 — nudge the isolate to exit; the cooperative flag is the
      // primary signal; beforeNextEvent is a fallback for any edge case
      // where the flag is not checked (e.g. crash recovery paths).
      _isolate!.kill(priority: Isolate.beforeNextEvent);

      // Wait up to 500 ms for a clean exit before proceeding.
      await exitCompleter.future
          .timeout(const Duration(milliseconds: 500), onTimeout: () {});
    }

    // Step 4 — hard kill and cleanup (idempotent if already exited).
    _isolate?.kill(priority: Isolate.immediate);
    _isolate = null;
    _receivePort?.close();
    _receivePort = null;
    _errorPort?.close();
    _errorPort = null;
    _exitPort?.close();
    _exitPort = null;
  }

  // ---------------------------------------------------------------------------
  // _onMessage()
  //
  // Called on the MAIN isolate whenever the background isolate sends a message.
  //
  // The message is a JSON string representing a list of events:
  //   [{"type":"MessageAdded","data":{...}}, {"type":"PeerUpdated","data":{...}}]
  //
  // We parse it, convert each item into a typed BackendEvent, and add it to
  // the stream so that all listeners (state objects) get notified.
  // ---------------------------------------------------------------------------
  /// Number of events dropped due to parse errors or unknown type (M2).
  /// Exposed for diagnostics — a non-zero value indicates backend/frontend
  /// version mismatch or a serialization bug.
  int get droppedEventCount => _droppedEventCount;
  int _droppedEventCount = 0;

  void _onMessage(dynamic message) {
    // Guard: we only handle String messages.  Other types (e.g. error objects
    // sent by the isolate framework) are ignored.
    if (message is! String) return;
    try {
      final decoded = jsonDecode(message); // String → Dart List
      if (decoded is! List) return;
      for (final item in decoded) {
        if (item is! Map<String, dynamic>) {
          _droppedEventCount++;
          continue;
        }
        // Convert the raw map into a typed BackendEvent subclass.
        // fromJson returns null for unknown event types — we count and skip.
        final event = BackendEvent.fromJson(item);
        if (event != null) {
          _controller.add(event); // publish to the stream
        } else {
          _droppedEventCount++;
          final type = item['type'] ?? '<missing>';
          debugPrint('[EventBus] Unknown event type "$type" — dropped (total: $_droppedEventCount)');
        }
      }
    } catch (e, st) {
      // Count and log parse errors.  A malformed event batch should not
      // crash the UI, but we want visibility into these failures (M2).
      _droppedEventCount++;
      debugPrint('[EventBus] Event parse error (total dropped: $_droppedEventCount): $e\n$st');
    }
  }

  // ---------------------------------------------------------------------------
  // _pollLoop() — runs entirely inside the BACKGROUND isolate
  //
  // This is a static method because instance methods cannot be passed to
  // Isolate.spawn() — they capture `this`, which would cross the isolate
  // boundary.
  //
  // WHAT THIS FUNCTION DOES:
  //   1. Re-opens the Rust shared library (we must re-open it because the
  //      background isolate has a separate memory space — it cannot reuse the
  //      DynamicLibrary from the main isolate).
  //   2. Resolves two Rust functions: mi_poll_events and mi_string_free.
  //   3. Reconstructs the context pointer from the integer address.
  //   4. Loops forever: call mi_poll_events, send results, sleep, repeat.
  // ---------------------------------------------------------------------------
  static void _pollLoop(_PollMessage msg) {
    // Re-open the library in this isolate's address space.
    // Because isolates share NO memory, we cannot pass the DynamicLibrary
    // handle from the main isolate.  But opening the same .so/.dylib/.dll again
    // is cheap — the OS maps the same physical pages into this process.
    final lib = _loadLibrary();

    // Resolve mi_poll_events — the Rust function that drains the event queue.
    //
    // Signature: mi_poll_events(ctx: *mut MeshContext, max_events: u32) -> *mut c_char
    //
    // It returns a JSON array string of up to `max_events` pending events.
    // Returns nullptr if there are no events.
    final pollEvents = lib.lookupFunction<
      Pointer<Utf8> Function(Pointer<Void>, Uint32),
      Pointer<Utf8> Function(Pointer<Void>, int)
    >('mi_poll_events');

    // Resolve mi_string_free — used to free the JSON string after we've read it.
    // Same as in backend_bridge.dart: Rust allocated the string, so Rust must
    // free it.  We cannot let Dart's GC handle it.
    final stringFree = lib.lookupFunction<
      Void Function(Pointer<Utf8>),
      void Function(Pointer<Utf8>)
    >('mi_string_free');

    // Reconstruct the context pointer from the raw integer address.
    //
    // The main isolate passed `bridge.contextAddress` (an int) to us.
    // Pointer.fromAddress() creates a Pointer<Void> that points to that same
    // memory location.  This is safe because:
    //   - The Rust context lives for the lifetime of the app process.
    //   - The integer address is guaranteed stable (Rust heap, not GC-moved).
    //   - Rust uses internal locking, so concurrent calls from both isolates
    //     are safe.
    final ctx = Pointer<Void>.fromAddress(msg.contextAddress);

    // Reconstruct the cooperative-stop flag pointer from the address integer.
    // This is the same native memory that EventBus._stopFlag points to on the
    // main isolate — both sides read/write the same physical bytes.
    final stopFlag = Pointer<Int32>.fromAddress(msg.stopFlagAddress);

    // THE POLL LOOP — runs until the stop flag is set or the isolate is killed.
    //
    // We check stopFlag.value at TWO points:
    //   (a) at the top of the loop — avoids entering a new FFI call after stop()
    //   (b) immediately after pollEvents() returns — exits before re-entering
    //       native code so mesh_destroy() can safely free the context.
    while (stopFlag.value == 0) {
      // Ask Rust for up to 64 pending events.
      // Requesting a batch (64) rather than one at a time reduces overhead —
      // if many events arrived at once (e.g. bulk message sync), we process
      // them all in one round rather than sleeping between each one.
      final ptr = pollEvents(ctx, 64);

      // (b) Check stop flag immediately after FFI returns.
      if (stopFlag.value != 0) {
        if (ptr != nullptr) stringFree(ptr);
        break;
      }

      if (ptr != nullptr) {
        // There were events.  Copy them out of native memory into a Dart String.
        final json = ptr.toDartString();
        // Free the native string immediately — we have our copy in `json`.
        stringFree(ptr);

        // A JSON array with zero events looks like "[]" which is 2 characters.
        // If the string is longer than 2 chars it actually has content.
        if (json.length > 2) {
          // Send the JSON string to the main isolate via the port.
          // SendPort.send() is the ONLY safe way to communicate with other isolates.
          // The message is deep-copied across the isolate boundary (for Strings
          // this is efficient — it's just copying bytes).
          msg.sendPort.send(json);

          // Skip the sleep and immediately poll again — there might be more
          // events in the queue right now (bursty network traffic, batch sync).
          continue;
        }
      }

      // No events this time.  Sleep before polling again to avoid burning 100%
      // CPU on a tight spin loop.  200ms gives a worst-case event latency of
      // 200ms (barely perceptible to humans) while keeping CPU usage near zero
      // when the mesh is quiet.
      //
      // WHY sleep() AND NOT await Future.delayed()?
      // We are inside an Isolate that runs plain (non-async) synchronous code.
      // The `sleep()` call from dart:io blocks the isolate thread — which is
      // exactly what we want.  Using Future.delayed would require an async
      // event loop, which adds complexity for no benefit in a tight poll loop.
      sleep(const Duration(milliseconds: 200));
    }
  }

  /// Open the platform-appropriate Rust shared library.
  /// This mirrors the logic in backend_bridge.dart — see that file for a
  /// detailed explanation of why each platform needs a different call.
  static DynamicLibrary _loadLibrary() {
    if (Platform.isAndroid) return DynamicLibrary.open('libmesh_infinity.so');
    if (Platform.isIOS) return DynamicLibrary.process();
    if (Platform.isMacOS) return DynamicLibrary.process(); // statically linked
    if (Platform.isWindows) return DynamicLibrary.open('mesh_infinity.dll');
    return DynamicLibrary.open('libmesh_infinity.so'); // Linux fallback
  }
}

// =============================================================================
// _PollMessage
//
// A plain data class used to pass the initial configuration from the main
// isolate to the background isolate when it starts up.
//
// WHY A SEPARATE CLASS?
// Isolate.spawn() allows only a SINGLE argument to the entry-point function.
// We need to send two pieces of information (the send port and the context
// address), so we bundle them into this class.
//
// Dart can send this across the isolate boundary because it only contains
// primitive-compatible types: SendPort and int are both isolate-sendable.
// =============================================================================

class _PollMessage {
  const _PollMessage({
    required this.sendPort,
    required this.contextAddress,
    required this.stopFlagAddress,
  });

  /// The port the background isolate uses to send event JSON back to the main
  /// isolate.  SendPort is safe to pass across isolate boundaries.
  final SendPort sendPort;

  /// The raw memory address (as an integer) of the Rust MeshContext pointer.
  /// The background isolate calls Pointer.fromAddress(contextAddress) to
  /// reconstruct a usable `Pointer<Void>` from this integer.
  final int contextAddress;

  /// The raw address of a native Int32 stop-flag allocated by calloc() in the
  /// main isolate.  The background isolate reconstructs a `Pointer<Int32>` from
  /// this address and checks its value at each loop iteration.  When the main
  /// isolate sets the flag to 1, the poll loop exits between FFI calls so that
  /// mesh_destroy() can run safely (C3 fix).
  final int stopFlagAddress;
}
