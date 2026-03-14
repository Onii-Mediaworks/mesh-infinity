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
    // Create a port that will receive messages FROM the background isolate.
    _receivePort = ReceivePort();

    // Register our message handler.  Every time the background isolate sends
    // a message, _onMessage() will be called on the main isolate's thread.
    _receivePort!.listen(_onMessage);

    // Spawn the background isolate.
    //
    // Isolate.spawn() takes:
    //   1. A top-level (or static) function to run in the new isolate.
    //      It MUST be a top-level or static function — closures that capture
    //      state from the enclosing scope cannot cross isolate boundaries.
    //   2. A single argument to pass to that function.  Complex objects must
    //      be serialisable; here we use a simple data class _PollMessage.
    //
    // errorsAreFatal: false means if the poll loop crashes with an unhandled
    // exception, the isolate dies silently rather than bringing down the
    // whole app.  This is acceptable because the worst case is that events
    // stop arriving (the UI goes stale) rather than the app crashing.
    Isolate.spawn(
      _pollLoop,                    // the function to run in the new isolate
      _PollMessage(
        sendPort: _receivePort!.sendPort, // how the isolate sends messages back
        contextAddress: contextAddress,   // the Rust context address (as int)
      ),
      errorsAreFatal: false,
    ).then((isolate) => _isolate = isolate); // save reference for later cleanup
  }

  // ---------------------------------------------------------------------------
  // stop()
  //
  // Kill the background isolate and clean up resources.
  // Called when the app widget is disposed (closing the app).
  // ---------------------------------------------------------------------------
  void stop() {
    // Isolate.immediate means "kill it now, don't wait for current task to
    // finish".  Safe here because the isolate only does FFI calls and sleeps.
    _isolate?.kill(priority: Isolate.immediate);
    _isolate = null;
    _receivePort?.close(); // Stop accepting messages.
    _receivePort = null;
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
  void _onMessage(dynamic message) {
    // Guard: we only handle String messages.  Other types (e.g. error objects
    // sent by the isolate framework) are ignored.
    if (message is! String) return;
    try {
      final decoded = jsonDecode(message); // String → Dart List
      if (decoded is! List) return;
      for (final item in decoded) {
        if (item is! Map<String, dynamic>) continue;
        // Convert the raw map into a typed BackendEvent subclass.
        // fromJson returns null for unknown event types — we skip those.
        final event = BackendEvent.fromJson(item);
        if (event != null) _controller.add(event); // publish to the stream
      }
    } catch (_) {
      // Swallow parse errors silently.  A malformed event batch should not
      // crash the UI.
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

    // THE POLL LOOP — runs until the isolate is killed.
    while (true) {
      // Ask Rust for up to 64 pending events.
      // Requesting a batch (64) rather than one at a time reduces overhead —
      // if many events arrived at once (e.g. bulk message sync), we process
      // them all in one round rather than sleeping between each one.
      final ptr = pollEvents(ctx, 64);

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
    if (Platform.isMacOS) return DynamicLibrary.open('libmesh_infinity.dylib');
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
  const _PollMessage({required this.sendPort, required this.contextAddress});

  /// The port the background isolate uses to send event JSON back to the main
  /// isolate.  SendPort is safe to pass across isolate boundaries.
  final SendPort sendPort;

  /// The raw memory address (as an integer) of the Rust MeshContext pointer.
  /// The background isolate calls Pointer.fromAddress(contextAddress) to
  /// reconstruct a usable Pointer<Void> from this integer.
  final int contextAddress;
}
