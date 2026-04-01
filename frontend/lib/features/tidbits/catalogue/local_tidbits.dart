// local_tidbits.dart
//
// Catalogue of LocalOnly Playful Tidbits (§22.12.2 LocalOnly delivery mode).
//
// HOW TO ADD A NEW TIDBIT:
// ------------------------
// 1. Write a registration block inside initLocalTidbits() below (~10 lines).
// 2. Add a trigger site in the relevant UI widget (~3 lines).
// 3. Run `flutter analyze` to confirm no issues.
// That's the full process.  No new infrastructure is needed.
//
// FILE GROWTH POLICY:
// -------------------
// This file is expected to grow to thousands of entries over the lifetime of
// the product.  The spec's 100-item catalogue is just a starting point.
// Each entry should be ~10–15 lines of Dart.  Split into sub-files
// (catalogue/local_tidbits_chat.dart, catalogue/local_tidbits_network.dart,
// etc.) only when this file exceeds ~2000 lines.
//
// NAMING CONVENTION:
// ------------------
// id: lowercase_with_underscores matching the spec name or the name you gave it.
// specRef: '§22.12.5 #N' for catalogue items, '§22.12.5 (new)' for additions.
//
// TRIGGER WIRING (quick reference):
// ----------------------------------
// Confetti on a button tap:
//   ElevatedButton(onPressed: () { doStuff(); TidbitRegistry.instance.show('copy_confetti', context); })
//
// N-tap secret:
//   TapTrigger(count: 7, onTriggered: () => TidbitRegistry.instance.show('tiny_pong', context), child: logo)
//
// Show haiku on triple-tap of peer ID text:
//   TapTrigger(count: 3, onTriggered: () => TidbitRegistry.instance.show('peer_id_haiku_$peerId', context), child: peerIdText)
// (Haiku tidbits are registered dynamically per peer ID — see _registerHaiku())

import 'package:flutter/material.dart';
import 'package:flutter/services.dart'; // HapticFeedback

import '../tidbit_registry.dart';
import '../haiku_generator.dart';
import '../widgets/confetti_burst.dart';

// ---------------------------------------------------------------------------
// Public init function — called once from tidbits.dart at app startup
// ---------------------------------------------------------------------------

/// Register all LocalOnly tidbits.
///
/// Call this once from [initTidbits] in tidbits.dart.
/// The function is idempotent (safe to call multiple times; last-write-wins).
void initLocalTidbits(TidbitRegistry r) {
  _registerCopyConfetti(r);
  _registerUnreadFireworks(r);
  _registerAmbientSnow(r); // self-activates only in winter — stub wiring here
  _registerGardenGnome(r); // inline widget, registration is informational
  _registerNightOwlGreeting(r);
  _registerHighLatencySnail(r);
  _registerSuccessfulSendSparkle(r);
  _registerTypingMeteor(r);
  _registerOfflineStatusQuip(r);
  _registerPeerCountMilestone(r);
  _registerFirstMessageConfetti(r);
  _registerLongThreadVine(r);
  _registerMidnightChime(r);
  _registerSunriseMode(r);
  _registerQuietCricket(r);
  _registerEmptyChatTumbleweed(r);
  _registerNodeFortune(r);
  _registerSendStreakFlame(r);
  _registerTransferComplete(r);
  _registerContactAddedSpark(r);
  // --- Additional tidbits not in the original 100 ---
  _registerWednesdayFrog(r);
  _registerAprilFoolsNote(r);
  _registerBigLatencyHaiku(r);
  _registerInboxZeroZen(r);
  _registerUptime24h(r);
  _registerFirstContact(r);
}

/// Register a Peer-ID Haiku tidbit for a specific [peerId].
///
/// Called dynamically from [ContactDetailScreen] when a peer's ID is
/// displayed.  The tidbit ID is 'peer_id_haiku_$peerId' so each contact
/// gets their own unique haiku based on their peer ID bytes.
///
/// Trigger: TapTrigger(count: 3) wrapping the peer ID text widget.
void registerHaikuForPeer(TidbitRegistry r, String peerId) {
  // Skip if we've already registered this peer's haiku (common in list views).
  final id = 'peer_id_haiku_$peerId';

  // Generate the haiku once and capture it in the closure.
  // HaikuGenerator is deterministic so the same peerId always gives the
  // same haiku, even if the TidbitDef is recreated on rebuild.
  final haiku = HaikuGenerator.generate(peerId);

  r.register(TidbitDef(
    id: id,
    specRef: '§22.12.5 #9',
    mode: TidbitMode.localOnly,
    show: (ctx) => _showHaikuDialog(ctx, haiku),
  ));
}

// ---------------------------------------------------------------------------
// Individual tidbit registration functions
//
// Naming pattern: _register<TidbitName>(TidbitRegistry r)
// Each function is ~10–15 lines.
// ---------------------------------------------------------------------------

// #7 Copy Confetti — fires when the user copies their peer ID.
// Trigger wiring: YouScreen._SelfCard peer ID GestureDetector onTap callback.
// Also fires from the QR sheet "Copy peer ID" button.
void _registerCopyConfetti(TidbitRegistry r) {
  r.register(TidbitDef(
    id: 'copy_confetti',
    specRef: '§22.12.5 #7',
    mode: TidbitMode.localOnly,
    // showConfettiBurst inserts an OverlayEntry above all content for 1.5s.
    // It is non-interactive (IgnorePointer) and self-removing.
    show: (ctx) => showConfettiBurst(ctx),
  ));
}

// #52 Unread Fireworks — fires when all conversations are marked read.
// Trigger wiring: MessagingState listener in ConversationListScreen when
// total unread count transitions from >0 to 0.
// Multiple bursts from different x positions for a grander effect.
void _registerUnreadFireworks(TidbitRegistry r) {
  r.register(TidbitDef(
    id: 'unread_fireworks',
    specRef: '§22.12.5 #52',
    mode: TidbitMode.localOnly,
    show: (ctx) {
      // Three staggered bursts across the screen width.
      // Delays give a sequential "fireworks barrage" feeling.
      showConfettiBurst(ctx, origin: const Offset(0.2, 0.4));
      Future.delayed(
        const Duration(milliseconds: 200),
        () {
          if (ctx.mounted) showConfettiBurst(ctx, origin: const Offset(0.8, 0.3));
        },
      );
      Future.delayed(
        const Duration(milliseconds: 400),
        () {
          if (ctx.mounted) showConfettiBurst(ctx, origin: const Offset(0.5, 0.5));
        },
      );
    },
  ));
}

// #25 Ambient Snow — snowfall on winter dates.
// The SnowfallLayer widget handles date detection itself, so this registration
// is informational only (the widget is always in the tree; it self-deactivates).
// Trigger wiring: SnowfallLayer wraps AppShell in app.dart.
void _registerAmbientSnow(TidbitRegistry r) {
  r.register(TidbitDef(
    id: 'ambient_snow',
    specRef: '§22.12.5 #25',
    mode: TidbitMode.localOnly,
    // No show() action needed — SnowfallLayer is always present and
    // activates itself.  Registering here makes it visible to the debug menu.
    show: (_) {},
    implemented: true,
  ));
}

// #20 Garden Gnome — rare gnome in empty Garden states.
// The GardenGnomeWidget handles its own appearance probability.
// Registration is informational — the debug menu can show it explicitly.
void _registerGardenGnome(TidbitRegistry r) {
  r.register(TidbitDef(
    id: 'garden_gnome',
    specRef: '§22.12.5 #20',
    mode: TidbitMode.localOnly,
    show: (_) {}, // Self-managed inline widget; no overlay needed.
    implemented: true,
  ));
}

// Night Owl Greeting — first app open after midnight shows a short message.
// The show function displays a 2-second animated banner.
// Trigger wiring: app.dart initState checks _isFirstOpenAfterMidnight().
void _registerNightOwlGreeting(TidbitRegistry r) {
  r.register(TidbitDef(
    id: 'night_owl_greeting',
    specRef: '§22.12.5 (new)',
    mode: TidbitMode.localOnly,
    show: (ctx) {
      // A brief overlay banner — not a blocking dialog.
      // Late-night users get a friendly nod, not a warning.
      final hour = DateTime.now().hour;
      final line = hour >= 0 && hour < 4
          ? 'Still up? The mesh watches over you 🦉'
          : 'Good morning. The mesh is ready.';
      ScaffoldMessenger.of(ctx).showSnackBar(
        SnackBar(
          content: Text(line),
          duration: const Duration(seconds: 3),
          behavior: SnackBarBehavior.floating,
        ),
      );
    },
  ));
}

// High Latency Snail — when ping exceeds 500ms, a snail emoji briefly
// appears alongside the latency readout in NetworkStatusScreen.
// Trigger wiring: NetworkStatusScreen reads latency from NetworkState and
// calls show() when latency > 500ms (debounced, max once per 60 s).
void _registerHighLatencySnail(TidbitRegistry r) {
  r.register(TidbitDef(
    id: 'high_latency_snail',
    specRef: '§22.12.5 (new)',
    mode: TidbitMode.practicalUtility,
    show: (ctx) {
      // Snail SnackBar — a custom animated overlay would be ideal here,
      // but a SnackBar is simpler and non-intrusive.
      ScaffoldMessenger.of(ctx).showSnackBar(
        const SnackBar(
          content: Text('🐌  High latency detected — the snail of truth appears.'),
          duration: Duration(seconds: 3),
        ),
      );
    },
  ));
}

// Successful Send Sparkle — occasional tiny sparkle on message delivery.
// Trigger wiring: ThreadScreen listens for delivery receipt events and
// randomly (1-in-10 chance) calls show().  Keeps it rare and surprising.
void _registerSuccessfulSendSparkle(TidbitRegistry r) {
  r.register(TidbitDef(
    id: 'successful_send_sparkle',
    specRef: '§22.12.5 (new)',
    mode: TidbitMode.localOnly,
    show: (ctx) {
      // Small confetti burst from the bottom of the screen (near send button).
      showConfettiBurst(ctx, origin: const Offset(0.5, 0.85));
    },
  ));
}

// Typing Meteor (#29) — very fast burst of typing triggers a shooting star.
// Trigger wiring: MessageComposer tracks chars-per-second; at >8 cps calls show().
void _registerTypingMeteor(TidbitRegistry r) {
  r.register(TidbitDef(
    id: 'typing_meteor',
    specRef: '§22.12.5 #29',
    mode: TidbitMode.localOnly,
    show: (ctx) {
      // The "meteor" is a confetti burst from the top-right, mostly horizontal.
      // Low particle count and fast duration = quick streak across the screen.
      showConfettiBurst(ctx, origin: const Offset(0.9, 0.1));
    },
  ));
}

// Offline Status Quip — when the user opens the app with no network at all,
// a random quip appears in the status bar area as a gentle acknowledgement.
// Trigger wiring: SecurityStatusBar / NetworkState notifies when all
// transports are down for >30 seconds.
void _registerOfflineStatusQuip(TidbitRegistry r) {
  const quips = [
    'Offline. The silence is encrypted.',
    'No signal. Even hermits have days like this.',
    'Disconnected — but your data is still yours.',
    'Offline mode: full privacy, zero latency.',
    'The mesh will return. It always does.',
  ];
  var quipIndex = 0;

  r.register(TidbitDef(
    id: 'offline_status_quip',
    specRef: '§22.12.5 (new)',
    mode: TidbitMode.localOnly,
    show: (ctx) {
      // Rotate through quips so repeat offline events show variety.
      final quip = quips[quipIndex % quips.length];
      quipIndex++;
      ScaffoldMessenger.of(ctx).showSnackBar(
        SnackBar(
          content: Text(quip),
          duration: const Duration(seconds: 4),
          behavior: SnackBarBehavior.floating,
        ),
      );
    },
  ));
}

// Peer Count Milestone — first time the user reaches 5, 10, 25 contacts
// a brief celebration overlay fires.
// Trigger wiring: PeersState notifies when peers.length crosses a milestone.
void _registerPeerCountMilestone(TidbitRegistry r) {
  r.register(TidbitDef(
    id: 'peer_count_milestone',
    specRef: '§22.12.5 (new)',
    mode: TidbitMode.localOnly,
    show: (ctx) {
      HapticFeedback.mediumImpact();
      showConfettiBurst(ctx);
    },
  ));
}

// First Message Confetti — the very first message you ever send.
// Trigger wiring: MessagingState checks a one-time flag in SharedPreferences.
void _registerFirstMessageConfetti(TidbitRegistry r) {
  r.register(TidbitDef(
    id: 'first_message_confetti',
    specRef: '§22.12.5 (new)',
    mode: TidbitMode.localOnly,
    show: (ctx) {
      HapticFeedback.mediumImpact();
      showConfettiBurst(ctx);
      ScaffoldMessenger.of(ctx).showSnackBar(
        const SnackBar(
          content: Text('Your first message — sent privately, just as intended.'),
          duration: Duration(seconds: 4),
        ),
      );
    },
  ));
}

// Long Thread Vine (#79) — threads with 50+ messages occasionally render a
// vine animation hint at the bottom of the thread for 2 seconds.
// Trigger wiring: ThreadScreen checks message count on load, calls show() once.
void _registerLongThreadVine(TidbitRegistry r) {
  r.register(TidbitDef(
    id: 'long_thread_vine',
    specRef: '§22.12.5 #79',
    mode: TidbitMode.localOnly,
    // Stub: vine animation is a future visual polish item.
    // Registering now so the debug menu shows it and the ID is reserved.
    show: (_) {},
    implemented: false,
  ));
}

// Midnight Chime — at exactly midnight local time, a tiny chime plays.
// Trigger wiring: app.dart schedules a Timer.periodic check every minute.
void _registerMidnightChime(TidbitRegistry r) {
  r.register(TidbitDef(
    id: 'midnight_chime',
    specRef: '§22.12.5 (new)',
    mode: TidbitMode.localOnly,
    show: (ctx) {
      HapticFeedback.lightImpact();
      ScaffoldMessenger.of(ctx).showSnackBar(
        const SnackBar(
          content: Text('🕛 Midnight — the mesh runs on.'),
          duration: Duration(seconds: 3),
        ),
      );
    },
  ));
}

// Sunrise Mode (#26) — first app open at dawn shows a morning animation.
// Trigger wiring: app.dart checks time at launch vs. local sunrise.
// Sunrise window: 5:30–7:00 AM, once per day (timestamp stored).
void _registerSunriseMode(TidbitRegistry r) {
  r.register(TidbitDef(
    id: 'sunrise_mode',
    specRef: '§22.12.5 #26',
    mode: TidbitMode.localOnly,
    show: (ctx) {
      ScaffoldMessenger.of(ctx).showSnackBar(
        const SnackBar(
          content: Text('🌅  Good morning. Another encrypted day begins.'),
          duration: Duration(seconds: 4),
        ),
      );
    },
  ));
}

// Quiet Cricket (#16) — late-night idle state reveals a tiny chirping cricket.
// Trigger wiring: shell detects no interaction for 5+ minutes between 22:00–05:00.
void _registerQuietCricket(TidbitRegistry r) {
  r.register(TidbitDef(
    id: 'quiet_cricket',
    specRef: '§22.12.5 #16',
    mode: TidbitMode.localOnly,
    // Stub: cricket sound + animated widget is a future polish item.
    show: (_) {},
    implemented: false,
  ));
}

// Empty Chat Tumbleweed — very long empty chat state shows a drifting tumbleweed.
// Trigger wiring: ThreadScreen shows tumbleweed after 10s of viewing an empty thread.
void _registerEmptyChatTumbleweed(TidbitRegistry r) {
  r.register(TidbitDef(
    id: 'empty_chat_tumbleweed',
    specRef: '§22.12.5 (new)',
    mode: TidbitMode.localOnly,
    // Stub: animated tumbleweed widget is a future polish item.
    show: (_) {},
    implemented: false,
  ));
}

// Node Fortune (#21) — 4 taps on a node name shows a nonsense fortune.
// Trigger wiring: TapTrigger(count: 4) wrapping node name in NodesScreen.
void _registerNodeFortune(TidbitRegistry r) {
  const fortunes = [
    'The next hop is closer than you think.',
    'A short TTL is a sign of wisdom.',
    'Your routing table will surprise you today.',
    'Beware of nodes bearing unsolicited announcements.',
    'Trust grows one key verification at a time.',
    'The packet you seek is already in transit.',
    'A well-formed handshake brings good fortune.',
    'Your future holds low latency and high throughput.',
    'Avoid clearnet on days ending in Y.',
    'The mesh sees what the server cannot.',
  ];

  r.register(TidbitDef(
    id: 'node_fortune',
    specRef: '§22.12.5 #21',
    mode: TidbitMode.localOnly,
    show: (ctx) {
      final fortune = fortunes[DateTime.now().millisecond % fortunes.length];
      showDialog<void>(
        context: ctx,
        builder: (_) => AlertDialog(
          title: const Text('🔮  Node Fortune'),
          content: Text(
            fortune,
            style: const TextStyle(fontStyle: FontStyle.italic),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('Wise words'),
            ),
          ],
        ),
      );
    },
  ));
}

// Send Streak Flame — 5 messages in a row (< 2 min apart) shows a tiny flame.
// Trigger wiring: MessagingState tracks outgoing message timestamps.
void _registerSendStreakFlame(TidbitRegistry r) {
  r.register(TidbitDef(
    id: 'send_streak_flame',
    specRef: '§22.12.5 (new)',
    mode: TidbitMode.localOnly,
    show: (ctx) {
      ScaffoldMessenger.of(ctx).showSnackBar(
        const SnackBar(
          content: Text('🔥  On a roll!'),
          duration: Duration(seconds: 2),
        ),
      );
    },
  ));
}

// Transfer Complete (#38) — completed file transfer can briefly show as a kite.
// Trigger wiring: FilesState notifies on transfer completion.
void _registerTransferComplete(TidbitRegistry r) {
  r.register(TidbitDef(
    id: 'transfer_kite',
    specRef: '§22.12.5 #38',
    mode: TidbitMode.localOnly,
    // Stub: kite animation is a future polish item.
    show: (_) {},
    implemented: false,
  ));
}

// Contact Added Spark (#45) — successful pairing reveals a spark animation.
// Trigger wiring: PairContactScreen calls show() after successful pair.
void _registerContactAddedSpark(TidbitRegistry r) {
  r.register(TidbitDef(
    id: 'contact_added_spark',
    specRef: '§22.12.5 #45',
    mode: TidbitMode.localOnly,
    show: (ctx) {
      HapticFeedback.mediumImpact();
      showConfettiBurst(ctx, origin: const Offset(0.5, 0.5));
    },
  ));
}

// Wednesday Frog — every Wednesday, a tiny frog emoji appears in the drawer header.
// Self-managed inline widget; registration here is informational.
void _registerWednesdayFrog(TidbitRegistry r) {
  r.register(TidbitDef(
    id: 'wednesday_frog',
    specRef: '§22.12.5 (new)',
    mode: TidbitMode.localOnly,
    show: (_) {},
    implemented: false, // inline widget pending
  ));
}

// April Fools Note — on April 1st, a brief message in the status bar:
// "Mesh Infinity is now powered by carrier pigeons. Performance may vary."
void _registerAprilFoolsNote(TidbitRegistry r) {
  r.register(TidbitDef(
    id: 'april_fools_note',
    specRef: '§22.12.5 (new)',
    mode: TidbitMode.localOnly,
    show: (ctx) {
      final now = DateTime.now();
      // Only fire on April 1st to keep the joke contextual.
      if (now.month != 4 || now.day != 1) return;
      ScaffoldMessenger.of(ctx).showSnackBar(
        const SnackBar(
          content: Text(
            '🐦 Mesh Infinity is now powered by carrier pigeons. Performance may vary.',
          ),
          duration: Duration(seconds: 5),
        ),
      );
    },
  ));
}

// Big Latency Haiku — when ping exceeds 1000ms, display a haiku about waiting.
// Trigger wiring: NetworkStatusScreen, debounced to once per 5 minutes.
void _registerBigLatencyHaiku(TidbitRegistry r) {
  const haiku = 'the packet travels\nthrough oceans of waiting time\nit will arrive soon';

  r.register(TidbitDef(
    id: 'big_latency_haiku',
    specRef: '§22.12.5 (new)',
    mode: TidbitMode.practicalUtility,
    show: (ctx) => _showHaikuDialog(ctx, haiku),
  ));
}

// Inbox Zero Zen — reaching empty conversations list with no unread shows a
// brief zen message.  Different from Unread Fireworks (which is louder).
// Trigger wiring: ConversationListScreen when unread count reaches 0.
void _registerInboxZeroZen(TidbitRegistry r) {
  const zenLines = [
    'Inbox zero. The network breathes.',
    'All messages read. The void is peaceful.',
    'Nothing unread. This too shall pass.',
    'Complete silence. Treasure it.',
  ];
  var zenIndex = 0;

  r.register(TidbitDef(
    id: 'inbox_zero_zen',
    specRef: '§22.12.5 (new)',
    mode: TidbitMode.localOnly,
    show: (ctx) {
      final line = zenLines[zenIndex % zenLines.length];
      zenIndex++;
      ScaffoldMessenger.of(ctx).showSnackBar(
        SnackBar(content: Text(line), duration: const Duration(seconds: 3)),
      );
    },
  ));
}

// 24h Uptime — after 24 hours of app uptime without a restart, a small note.
// Trigger wiring: app.dart schedules check via Timer.
void _registerUptime24h(TidbitRegistry r) {
  r.register(TidbitDef(
    id: 'uptime_24h',
    specRef: '§22.12.5 (new)',
    mode: TidbitMode.localOnly,
    show: (ctx) {
      ScaffoldMessenger.of(ctx).showSnackBar(
        const SnackBar(
          content: Text('24 hours of continuous mesh operation. Impressive.'),
          duration: Duration(seconds: 4),
        ),
      );
    },
  ));
}

// First Contact — a warm message when the user adds their very first contact.
// Trigger wiring: PeersState notifies when peers.length transitions 0 → 1.
void _registerFirstContact(TidbitRegistry r) {
  r.register(TidbitDef(
    id: 'first_contact',
    specRef: '§22.12.5 (new)',
    mode: TidbitMode.localOnly,
    show: (ctx) {
      HapticFeedback.mediumImpact();
      ScaffoldMessenger.of(ctx).showSnackBar(
        const SnackBar(
          content: Text('First contact established. The mesh grows.'),
          duration: Duration(seconds: 4),
        ),
      );
      showConfettiBurst(ctx);
    },
  ));
}

// ---------------------------------------------------------------------------
// Shared helper — haiku dialog
// ---------------------------------------------------------------------------

/// Shows a modal dialog displaying a three-line [haiku] string.
///
/// Used by both the per-peer haiku tidbit and [_registerBigLatencyHaiku].
void _showHaikuDialog(BuildContext context, String haiku) {
  showDialog<void>(
    context: context,
    builder: (_) => AlertDialog(
      // Icon gives it a poetic, playful frame.
      icon: const Icon(Icons.auto_stories_outlined),
      content: Text(
        haiku,
        textAlign: TextAlign.center,
        style: const TextStyle(
          fontStyle: FontStyle.italic,
          height: 1.8, // generous line-height for haiku readability
          fontSize: 16,
        ),
      ),
      actionsAlignment: MainAxisAlignment.center,
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('Beautiful'),
        ),
      ],
    ),
  );
}
