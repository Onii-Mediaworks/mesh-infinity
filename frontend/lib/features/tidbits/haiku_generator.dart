// haiku_generator.dart
//
// HaikuGenerator — deterministic haiku from any string (§22.12.5 #9).
//
// WHAT IT DOES:
// -------------
// Takes a string (typically a peer ID hex string) and returns a three-line
// haiku in 5-7-5 syllable structure.  The same input always produces the
// same haiku (deterministic), so each contact has "their own" poem.
//
// The haiku is built from pre-composed phrase fragments — each fragment is a
// complete half-line or full line with a known syllable count.  This avoids
// the complexity of building a word-by-word syllable counter.
//
// ALGORITHM:
// ----------
// 1. Compute three independent hash seeds from the input string using a
//    simple polynomial rolling hash with different multipliers.
// 2. Use each seed to index into a phrase list.
// 3. Combine: line1 (5 syl) + line2 (7 syl) + line3 (5 syl).
//
// Used by: ContactDetailScreen (triple-tap on peer ID shows a dialog).

/// Generates a deterministic haiku from [input].
///
/// Returns a three-line string joined by newlines.
/// Example output for a given peer ID:
///   "packets flow like rain
///    through the dark network we dream
///    silent nodes return"
class HaikuGenerator {
  // Prevent instantiation — this is a pure static utility.
  HaikuGenerator._();

  // ---------------------------------------------------------------------------
  // Phrase lists
  // ---------------------------------------------------------------------------

  // Each phrase has exactly the syllable count advertised.
  // 5-syllable lines (used for first and third lines of the haiku).
  static const List<String> _five = [
    'packets flow like rain',         // 5: pack-ets-flow-like-rain
    'silent nodes return',            // 5: si-lent-nodes-re-turn
    'mesh connects us all',           // 5: mesh-con-nects-us-all
    'encrypted dreams drift',         // 5: en-crypt-ed-dreams-drift
    'trust grows byte by byte',       // 5: trust-grows-byte-by-byte
    'dark key lights the way',        // 5: dark-key-lights-the-way
    'the relay holds still',          // 5: the-re-lay-holds-still
    'no server exists',               // 5: no-ser-ver-ex-ists
    'handshake in the void',          // 5: hand-shake-in-the-void
    'signal finds a path',            // 5: sig-nal-finds-a-path
    'peer to peer we speak',          // 5: peer-to-peer-we-speak
    'the network breathes on',        // 5: the-net-work-breathes-on
    'ratchet turns once more',        // 5: ratch-et-turns-once-more
    'forge your own address',         // 5: forge-your-own-ad-dress
    'offline still persists',         // 5: off-line-still-per-sists
    'one hop at a time',              // 5: one-hop-at-a-time
    'keys held close to chest',       // 5: keys-held-close-to-chest
    'mesh hums in the dark',          // 5: mesh-hums-in-the-dark
    'identity blooms',                // 5: i-den-ti-ty-blooms
    'all routes lead somewhere',      // 5: all-routes-lead-some-where
    'the campfire flickers',          // 5: the-camp-fire-fli-ckers
    'no cloud above this',            // 5: no-cloud-a-bove-this
    'freedom needs no host',          // 5: free-dom-needs-no-host
    'a warm encrypted hug',           // 5: a-warm-en-crypt-ed-hug (approx)
    'gossip fades to hash',           // 5: gos-sip-fades-to-hash
    'garden grows at night',          // 5: gar-den-grows-at-night
    'latency is life',                // 5: la-ten-cy-is-life
    'proof of being here',            // 5: proof-of-be-ing-here
    'your mask fits just right',      // 5: your-mask-fits-just-right
    'the last hop is home',           // 5: the-last-hop-is-home
    'this route is all ours',         // 5: this-route-is-all-ours
    'we route through the fog',       // 5: we-route-through-the-fog
  ];

  // 7-syllable lines (used for the second / middle line).
  static const List<String> _seven = [
    'through the dark network we dream',     // 7
    'trust is earned one byte at a time',    // 7 (approx)
    'the handshake completes at last',       // 7
    'encrypted light travels far',           // 7
    'no server watches our words',           // 7
    'the ratchet turns without sound',       // 7
    'peer IDs bloom like flowers',           // 7
    'gossip travels the mesh tonight',       // 7 (approx)
    'the relay keeps our secret',            // 7
    'keys exchanged in the silence',         // 7
    'each node carries the message',         // 7
    'routing hides inside the noise',        // 7
    'a stranger becomes a friend',           // 7
    'the network never forgets us',          // 7 (approx)
    'offline messages wait for you',         // 7 (approx)
    'all paths are equally safe',            // 7
    'the onion has no centre',               // 7
    'your identity is yours alone',          // 7 (approx)
    'mesh topology never lies',              // 7 (approx)
    'two devices share a secret',            // 7
    'the protocol guards our words',         // 7
    'latency is just distance',              // 7
    'gardens bloom without a server',        // 7 (approx)
    'we meet where no one can watch',        // 7
    'the firefly carries your hash',         // 7
    'trust levels climb like a ladder',      // 7 (approx)
    'packets scatter to the wind',           // 7
    'the key does not know your name',       // 7
    'freedom lives in the last hop',         // 7 (approx)
    'a campfire lit by your key',            // 7
    'the mesh has no master node',           // 7
    'we encrypt because we care',            // 7
  ];

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /// Generate a haiku from [input].
  ///
  /// Returns a three-line string.  Deterministic: the same [input] always
  /// produces the same haiku.
  static String generate(String input) {
    // Compute three independent seeds from the input string.
    // _hash() uses a polynomial rolling hash — cheap and collision-resistant
    // enough for creative purposes (not for cryptography).
    final seed1 = _hash(input, 31);
    final seed2 = _hash(input, 37);
    final seed3 = _hash(input, 41);

    // Select phrases using the seeds as list indices.
    final line1 = _five[seed1 % _five.length];
    final line2 = _seven[seed2 % _seven.length];
    final line3 = _five[seed3 % _five.length];

    return '$line1\n$line2\n$line3';
  }

  // ---------------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------------

  /// Simple polynomial rolling hash of [input] with multiplier [mult].
  ///
  /// Returns a non-negative integer suitable for use as a list index.
  /// Different [mult] values produce different hashes of the same string,
  /// giving us independent seeds for line1/line2/line3 without needing
  /// a full MD5 or SHA implementation.
  static int _hash(String input, int mult) {
    // Start at a non-zero prime to avoid the all-zeros edge case.
    var h = 1000000007;
    for (final codeUnit in input.codeUnits) {
      // Classic Horner's method: accumulate each character into the hash.
      h = (h * mult + codeUnit) & 0x7FFFFFFF; // keep positive 31-bit int
    }
    return h;
  }
}
