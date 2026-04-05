//! KCP Reliability Sublayer (§5.31)
//!
//! KCP is a fast, reliable ARQ protocol that sits inside the WireGuard
//! encryption envelope.  It provides:
//!
//! - Selective retransmission (only lost packets are retransmitted)
//! - Fast retransmit after 2 out-of-order ACKs
//! - 1.5× RTO backoff (vs TCP's 2×) — roughly 3× faster recovery under loss
//! - Configurable ACK behavior
//! - No congestion control (`nc=1`) — mesh routing layer handles this
//!
//! ## Stack position
//!
//! ```text
//! Application / mesh protocol
//!         ↓
//!     KCP (reliability, ordering, retransmission)  ← this module
//!         ↓
//!   WireGuard (encryption, peer authentication)
//!         ↓
//!   Obfuscation layer (§5.26, if active)
//!         ↓
//!       UDP / network
//! ```
//!
//! ## Mesh default configuration
//!
//! | Parameter  | Value | Reason |
//! |-----------|-------|--------|
//! | nodelay   | 1     | RTO minimum 30 ms instead of 100 ms |
//! | interval  | 20 ms | internal update tick |
//! | resend    | 2     | fast retransmit after 2 out-of-order ACKs |
//! | nc        | 1     | congestion control disabled — routing layer handles this |
//! | mtu       | 1400  | default path MTU |
//! | snd_wnd   | 128   | send window (raised from KCP default 32) |
//! | rcv_wnd   | 128   | receive window |
//! | dead_link | 20    | declare dead after 20 consecutive unacked retransmits |
//!
//! ## Session lifecycle
//!
//! KCP sessions are created and destroyed with their WireGuard sessions.
//! The conversation ID (`conv`) is derived from the first 4 bytes of the
//! WireGuard session key so both peers compute it independently.
//! When `dead_link` is reached the WireGuard session is torn down and a new
//! handshake begins.

use std::collections::VecDeque;

// ────────────────────────────────────────────────────────────────────────────
// Protocol constants
// ────────────────────────────────────────────────────────────────────────────

/// KCP command: data push — carries a segment of user data.
/// Wire value 81 (0x51) per the KCP protocol spec; values differ from TCP's
/// SYN/ACK/FIN to avoid confusion when debugging mixed-protocol captures.
const CMD_PUSH: u8 = 81;

/// KCP command: selective ACK — acknowledges receipt of a specific segment SN.
/// Unlike TCP's cumulative ACK, KCP ACKs each segment individually so that
/// only genuinely lost segments need retransmission.
const CMD_ACK: u8 = 82;

/// KCP command: window probe request — sent when the remote window is zero.
/// Prevents deadlock: if the responder's last window update was lost, the
/// sender would never learn the window has re-opened without this probe.
const CMD_WASK: u8 = 83;

/// KCP command: window size advertisement — reply to a WASK probe.
/// The remote window size is carried in the `wnd` header field of this segment.
const CMD_WINS: u8 = 84;

/// Fixed overhead per KCP segment header (bytes).
///
/// Wire layout (all little-endian):
///   conv(4) + cmd(1) + frg(1) + wnd(2) + ts(4) + sn(4) + una(4) + len(4) = 24
/// This is subtracted from `mtu` to get the maximum segment size (MSS).
pub const OVERHEAD: usize = 24;

/// Mesh Infinity default configuration.
///
/// MTU set to 1400 to fit inside WireGuard's 1420-byte inner MTU after the
/// KCP header (24 bytes), leaving margin for path MTU variance.
pub const DEFAULT_MTU: usize = 1400;

/// Send and receive windows are 4x the KCP default of 32 to accommodate
/// the higher-latency paths common in mesh and overlay networks.  At 128
/// segments and 20ms intervals, this supports ~175 KB in-flight data.
pub const DEFAULT_SND_WND: u16 = 128;
pub const DEFAULT_RCV_WND: u16 = 128;

/// Nodelay mode enables a 30ms minimum RTO (vs 100ms in normal mode),
/// which is critical for interactive messaging over mesh networks where
/// a 100ms floor would unnecessarily amplify tail latency.
pub const DEFAULT_NODELAY: bool = true;

/// 20ms flush interval matches the WireGuard rekey timer granularity and
/// keeps KCP responsive without excessive CPU wake-ups on battery devices.
pub const DEFAULT_INTERVAL_MS: u32 = 20;

/// Fast retransmit after 2 out-of-order ACKs (NACK-equivalent).  Lower
/// values (e.g. 1) cause spurious retransmits on reordered paths; higher
/// values delay recovery.  2 is the same trade-off TCP SACK uses.
pub const DEFAULT_FAST_RESEND: u32 = 2;

/// Declare a link dead after 20 consecutive unacked retransmissions.
/// At 1.5x backoff from a 200ms initial RTO, this takes roughly 40 seconds
/// of total silence before triggering a WireGuard session teardown.
pub const DEFAULT_DEAD_LINK: u32 = 20;

/// Minimum RTO in nodelay mode (ms).
/// 30ms is roughly 2× the one-way latency of a local mesh hop, ensuring
/// we retransmit fast without firing on every slightly-delayed ACK.
const RTO_NDL: u32 = 30;

/// Minimum RTO in normal mode (ms) — used only when nodelay is disabled.
const RTO_MIN: u32 = 100;

/// Initial RTO before any RTT samples (ms).  Conservative enough to avoid
/// spurious retransmits during the first exchange, but low enough for
/// responsive mesh startup.
const RTO_DEF: u32 = 200;

/// RTO ceiling (ms).  Prevents exponential backoff from growing unboundedly
/// on very lossy links — beyond 5 seconds the dead_link counter should be
/// catching the problem anyway.
const RTO_MAX: u32 = 5000;

/// 1.5× backoff (stored as 3/2 integer fraction to avoid floating point).
/// TCP uses 2×; KCP's 1.5× recovers from isolated losses ~33% faster,
/// which matters for short mesh messages that would otherwise stall.
const RTO_BACKOFF_NUM: u32 = 3;
const RTO_BACKOFF_DEN: u32 = 2;

/// Bitflags controlling which probe messages to send in the next flush.
/// ASK_SEND triggers a CMD_WASK (request the peer's window); ASK_TELL
/// triggers a CMD_WINS (advertise our window).  Both are cleared after flush.
const ASK_SEND: u32 = 1;
const ASK_TELL: u32 = 2;

/// Initial zero-window probe delay (ms).  When the remote advertises a
/// zero receive window, we wait this long before sending a CMD_WASK probe.
/// 7 seconds is generous enough for the peer to drain its queue under
/// normal conditions while still detecting stuck peers in reasonable time.
const PROBE_INIT_MS: u32 = 7000;

/// Maximum probe interval (ms).  Probes use 1.5× exponential backoff
/// starting from PROBE_INIT_MS, capped here at 2 minutes.  Beyond this,
/// the dead_link mechanism should be catching the failure.
const PROBE_LIMIT_MS: u32 = 120_000;

// ────────────────────────────────────────────────────────────────────────────
// Internal segment
// ────────────────────────────────────────────────────────────────────────────

/// Internal representation of a single KCP segment, used for both send and
/// receive paths.  The wire layout of the header (24 bytes) is defined above
/// in `OVERHEAD`; the `encode` method serialises it in little-endian order.
///
/// Fragment numbering (`frg`) counts DOWN from `total_fragments - 1` to 0,
/// so the receiver can detect the final fragment (frg == 0) and begin
/// reassembly without knowing the total count in advance.
#[derive(Clone)]
struct Segment {
    /// Conversation ID — shared between both peers, derived from the
    /// WireGuard session key.  Segments with a mismatched conv are silently
    /// dropped, providing a lightweight demux for multiplexed channels.
    conv: u32,
    cmd: u8,
    /// Fragment index, counting down.  0 = last (or only) fragment of a
    /// message.  This design lets `recv()` detect completeness by peeking
    /// at the first queued segment's frg without buffering metadata.
    frg: u8,
    /// Advertised receive window (in segments).  Piggybacked on every
    /// outgoing segment so the peer always has a recent window estimate
    /// without needing a dedicated window-update message.
    wnd: u16,
    /// Timestamp (ms) when this segment was last sent.  Used by the
    /// receiver to compute RTT: `rtt = current - ack.ts`.
    ts: u32,
    /// Sequence number.  Monotonically increasing per conversation,
    /// wrapping at u32::MAX.  All comparisons use wrapping arithmetic
    /// to handle the wraparound correctly.
    sn: u32,
    /// Cumulative ACK: "I have received all segments with sn < una".
    /// Piggybacked on every outgoing segment, allowing the sender to
    /// bulk-release segments from `snd_buf` without individual ACKs.
    una: u32,
    data: Vec<u8>,

    // --- Retransmission state (used only for segments in snd_buf) ---
    /// Absolute timestamp (ms) when the next retransmission is due.
    resendts: u32,
    /// Per-segment RTO, initialised from the global `rx_rto` and then
    /// backed off by 1.5× on each timeout retransmit.
    rto: u32,
    /// Number of out-of-order ACKs past this segment's SN.  When this
    /// exceeds `fast_resend`, the segment is retransmitted immediately
    /// without waiting for the RTO timer — the "fast retransmit" path.
    fastack: u32,
    /// Transmission count.  Incremented each time the segment is sent
    /// (including the initial transmission).  Drives the dead_link counter.
    xmit: u32,
}

impl Segment {
    fn new_data(conv: u32, sn: u32, frg: u8, data: Vec<u8>) -> Self {
        Segment {
            conv,
            cmd: CMD_PUSH,
            frg,
            wnd: 0,
            ts: 0,
            sn,
            una: 0,
            data,
            resendts: 0,
            rto: RTO_DEF,
            fastack: 0,
            xmit: 0,
        }
    }

    /// Serialize this segment's header + payload into `buf` in the KCP wire
    /// format.  All multi-byte fields are little-endian.  Multiple segments
    /// may be packed into a single UDP datagram (up to MTU), which is why
    /// `buf` is appended to rather than replaced.
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.conv.to_le_bytes());
        buf.push(self.cmd);
        buf.push(self.frg);
        buf.extend_from_slice(&self.wnd.to_le_bytes());
        buf.extend_from_slice(&self.ts.to_le_bytes());
        buf.extend_from_slice(&self.sn.to_le_bytes());
        buf.extend_from_slice(&self.una.to_le_bytes());
        buf.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.data);
    }
}

// ────────────────────────────────────────────────────────────────────────────
// KCP state
// ────────────────────────────────────────────────────────────────────────────

/// Callback type used to deliver KCP frames to the underlying transport.
type KcpOutputFn = Box<dyn FnMut(&[u8]) + Send + 'static>;

/// A KCP conversation providing reliable, ordered delivery over an unreliable
/// channel.
///
/// The caller provides an `output` callback that delivers KCP frames to the
/// underlying transport (WireGuard).  Bytes arriving from the peer are fed
/// into [`KcpState::input`]; assembled messages are retrieved via
/// [`KcpState::recv`].
pub struct KcpState {
    /// Conversation ID — first 4 bytes of the WireGuard session key.
    conv: u32,

    // MTU / window
    mtu: usize,
    /// Local send window cap.
    snd_wnd: u16,
    /// Local receive window cap.
    rcv_wnd: u16,
    /// Remote peer's last advertised receive window.  Limits how many
    /// segments we can have in-flight to prevent overrunning the peer.
    rmt_wnd: u16,
    /// Congestion window — unused when `nocwnd` is true (mesh default),
    /// because mesh routing handles congestion at a higher layer.
    cwnd: u16,

    // Sequence numbers
    /// Oldest unacknowledged sequence number (send-side cumulative ACK).
    snd_una: u32,
    /// Next sequence number to assign to an outgoing segment.
    snd_nxt: u32,
    /// Next expected receive sequence number.  Segments arriving with
    /// sn == rcv_nxt are delivered immediately; others go to rcv_buf.
    rcv_nxt: u32,

    // Queues — the two-stage pipeline (queue → buf) separates flow control
    // from the application interface: `send()` pushes to snd_queue without
    // blocking; `flush()` moves segments to snd_buf up to the cwnd limit.
    snd_queue: VecDeque<Segment>,
    snd_buf: VecDeque<Segment>,
    /// Fully ordered, ready-for-consumption segments.  `recv()` reads here.
    rcv_queue: VecDeque<Segment>,
    /// Out-of-order receive buffer, sorted by SN.  Segments are promoted
    /// to rcv_queue once the gap (rcv_nxt) is filled.
    rcv_buf: VecDeque<Segment>,

    /// ACKs accumulated during `input()`, flushed as CMD_ACK segments
    /// in the next `flush()`.  Batching ACKs reduces per-segment overhead
    /// on high-throughput links.
    acklist: Vec<(u32, u32)>, // (sn, ts) pairs

    // RTT estimation — Jacobson/Karels algorithm (same as TCP RFC 6298),
    // producing a smoothed RTT and a variance estimate that drive the
    // retransmission timeout.
    rx_srtt: u32,
    rx_rttval: u32,
    rx_rto: u32,
    rx_minrto: u32,

    // Timing — all values are monotonic milliseconds, wrapping-safe.
    current: u32,
    interval: u32,
    /// Next scheduled flush time.  `update()` calls `flush()` when
    /// `current >= ts_flush`.
    ts_flush: u32,

    // Probing — handles the zero-window deadlock scenario (§5.31).
    probe: u32,
    ts_probe: u32,
    probe_wait: u32,

    // Dead-link detection — if the same segment is retransmitted
    // `dead_link` times without any ACK, the link is declared dead
    // and the WireGuard session should be torn down.
    dead_link: u32,
    /// Number of consecutive unacknowledged retransmissions.
    pub xmit_count: u32,

    // Config
    /// Minimum out-of-order ACK count to trigger fast retransmit.
    fast_resend: u32,
    /// When true, congestion window is bypassed — send rate is limited
    /// only by `snd_wnd` and `rmt_wnd`.  Enabled by default because the
    /// mesh routing layer performs its own congestion management.
    nocwnd: bool,

    /// Callback invoked with assembled KCP frame bytes ready for the
    /// WireGuard layer.  Called from within `flush()`.
    output: KcpOutputFn,

    /// Set to `true` when `dead_link` threshold is reached.
    pub dead: bool,
}

impl KcpState {
    /// Create a new KCP state with mesh-default configuration.
    ///
    /// `conv` — conversation ID derived from `wg_session_key[0..4]` as LE u32.
    /// `output` — closure that writes KCP frame bytes to WireGuard.
    pub fn new(conv: u32, output: impl FnMut(&[u8]) + Send + 'static) -> Self {
        KcpState {
            conv,
            mtu: DEFAULT_MTU,
            snd_wnd: DEFAULT_SND_WND,
            rcv_wnd: DEFAULT_RCV_WND,
            rmt_wnd: DEFAULT_RCV_WND,
            cwnd: 0,
            snd_una: 0,
            snd_nxt: 0,
            rcv_nxt: 0,
            snd_queue: VecDeque::new(),
            snd_buf: VecDeque::new(),
            rcv_queue: VecDeque::new(),
            rcv_buf: VecDeque::new(),
            acklist: Vec::new(),
            rx_srtt: 0,
            rx_rttval: 0,
            rx_rto: RTO_DEF,
            rx_minrto: if DEFAULT_NODELAY { RTO_NDL } else { RTO_MIN },
            current: 0,
            interval: DEFAULT_INTERVAL_MS,
            ts_flush: DEFAULT_INTERVAL_MS,
            probe: 0,
            ts_probe: 0,
            probe_wait: 0,
            dead_link: DEFAULT_DEAD_LINK,
            xmit_count: 0,
            fast_resend: DEFAULT_FAST_RESEND,
            nocwnd: true,
            output: Box::new(output),
            dead: false,
        }
    }

    /// Derive a `conv` ID from a 32-byte WireGuard session key.
    pub fn conv_from_wg_key(key: &[u8]) -> u32 {
        if key.len() < 4 {
            return 0;
        }
        u32::from_le_bytes([key[0], key[1], key[2], key[3]])
    }

    /// Queue `data` for reliable delivery.
    ///
    /// The data is split into MTU-sized fragments and added to `snd_queue`.
    /// Actual transmission happens in the next [`flush`] call.
    ///
    /// Returns the number of bytes queued, or `Err` if the send queue is full.
    pub fn send(&mut self, data: &[u8]) -> Result<usize, &'static str> {
        if data.is_empty() {
            return Err("empty send");
        }
        let mss = self.mtu - OVERHEAD;
        let count = data.len().div_ceil(mss);
        // Fragment index is a u8, so maximum 255 fragments.  At 1376 bytes
        // per MSS (1400 MTU - 24 overhead), this limits a single KCP message
        // to ~351 KB, which is sufficient for mesh control + messaging payloads.
        if count >= 256 {
            return Err("data too large");
        }
        for (i, chunk) in data.chunks(mss).enumerate() {
            // Fragment index counts down: first chunk gets (count-1), last
            // gets 0.  The receiver detects "message complete" when frg == 0.
            let frg = (count - 1 - i) as u8;
            let seg = Segment::new_data(self.conv, self.snd_nxt, frg, chunk.to_vec());
            // SN is assigned later in flush() when the segment moves from
            // snd_queue to snd_buf — this decouples queuing from flow control.
            self.snd_queue.push_back(seg);
        }
        Ok(data.len())
    }

    /// Consume the next fully-reassembled message from the receive queue.
    ///
    /// Returns `None` if no complete message is available.
    pub fn recv(&mut self) -> Option<Vec<u8>> {
        if self.rcv_queue.is_empty() {
            return None;
        }
        // Peek at frg of the first segment — 0 means single or last fragment.
        let frg = self.rcv_queue.front()?.frg as usize;
        if frg + 1 > self.rcv_queue.len() {
            return None; // incomplete
        }
        let mut out = Vec::new();
        for _ in 0..=frg {
            let seg = self.rcv_queue.pop_front()?;
            out.extend_from_slice(&seg.data);
            if seg.frg == 0 {
                break;
            }
        }
        // Recover window by moving rcv_buf → rcv_queue.
        self.move_rcv_buf();
        Some(out)
    }

    /// Feed raw bytes received from the WireGuard layer.
    ///
    /// Parses KCP headers, updates ACK/send state, and moves segments into
    /// the receive buffer.
    pub fn input(&mut self, data: &[u8]) {
        if data.len() < OVERHEAD {
            return;
        }
        let old_una = self.snd_una;
        let mut pos = 0;

        while pos + OVERHEAD <= data.len() {
            let conv = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
            if conv != self.conv {
                return;
            }
            let cmd = data[pos + 4];
            let frg = data[pos + 5];
            let wnd = u16::from_le_bytes(data[pos + 6..pos + 8].try_into().unwrap());
            let ts = u32::from_le_bytes(data[pos + 8..pos + 12].try_into().unwrap());
            let sn = u32::from_le_bytes(data[pos + 12..pos + 16].try_into().unwrap());
            let una = u32::from_le_bytes(data[pos + 16..pos + 20].try_into().unwrap());
            let len = u32::from_le_bytes(data[pos + 20..pos + 24].try_into().unwrap()) as usize;
            pos += OVERHEAD;

            if pos + len > data.len() {
                return;
            }
            let seg_data = data[pos..pos + len].to_vec();
            pos += len;

            match cmd {
                CMD_ACK => {
                    self.update_ack(self.current.wrapping_sub(ts));
                    self.process_ack(sn);
                    self.parse_una(una);
                    self.shrink_buf();
                }
                CMD_PUSH => {
                    self.rmt_wnd = wnd;
                    self.parse_una(una);
                    self.shrink_buf();
                    if sn.wrapping_sub(self.rcv_nxt) < self.rcv_wnd as u32 {
                        self.acklist.push((sn, ts));
                        self.store_segment(sn, frg, seg_data);
                    }
                }
                CMD_WASK => {
                    self.probe |= ASK_TELL;
                }
                CMD_WINS => {
                    self.rmt_wnd = wnd;
                }
                _ => {}
            }
        }

        // Fast retransmit: if snd_una advanced, check for fastack.
        if self.snd_una != old_una {
            for seg in &mut self.snd_buf {
                if self.snd_una > seg.sn {
                    seg.fastack += 1;
                }
            }
        }

        self.move_rcv_buf();
    }

    /// Flush pending ACKs, retransmissions, and queued sends.
    ///
    /// Should be called periodically (every `interval` ms) via
    /// [`update`].
    pub fn flush(&mut self) {
        let current = self.current;
        let mut buf: Vec<u8> = Vec::with_capacity(self.mtu * 3);

        // Flush ACKs.
        let wnd = self.wnd_unused();
        let acklist = std::mem::take(&mut self.acklist);
        for (sn, ts) in acklist {
            let seg = Segment {
                conv: self.conv,
                cmd: CMD_ACK,
                frg: 0,
                wnd,
                ts,
                sn,
                una: self.rcv_nxt,
                data: Vec::new(),
                resendts: 0,
                rto: 0,
                fastack: 0,
                xmit: 0,
            };
            seg.encode(&mut buf);
            if buf.len() >= self.mtu {
                (self.output)(&buf);
                buf.clear();
            }
        }

        // Window probes.
        if self.rmt_wnd == 0 {
            if self.probe_wait == 0 {
                self.probe_wait = PROBE_INIT_MS;
                self.ts_probe = current + self.probe_wait;
            } else if current >= self.ts_probe {
                self.probe_wait = (self.probe_wait * 3 / 2).clamp(PROBE_INIT_MS, PROBE_LIMIT_MS);
                self.ts_probe = current + self.probe_wait;
                self.probe |= ASK_SEND;
            }
        } else {
            self.probe_wait = 0;
            self.ts_probe = 0;
        }
        if self.probe & ASK_SEND != 0 {
            let seg = self.make_ctrl_seg(CMD_WASK);
            seg.encode(&mut buf);
        }
        if self.probe & ASK_TELL != 0 {
            let seg = self.make_ctrl_seg(CMD_WINS);
            seg.encode(&mut buf);
        }
        self.probe = 0;

        // Calculate effective cwnd.
        let cwnd = if self.nocwnd {
            self.snd_wnd.min(self.rmt_wnd)
        } else {
            self.snd_wnd.min(self.rmt_wnd).min(self.cwnd)
        } as u32;

        // Move snd_queue → snd_buf up to cwnd.
        while self.snd_nxt.wrapping_sub(self.snd_una) < cwnd {
            if let Some(mut seg) = self.snd_queue.pop_front() {
                seg.sn = self.snd_nxt;
                seg.una = self.rcv_nxt;
                seg.wnd = wnd;
                seg.ts = current;
                seg.rto = self.rx_rto;
                seg.resendts = current + seg.rto;
                seg.xmit = 0;
                seg.fastack = 0;
                self.snd_nxt = self.snd_nxt.wrapping_add(1);
                self.snd_buf.push_back(seg);
            } else {
                break;
            }
        }

        // Retransmission / fast retransmit.
        let resend = if self.fast_resend > 0 {
            self.fast_resend
        } else {
            u32::MAX
        };

        let mut need_flush = false;
        for seg in &mut self.snd_buf {
            let mut do_send = false;

            if seg.xmit == 0 {
                seg.xmit += 1;
                seg.rto = self.rx_rto;
                seg.resendts = current + seg.rto;
                do_send = true;
            } else if current >= seg.resendts {
                // Timeout retransmit.
                seg.xmit += 1;
                self.xmit_count += 1;
                if self.xmit_count >= self.dead_link {
                    self.dead = true;
                }
                // 1.5× backoff.
                seg.rto = ((seg.rto * RTO_BACKOFF_NUM) / RTO_BACKOFF_DEN).min(RTO_MAX);
                seg.resendts = current + seg.rto;
                need_flush = true;
                do_send = true;
            } else if seg.fastack >= resend {
                // Fast retransmit.
                seg.xmit += 1;
                seg.fastack = 0;
                seg.resendts = current + seg.rto;
                do_send = true;
            }

            if do_send {
                seg.ts = current;
                seg.wnd = wnd;
                seg.una = self.rcv_nxt;
                seg.encode(&mut buf);
                if buf.len() >= self.mtu {
                    (self.output)(&buf);
                    buf.clear();
                }
            }
        }
        let _ = need_flush;

        if !buf.is_empty() {
            (self.output)(&buf);
        }
    }

    /// Advance internal clock to `current_ms` and call `flush` if the
    /// interval has elapsed.
    ///
    /// `current_ms` — monotonic millisecond counter (use `std::time::Instant`
    /// or equivalent; only the relative value matters).
    pub fn update(&mut self, current_ms: u32) {
        self.current = current_ms;
        if current_ms >= self.ts_flush {
            self.ts_flush = current_ms + self.interval;
            self.flush();
        }
    }

    /// Returns the number of milliseconds until the next `update` call is
    /// needed (for scheduling the update loop).
    pub fn check(&self, current_ms: u32) -> u32 {
        if current_ms >= self.ts_flush {
            return 0;
        }
        let mut minimal = self.ts_flush - current_ms;
        for seg in &self.snd_buf {
            if current_ms < seg.resendts {
                let d = seg.resendts - current_ms;
                minimal = minimal.min(d);
            } else {
                return 0;
            }
        }
        minimal.min(self.interval)
    }

    // ──────────────────────────────────────────────────────────────────────
    // Private helpers
    // ──────────────────────────────────────────────────────────────────────

    fn wnd_unused(&self) -> u16 {
        if self.rcv_queue.len() < self.rcv_wnd as usize {
            self.rcv_wnd - self.rcv_queue.len() as u16
        } else {
            0
        }
    }

    fn make_ctrl_seg(&self, cmd: u8) -> Segment {
        Segment {
            conv: self.conv,
            cmd,
            frg: 0,
            wnd: self.wnd_unused(),
            ts: self.current,
            sn: 0,
            una: self.rcv_nxt,
            data: Vec::new(),
            resendts: 0,
            rto: 0,
            fastack: 0,
            xmit: 0,
        }
    }

    /// Jacobson/Karels RTT estimator (RFC 6298 §2).
    ///
    /// On the first sample, SRTT and RTTVAR are initialised directly.
    /// Subsequent samples use exponentially weighted moving averages:
    ///   RTTVAR = 3/4 * RTTVAR + 1/4 * |SRTT - R|
    ///   SRTT   = 7/8 * SRTT   + 1/8 * R
    ///   RTO    = SRTT + max(4 * RTTVAR, interval)
    ///
    /// The RTO is clamped between `rx_minrto` (30ms in nodelay) and
    /// `RTO_MAX` (5s) to bound both aggressive and conservative behaviour.
    fn update_ack(&mut self, rtt: u32) {
        if self.rx_srtt == 0 {
            self.rx_srtt = rtt;
            self.rx_rttval = rtt / 2;
        } else {
            let delta = rtt.abs_diff(self.rx_srtt);
            self.rx_rttval = (3 * self.rx_rttval + delta) / 4;
            self.rx_srtt = (7 * self.rx_srtt + rtt) / 8;
            if self.rx_srtt < 1 {
                self.rx_srtt = 1;
            }
        }
        let rto = self.rx_srtt + (4 * self.rx_rttval).max(self.interval);
        self.rx_rto = rto.max(self.rx_minrto).min(RTO_MAX);
    }

    /// Remove the individually-ACKed segment from the send buffer.
    /// Wrapping arithmetic ensures correct comparison even after u32 rollover.
    /// Any received ACK proves the link is alive, so the dead-link counter
    /// is reset — this prevents a single successful ACK from being negated by
    /// earlier accumulated retransmit counts.
    fn process_ack(&mut self, sn: u32) {
        if sn.wrapping_sub(self.snd_una) < self.snd_nxt.wrapping_sub(self.snd_una) {
            self.snd_buf.retain(|seg| seg.sn != sn);
            self.xmit_count = 0;
        }
    }

    /// Cumulative ACK: remove all segments with sn < una from the send buffer.
    /// The wrapping comparison `sn - una < MAX/2` is the standard technique
    /// for determining "sn is before una" in modular arithmetic.
    fn parse_una(&mut self, una: u32) {
        self.snd_buf
            .retain(|seg| seg.sn.wrapping_sub(una) < u32::MAX / 2);
    }

    /// Update snd_una to reflect the current oldest unacknowledged segment.
    /// Called after removing ACKed segments to advance the send window.
    fn shrink_buf(&mut self) {
        if let Some(seg) = self.snd_buf.front() {
            self.snd_una = seg.sn;
        } else {
            self.snd_una = self.snd_nxt;
        }
    }

    /// Insert a received data segment into the receive pipeline.
    /// In-order segments (sn == rcv_nxt) skip the out-of-order buffer
    /// entirely for zero-copy fast-path delivery.  Out-of-order segments
    /// are inserted into rcv_buf in sorted order with deduplication.
    fn store_segment(&mut self, sn: u32, frg: u8, data: Vec<u8>) {
        if sn == self.rcv_nxt {
            // Fast path: in-order delivery.
            self.rcv_nxt = sn.wrapping_add(1);
            let seg = Segment {
                conv: self.conv,
                cmd: CMD_PUSH,
                frg,
                wnd: 0,
                ts: 0,
                sn,
                una: 0,
                data,
                resendts: 0,
                rto: 0,
                fastack: 0,
                xmit: 0,
            };
            self.rcv_queue.push_back(seg);
        } else if sn.wrapping_sub(self.rcv_nxt) < self.rcv_wnd as u32 {
            // Out-of-order: store in rcv_buf sorted by sn.
            let pos = self
                .rcv_buf
                .partition_point(|s| s.sn.wrapping_sub(sn) >= u32::MAX / 2);
            // Dedup.
            if self.rcv_buf.get(pos).map(|s| s.sn) == Some(sn) {
                return;
            }
            let seg = Segment {
                conv: self.conv,
                cmd: CMD_PUSH,
                frg,
                wnd: 0,
                ts: 0,
                sn,
                una: 0,
                data,
                resendts: 0,
                rto: 0,
                fastack: 0,
                xmit: 0,
            };
            self.rcv_buf.insert(pos, seg);
        }
    }

    /// Promote contiguous segments from the out-of-order buffer (rcv_buf)
    /// to the reassembly queue (rcv_queue) once gaps are filled.  This is
    /// called after every `input()` and `recv()` to keep the pipeline flowing.
    fn move_rcv_buf(&mut self) {
        while let Some(seg) = self.rcv_buf.front() {
            if seg.sn == self.rcv_nxt {
                let seg = self.rcv_buf.pop_front().unwrap();
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                self.rcv_queue.push_back(seg);
            } else {
                break;
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn conv_from_wg_key() {
        let key = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06];
        let conv = KcpState::conv_from_wg_key(&key);
        assert_eq!(conv, 0x04030201);
    }

    #[test]
    fn conv_from_wg_key_short() {
        let key = [0x01u8, 0x02];
        assert_eq!(KcpState::conv_from_wg_key(&key), 0);
    }

    #[test]
    fn send_recv_roundtrip() {
        let sent: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let sent2 = Arc::clone(&sent);

        let mut kcp_a = KcpState::new(1, move |data: &[u8]| {
            sent.lock().unwrap().push(data.to_vec());
        });
        let received: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let recv2 = Arc::clone(&received);
        let mut kcp_b = KcpState::new(1, move |_| {});
        drop(recv2);

        // A sends.
        kcp_a.send(b"hello mesh").unwrap();
        kcp_a.flush(); // flush() directly; update(0) would not fire (ts_flush=20)

        // Feed A's output to B.
        let frames = std::mem::take(&mut *sent2.lock().unwrap());
        for frame in &frames {
            kcp_b.input(frame);
        }

        // B should have the message.
        let msg = kcp_b.recv().expect("B should have received the message");
        assert_eq!(msg, b"hello mesh");
    }

    #[test]
    fn fragment_large_message() {
        let sent: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let sent2 = Arc::clone(&sent);
        let mut kcp_a = KcpState::new(42, move |data: &[u8]| {
            sent.lock().unwrap().push(data.to_vec());
        });
        let mut kcp_b = KcpState::new(42, move |_| {});

        // Send 4000 bytes (> mtu-overhead → multiple fragments).
        let big_data: Vec<u8> = (0u8..=255).cycle().take(4000).collect();
        kcp_a.send(&big_data).unwrap();
        kcp_a.flush();

        for frame in std::mem::take(&mut *sent2.lock().unwrap()) {
            kcp_b.input(&frame);
        }

        let msg = kcp_b.recv().expect("reassembly should produce message");
        assert_eq!(msg, big_data);
    }

    #[test]
    fn dead_link_after_repeated_loss() {
        let mut kcp = KcpState::new(7, move |_| {}); // output discards all → simulates total loss
        kcp.send(b"test").unwrap();

        // Force all snd_queue into snd_buf.
        kcp.flush();
        // Simulate repeated update ticks where retransmits are triggered.
        let mut t = 0u32;
        for _ in 0..100 {
            t += 6000; // jump far into the future each tick to trigger RTO
            kcp.update(t);
            if kcp.dead {
                break;
            }
        }
        assert!(
            kcp.dead,
            "KCP should declare dead_link after enough retransmits"
        );
    }

    #[test]
    fn overhead_constant() {
        // OVERHEAD must equal the KCP header size.
        assert_eq!(OVERHEAD, 24);
    }
}
