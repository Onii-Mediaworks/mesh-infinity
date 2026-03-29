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

/// KCP command: data push.
const CMD_PUSH: u8 = 81;
/// KCP command: ACK.
const CMD_ACK: u8 = 82;
/// KCP command: window probe request.
const CMD_WASK: u8 = 83;
/// KCP command: window size advertisement.
const CMD_WINS: u8 = 84;

/// Fixed overhead per KCP segment header (bytes).
pub const OVERHEAD: usize = 24;

/// Mesh Infinity default configuration.
pub const DEFAULT_MTU: usize = 1400;
pub const DEFAULT_SND_WND: u16 = 128;
pub const DEFAULT_RCV_WND: u16 = 128;
pub const DEFAULT_NODELAY: bool = true;
pub const DEFAULT_INTERVAL_MS: u32 = 20;
pub const DEFAULT_FAST_RESEND: u32 = 2;
pub const DEFAULT_DEAD_LINK: u32 = 20;

/// Minimum RTO in nodelay mode (ms).
const RTO_NDL: u32 = 30;
/// Minimum RTO in normal mode (ms).
const RTO_MIN: u32 = 100;
/// Initial RTO (ms).
const RTO_DEF: u32 = 200;
/// Maximum RTO (ms).
const RTO_MAX: u32 = 5000;
/// RTO backoff multiplier: 1.5× (stored as 3/2).
const RTO_BACKOFF_NUM: u32 = 3;
const RTO_BACKOFF_DEN: u32 = 2;

/// Probe window ask / answer flags.
const ASK_SEND: u32 = 1;
const ASK_TELL: u32 = 2;

/// After `PROBE_INIT_MS` without an ACK from a zero-window, send a probe.
const PROBE_INIT_MS: u32 = 7000;
/// Maximum probe interval.
const PROBE_LIMIT_MS: u32 = 120_000;

// ────────────────────────────────────────────────────────────────────────────
// Internal segment
// ────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct Segment {
    conv: u32,
    cmd: u8,
    frg: u8,
    wnd: u16,
    ts: u32,
    sn: u32,
    una: u32,
    data: Vec<u8>,
    // Retransmission state (snd_buf only)
    resendts: u32,
    rto: u32,
    fastack: u32,
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
    snd_wnd: u16,
    rcv_wnd: u16,
    rmt_wnd: u16,
    cwnd: u16,

    // Sequence numbers
    snd_una: u32,
    snd_nxt: u32,
    rcv_nxt: u32,

    // Queues
    snd_queue: VecDeque<Segment>,
    snd_buf: VecDeque<Segment>,
    rcv_queue: VecDeque<Segment>,
    rcv_buf: VecDeque<Segment>,

    // ACK list accumulated during input()
    acklist: Vec<(u32, u32)>, // (sn, ts) pairs

    // RTT estimation
    rx_srtt: u32,
    rx_rttval: u32,
    rx_rto: u32,
    rx_minrto: u32,

    // Timing
    current: u32,
    interval: u32,
    ts_flush: u32,

    // Probing
    probe: u32,
    ts_probe: u32,
    probe_wait: u32,

    // Dead-link counter
    dead_link: u32,
    /// Number of consecutive unacknowledged retransmissions.
    pub xmit_count: u32,

    // Config
    fast_resend: u32,
    nocwnd: bool, // nc=1

    // Output callback: called with a frame slice to send over WireGuard.
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
        if count >= 256 {
            return Err("data too large");
        }
        for (i, chunk) in data.chunks(mss).enumerate() {
            let frg = (count - 1 - i) as u8;
            let seg = Segment::new_data(self.conv, self.snd_nxt, frg, chunk.to_vec());
            // snd_nxt advances in flush, not here; store with placeholder sn.
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
                self.probe_wait =
                    (self.probe_wait * 3 / 2).clamp(PROBE_INIT_MS, PROBE_LIMIT_MS);
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

    fn process_ack(&mut self, sn: u32) {
        if sn.wrapping_sub(self.snd_una) < self.snd_nxt.wrapping_sub(self.snd_una) {
            self.snd_buf.retain(|seg| seg.sn != sn);
            self.xmit_count = 0; // reset dead-link counter on any ACK
        }
    }

    fn parse_una(&mut self, una: u32) {
        self.snd_buf
            .retain(|seg| seg.sn.wrapping_sub(una) < u32::MAX / 2);
    }

    fn shrink_buf(&mut self) {
        if let Some(seg) = self.snd_buf.front() {
            self.snd_una = seg.sn;
        } else {
            self.snd_una = self.snd_nxt;
        }
    }

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

    fn loopback_pair() -> (KcpState, KcpState) {
        let a_out: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let b_out: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let a_out2 = Arc::clone(&a_out);
        let b_out2 = Arc::clone(&b_out);

        let kcp_a = KcpState::new(1, move |data: &[u8]| {
            a_out.lock().unwrap().push(data.to_vec());
        });
        let kcp_b = KcpState::new(1, move |data: &[u8]| {
            b_out.lock().unwrap().push(data.to_vec());
        });
        let _ = (a_out2, b_out2);
        (kcp_a, kcp_b)
    }

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
        assert!(kcp.dead, "KCP should declare dead_link after enough retransmits");
    }

    #[test]
    fn overhead_constant() {
        // OVERHEAD must equal the KCP header size.
        assert_eq!(OVERHEAD, 24);
    }
}
