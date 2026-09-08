//! Passive Assist Mode (§5.27.6)
//!
//! # What is Passive Assist?
//!
//! Passive assist is a routing mode in which Mesh Infinity observes permitted
//! local or transit traffic and derives:
//!
//! - peer IP presence hints
//! - path quality / latency hints
//! - activity windows
//! - cover opportunities
//! - candidate deniable carrier families
//!
//! In passive assist mode the node participates in mesh routing but sends NO
//! traffic from its own address.  All packets the node needs to deliver are
//! forwarded via relay peers.  The node's own IP is never present as the source
//! of any packet on the wire.
//!
//! # When is Passive Assist Used?
//!
//! Passive assist is activated when:
//!
//! - `ThreatContext::Critical` is active AND
//! - at least one relay peer is available AND
//! - the platform supports passive observation (desktop / Unix / router)
//!
//! On mobile platforms (Android, iOS) passive assist is limited to the VPN
//! interface.  On desktop and Unix platforms, it can use raw sockets or
//! libpcap-level capture where policy permits.
//!
//! # Integration with Carrier Ladder
//!
//! Passive assist feeds the carrier ladder (§5.27) with live traffic context:
//!
//! - When the node observes QUIC/UDP flows on the local network, the ladder
//!   can open a `QuicHttp3Carrier` parallel covert session correlated with
//!   that flow (§5.27.6 parallel covert session).
//! - Observed XMPP or chat flows trigger `XmppCarrier` availability hints.
//! - Any observed DNS traffic makes the `DnsCarrier` plausible as cover.
//!
//! The node derives cover context from observed flows.  It does NOT inject
//! payloads into third-party traffic it only observes (§5.27.6 rule).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Observed Flow Record
// ---------------------------------------------------------------------------

/// A traffic flow observed on the local network (§5.27.6).
///
/// Passive assist records these to drive carrier-ladder hints and
/// parallel covert session opportunities.
#[derive(Clone, Debug)]
pub struct ObservedFlow {
    /// Source IP as string (v4 or v6).
    pub src_ip: String,
    /// Destination IP as string.
    pub dst_ip: String,
    /// Destination port (0 if unknown or ICMP).
    pub dst_port: u16,
    /// Heuristic protocol family (DNS, QUIC, XMPP, HTTP, Other).
    pub protocol_hint: ProtocolHint,
    /// When this flow was last seen.
    pub last_seen: Instant,
    /// Approximate bytes observed on this flow (rolling window).
    pub bytes_seen: u64,
}

/// Heuristic classification of an observed flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProtocolHint {
    /// UDP port 443 or 80 — likely QUIC/HTTP3.
    QuicHttp3,
    /// TCP port 5222 or 5269 — likely XMPP client or federation.
    Xmpp,
    /// UDP port 53 — DNS.
    Dns,
    /// TCP port 443 — likely HTTPS.
    Https,
    /// TCP port 25 / 587 / 993 — email.
    Email,
    /// Everything else.
    Other,
}

impl ProtocolHint {
    /// Classify a flow from its transport-layer protocol and destination port.
    pub fn classify(is_udp: bool, dst_port: u16) -> Self {
        match (is_udp, dst_port) {
            (true, 443) | (true, 80) => Self::QuicHttp3,
            (false, 5222) | (false, 5269) => Self::Xmpp,
            (true, 53) | (false, 53) => Self::Dns,
            (false, 443) | (false, 80) => Self::Https,
            (false, 25) | (false, 587) | (false, 993) | (false, 143) => Self::Email,
            _ => Self::Other,
        }
    }
}

// ---------------------------------------------------------------------------
// Passive Assist State
// ---------------------------------------------------------------------------

/// Maximum number of flows to track before evicting the oldest.
const MAX_FLOW_ENTRIES: usize = 4096;

/// Flow entries older than this are evicted as stale.
const FLOW_STALE_SECS: u64 = 300;

/// Per-protocol hint counts used to score carrier ladder availability.
#[derive(Clone, Debug, Default)]
pub struct CoverContext {
    /// Number of active QUIC/HTTP3 flows observed.
    pub quic_http3_flows: usize,
    /// Number of active XMPP flows observed.
    pub xmpp_flows: usize,
    /// Number of active DNS flows observed.
    pub dns_flows: usize,
    /// Number of active HTTPS flows observed.
    pub https_flows: usize,
    /// Number of active email flows observed.
    pub email_flows: usize,
}

impl CoverContext {
    /// Whether QUIC/HTTP3 cover is currently ambient (§5.27.8 AmbientCover).
    pub fn has_quic_cover(&self) -> bool {
        self.quic_http3_flows > 0
    }

    /// Whether XMPP cover is currently ambient.
    pub fn has_xmpp_cover(&self) -> bool {
        self.xmpp_flows > 0
    }

    /// Whether DNS cover is currently ambient.
    pub fn has_dns_cover(&self) -> bool {
        self.dns_flows > 0
    }
}

/// The passive assist engine (§5.27.6).
///
/// Records observed flows and exports carrier-ladder cover context to the
/// `CarrierLadder` so the ladder can select rungs that blend with ambient
/// traffic.
pub struct PassiveAssistEngine {
    /// Active flows keyed by (src_ip, dst_ip, dst_port, is_udp).
    flows: Mutex<HashMap<(String, String, u16, bool), ObservedFlow>>,
    /// Whether passive observation is enabled on this platform.
    enabled: bool,
}

impl PassiveAssistEngine {
    /// Create a new passive assist engine.
    ///
    /// `enabled` should be `true` on desktop / Unix / router platforms.
    /// On mobile platforms set `enabled = false` unless a VPN interface
    /// is in use.
    pub fn new(enabled: bool) -> Arc<Self> {
        Arc::new(Self {
            flows: Mutex::new(HashMap::new()),
            enabled,
        })
    }

    /// Record an observed packet.  Call this for every packet the node
    /// captures or routes through the passive-assist interface.
    ///
    /// This is a no-op when `enabled = false`.
    pub fn observe(&self, src_ip: &str, dst_ip: &str, is_udp: bool, dst_port: u16, bytes: u64) {
        if !self.enabled {
            return;
        }

        let mut flows = self.flows.lock().unwrap();

        // Evict stale flows before inserting to bound memory.
        let now = Instant::now();
        let stale_threshold = Duration::from_secs(FLOW_STALE_SECS);
        if flows.len() >= MAX_FLOW_ENTRIES {
            flows.retain(|_, v| now.duration_since(v.last_seen) < stale_threshold);
        }

        let key = (src_ip.to_string(), dst_ip.to_string(), dst_port, is_udp);
        let entry = flows.entry(key).or_insert_with(|| ObservedFlow {
            src_ip: src_ip.to_string(),
            dst_ip: dst_ip.to_string(),
            dst_port,
            protocol_hint: ProtocolHint::classify(is_udp, dst_port),
            last_seen: now,
            bytes_seen: 0,
        });
        entry.last_seen = now;
        entry.bytes_seen = entry.bytes_seen.saturating_add(bytes);
    }

    /// Export a snapshot of the current cover context.
    ///
    /// The carrier ladder calls this to decide which rungs have ambient cover
    /// available, allowing synthetic cover traffic to be reduced (§5.27.8).
    pub fn cover_context(&self) -> CoverContext {
        let flows = self.flows.lock().unwrap();
        let now = Instant::now();
        let stale_threshold = Duration::from_secs(FLOW_STALE_SECS);

        let mut ctx = CoverContext::default();
        for flow in flows.values() {
            if now.duration_since(flow.last_seen) >= stale_threshold {
                continue; // skip stale entries without locking again
            }
            match flow.protocol_hint {
                ProtocolHint::QuicHttp3 => ctx.quic_http3_flows += 1,
                ProtocolHint::Xmpp => ctx.xmpp_flows += 1,
                ProtocolHint::Dns => ctx.dns_flows += 1,
                ProtocolHint::Https => ctx.https_flows += 1,
                ProtocolHint::Email => ctx.email_flows += 1,
                ProtocolHint::Other => {}
            }
        }
        ctx
    }

    /// Evict all flows older than `FLOW_STALE_SECS`.
    pub fn prune_stale(&self) {
        let mut flows = self.flows.lock().unwrap();
        let now = Instant::now();
        let stale_threshold = Duration::from_secs(FLOW_STALE_SECS);
        flows.retain(|_, v| now.duration_since(v.last_seen) < stale_threshold);
    }

    /// Whether passive observation is active on this node.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_hint_classify_quic() {
        assert_eq!(ProtocolHint::classify(true, 443), ProtocolHint::QuicHttp3);
        assert_eq!(ProtocolHint::classify(true, 80), ProtocolHint::QuicHttp3);
    }

    #[test]
    fn protocol_hint_classify_xmpp() {
        assert_eq!(ProtocolHint::classify(false, 5222), ProtocolHint::Xmpp);
        assert_eq!(ProtocolHint::classify(false, 5269), ProtocolHint::Xmpp);
    }

    #[test]
    fn protocol_hint_classify_dns() {
        assert_eq!(ProtocolHint::classify(true, 53), ProtocolHint::Dns);
        assert_eq!(ProtocolHint::classify(false, 53), ProtocolHint::Dns);
    }

    #[test]
    fn passive_assist_disabled_does_not_record() {
        let engine = PassiveAssistEngine::new(false);
        engine.observe("1.2.3.4", "5.6.7.8", true, 443, 1200);
        let ctx = engine.cover_context();
        assert_eq!(ctx.quic_http3_flows, 0);
    }

    #[test]
    fn passive_assist_records_quic_flow() {
        let engine = PassiveAssistEngine::new(true);
        engine.observe("10.0.0.1", "10.0.0.2", true, 443, 1500);
        let ctx = engine.cover_context();
        assert!(ctx.has_quic_cover());
        assert_eq!(ctx.quic_http3_flows, 1);
    }

    #[test]
    fn passive_assist_records_multiple_protocols() {
        let engine = PassiveAssistEngine::new(true);
        engine.observe("10.0.0.1", "10.0.0.2", true, 443, 1000); // QUIC
        engine.observe("10.0.0.1", "10.0.0.3", false, 5222, 500); // XMPP
        engine.observe("10.0.0.1", "10.0.0.4", true, 53, 64); // DNS
        let ctx = engine.cover_context();
        assert!(ctx.has_quic_cover());
        assert!(ctx.has_xmpp_cover());
        assert!(ctx.has_dns_cover());
    }

    #[test]
    fn passive_assist_accumulates_bytes() {
        let engine = PassiveAssistEngine::new(true);
        engine.observe("10.0.0.1", "10.0.0.2", true, 443, 1000);
        engine.observe("10.0.0.1", "10.0.0.2", true, 443, 500);
        let flows = engine.flows.lock().unwrap();
        let key = ("10.0.0.1".to_string(), "10.0.0.2".to_string(), 443u16, true);
        assert_eq!(flows[&key].bytes_seen, 1500);
    }

    #[test]
    fn solver_falls_back_to_deniable_carrier_in_elevated_context() {
        use crate::network::threat_context::ThreatContext;
        use crate::network::transport_hint::TransportType;
        use crate::transport::health::{HealthState, TransportStatus};
        use crate::transport::solver::{solve, Priority, SolverHint, SolverInput, SolverOutput};

        // All available transports are clearnet — Elevated context blocks them all.
        let input = SolverInput {
            hint: SolverHint {
                min_bandwidth_bps: None,
                max_latency_ms: None,
                min_anonymization: None,
                stream: false,
                priority: Priority::Normal,
            },
            threat_context: ThreatContext::Elevated,
            available: vec![TransportStatus {
                transport: TransportType::Clearnet,
                hardware_available: true,
                health: HealthState::Live,
                latency_ema: None,
                bandwidth: crate::network::transport_hint::BandwidthClass::High,
            }],
            peer_transports: vec![TransportType::Clearnet],
            active_transport_count: 1,
        };

        match solve(&input) {
            SolverOutput::Single(t) => assert_eq!(t, TransportType::DeniableCarrier),
            other => panic!("expected DeniableCarrier fallback, got {other:?}"),
        }
    }
}
