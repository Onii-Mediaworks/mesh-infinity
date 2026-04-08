import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'network_state.dart';
import 'widgets/transport_toggle_row.dart';

/// TransportsScreen — quick-access toggle panel for all network transports.
///
/// This is the simplified "Transports" sub-page of the Network section.  It
/// groups transports into three categories for ease of navigation:
///
///   Internet transports — carry traffic over the public internet:
///     Clearnet: raw TCP/IP — fast but reveals the device's real IP address.
///     Tor: traffic routed through the Tor onion network — hides the real IP
///       at the cost of higher latency (usually 200 – 800 ms extra).
///     I2P: garlic-routed overlay network — similar privacy properties to Tor
///       but with different topology; favoured for internal mesh traffic.
///
///   Local transports — work without internet access:
///     Bluetooth: short-range (~10 m) direct peer-to-peer links.
///     mDNS: Multicast DNS discovery on the local Wi-Fi — finds other Mesh
///       Infinity nodes on the same network without a server.
///
///   Routing options:
///     Allow relays: let the backend forward encrypted packets through relay
///       nodes when two peers cannot reach each other directly.
///
/// The full NetworkScreen (screens/network_screen.dart) provides the same
/// toggles plus port configuration, overlay transports (Tailscale / ZeroTier),
/// trusted contexts, and statistics.  This screen exists for quick access.
///
/// Settings are persisted by the Rust backend.  Pull-to-refresh re-fetches the
/// current state from [NetworkState.loadAll] to keep the UI in sync.
class TransportsScreen extends StatelessWidget {
  const TransportsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final net = context.watch<NetworkState>();
    // s may be null on first render before loadAll() completes.  All
    // transport values fall back to `false` (disabled) in that case so the
    // switches are shown in a safe default state.
    final s = net.settings;

    return Scaffold(
      body: RefreshIndicator(
        onRefresh: net.loadAll,
        child: ListView(
          children: [
            // ── Internet transports ───────────────────────────────────────
            const Padding(
              padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
              child: Text(
                'Internet transports',
                style: TextStyle(fontWeight: FontWeight.w600),
              ),
            ),
            // Clearnet: direct TCP/IP — least private, highest performance.
            // Suitable for low-threat environments or when paired with Tor.
            TransportToggleRow(
              icon: Icons.language,
              label: 'Clearnet',
              description: 'Direct TCP connections. Fast, reveals your IP.',
              value: s?.enableClearnet ?? false,
              onChanged: (v) => net.toggleTransport('clearnet', v),
            ),
            // Tor: three-hop onion routing — hides origin IP from destination
            // and from each individual relay.  Higher latency than clearnet.
            TransportToggleRow(
              icon: Icons.security,
              label: 'Tor',
              description: 'Onion-routed connections. High privacy, higher latency.',
              value: s?.enableTor ?? false,
              onChanged: (v) => net.toggleTransport('tor', v),
            ),
            // I2P: "garlic routing" — bundles multiple messages into one
            // encrypted packet.  Primarily designed for internal network
            // services rather than clearnet access.
            TransportToggleRow(
              icon: Icons.vpn_lock,
              label: 'I2P',
              description: 'Garlic-routed overlay network.',
              value: s?.enableI2p ?? false,
              onChanged: (v) => net.toggleTransport('i2p', v),
            ),
            const Divider(height: 1),

            // ── Local transports ──────────────────────────────────────────
            const Padding(
              padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
              child: Text(
                'Local transports',
                style: TextStyle(fontWeight: FontWeight.w600),
              ),
            ),
            // Bluetooth: short-range peer-to-peer without any internet
            // connection.  Useful at protests, shelters, or conferences.
            TransportToggleRow(
              icon: Icons.bluetooth,
              label: 'Bluetooth',
              description: 'Short-range local mesh without internet.',
              value: s?.enableBluetooth ?? false,
              onChanged: (v) => net.toggleTransport('bluetooth', v),
            ),
            // mDNS (Multicast DNS): broadcasts a DNS-SD service record on the
            // local subnet.  Other Mesh Infinity nodes respond automatically.
            // Note: mDNS state comes from `net.mdnsRunning`, not settings,
            // because it is managed separately through its own bridge calls.
            TransportToggleRow(
              icon: Icons.wifi,
              label: 'mDNS',
              description: 'Find nodes on the same Wi-Fi network.',
              value: net.mdnsRunning,
              // mDNS uses dedicated enable/disable calls rather than the
              // generic toggleTransport() because it returns a discovered-peers
              // list (not just a bool) and needs its own state tracking.
              onChanged: (v) => v ? net.enableMdns() : net.disableMdns(),
            ),
            const Divider(height: 1),

            // ── Routing ───────────────────────────────────────────────────
            const Padding(
              padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
              child: Text(
                'Routing',
                style: TextStyle(fontWeight: FontWeight.w600),
              ),
            ),
            // Allow relays: when enabled, the backend may route traffic
            // through intermediate relay nodes to bridge NAT boundaries.
            // Relays forward encrypted packets without being able to read them.
            TransportToggleRow(
              icon: Icons.hub,
              label: 'Allow relays',
              description: 'Route traffic through trusted relay nodes.',
              value: s?.allowRelays ?? false,
              onChanged: (v) => net.toggleTransport('relays', v),
            ),
          ],
        ),
      ),
    );
  }
}
