import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'network_state.dart';
import 'widgets/transport_toggle_row.dart';

class TransportsScreen extends StatelessWidget {
  const TransportsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final net = context.watch<NetworkState>();
    final s = net.settings;

    return Scaffold(
      body: RefreshIndicator(
        onRefresh: net.loadAll,
        child: ListView(
          children: [
            const Padding(
              padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
              child: Text(
                'Internet transports',
                style: TextStyle(fontWeight: FontWeight.w600),
              ),
            ),
            TransportToggleRow(
              icon: Icons.language,
              label: 'Clearnet',
              description: 'Direct TCP connections. Fast, reveals your IP.',
              value: s?.enableClearnet ?? false,
              onChanged: (v) => net.toggleTransport('clearnet', v),
            ),
            TransportToggleRow(
              icon: Icons.security,
              label: 'Tor',
              description: 'Onion-routed connections. High privacy, higher latency.',
              value: s?.enableTor ?? false,
              onChanged: (v) => net.toggleTransport('tor', v),
            ),
            TransportToggleRow(
              icon: Icons.vpn_lock,
              label: 'I2P',
              description: 'Garlic-routed overlay network.',
              value: s?.enableI2p ?? false,
              onChanged: (v) => net.toggleTransport('i2p', v),
            ),
            const Divider(height: 1),
            const Padding(
              padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
              child: Text(
                'Local transports',
                style: TextStyle(fontWeight: FontWeight.w600),
              ),
            ),
            TransportToggleRow(
              icon: Icons.bluetooth,
              label: 'Bluetooth',
              description: 'Short-range local mesh without internet.',
              value: s?.enableBluetooth ?? false,
              onChanged: (v) => net.toggleTransport('bluetooth', v),
            ),
            TransportToggleRow(
              icon: Icons.wifi,
              label: 'mDNS',
              description: 'Find nodes on the same Wi-Fi network.',
              value: net.mdnsRunning,
              onChanged: (v) => v ? net.enableMdns() : net.disableMdns(),
            ),
            const Divider(height: 1),
            const Padding(
              padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
              child: Text(
                'Routing',
                style: TextStyle(fontWeight: FontWeight.w600),
              ),
            ),
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
