// my_services_screen.dart
//
// MyServicesScreen — the "My Services" sub-page of the Services section.
//
// WHAT THIS SHOWS:
// ----------------
// This screen shows the services that the user has pinned / subscribed to from
// the mesh — not the services this device is hosting (that's HostingScreen).
// Each card shows the service name, a live enable/disable switch, a status
// dot, and the service address (e.g. "mesh://peer-id/svc/remoteDesktop").
//
// GRID LAYOUT:
// ------------
// Services are shown in a responsive grid using SliverGridDelegateWithMax-
// CrossAxisExtent. maxCrossAxisExtent=180 means each card is at most 180 px
// wide, so the grid naturally fills available horizontal space — 2 columns on
// phones, 3–4 on tablets, more on desktop.
//
// EMPTY STATE:
// ------------
// If no services are pinned, a centred empty-state card guides the user to the
// Browse sub-page where they can discover and pin services.
//
// Reached from: Services section, first sub-page.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../app/app_theme.dart';
import '../../backend/models/settings_models.dart';
import 'services_state.dart';

/// Shows the list of pinned / subscribed mesh services for this user.
///
/// Stateless because all mutable data lives in [ServicesState] (provided
/// by the ancestor Provider tree).
class MyServicesScreen extends StatelessWidget {
  const MyServicesScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final state = context.watch<ServicesState>();
    final services = state.services;

    return Scaffold(
      body: RefreshIndicator(
        // Pull-to-refresh triggers a full re-fetch from the backend.
        onRefresh: state.refresh,
        child: services.isEmpty
            ? const _EmptyServices()
            : GridView.builder(
                padding: const EdgeInsets.all(12),
                gridDelegate:
                    const SliverGridDelegateWithMaxCrossAxisExtent(
                  // Each card is at most 180 px wide; the grid picks the column
                  // count to fill available width without exceeding this limit.
                  maxCrossAxisExtent: 180,
                  // Fixed card height of 136 px regardless of content, so all
                  // cards in a row are the same size even with varying name length.
                  mainAxisExtent: 136,
                  mainAxisSpacing: 10,
                  crossAxisSpacing: 10,
                ),
                itemCount: services.length,
                itemBuilder: (context, i) =>
                    _ServiceTile(service: services[i], state: state),
              ),
      ),
    );
  }
}

/// A compact grid card for a single pinned service.
///
/// Shows: icon + enable switch (top row), name + status dot (middle row),
/// status label, and the service mesh address (bottom row).
class _ServiceTile extends StatelessWidget {
  const _ServiceTile({required this.service, required this.state});

  /// The service data model to display.
  final ServiceModel service;

  /// Reference to [ServicesState] for toggle mutations.
  final ServicesState state;

  @override
  Widget build(BuildContext context) {
    // Status colour: green when the service is reachable, grey when off/unknown.
    final statusColor =
        service.enabled ? MeshTheme.secGreen : Theme.of(context).colorScheme.outline;

    // Status label: shown below the service name in small text.
    final statusLabel = service.enabled ? 'Available to mesh peers' : 'Off';

    return Card(
      // Clip.antiAlias ensures the InkWell ripple doesn't escape the card's
      // rounded corners.
      clipBehavior: Clip.antiAlias,
      child: InkWell(
        // onTap is a placeholder — tapping the card will eventually open a
        // detail/settings sheet for this service.
        onTap: () {},
        child: Padding(
          padding: const EdgeInsets.all(12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // ── Top row: icon (left) + switch (right) ─────────────────
              Row(
                children: [
                  const Icon(Icons.hub_outlined, size: 28),
                  const Spacer(),
                  Switch(
                    value: service.enabled,
                    onChanged: (value) => state.setEnabled(service.id, value),
                    // shrinkWrap reduces the switch's tap target height so it
                    // fits inside the fixed-height card without overflow.
                    materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
                  ),
                ],
              ),
              const SizedBox(height: 8),

              // ── Middle row: name (truncated) + status dot ──────────────
              Row(
                children: [
                  Expanded(
                    child: Text(
                      service.name,
                      style: Theme.of(context).textTheme.labelLarge,
                      // Single-line with ellipsis — card width is too narrow
                      // for long service names to wrap.
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                  // 10×10 status dot — colour matches statusColor computed above.
                  Container(
                    width: 10,
                    height: 10,
                    decoration: BoxDecoration(
                      color: statusColor,
                      shape: BoxShape.circle,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 2),

              // Status label in matching colour.
              Text(
                statusLabel,
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                      color: statusColor,
                    ),
              ),

              // Push the address to the bottom of the fixed-height card.
              const Spacer(),

              // Mesh address in monospace — e.g. "mesh://abc123/svc/remoteDesktop".
              // Single-line with ellipsis so long addresses don't overflow.
              Text(
                service.address,
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                      fontFamily: 'monospace',
                      color: Theme.of(context).colorScheme.outline,
                    ),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
              ),
            ],
          ),
        ),
      ),
    );
  }
}

/// Empty state shown when no services have been pinned yet.
///
/// Guides the user to the Browse sub-page where they can discover and add
/// services from the mesh.
class _EmptyServices extends StatelessWidget {
  const _EmptyServices();

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.hub_outlined,
              size: 56, color: Theme.of(context).colorScheme.outline),
          const SizedBox(height: 16),
          Text(
            'No services pinned',
            style: Theme.of(context).textTheme.titleMedium?.copyWith(
                  color: Theme.of(context).colorScheme.outline,
                ),
          ),
          const SizedBox(height: 8),
          Text(
            'Browse to discover and pin services from the mesh.',
            style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  color: Theme.of(context).colorScheme.outline,
                ),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }
}
