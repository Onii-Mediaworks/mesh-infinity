import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../app/app_theme.dart';
import '../../backend/models/settings_models.dart';
import 'services_state.dart';

class MyServicesScreen extends StatelessWidget {
  const MyServicesScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final state = context.watch<ServicesState>();
    final services = state.services;

    return Scaffold(
      body: RefreshIndicator(
        onRefresh: state.refresh,
        child: services.isEmpty
            ? const _EmptyServices()
            : GridView.builder(
                padding: const EdgeInsets.all(12),
                gridDelegate:
                    const SliverGridDelegateWithMaxCrossAxisExtent(
                  maxCrossAxisExtent: 180,
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

class _ServiceTile extends StatelessWidget {
  const _ServiceTile({required this.service, required this.state});
  final ServiceModel service;
  final ServicesState state;

  @override
  Widget build(BuildContext context) {
    final health = service.health;
    final statusColor = switch (health) {
      ServiceHealth.healthy => MeshTheme.secGreen,
      ServiceHealth.degraded => MeshTheme.secAmber,
      ServiceHealth.offline => MeshTheme.secRed,
    };
    final statusLabel = switch (health) {
      ServiceHealth.healthy => 'Online',
      ServiceHealth.degraded => 'Degraded',
      ServiceHealth.offline => 'Offline',
    };

    return Card(
      clipBehavior: Clip.antiAlias,
      child: InkWell(
        onTap: () {},
        child: Padding(
          padding: const EdgeInsets.all(12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  const Icon(Icons.hub_outlined, size: 28),
                  const Spacer(),
                  GestureDetector(
                    onTap: () =>
                        state.setEnabled(service.id, !service.enabled),
                    child: Container(
                      width: 10,
                      height: 10,
                      decoration: BoxDecoration(
                        color: statusColor,
                        shape: BoxShape.circle,
                      ),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              Text(
                service.name,
                style: Theme.of(context).textTheme.labelLarge,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
              ),
              const SizedBox(height: 2),
              Text(
                statusLabel,
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                      color: statusColor,
                    ),
              ),
              const Spacer(),
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
