import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../backend/backend_bridge.dart';
import '../../core/widgets/empty_state.dart';
import '../../app/app_theme.dart';

class BrowseScreen extends StatefulWidget {
  const BrowseScreen({super.key});
  @override
  State<BrowseScreen> createState() => _BrowseScreenState();
}

class _BrowseScreenState extends State<BrowseScreen> {
  List<Map<String, dynamic>> _services = const [];
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final bridge = context.read<BackendBridge>();
    final services = bridge.discoverMeshServices();
    if (mounted) setState(() { _services = services; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator());
    if (_services.isEmpty) {
      return const EmptyState(
        icon: Icons.search,
        title: 'No services found',
        body: 'Services from this device and any discovered peers will appear here.',
      );
    }
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.all(16),
        itemCount: _services.length,
        itemBuilder: (context, i) => _ServiceTile(service: _services[i]),
      ),
    );
  }
}

class _ServiceTile extends StatelessWidget {
  const _ServiceTile({required this.service});
  final Map<String, dynamic> service;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;
    final name      = service['name']      as String? ?? 'Unknown';
    final type      = service['type']      as String? ?? '';
    final hostName  = service['hostName']  as String? ?? '';
    final trustReq  = (service['trustRequired'] as num?)?.toInt() ?? 0;
    final isLocal = service['hostPeerId'] == '' || hostName == 'This device';

    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: ListTile(
        contentPadding:
            const EdgeInsets.fromLTRB(16, 8, 8, 8),
        leading: Container(
          width: 40, height: 40,
          decoration: BoxDecoration(
            color: MeshTheme.brand.withValues(alpha: 0.12),
            borderRadius: BorderRadius.circular(10),
          ),
          child: Icon(_iconForType(type), size: 20, color: MeshTheme.brand),
        ),
        title: Text(name, style: theme.textTheme.titleSmall),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              isLocal
                  ? 'Hosted on this device'
                  : hostName.isNotEmpty
                      ? 'Hosted by $hostName'
                      : type,
              style: theme.textTheme.bodySmall
                  ?.copyWith(color: cs.onSurfaceVariant),
            ),
            if (trustReq > 0)
              Text('Requires trust level $trustReq',
                style: theme.textTheme.bodySmall
                    ?.copyWith(color: MeshTheme.secAmber)),
          ],
        ),
        isThreeLine: trustReq > 0,
        trailing: Icon(
          isLocal ? Icons.smartphone_outlined : Icons.route_outlined,
          color: cs.onSurfaceVariant,
        ),
      ),
    );
  }

  IconData _iconForType(String type) => switch (type) {
    'remoteDesktop' => Icons.desktop_windows_outlined,
    'remoteShell'   => Icons.terminal_outlined,
    'fileAccess'    => Icons.folder_shared_outlined,
    'apiGateway'    => Icons.api_outlined,
    'clipboardSync' => Icons.content_copy_outlined,
    'screenShare'   => Icons.monitor_outlined,
    'printService'  => Icons.print_outlined,
    _               => Icons.miscellaneous_services_outlined,
  };
}
