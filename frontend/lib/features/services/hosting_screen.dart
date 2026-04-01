import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../backend/backend_bridge.dart';
import '../../core/widgets/section_header.dart';
import '../../app/app_theme.dart';

class HostingScreen extends StatefulWidget {
  const HostingScreen({super.key});
  @override
  State<HostingScreen> createState() => _HostingScreenState();
}

class _HostingScreenState extends State<HostingScreen> {
  Map<String, dynamic> _config = const {};
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final bridge = context.read<BackendBridge>();
    final cfg = bridge.fetchHostingConfig() ?? const {};
    if (mounted) setState(() { _config = cfg; _loading = false; });
  }

  Future<void> _toggle(String serviceId, bool enabled) async {
    final bridge = context.read<BackendBridge>();
    final ok = bridge.setHostedService(serviceId, enabled: enabled);
    if (ok) {
      setState(() => _config = {..._config, serviceId: enabled});
    } else if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Failed to update service')),
      );
    }
  }

  bool _isEnabled(String serviceId) =>
      _config[serviceId] as bool? ?? false;

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator());

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        const SectionHeader('Remote Access'),
        _ServiceTile(
          icon: Icons.desktop_windows_outlined,
          title: 'Remote Desktop',
          subtitle: 'Stream your screen or individual apps to trusted contacts.',
          serviceId: 'remoteDesktop',
          enabled: _isEnabled('remoteDesktop'),
          onToggle: (v) => _toggle('remoteDesktop', v),
        ),
        _ServiceTile(
          icon: Icons.terminal_outlined,
          title: 'Remote Shell',
          subtitle: 'Secure terminal access from any mesh device.',
          serviceId: 'remoteShell',
          enabled: _isEnabled('remoteShell'),
          onToggle: (v) => _toggle('remoteShell', v),
        ),
        const SizedBox(height: 8),
        const SectionHeader('Files & Data'),
        _ServiceTile(
          icon: Icons.folder_shared_outlined,
          title: 'File Access',
          subtitle: 'Share folders and drives with mesh contacts.',
          serviceId: 'fileAccess',
          enabled: _isEnabled('fileAccess'),
          onToggle: (v) => _toggle('fileAccess', v),
        ),
        _ServiceTile(
          icon: Icons.api_outlined,
          title: 'API Gateway',
          subtitle: 'Expose local HTTP, gRPC, or WebSocket services to the mesh.',
          serviceId: 'apiGateway',
          enabled: _isEnabled('apiGateway'),
          onToggle: (v) => _toggle('apiGateway', v),
        ),
        const SizedBox(height: 8),
        const SectionHeader('Sharing'),
        _ServiceTile(
          icon: Icons.content_copy_outlined,
          title: 'Clipboard Sync',
          subtitle: 'Keep clipboard in sync across your devices.',
          serviceId: 'clipboardSync',
          enabled: _isEnabled('clipboardSync'),
          onToggle: (v) => _toggle('clipboardSync', v),
        ),
        _ServiceTile(
          icon: Icons.monitor_outlined,
          title: 'Screen Share',
          subtitle: 'Share a view-only display with contacts.',
          serviceId: 'screenShare',
          enabled: _isEnabled('screenShare'),
          onToggle: (v) => _toggle('screenShare', v),
        ),
        _ServiceTile(
          icon: Icons.print_outlined,
          title: 'Print Services',
          subtitle: 'Share printers with mesh contacts.',
          serviceId: 'printService',
          enabled: _isEnabled('printService'),
          onToggle: (v) => _toggle('printService', v),
        ),
        const SizedBox(height: 24),
      ],
    );
  }
}

class _ServiceTile extends StatelessWidget {
  const _ServiceTile({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.serviceId,
    required this.enabled,
    required this.onToggle,
  });

  final IconData icon;
  final String title;
  final String subtitle;
  final String serviceId;
  final bool enabled;
  final ValueChanged<bool> onToggle;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;

    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: ListTile(
        contentPadding: const EdgeInsets.fromLTRB(16, 8, 8, 8),
        leading: Container(
          width: 40, height: 40,
          decoration: BoxDecoration(
            color: enabled
                ? MeshTheme.brand.withValues(alpha: 0.12)
                : cs.surfaceContainerHighest,
            borderRadius: BorderRadius.circular(10),
          ),
          child: Icon(icon, size: 20,
            color: enabled ? MeshTheme.brand : cs.onSurfaceVariant),
        ),
        title: Text(title, style: theme.textTheme.titleSmall),
        subtitle: Text(subtitle,
          style: theme.textTheme.bodySmall
              ?.copyWith(color: cs.onSurfaceVariant)),
        isThreeLine: true,
        trailing: Switch(value: enabled, onChanged: onToggle),
      ),
    );
  }
}
