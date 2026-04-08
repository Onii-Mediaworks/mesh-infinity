// tailnet_acl_page.dart
//
// TailnetAclPage — the ACL tab content for one tailnet instance.
//
// WHAT ARE TAILSCALE ACLs?
// ------------------------
// Access Control Lists (ACLs) are policy rules enforced by the Tailscale
// control plane.  They determine which devices and users within the tailnet
// can reach which other devices and which ports.  ACLs are written in HuJSON
// (a superset of JSON that allows comments) and are hosted on the control
// server — not on individual devices.
//
// WHY IS THIS A SEPARATE TAB?
// ----------------------------
// ACL management (read + write) requires interaction with the control server
// admin API.  The Mesh Infinity backend does not currently proxy ACL reads,
// so this tab provides:
//   1. A link to the appropriate admin console where the user can view and
//      edit ACLs in their browser.
//   2. A copy-URL button for environments without a browser integration.
//   3. Context explaining what ACLs do so that less-experienced users are
//      not confused by the tab.
//
// VENDOR vs HEADSCALE
// --------------------
// • Tailscale vendor: admin console is at https://login.tailscale.com/admin/acls
// • Headscale: no built-in web UI for ACLs; users access the Headscale admin
//   API directly at <controller_url>/api/v1/acls.  We display the API URL
//   with a note to use the Headscale CLI or a compatible web UI.
//
// Spec reference: §5.22 (multi-instance Tailscale overlay — ACL awareness)

import 'package:flutter/material.dart';
// Material widgets: ListView, Card, ListTile, FilledButton.

import 'package:flutter/services.dart';
// Clipboard.setData() — for copy admin URL to clipboard.

import 'models/tailnet_instance.dart';
// TailnetInstance — used to derive the correct admin console URL.

// ---------------------------------------------------------------------------
// TailnetAclPage
// ---------------------------------------------------------------------------

/// The ACL tab content shown inside [TailnetDetailScreen].
///
/// Displays ACL context, the admin console URL for this instance, and a
/// copy button.  Full ACL editing requires visiting the admin console.
///
/// Spec reference: §5.22
class TailnetAclPage extends StatelessWidget {
  /// Creates a [TailnetAclPage] for the given [instance].
  const TailnetAclPage({super.key, required this.instance});

  /// The tailnet instance whose ACL admin URL to display.
  final TailnetInstance instance;

  // ---------------------------------------------------------------------------
  // Admin console URL logic
  // ---------------------------------------------------------------------------

  /// Returns the admin console URL appropriate for this instance.
  ///
  /// • Vendor Tailscale (controller == null or empty): the ACLs tab of the
  ///   Tailscale admin panel.
  /// • Headscale (controller contains a URL): the Headscale ACL API endpoint.
  ///   Headscale does not ship a built-in web UI; users interact via curl or
  ///   a compatible GUI like Headscale-UI.
  String get _adminUrl {
    final ctrl = instance.controller;
    // Headscale — point to the ACL API; the user must use their own tooling.
    if (ctrl != null && ctrl.isNotEmpty) {
      // Strip trailing slash so the URL is always clean.
      return '${ctrl.replaceAll(RegExp(r'/$'), '')}/api/v1/policy';
    }
    // Vendor Tailscale — deep-link into the ACLs section of the admin panel.
    return 'https://login.tailscale.com/admin/acls';
  }

  /// True when this instance uses a self-hosted Headscale controller.
  bool get _isHeadscale =>
      instance.controller != null && instance.controller!.isNotEmpty;

  // ---------------------------------------------------------------------------
  // _copyUrl
  // ---------------------------------------------------------------------------

  void _copyUrl(BuildContext context) {
    Clipboard.setData(ClipboardData(text: _adminUrl));
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Admin URL copied to clipboard'),
        duration: Duration(seconds: 2),
        behavior: SnackBarBehavior.floating,
        width: 280,
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // ---- What are ACLs? -----------------------------------------------
        Text('Access Control Lists', style: tt.titleMedium),
        const SizedBox(height: 8),
        Text(
          'ACLs are rules enforced by your control server that define which '
          'devices within the tailnet can reach which other devices and ports. '
          'They are written in HuJSON format and managed centrally — not on '
          'individual devices.',
          style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
        ),

        const SizedBox(height: 20),
        const Divider(),
        const SizedBox(height: 16),

        // ---- Admin console URL card --------------------------------------
        Text('Admin Console', style: tt.titleSmall),
        const SizedBox(height: 8),

        // Headscale note — shown only for self-hosted instances.
        if (_isHeadscale) ...[
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: cs.tertiaryContainer.withValues(alpha: 0.5),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Icon(Icons.info_outline,
                    size: 16, color: cs.onTertiaryContainer),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    'This instance uses a self-hosted Headscale controller. '
                    'Headscale does not include a built-in web UI for ACL '
                    'management — the URL below is the Headscale ACL API '
                    'endpoint. Use the Headscale CLI or a compatible web UI '
                    '(e.g. headscale-ui) to view and edit ACL rules.',
                    style: tt.bodySmall?.copyWith(
                      color: cs.onTertiaryContainer,
                    ),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 12),
        ],

        // URL card.
        Card(
          margin: EdgeInsets.zero,
          child: Padding(
            padding: const EdgeInsets.all(14),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Label.
                Text(
                  _isHeadscale
                      ? 'Headscale ACL API endpoint'
                      : 'Tailscale admin panel — ACLs',
                  style: tt.labelMedium
                      ?.copyWith(color: cs.onSurfaceVariant),
                ),
                const SizedBox(height: 6),
                // URL in monospace.
                SelectableText(
                  _adminUrl,
                  style: tt.bodySmall?.copyWith(
                    fontFamily: 'monospace',
                    color: cs.primary,
                  ),
                ),
                const SizedBox(height: 12),
                // Copy button.
                FilledButton.tonalIcon(
                  onPressed: () => _copyUrl(context),
                  icon: const Icon(Icons.copy, size: 16),
                  label: const Text('Copy URL'),
                ),
              ],
            ),
          ),
        ),

        const SizedBox(height: 24),
        const Divider(),
        const SizedBox(height: 16),

        // ---- How ACLs work -----------------------------------------------
        Text('How ACLs work', style: tt.titleSmall),
        const SizedBox(height: 8),

        // Step list — a compact, numbered guide that gives the user enough
        // context to understand what they are editing without leaving the app.
        ..._aclSteps(cs, tt),

        const SizedBox(height: 20),

        // ---- Privacy note ------------------------------------------------
        Text(
          _isHeadscale
              ? 'ACL rules are stored on your self-hosted Headscale server '
                  'and are not visible to Tailscale Inc.'
              : 'ACL rules are stored on Tailscale\'s coordination servers '
                  'and are visible to Tailscale Inc. For maximum privacy, '
                  'consider migrating to a self-hosted Headscale controller.',
          style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
          textAlign: TextAlign.center,
        ),
      ],
    );
  }

  // ---------------------------------------------------------------------------
  // ACL step helper
  // ---------------------------------------------------------------------------

  /// Returns a list of ListTile widgets that explain the ACL workflow.
  List<Widget> _aclSteps(ColorScheme cs, TextTheme tt) {
    // Each step: (icon, title, description)
    const steps = [
      (Icons.edit_outlined, 'Define sources and destinations',
          'ACL rules specify which users or device tags are allowed to reach '
              'other tags or specific IP ranges.'),
      (Icons.upload_outlined, 'Push to control server',
          'Rules are uploaded to the control plane (Tailscale or Headscale) '
              'and distributed to all enrolled devices.'),
      (Icons.verified_outlined, 'Devices enforce locally',
          'Each device\'s Tailscale daemon enforces the received rules in its '
              'WireGuard filter table — enforcement is distributed, not centralised.'),
      (Icons.refresh, 'Changes take effect within seconds',
          'After an ACL update, all connected devices receive the new rules '
              'within seconds without needing to reconnect.'),
    ];

    return steps.indexed.map(((int, (IconData, String, String)) entry) {
      final (i, (icon, title, desc)) = entry;
      return Padding(
        padding: const EdgeInsets.only(bottom: 14),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Step number circle.
            Container(
              width: 26,
              height: 26,
              decoration: BoxDecoration(
                color: cs.primary.withValues(alpha: 0.12),
                shape: BoxShape.circle,
              ),
              alignment: Alignment.center,
              child: Text(
                '${i + 1}',
                style: tt.labelSmall?.copyWith(
                  color: cs.primary,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Icon(icon, size: 16, color: cs.onSurfaceVariant),
                      const SizedBox(width: 6),
                      Text(title,
                          style: tt.bodyMedium
                              ?.copyWith(fontWeight: FontWeight.w600)),
                    ],
                  ),
                  const SizedBox(height: 3),
                  Text(desc,
                      style:
                          tt.bodySmall?.copyWith(color: cs.onSurfaceVariant)),
                ],
              ),
            ),
          ],
        ),
      );
    }).toList();
  }
}
