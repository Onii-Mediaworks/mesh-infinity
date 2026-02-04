import 'package:flutter/material.dart';

import '../../backend/thread_store.dart';
import '../../core/layout/layout_spec.dart';
import '../../models/thread_models.dart';
import 'widgets/composer_bar.dart';
import 'widgets/conversation_list.dart';
import 'widgets/top_bar.dart';
import 'widgets/thread_sidebar.dart';
import 'widgets/section_sidebar.dart';
import '../menu/global_menu.dart';
import '../menu/global_drawer.dart';
import '../menu/menu_models.dart';
import '../../backend/backend_models.dart';

class SignalShell extends StatefulWidget {
  const SignalShell({super.key});

  @override
  State<SignalShell> createState() => _SignalShellState();
}

class _SignalShellState extends State<SignalShell> {
  final TextEditingController _composer = TextEditingController();
  final GlobalKey<ScaffoldState> _scaffoldKey = GlobalKey<ScaffoldState>();
  late final ThreadStore _store;
  final FocusNode _composerFocus = FocusNode();
  GlobalMenuSelection _menuSelection = const GlobalMenuSelection(
    section: GlobalMenuSection.chat,
    title: 'Chat',
  );
  String? _activeSubSectionId;

  @override
  void initState() {
    super.initState();
    _store = ThreadStore();
    _store.initialize();
  }

  @override
  void dispose() {
    _composer.dispose();
    _composerFocus.dispose();
    _store.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _store,
      builder: (context, _) {
        return LayoutBuilder(
          builder: (context, constraints) {
            final layout = LayoutSpec.resolve(constraints);
            final threads = _store.threads;
            final activeThread = _resolveActiveThread(threads, _store.activeThreadId);
            final isChatActive = _menuSelection.section == GlobalMenuSection.chat;
            final showConversationPane = layout.showSecondaryPane && isChatActive;
    if (isChatActive && _activeSubSectionId == null) {
      _activeSubSectionId = _store.activeThreadId ?? 'chat-list';
    }
            final sidebarSelectionId = _sidebarSelectionId(
              section: _menuSelection.section,
              explicit: _activeSubSectionId,
            );

            final sidebar = _buildSectionSidebar(
              context,
              section: _menuSelection.section,
              threads: threads,
              layout: layout,
              selectionId: sidebarSelectionId,
            );
            final showMainList = !layout.showSidebar && !showConversationPane;

            return Scaffold(
              key: _scaffoldKey,
              body: SafeArea(
                child: Row(
                  children: [
                    Expanded(
                      child: Column(
                        children: [
                          TopBar(
                            title: isChatActive
                                ? (activeThread?.title ?? 'Mesh Infinity')
                                : _resolveSectionTitle(_menuSelection.section, _activeSubSectionId),
                            subtitle: isChatActive
                                ? (activeThread != null ? 'End-to-end encrypted · P2P mesh' : null)
                                : _resolveSectionSubtitle(_menuSelection.section, _activeSubSectionId),
                            sectionIcon: isChatActive ? null : _iconForSection(_menuSelection.section),
                            showMenuButton: true,
                            onMenuTap: () => _scaffoldKey.currentState?.openDrawer(),
                            showBackButton: _showBackButtonForSection(),
                            onBackTap: _handleBack,
                            leading: const [],
                            trailing: _buildTopActions(isChatActive),
                          ),
                          Expanded(
                            child: showConversationPane
                                ? Row(
                                    children: [
                                      SizedBox(
                                        width: layout.secondaryPaneWidth,
                                        child: ThreadSidebar(
                                          threads: threads,
                                          activeThreadId: _store.activeThreadId,
                                          activeSection: _menuSelection.section,
                                          onSelectThread: _onThreadSelected,
                                          onCreateThread: _promptCreateThread,
                                          onSelectSection: _onNavSection,
                                          pairingCode: _store.pairingCode,
                                          footer: _buildChatSettingsFooter(),
                                        ),
                                      ),
                                      const VerticalDivider(width: 1),
                                      Expanded(child: _buildPrimaryContent(threads, activeThread)),
                                    ],
                                  )
                                : (showMainList ? sidebar : _buildPrimaryContent(threads, activeThread)),
                          ),
                          if (isChatActive)
                            ComposerBar(
                              controller: _composer,
                              onAdd: _promptCreateThread,
                              onSend: _handleSend,
                              enabled: activeThread != null,
                              focusNode: _composerFocus,
                            ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
              drawer: Drawer(
                child: GlobalMenuDrawer(
                  activeSection: _menuSelection.section,
                  onSelect: _handleDrawerSelect,
                ),
              ),
            );
          },
        );
      },
    );
  }

  // --- navigation helpers ---

  void _onThreadSelected(String id) {
    _store.selectThread(id);
    if (_menuSelection.section != GlobalMenuSection.chat) {
      setState(() {
        _menuSelection = _selectionForSection(GlobalMenuSection.chat);
      });
    }
    _activeSubSectionId = id;
    _composerFocus.requestFocus();
    _closeDrawer();
  }

  void _onNavSection(GlobalMenuSection section) {
    setState(() {
      _menuSelection = _selectionForSection(section);
      _activeSubSectionId = _defaultSubSectionId(section);
    });
    _closeDrawer();
  }

  void _closeDrawer() {
    if (_scaffoldKey.currentState?.isDrawerOpen == true) {
      _scaffoldKey.currentState?.closeDrawer();
    }
  }

  void _handleSelectSection(GlobalMenuSelection selection) {
    setState(() {
      _menuSelection = selection;
      _activeSubSectionId = selection.subSectionId ?? _activeSubSectionId;
    });
  }

  void _handleDrawerSelect(GlobalMenuSection section) {
    setState(() {
      _menuSelection = _selectionForSection(section);
      _activeSubSectionId = _defaultSubSectionId(section);
    });
    _closeDrawer();
  }

  static GlobalMenuSelection _selectionForSection(GlobalMenuSection section) {
    switch (section) {
      case GlobalMenuSection.chat:
        return const GlobalMenuSelection(section: GlobalMenuSection.chat, title: 'Chat');
      case GlobalMenuSection.files:
        return const GlobalMenuSelection(
            section: GlobalMenuSection.files, title: 'Files', subtitle: 'Transfer activity and history');
      case GlobalMenuSection.networkOptions:
        return const GlobalMenuSelection(
            section: GlobalMenuSection.networkOptions, title: 'Network', subtitle: 'VPN routing and discovery');
      case GlobalMenuSection.meshOptions:
        return const GlobalMenuSelection(
            section: GlobalMenuSection.meshOptions, title: 'Peers', subtitle: 'Connected peers and trust');
      case GlobalMenuSection.trustCenter:
        return const GlobalMenuSelection(
            section: GlobalMenuSection.trustCenter, title: 'Trust Center', subtitle: 'Attestations and verification');
      case GlobalMenuSection.applicationSettings:
        return const GlobalMenuSelection(
            section: GlobalMenuSection.applicationSettings, title: 'Settings', subtitle: 'Preferences and node mode');
    }
  }

  static IconData? _iconForSection(GlobalMenuSection section) {
    switch (section) {
      case GlobalMenuSection.chat:
        return null;
      case GlobalMenuSection.files:
        return Icons.folder_open_outlined;
      case GlobalMenuSection.networkOptions:
        return Icons.hub_outlined;
      case GlobalMenuSection.meshOptions:
        return Icons.people_outlined;
      case GlobalMenuSection.trustCenter:
        return Icons.shield_outlined;
      case GlobalMenuSection.applicationSettings:
        return Icons.settings_outlined;
    }
  }

  // --- backend action handlers (unchanged) ---

  void _handleUpdateSettings(BackendSettings updated) {
    final bridge = _store.backendBridge;
    final success = bridge.setTransportFlags(
      enableTor: updated.enableTor,
      enableClearnet: updated.enableClearnet,
      meshDiscovery: updated.meshDiscovery,
      allowRelays: updated.allowRelays,
      enableI2p: updated.enableI2p,
      enableBluetooth: updated.enableBluetooth,
    );
    if (success) {
      _store.refreshSettings();
    }
  }

  void _handleSelectNodeMode(BackendNodeMode mode) {
    final bridge = _store.backendBridge;
    final success = bridge.setNodeMode(mode.wireValue);
    if (success) {
      _store.refreshSettings();
    }
  }

  void _handleAttestTrust(TrustAttestationRequest request) {
    _store.attestTrust(
      targetPeerId: request.peerId,
      trustLevel: request.trustLevel,
      verificationMethod: request.verificationMethod,
    );
  }

  void _handleVerifyTrust(String peerId) {
    _store.verifyTrust(peerId);
  }

  ThreadSummary? _resolveActiveThread(List<ThreadSummary> threads, String? activeId) {
    if (threads.isEmpty) {
      return null;
    }
    if (activeId == null) {
      return threads.first;
    }
    return threads.firstWhere(
      (thread) => thread.id == activeId,
      orElse: () => threads.first,
    );
  }

  Future<void> _promptCreateThread() async {
    final controller = TextEditingController();
    final name = await showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('New conversation'),
        content: TextField(
          controller: controller,
          autofocus: true,
          decoration: const InputDecoration(hintText: 'Conversation name'),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, controller.text),
            child: const Text('Create'),
          ),
        ],
      ),
    );
    controller.dispose();
    if (name == null) {
      return;
    }
    final trimmed = name.trim();
    if (trimmed.isEmpty) {
      return;
    }
    await _store.createThread(trimmed);
  }

  void _handleSend(String text) {
    if (text.trim().isEmpty) {
      return;
    }
    _store.sendMessage(text);
    _composer.clear();
  }

  void _returnToChatList() {
    setState(() {
      _menuSelection = _selectionForSection(GlobalMenuSection.chat);
      _activeSubSectionId = 'chat-list';
    });
  }

  Widget _buildPrimaryContent(List<ThreadSummary> threads, ThreadSummary? activeThread) {
    final isChatActive = _menuSelection.section == GlobalMenuSection.chat;
    if (isChatActive) {
      return ConversationList(
        messages: _store.activeMessages,
        emptyState: activeThread == null
            ? _EmptyState(onCreate: _promptCreateThread)
            : _ChatEmptyState(onStart: () => _composerFocus.requestFocus()),
      );
    }
    return GlobalMenu(
      showHeader: false,
      selection: _menuSelection.subSectionId == null
          ? _menuSelection.copyWith(subSectionId: _activeSubSectionId)
          : _menuSelection,
      pairingCode: _store.pairingCode,
      peerCount: _store.peerCount,
      peers: _store.peers,
      transfers: _store.transfers,
      threads: threads,
      activeThreadId: _store.activeThreadId,
      onSelectThread: (id) => _store.selectThread(id),
      settings: _store.settings,
      onSelect: _handleSelectSection,
      onUpdateSettings: _handleUpdateSettings,
      onSelectNodeMode: _handleSelectNodeMode,
      onAttestTrust: _handleAttestTrust,
      onVerifyTrust: _handleVerifyTrust,
      lastVerifiedTrustLevel: _store.lastVerifiedTrustLevel,
    );
  }

  List<Widget> _buildTopActions(bool isChatActive) {
    final actions = <Widget>[
      IconButton(
        onPressed: () {},
        icon: const Icon(Icons.search),
        tooltip: 'Search',
      ),
    ];
    if (isChatActive) {
      actions.add(
        IconButton(
          onPressed: _promptCreateThread,
          icon: const Icon(Icons.add_comment_outlined),
          tooltip: 'New conversation',
        ),
      );
    }
    actions.add(
      IconButton(
        onPressed: () {},
        icon: const Icon(Icons.more_vert),
        tooltip: 'More',
      ),
    );
    return actions;
  }


  Widget _buildChatSettingsFooter() {
    final cs = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
      child: Column(
        children: [
          OutlinedButton.icon(
            onPressed: () => _openChatSettings(),
            icon: const Icon(Icons.settings_outlined, size: 18),
            label: const Text('Chat settings'),
          ),
          const SizedBox(height: 8),
          Text('TODO: add per-chat preferences', style: TextStyle(color: cs.onSurfaceVariant, fontSize: 12)),
        ],
      ),
    );
  }

  Widget _buildSectionSidebar(
    BuildContext context, {
    required GlobalMenuSection section,
    required List<ThreadSummary> threads,
    required LayoutSpec layout,
    required String? selectionId,
  }) {
    switch (section) {
      case GlobalMenuSection.chat:
        return ThreadSidebar(
          threads: threads,
          activeThreadId: _store.activeThreadId,
          activeSection: section,
          onSelectThread: _onThreadSelected,
          onCreateThread: _promptCreateThread,
          onSelectSection: _onNavSection,
          pairingCode: _store.pairingCode,
          footer: _buildChatSettingsFooter(),
        );
      case GlobalMenuSection.files:
        return SectionSidebar(
          title: 'Files',
          items: _filesSidebarItems(),
          activeSectionId: selectionId,
          onSelect: _onFilesSubSection,
        );
      case GlobalMenuSection.networkOptions:
        return SectionSidebar(
          title: 'Network',
          items: _networkSidebarItems(),
          activeSectionId: selectionId,
          onSelect: _onNetworkSubSection,
        );
      case GlobalMenuSection.meshOptions:
      case GlobalMenuSection.trustCenter:
        return SectionSidebar(
          title: 'Peers',
          items: _peersSidebarItems(),
          activeSectionId: selectionId,
          onSelect: _onPeersSubSection,
        );
      case GlobalMenuSection.applicationSettings:
        return SectionSidebar(
          title: 'Settings',
          items: _settingsSidebarItems(),
          activeSectionId: selectionId,
          onSelect: _onSettingsSubSection,
        );
    }
  }

  String? _sidebarSelectionId({
    required GlobalMenuSection section,
    required String? explicit,
  }) {
    if (section == GlobalMenuSection.trustCenter) {
      return 'trust-center';
    }
    return explicit ?? _defaultSubSectionId(section);
  }

  String? _defaultSubSectionId(GlobalMenuSection section) {
    switch (section) {
      case GlobalMenuSection.chat:
        return _store.activeThreadId ?? 'chat-list';
      case GlobalMenuSection.files:
        return 'transfers';
      case GlobalMenuSection.networkOptions:
        return 'transports';
      case GlobalMenuSection.meshOptions:
        return 'peers';
      case GlobalMenuSection.trustCenter:
        return 'trust-center';
      case GlobalMenuSection.applicationSettings:
        return 'preferences';
    }
  }

  List<SectionNavItem> _filesSidebarItems() {
    return SectionNavCatalog.files;
  }

  List<SectionNavItem> _chatSidebarItems() {
    return SectionNavCatalog.chat;
  }

  List<SectionNavItem> _networkSidebarItems() {
    return SectionNavCatalog.network;
  }

  List<SectionNavItem> _peersSidebarItems() {
    return SectionNavCatalog.peers;
  }

  List<SectionNavItem> _settingsSidebarItems() {
    return SectionNavCatalog.settings;
  }

  void _onFilesSubSection(String id) {
    setState(() => _activeSubSectionId = id);
  }

  void _onChatSubSection(String id) {
    setState(() => _activeSubSectionId = id);
  }

  void _onNetworkSubSection(String id) {
    setState(() => _activeSubSectionId = id);
  }

  void _onPeersSubSection(String id) {
    setState(() {
      _activeSubSectionId = id;
      if (id == 'trust-center') {
        _menuSelection = _selectionForSection(GlobalMenuSection.trustCenter);
      } else {
        _menuSelection = _selectionForSection(GlobalMenuSection.meshOptions);
      }
    });
  }

  void _onSettingsSubSection(String id) {
    setState(() => _activeSubSectionId = id);
  }

  void _openChatSettings() {
    setState(() {
      _menuSelection = _selectionForSection(GlobalMenuSection.chat);
      _activeSubSectionId = 'chat-settings';
    });
  }

  bool _showBackButtonForSection() {
    switch (_menuSelection.section) {
      case GlobalMenuSection.chat:
        return _activeSubSectionId != null && _activeSubSectionId != 'chat-list';
      case GlobalMenuSection.applicationSettings:
        return _activeSubSectionId != null && _activeSubSectionId != 'preferences';
      case GlobalMenuSection.files:
        return _activeSubSectionId != null && _activeSubSectionId != 'transfers';
      case GlobalMenuSection.networkOptions:
        return _activeSubSectionId != null && _activeSubSectionId != 'transports';
      case GlobalMenuSection.meshOptions:
        return _activeSubSectionId != null && _activeSubSectionId != 'peers';
      case GlobalMenuSection.trustCenter:
        return true;
    }
  }

  void _handleBack() {
    switch (_menuSelection.section) {
      case GlobalMenuSection.chat:
        _returnToChatList();
        return;
      case GlobalMenuSection.applicationSettings:
        setState(() => _activeSubSectionId = 'preferences');
        return;
      case GlobalMenuSection.files:
        setState(() => _activeSubSectionId = 'transfers');
        return;
      case GlobalMenuSection.networkOptions:
        setState(() => _activeSubSectionId = 'transports');
        return;
      case GlobalMenuSection.meshOptions:
        setState(() => _activeSubSectionId = 'peers');
        return;
      case GlobalMenuSection.trustCenter:
        setState(() {
          _menuSelection = _selectionForSection(GlobalMenuSection.meshOptions);
          _activeSubSectionId = 'peers';
        });
        return;
    }
  }

  String _resolveSectionTitle(GlobalMenuSection section, String? subSectionId) {
    final item = _lookupSubSection(section, subSectionId);
    if (item != null) {
      return item.title;
    }
    return _menuSelection.title;
  }

  String? _resolveSectionSubtitle(GlobalMenuSection section, String? subSectionId) {
    final item = _lookupSubSection(section, subSectionId);
    if (item != null) {
      return item.subtitle;
    }
    return _menuSelection.subtitle;
  }

  SectionNavItem? _lookupSubSection(GlobalMenuSection section, String? subSectionId) {
    if (subSectionId == null) {
      return null;
    }
    final items = _sidebarItemsForSection(section);
    return items.firstWhere(
      (item) => item.id == subSectionId,
      orElse: () => SectionNavItem(
        id: 'unknown',
        title: _menuSelection.title,
        icon: _iconForSection(section) ?? Icons.view_list_outlined,
        subtitle: _menuSelection.subtitle,
      ),
    );
  }

  List<SectionNavItem> _sidebarItemsForSection(GlobalMenuSection section) {
    switch (section) {
      case GlobalMenuSection.files:
        return SectionNavCatalog.files;
      case GlobalMenuSection.networkOptions:
        return SectionNavCatalog.network;
      case GlobalMenuSection.meshOptions:
      case GlobalMenuSection.trustCenter:
        return SectionNavCatalog.peers;
      case GlobalMenuSection.applicationSettings:
        return SectionNavCatalog.settings;
      case GlobalMenuSection.chat:
        return const [];
    }
  }
}

class _EmptyState extends StatelessWidget {
  const _EmptyState({super.key, required this.onCreate});

  final VoidCallback onCreate;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.forum_outlined, size: 48, color: cs.onSurfaceVariant),
            const SizedBox(height: 12),
            Text(
              'No conversations yet',
              style: Theme.of(context).textTheme.bodyLarge?.copyWith(fontWeight: FontWeight.w600),
            ),
            const SizedBox(height: 6),
            Text(
              'Create a conversation to start exchanging keys and messages.',
              textAlign: TextAlign.center,
              style: TextStyle(color: cs.onSurfaceVariant),
            ),
            const SizedBox(height: 16),
            FilledButton.icon(
              onPressed: onCreate,
              icon: const Icon(Icons.add_comment_outlined),
              label: const Text('New conversation'),
            ),
          ],
        ),
      ),
    );
  }
}

class _ChatEmptyState extends StatelessWidget {
  const _ChatEmptyState({super.key, required this.onStart});

  final VoidCallback onStart;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.chat_bubble_outline, size: 46, color: cs.onSurfaceVariant),
            const SizedBox(height: 12),
            Text(
              'Conversation ready',
              style: Theme.of(context).textTheme.bodyLarge?.copyWith(fontWeight: FontWeight.w600),
            ),
            const SizedBox(height: 6),
            Text(
              'Send a message or share a pairing code to begin.',
              textAlign: TextAlign.center,
              style: TextStyle(color: cs.onSurfaceVariant),
            ),
            const SizedBox(height: 16),
            FilledButton.icon(
              onPressed: onStart,
              icon: const Icon(Icons.edit_outlined),
              label: const Text('Start typing'),
            ),
          ],
        ),
      ),
    );
  }
}
