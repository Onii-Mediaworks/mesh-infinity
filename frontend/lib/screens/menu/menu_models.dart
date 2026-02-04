import 'package:flutter/material.dart';

enum GlobalMenuSection {
  chat,
  files,
  networkOptions,
  meshOptions,
  trustCenter,
  applicationSettings,
}

class GlobalMenuSelection {
  const GlobalMenuSelection({
    required this.section,
    required this.title,
    this.subtitle,
    this.subSectionId,
  });

  final GlobalMenuSection section;
  final String title;
  final String? subtitle;
  final String? subSectionId;

  GlobalMenuSelection copyWith({
    GlobalMenuSection? section,
    String? title,
    String? subtitle,
    String? subSectionId,
  }) {
    return GlobalMenuSelection(
      section: section ?? this.section,
      title: title ?? this.title,
      subtitle: subtitle ?? this.subtitle,
      subSectionId: subSectionId ?? this.subSectionId,
    );
  }
}

class SectionNavItem {
  const SectionNavItem({
    required this.id,
    required this.title,
    required this.icon,
    this.subtitle,
  });

  final String id;
  final String title;
  final IconData icon;
  final String? subtitle;
}

class SectionNavCatalog {
  static const chat = [
    SectionNavItem(
      id: 'chat-settings',
      title: 'Chat settings',
      subtitle: 'Messaging defaults',
      icon: Icons.tune_outlined,
    ),
  ];

  static const files = [
    SectionNavItem(
      id: 'transfers',
      title: 'Transfers',
      subtitle: 'Active and queued',
      icon: Icons.swap_vert_circle_outlined,
    ),
    SectionNavItem(
      id: 'history',
      title: 'History',
      subtitle: 'Completed and failed',
      icon: Icons.history,
    ),
    SectionNavItem(
      id: 'storage',
      title: 'Storage',
      subtitle: 'Local caches and paths',
      icon: Icons.sd_storage_outlined,
    ),
    SectionNavItem(
      id: 'settings',
      title: 'Settings',
      subtitle: 'Transfer behavior',
      icon: Icons.tune_outlined,
    ),
  ];

  static const network = [
    SectionNavItem(
      id: 'transports',
      title: 'Transports',
      subtitle: 'Connectivity options',
      icon: Icons.hub_outlined,
    ),
    SectionNavItem(
      id: 'routing',
      title: 'Routing',
      subtitle: 'Exit nodes and VPN',
      icon: Icons.alt_route_outlined,
    ),
    SectionNavItem(
      id: 'discovery',
      title: 'Discovery',
      subtitle: 'Mesh availability',
      icon: Icons.radar,
    ),
    SectionNavItem(
      id: 'settings',
      title: 'Settings',
      subtitle: 'Network defaults',
      icon: Icons.tune_outlined,
    ),
  ];

  static const peers = [
    SectionNavItem(
      id: 'peers',
      title: 'Connected peers',
      subtitle: 'Trust + presence',
      icon: Icons.people_outlined,
    ),
    SectionNavItem(
      id: 'trust-center',
      title: 'Trust Center',
      subtitle: 'Attestations and verification',
      icon: Icons.shield_outlined,
    ),
    SectionNavItem(
      id: 'settings',
      title: 'Settings',
      subtitle: 'Trust defaults',
      icon: Icons.tune_outlined,
    ),
  ];

  static const settings = [
    SectionNavItem(
      id: 'preferences',
      title: 'Preferences',
      subtitle: 'Theme and defaults',
      icon: Icons.tune_outlined,
    ),
    SectionNavItem(
      id: 'node',
      title: 'Node mode',
      subtitle: 'Client, server, dual',
      icon: Icons.device_hub_outlined,
    ),
    SectionNavItem(
      id: 'identity',
      title: 'Identity',
      subtitle: 'Local peer profile',
      icon: Icons.badge_outlined,
    ),
    SectionNavItem(
      id: 'about',
      title: 'About',
      subtitle: 'Versions and licenses',
      icon: Icons.info_outline,
    ),
  ];
}
