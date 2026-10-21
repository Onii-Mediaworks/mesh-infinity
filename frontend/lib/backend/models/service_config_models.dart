// service_config_models.dart
//
// Typed models for the protocol server settings edited by the §22.54.5–
// §22.54.9 configuration screens.  Each class mirrors the Rust struct of the
// same name in `backend/services/server_config.rs`, field for field, with
// the same `snake_case` JSON keys, so a value that round-trips here
// round-trips there.
//
// WHY TYPED MODELS?
// -----------------
// The screens validate on every keystroke (§22.54.4) and need to compare an
// edited copy against the loaded one to know whether to prompt "Discard
// changes?".  Immutable value objects with `copyWith` and `==` make both
// cheap and obvious; raw maps would hide typos until runtime.
//
// The floors and limits here duplicate the Rust constants on purpose: the
// spec requires the UI and backend limits to agree so that nothing the UI
// accepts is refused for a format reason.

import 'package:flutter/foundation.dart';

// ---------------------------------------------------------------------------
// Shared constants (§20 floors, §22.54 limits)
// ---------------------------------------------------------------------------

/// Highest trust level in the §8.1 table.
const int trustMax = 8;

/// §20.2.1: view-only Remote Desktop floor.
const int mnrdpViewFloor = 5;

/// §20.2.1: input / AppStream / AppGallery floor.
const int mnrdpInputFloor = 6;

/// §22.54.5: the sessions slider runs 1–8.
const int mnrdpMaxSessions = 8;

/// §20.3.1: shell access floor.
const int mnspFloor = 6;

/// §20.4.1: file read floor.
const int mnfpFloor = 6;

/// §20.4.1: default file write floor.
const int mnfpWriteDefault = 7;

/// §20.5.1: API gateway floor.
const int apiGatewayFloor = 5;

/// §22.54.8: the rate limit runs 1–100 000.
const int apiGatewayRateMax = 100000;

/// §20.8.1: print floor.
const int printFloor = 5;

/// §22.54.7 / §22.54.9: names are 1–64 characters.
const int nameMaxChars = 64;

/// The HTTP methods the §22.54.8 chip set offers, in display order.
const List<String> httpMethods = [
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'HEAD',
  'OPTIONS',
];

/// §8.1 names for levels 0–8, used by the trust floor selector rows.
const List<String> trustLevelNames = [
  'Unknown',
  'Public',
  'Vouched',
  'Referenced',
  'Ally',
  'Acquaintance',
  'Trusted',
  'Highly Trusted',
  'Inner Circle',
];

/// Read an int from JSON tolerating `num`, clamping nothing: the backend
/// already validated the stored value, and the screens validate edits.
int _int(Object? v, int fallback) => v is num ? v.toInt() : fallback;

/// Read a bool from JSON.
bool _bool(Object? v, bool fallback) => v is bool ? v : fallback;

/// Read a string from JSON.
String _str(Object? v, String fallback) => v is String ? v : fallback;

/// Read a list of strings from JSON, dropping non-string entries.
List<String> _strings(Object? v) =>
    v is List ? v.whereType<String>().toList() : const [];

/// Read a list of maps from JSON, dropping other entries.
List<Map<String, dynamic>> _maps(Object? v) => v is List
    ? v.whereType<Map>().map((m) => Map<String, dynamic>.from(m)).toList()
    : const [];

// ---------------------------------------------------------------------------
// MNRDP — Remote Desktop (§22.54.5)
// ---------------------------------------------------------------------------

/// Remote Desktop server settings.
@immutable
class MnrdpConfig {
  const MnrdpConfig({
    this.view_floor = mnrdpViewFloor,
    this.input_floor = mnrdpInputFloor,
    this.full_desktop = true,
    this.app_stream = true,
    this.app_gallery = true,
    this.vnc_adapter = false,
    this.nx_adapter = false,
    this.ard_adapter = false,
    this.max_sessions = 2,
  });

  /// Lowest level allowed to connect in view-only mode.
  final int view_floor;

  /// Lowest level allowed input, AppStream and AppGallery.
  final int input_floor;

  /// Offer full-desktop sessions.
  final bool full_desktop;

  /// Offer app-streaming sessions.
  final bool app_stream;

  /// Offer the app gallery.
  final bool app_gallery;

  /// Bridge existing VNC clients.
  final bool vnc_adapter;

  /// Bridge existing NX clients.
  final bool nx_adapter;

  /// Bridge Apple Remote Desktop (macOS only).
  final bool ard_adapter;

  /// Simultaneous sessions, 1–8.
  final int max_sessions;

  factory MnrdpConfig.fromJson(Map<String, dynamic> j) => MnrdpConfig(
    view_floor: _int(j['view_floor'], mnrdpViewFloor),
    input_floor: _int(j['input_floor'], mnrdpInputFloor),
    full_desktop: _bool(j['full_desktop'], true),
    app_stream: _bool(j['app_stream'], true),
    app_gallery: _bool(j['app_gallery'], true),
    vnc_adapter: _bool(j['vnc_adapter'], false),
    nx_adapter: _bool(j['nx_adapter'], false),
    ard_adapter: _bool(j['ard_adapter'], false),
    max_sessions: _int(j['max_sessions'], 2),
  );

  Map<String, dynamic> toJson() => {
    'view_floor': view_floor,
    'input_floor': input_floor,
    'full_desktop': full_desktop,
    'app_stream': app_stream,
    'app_gallery': app_gallery,
    'vnc_adapter': vnc_adapter,
    'nx_adapter': nx_adapter,
    'ard_adapter': ard_adapter,
    'max_sessions': max_sessions,
  };

  MnrdpConfig copyWith({
    int? view_floor,
    int? input_floor,
    bool? full_desktop,
    bool? app_stream,
    bool? app_gallery,
    bool? vnc_adapter,
    bool? nx_adapter,
    bool? ard_adapter,
    int? max_sessions,
  }) => MnrdpConfig(
    view_floor: view_floor ?? this.view_floor,
    input_floor: input_floor ?? this.input_floor,
    full_desktop: full_desktop ?? this.full_desktop,
    app_stream: app_stream ?? this.app_stream,
    app_gallery: app_gallery ?? this.app_gallery,
    vnc_adapter: vnc_adapter ?? this.vnc_adapter,
    nx_adapter: nx_adapter ?? this.nx_adapter,
    ard_adapter: ard_adapter ?? this.ard_adapter,
    max_sessions: max_sessions ?? this.max_sessions,
  );

  /// At least one session mode must stay on (§22.54.5).
  bool get any_mode => full_desktop || app_stream || app_gallery;

  @override
  bool operator ==(Object other) =>
      other is MnrdpConfig && mapEquals(toJson(), other.toJson());

  @override
  int get hashCode => Object.hashAll(toJson().values);
}

// ---------------------------------------------------------------------------
// MNSP — Remote Shell (§22.54.6)
// ---------------------------------------------------------------------------

/// One explicit shell grant: a contact mapped to a local OS account.
@immutable
class MnspUserMapping {
  const MnspUserMapping({
    required this.peer_id,
    required this.display_name,
    required this.local_user,
    required this.allowed_shells,
    this.allowed_commands,
    required this.working_dir,
  });

  /// Hex mesh peer ID.
  final String peer_id;

  /// Name captured when the grant was made (for the row label).
  final String display_name;

  /// Local OS account the session runs as.
  final String local_user;

  /// Shells the contact may use; at least one.
  final List<String> allowed_shells;

  /// Null = any command; otherwise a command allowlist.
  final List<String>? allowed_commands;

  /// Starting folder.
  final String working_dir;

  factory MnspUserMapping.fromJson(Map<String, dynamic> j) => MnspUserMapping(
    peer_id: _str(j['peer_id'], ''),
    display_name: _str(j['display_name'], ''),
    local_user: _str(j['local_user'], ''),
    allowed_shells: _strings(j['allowed_shells']),
    allowed_commands: j['allowed_commands'] == null
        ? null
        : _strings(j['allowed_commands']),
    working_dir: _str(j['working_dir'], ''),
  );

  Map<String, dynamic> toJson() => {
    'peer_id': peer_id,
    'display_name': display_name,
    'local_user': local_user,
    'allowed_shells': allowed_shells,
    'allowed_commands': allowed_commands,
    'working_dir': working_dir,
  };

  MnspUserMapping copyWith({
    String? peer_id,
    String? display_name,
    String? local_user,
    List<String>? allowed_shells,
    // A sentinel distinguishes "leave as is" from "set to any command".
    Object? allowed_commands = _unset,
    String? working_dir,
  }) => MnspUserMapping(
    peer_id: peer_id ?? this.peer_id,
    display_name: display_name ?? this.display_name,
    local_user: local_user ?? this.local_user,
    allowed_shells: allowed_shells ?? this.allowed_shells,
    allowed_commands: identical(allowed_commands, _unset)
        ? this.allowed_commands
        : allowed_commands as List<String>?,
    working_dir: working_dir ?? this.working_dir,
  );

  /// Label for the list row: the captured name, else a shortened ID.
  String get label => display_name.isNotEmpty
      ? display_name
      : (peer_id.length > 12 ? '${peer_id.substring(0, 12)}…' : peer_id);

  @override
  bool operator ==(Object other) =>
      other is MnspUserMapping &&
      peer_id == other.peer_id &&
      display_name == other.display_name &&
      local_user == other.local_user &&
      listEquals(allowed_shells, other.allowed_shells) &&
      listEquals(allowed_commands, other.allowed_commands) &&
      working_dir == other.working_dir;

  @override
  int get hashCode => Object.hash(
    peer_id,
    display_name,
    local_user,
    Object.hashAll(allowed_shells),
    allowed_commands == null ? null : Object.hashAll(allowed_commands!),
    working_dir,
  );
}

/// Sentinel for `copyWith` optional-nullable fields.
const Object _unset = Object();

/// Remote Shell server settings.
@immutable
class MnspConfig {
  const MnspConfig({
    this.trust_floor = mnspFloor,
    this.user_map = const [],
    this.ssh_adapter = false,
    this.sshd_port = 22,
  });

  /// Lowest level that may hold a shell grant.
  final int trust_floor;

  /// Explicit grants; empty means nobody can connect.
  final List<MnspUserMapping> user_map;

  /// Forward mesh connections to the local sshd.
  final bool ssh_adapter;

  /// Local sshd port.
  final int sshd_port;

  factory MnspConfig.fromJson(Map<String, dynamic> j) => MnspConfig(
    trust_floor: _int(j['trust_floor'], mnspFloor),
    user_map: _maps(j['user_map']).map(MnspUserMapping.fromJson).toList(),
    ssh_adapter: _bool(j['ssh_adapter'], false),
    sshd_port: _int(j['sshd_port'], 22),
  );

  Map<String, dynamic> toJson() => {
    'trust_floor': trust_floor,
    'user_map': user_map.map((m) => m.toJson()).toList(),
    'ssh_adapter': ssh_adapter,
    'sshd_port': sshd_port,
  };

  MnspConfig copyWith({
    int? trust_floor,
    List<MnspUserMapping>? user_map,
    bool? ssh_adapter,
    int? sshd_port,
  }) => MnspConfig(
    trust_floor: trust_floor ?? this.trust_floor,
    user_map: user_map ?? this.user_map,
    ssh_adapter: ssh_adapter ?? this.ssh_adapter,
    sshd_port: sshd_port ?? this.sshd_port,
  );

  @override
  bool operator ==(Object other) =>
      other is MnspConfig &&
      trust_floor == other.trust_floor &&
      listEquals(user_map, other.user_map) &&
      ssh_adapter == other.ssh_adapter &&
      sshd_port == other.sshd_port;

  @override
  int get hashCode =>
      Object.hash(trust_floor, Object.hashAll(user_map), ssh_adapter, sshd_port);
}

// ---------------------------------------------------------------------------
// MNFP — File Access (§22.54.7)
// ---------------------------------------------------------------------------

/// §20.4.1 `MnfpAccess`, serialised with the Rust variant names.
enum MnfpAccess {
  readOnly('ReadOnly', 'Read only'),
  readWrite('ReadWrite', 'Read and write'),
  writeOnly('WriteOnly', 'Write only');

  const MnfpAccess(this.wire, this.label);

  /// The Rust enum variant name on the wire.
  final String wire;

  /// Plain-language label for the segmented control.
  final String label;

  /// Whether this access lets contacts change files.
  bool get allows_write => this != MnfpAccess.readOnly;

  static MnfpAccess fromWire(Object? v) => MnfpAccess.values.firstWhere(
    (a) => a.wire == v,
    orElse: () => MnfpAccess.readOnly,
  );
}

/// A per-contact exception on a share.
@immutable
class MnfpPeerOverride {
  const MnfpPeerOverride({
    required this.peer_id,
    required this.display_name,
    required this.access,
  });

  /// Hex mesh peer ID.
  final String peer_id;

  /// Name captured when the exception was made.
  final String display_name;

  /// Access this contact gets instead of the share's.
  final MnfpAccess access;

  factory MnfpPeerOverride.fromJson(Map<String, dynamic> j) => MnfpPeerOverride(
    peer_id: _str(j['peer_id'], ''),
    display_name: _str(j['display_name'], ''),
    access: MnfpAccess.fromWire(j['access']),
  );

  Map<String, dynamic> toJson() => {
    'peer_id': peer_id,
    'display_name': display_name,
    'access': access.wire,
  };

  /// Label for the row: the captured name, else a shortened ID.
  String get label => display_name.isNotEmpty
      ? display_name
      : (peer_id.length > 12 ? '${peer_id.substring(0, 12)}…' : peer_id);

  @override
  bool operator ==(Object other) =>
      other is MnfpPeerOverride &&
      peer_id == other.peer_id &&
      display_name == other.display_name &&
      access == other.access;

  @override
  int get hashCode => Object.hash(peer_id, display_name, access);
}

/// One shared folder.
@immutable
class MnfpShare {
  const MnfpShare({
    required this.name,
    required this.root_path,
    this.access = MnfpAccess.readOnly,
    this.min_trust_level = mnfpFloor,
    this.write_trust_level = mnfpWriteDefault,
    this.peer_overrides = const [],
    this.hidden = false,
  });

  /// Share name, 1–64 characters, unique.
  final String name;

  /// Absolute folder path.
  final String root_path;

  /// Maximum access granted.
  final MnfpAccess access;

  /// Read floor.
  final int min_trust_level;

  /// Write floor (≥ read floor).
  final int write_trust_level;

  /// Per-contact exceptions.
  final List<MnfpPeerOverride> peer_overrides;

  /// Not advertised; reachable by name only.
  final bool hidden;

  factory MnfpShare.fromJson(Map<String, dynamic> j) => MnfpShare(
    name: _str(j['name'], ''),
    root_path: _str(j['root_path'], ''),
    access: MnfpAccess.fromWire(j['access']),
    min_trust_level: _int(j['min_trust_level'], mnfpFloor),
    write_trust_level: _int(j['write_trust_level'], mnfpWriteDefault),
    peer_overrides: _maps(
      j['peer_overrides'],
    ).map(MnfpPeerOverride.fromJson).toList(),
    hidden: _bool(j['hidden'], false),
  );

  Map<String, dynamic> toJson() => {
    'name': name,
    'root_path': root_path,
    'access': access.wire,
    'min_trust_level': min_trust_level,
    'write_trust_level': write_trust_level,
    'peer_overrides': peer_overrides.map((o) => o.toJson()).toList(),
    'hidden': hidden,
  };

  MnfpShare copyWith({
    String? name,
    String? root_path,
    MnfpAccess? access,
    int? min_trust_level,
    int? write_trust_level,
    List<MnfpPeerOverride>? peer_overrides,
    bool? hidden,
  }) => MnfpShare(
    name: name ?? this.name,
    root_path: root_path ?? this.root_path,
    access: access ?? this.access,
    min_trust_level: min_trust_level ?? this.min_trust_level,
    write_trust_level: write_trust_level ?? this.write_trust_level,
    peer_overrides: peer_overrides ?? this.peer_overrides,
    hidden: hidden ?? this.hidden,
  );

  @override
  bool operator ==(Object other) =>
      other is MnfpShare &&
      name == other.name &&
      root_path == other.root_path &&
      access == other.access &&
      min_trust_level == other.min_trust_level &&
      write_trust_level == other.write_trust_level &&
      listEquals(peer_overrides, other.peer_overrides) &&
      hidden == other.hidden;

  @override
  int get hashCode => Object.hash(
    name,
    root_path,
    access,
    min_trust_level,
    write_trust_level,
    Object.hashAll(peer_overrides),
    hidden,
  );
}

/// File Access server settings.
@immutable
class MnfpConfig {
  const MnfpConfig({
    this.shares = const [],
    this.smb_adapter = false,
    this.nfs_adapter = false,
    this.sftp_via_ssh = false,
  });

  /// Shared folders.
  final List<MnfpShare> shares;

  /// Bridge the SMB adapter.
  final bool smb_adapter;

  /// Bridge the NFS adapter.
  final bool nfs_adapter;

  /// SFTP via the Remote Shell SSH adapter.
  final bool sftp_via_ssh;

  factory MnfpConfig.fromJson(Map<String, dynamic> j) => MnfpConfig(
    shares: _maps(j['shares']).map(MnfpShare.fromJson).toList(),
    smb_adapter: _bool(j['smb_adapter'], false),
    nfs_adapter: _bool(j['nfs_adapter'], false),
    sftp_via_ssh: _bool(j['sftp_via_ssh'], false),
  );

  Map<String, dynamic> toJson() => {
    'shares': shares.map((s) => s.toJson()).toList(),
    'smb_adapter': smb_adapter,
    'nfs_adapter': nfs_adapter,
    'sftp_via_ssh': sftp_via_ssh,
  };

  MnfpConfig copyWith({
    List<MnfpShare>? shares,
    bool? smb_adapter,
    bool? nfs_adapter,
    bool? sftp_via_ssh,
  }) => MnfpConfig(
    shares: shares ?? this.shares,
    smb_adapter: smb_adapter ?? this.smb_adapter,
    nfs_adapter: nfs_adapter ?? this.nfs_adapter,
    sftp_via_ssh: sftp_via_ssh ?? this.sftp_via_ssh,
  );

  @override
  bool operator ==(Object other) =>
      other is MnfpConfig &&
      listEquals(shares, other.shares) &&
      smb_adapter == other.smb_adapter &&
      nfs_adapter == other.nfs_adapter &&
      sftp_via_ssh == other.sftp_via_ssh;

  @override
  int get hashCode =>
      Object.hash(Object.hashAll(shares), smb_adapter, nfs_adapter, sftp_via_ssh);
}

// ---------------------------------------------------------------------------
// API Gateway (§22.54.8)
// ---------------------------------------------------------------------------

/// §20.5.1 `MeshApiAuthMode`, serialised with the Rust variant names.
enum ApiAuthMode {
  none('None', 'Trust gate only', 'The service sees the contact\'s mesh ID and trust level in request headers, nothing else.'),
  bearerPeerToken('BearerPeerToken', 'Bearer token per peer', 'Each contact gets a stable token in the Authorization header so the service can tell them apart.'),
  clientCert('ClientCert', 'Client certificate', 'Each request carries a certificate signed by this device so the service can verify who is calling.');

  const ApiAuthMode(this.wire, this.label, this.helper);

  /// The Rust enum variant name on the wire.
  final String wire;

  /// Radio label.
  final String label;

  /// One-line helper describing what the upstream receives (§22.54.8).
  final String helper;

  static ApiAuthMode fromWire(Object? v) => ApiAuthMode.values.firstWhere(
    (a) => a.wire == v,
    orElse: () => ApiAuthMode.none,
  );
}

/// API Gateway settings.
@immutable
class ApiGatewayConfig {
  const ApiGatewayConfig({
    this.upstream_url = 'http://127.0.0.1:8080',
    this.min_trust_level = apiGatewayFloor,
    this.auth_mode = ApiAuthMode.none,
    this.rate_limit,
    this.allowed_methods,
    this.path_prefix,
  });

  /// Local service address.
  final String upstream_url;

  /// Trust floor.
  final int min_trust_level;

  /// Authentication mode.
  final ApiAuthMode auth_mode;

  /// Requests per minute per contact; null = unlimited.
  final int? rate_limit;

  /// Allowed methods; null = all.
  final List<String>? allowed_methods;

  /// Path prefix; null = all paths.
  final String? path_prefix;

  factory ApiGatewayConfig.fromJson(Map<String, dynamic> j) => ApiGatewayConfig(
    upstream_url: _str(j['upstream_url'], 'http://127.0.0.1:8080'),
    min_trust_level: _int(j['min_trust_level'], apiGatewayFloor),
    auth_mode: ApiAuthMode.fromWire(j['auth_mode']),
    rate_limit: j['rate_limit'] is num ? (j['rate_limit'] as num).toInt() : null,
    allowed_methods: j['allowed_methods'] == null
        ? null
        : _strings(j['allowed_methods']),
    path_prefix: j['path_prefix'] is String ? j['path_prefix'] as String : null,
  );

  Map<String, dynamic> toJson() => {
    'upstream_url': upstream_url,
    'min_trust_level': min_trust_level,
    'auth_mode': auth_mode.wire,
    'rate_limit': rate_limit,
    'allowed_methods': allowed_methods,
    'path_prefix': path_prefix,
  };

  ApiGatewayConfig copyWith({
    String? upstream_url,
    int? min_trust_level,
    ApiAuthMode? auth_mode,
    Object? rate_limit = _unset,
    Object? allowed_methods = _unset,
    Object? path_prefix = _unset,
  }) => ApiGatewayConfig(
    upstream_url: upstream_url ?? this.upstream_url,
    min_trust_level: min_trust_level ?? this.min_trust_level,
    auth_mode: auth_mode ?? this.auth_mode,
    rate_limit: identical(rate_limit, _unset)
        ? this.rate_limit
        : rate_limit as int?,
    allowed_methods: identical(allowed_methods, _unset)
        ? this.allowed_methods
        : allowed_methods as List<String>?,
    path_prefix: identical(path_prefix, _unset)
        ? this.path_prefix
        : path_prefix as String?,
  );

  /// The methods currently allowed: the explicit list, or all of them.
  List<String> get effective_methods => allowed_methods ?? httpMethods;

  @override
  bool operator ==(Object other) =>
      other is ApiGatewayConfig &&
      upstream_url == other.upstream_url &&
      min_trust_level == other.min_trust_level &&
      auth_mode == other.auth_mode &&
      rate_limit == other.rate_limit &&
      listEquals(allowed_methods, other.allowed_methods) &&
      path_prefix == other.path_prefix;

  @override
  int get hashCode => Object.hash(
    upstream_url,
    min_trust_level,
    auth_mode,
    rate_limit,
    allowed_methods == null ? null : Object.hashAll(allowed_methods!),
    path_prefix,
  );
}

// ---------------------------------------------------------------------------
// Print Services (§22.54.9)
// ---------------------------------------------------------------------------

/// One shared printer queue.
@immutable
class SharedPrinter {
  const SharedPrinter({
    required this.ipp_url,
    required this.printer_name,
    this.min_trust_level = printFloor,
    this.capabilities = const [],
  });

  /// IPP queue URL.
  final String ipp_url;

  /// Name shown to contacts.
  final String printer_name;

  /// Who can print.
  final int min_trust_level;

  /// Capability tags discovered from the queue.
  final List<String> capabilities;

  factory SharedPrinter.fromJson(Map<String, dynamic> j) => SharedPrinter(
    ipp_url: _str(j['ipp_url'], ''),
    printer_name: _str(j['printer_name'], ''),
    min_trust_level: _int(j['min_trust_level'], printFloor),
    capabilities: _strings(j['capabilities']),
  );

  Map<String, dynamic> toJson() => {
    'ipp_url': ipp_url,
    'printer_name': printer_name,
    'min_trust_level': min_trust_level,
    'capabilities': capabilities,
  };

  SharedPrinter copyWith({
    String? ipp_url,
    String? printer_name,
    int? min_trust_level,
    List<String>? capabilities,
  }) => SharedPrinter(
    ipp_url: ipp_url ?? this.ipp_url,
    printer_name: printer_name ?? this.printer_name,
    min_trust_level: min_trust_level ?? this.min_trust_level,
    capabilities: capabilities ?? this.capabilities,
  );

  @override
  bool operator ==(Object other) =>
      other is SharedPrinter &&
      ipp_url == other.ipp_url &&
      printer_name == other.printer_name &&
      min_trust_level == other.min_trust_level &&
      listEquals(capabilities, other.capabilities);

  @override
  int get hashCode => Object.hash(
    ipp_url,
    printer_name,
    min_trust_level,
    Object.hashAll(capabilities),
  );
}

/// Print Services settings.
@immutable
class PrintConfig {
  const PrintConfig({this.printers = const []});

  /// Shared printers.
  final List<SharedPrinter> printers;

  factory PrintConfig.fromJson(Map<String, dynamic> j) => PrintConfig(
    printers: _maps(j['printers']).map(SharedPrinter.fromJson).toList(),
  );

  Map<String, dynamic> toJson() => {
    'printers': printers.map((p) => p.toJson()).toList(),
  };

  PrintConfig copyWith({List<SharedPrinter>? printers}) =>
      PrintConfig(printers: printers ?? this.printers);

  @override
  bool operator ==(Object other) =>
      other is PrintConfig && listEquals(printers, other.printers);

  @override
  int get hashCode => Object.hashAll(printers);
}

/// A queue reported by the local spooler or probed by URL.
@immutable
class PrintQueue {
  const PrintQueue({
    required this.name,
    required this.url,
    required this.capabilities,
  });

  /// Queue name.
  final String name;

  /// Queue URL.
  final String url;

  /// Capability tags.
  final List<String> capabilities;

  factory PrintQueue.fromJson(Map<String, dynamic> j) => PrintQueue(
    name: _str(j['name'], ''),
    url: _str(j['url'], ''),
    capabilities: _strings(j['capabilities']),
  );
}

// ---------------------------------------------------------------------------
// Host facts
// ---------------------------------------------------------------------------

/// Facts about this machine the screens need (`mi_service_host_facts`).
@immutable
class ServiceHostFacts {
  const ServiceHostFacts({
    this.platform = '',
    this.hostname,
    this.vnc_available = false,
    this.nx_available = false,
    this.ard_available = false,
    this.default_user = '',
    this.home = '',
    this.users = const [],
    this.shells = const [],
  });

  /// `std::env::consts::OS` on the backend.
  final String platform;

  /// This machine's hostname, when the backend could determine it.
  final String? hostname;

  /// Whether the VNC adapter exists on this platform (§20.2.3).
  final bool vnc_available;

  /// Whether the NX adapter exists on this platform (§20.2.4).
  final bool nx_available;

  /// Whether the Apple Remote Desktop adapter exists (§20.2.5).
  final bool ard_available;

  /// The app's own OS user.
  final String default_user;

  /// That user's home folder.
  final String home;

  /// Login accounts a shell grant may map to.  Empty when the platform
  /// cannot list accounts; the backend then checks on save.
  final List<String> users;

  /// Shells found on this OS.
  final List<String> shells;

  factory ServiceHostFacts.fromJson(Map<String, dynamic> j) {
    final adapters = j['mnrdp_adapters'] is Map
        ? Map<String, dynamic>.from(j['mnrdp_adapters'] as Map)
        : const <String, dynamic>{};
    final mnsp = j['mnsp'] is Map
        ? Map<String, dynamic>.from(j['mnsp'] as Map)
        : const <String, dynamic>{};
    return ServiceHostFacts(
      platform: _str(j['platform'], ''),
      hostname: j['hostname'] is String ? j['hostname'] as String : null,
      vnc_available: _bool(adapters['vnc'], false),
      nx_available: _bool(adapters['nx'], false),
      ard_available: _bool(adapters['ard'], false),
      default_user: _str(mnsp['default_user'], ''),
      home: _str(mnsp['home'], ''),
      users: _strings(mnsp['users']),
      shells: _strings(mnsp['shells']),
    );
  }
}
