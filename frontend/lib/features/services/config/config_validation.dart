// config_validation.dart
//
// Field rules shared by the §22.54.5–§22.54.9 configuration screens.
//
// WHY A SEPARATE FILE?
// --------------------
// §22.54.4 requires that "backend-side limits are the same as the UI limits
// so a value the UI accepts is never rejected server-side for format
// reasons".  Keeping the Dart rules in one place next to their Rust
// counterparts (`backend/services/server_config.rs`) makes that parity
// reviewable: every function here has a namesake there with the same
// inputs and the same answer.
//
// Every validator returns the plain-language inline reason (§22.51 inline
// rule) or null when the value is fine.

import 'dart:io';

import '../../../backend/models/service_config_models.dart';

/// Parsed `scheme://host[:port][/path]`; mirrors Rust `split_url`.
class SplitUrl {
  const SplitUrl(this.scheme, this.host, this.port, this.path);

  /// Lower-cased scheme.
  final String scheme;

  /// Host literal or name, without brackets.
  final String host;

  /// Explicit port, or null.
  final int? port;

  /// Path, `/` when absent.
  final String path;
}

/// Split a URL without resolving anything; null when it has no usable shape.
SplitUrl? split_url(String url) {
  final sep = url.indexOf('://');
  if (sep <= 0) return null;
  final scheme = url.substring(0, sep);
  if (!RegExp(r'^[A-Za-z]+$').hasMatch(scheme)) return null;
  final rest = url.substring(sep + 3);
  final slash = rest.indexOf('/');
  final authority = slash < 0 ? rest : rest.substring(0, slash);
  final path = slash < 0 ? '/' : rest.substring(slash);
  // Userinfo is never meaningful for a local upstream; refuse it.
  if (authority.isEmpty || authority.contains('@')) return null;
  String host;
  int? port;
  if (authority.startsWith('[')) {
    final end = authority.indexOf(']');
    if (end < 0) return null;
    host = authority.substring(1, end);
    final after = authority.substring(end + 1);
    if (after.isNotEmpty) {
      if (!after.startsWith(':')) return null;
      port = _port(after.substring(1));
      if (port == null) return null;
    }
  } else {
    final colon = authority.lastIndexOf(':');
    if (colon >= 0) {
      host = authority.substring(0, colon);
      port = _port(authority.substring(colon + 1));
      if (port == null) return null;
    } else {
      host = authority;
    }
  }
  if (host.isEmpty) return null;
  return SplitUrl(scheme.toLowerCase(), host, port, path);
}

/// Parse a 1–65535 port, or null.
int? _port(String text) {
  final value = int.tryParse(text);
  if (value == null || value < 1 || value > 65535) return null;
  return value;
}

/// Whether [host] names this machine: loopback literal, `localhost` and its
/// subdomains, or the machine's own [hostname].  No DNS is consulted.
bool is_local_host(String host, String? hostname) {
  final lower = host.toLowerCase();
  final ip = InternetAddress.tryParse(lower);
  if (ip != null) return ip.isLoopback;
  if (lower == 'localhost' ||
      lower.endsWith('.localhost') ||
      lower == 'localhost.localdomain') {
    return true;
  }
  return hostname != null && lower == hostname.toLowerCase();
}

/// Whether [host] is on the local network: local, RFC 1918, link-local,
/// unique-local IPv6, or a LAN name.  Mirrors Rust `is_lan_host`.
bool is_lan_host(String host, String? hostname) {
  if (is_local_host(host, hostname)) return true;
  final lower = host.toLowerCase();
  final ip = InternetAddress.tryParse(lower);
  if (ip != null) {
    final b = ip.rawAddress;
    if (ip.type == InternetAddressType.IPv4) {
      return b[0] == 10 ||
          (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
          (b[0] == 192 && b[1] == 168) ||
          (b[0] == 169 && b[1] == 254);
    }
    // fc00::/7 unique-local and fe80::/10 link-local.
    return (b[0] & 0xfe) == 0xfc || (b[0] == 0xfe && (b[1] & 0xc0) == 0x80);
  }
  if (lower.isEmpty || RegExp(r'[/\\ ]').hasMatch(lower)) return false;
  return !lower.contains('.') ||
      lower.endsWith('.local') ||
      lower.endsWith('.lan') ||
      lower.endsWith('.home') ||
      lower.endsWith('.internal');
}

/// §22.54.7 / §22.54.9 name rule: 1–64 characters, no control characters.
String? validate_name(String name) {
  final trimmed = name.trim();
  if (trimmed.isEmpty) return 'Enter a name';
  if (trimmed.runes.length > nameMaxChars) {
    return 'Names are at most $nameMaxChars characters';
  }
  if (trimmed.runes.any((r) => r < 0x20 || r == 0x7f)) {
    return "Names can't contain control characters";
  }
  return null;
}

/// §22.54.8 upstream rule: `http(s)://` to a host on this machine.
String? validate_upstream_url(String url, String? hostname) {
  final parsed = split_url(url.trim());
  if (parsed == null) return 'Enter an address like http://127.0.0.1:8080';
  if (parsed.scheme != 'http' && parsed.scheme != 'https') {
    return 'The address must start with http:// or https://';
  }
  if (!is_local_host(parsed.host, hostname)) {
    return 'The gateway only forwards to services on this device';
  }
  return null;
}

/// §22.54.9 printer URL rule: IPP/HTTP to this machine or the local network.
String? validate_printer_url(String url, String? hostname) {
  final parsed = split_url(url.trim());
  if (parsed == null) {
    return 'Enter an address like ipp://127.0.0.1:631/printers/office';
  }
  if (!const ['ipp', 'ipps', 'http', 'https'].contains(parsed.scheme)) {
    return 'The address must start with ipp://, ipps://, http:// or https://';
  }
  if (!is_lan_host(parsed.host, hostname)) {
    return 'Only printers on this device or your local network can be shared';
  }
  return null;
}

/// §22.54.8 path prefix rule: starts with `/`, no `..` segment.
String? validate_path_prefix(String prefix) {
  if (prefix.isEmpty) return null;
  if (!prefix.startsWith('/')) return 'The prefix must start with /';
  if (prefix.split('/').contains('..')) return "The prefix can't contain ..";
  return null;
}

/// §22.54.8 rate limit rule: 1–100 000.
String? validate_rate_limit(String text) {
  final value = int.tryParse(text.trim());
  if (value == null || value < 1 || value > apiGatewayRateMax) {
    return 'Enter a number from 1 to 100 000';
  }
  return null;
}

/// §22.54.6 port rule: 1–65535.
String? validate_port(String text) =>
    _port(text.trim()) == null ? 'Enter a port from 1 to 65535' : null;

/// Whether [path] is an existing directory on this device.
bool directory_exists(String path) =>
    path.trim().isNotEmpty && Directory(path.trim()).existsSync();

/// Last path segment of [path], for the share-name default.
String folder_name(String path) {
  final trimmed = path.trim().replaceAll(RegExp(r'[\\/]+$'), '');
  final cut = trimmed.lastIndexOf(RegExp(r'[\\/]'));
  return cut < 0 ? trimmed : trimmed.substring(cut + 1);
}
