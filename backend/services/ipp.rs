//! Minimal IPP client for Print Services configuration (§20.8.1, §22.54.9).
//!
//! # Why this exists
//!
//! The Print Services screen lists "local IPP queues the OS reports" and
//! shows each queue's capabilities (`duplex`, `color`, paper sizes)
//! "discovered from the queue".  Every modern spooler and printer speaks IPP
//! (RFC 8010/8011) over HTTP on port 631, so two operations cover both needs
//! without a platform API per operating system:
//!
//! * `CUPS-Get-Printers` (0x4002) against the local spooler lists the
//!   queues it manages (CUPS on Linux/macOS; cups-compatible spoolers
//!   elsewhere).  Where no spooler answers on loopback, the list is simply
//!   empty and the user shares a printer by URL.
//! * `Get-Printer-Attributes` (0x000B) against any queue URL reports its
//!   name and the attributes the capability chips are derived from.
//!
//! # Trust boundary
//!
//! The response bytes come from a network socket — loopback or LAN, but a
//! socket all the same — so `parse_message` is a hardened parser: every
//! length is checked before it is used, the attribute count and total size
//! are bounded, and nothing panics on malformed input.  It is fuzzed by
//! `fuzz_ipp_response` (see `fuzz/targets.toml`).
//!
//! # Transport
//!
//! Plain HTTP/1.1 over `std::net::TcpStream` with short timeouts.  TLS
//! (`ipps://`, `https://`) is not spoken here: a local printer's certificate
//! is almost always self-signed, and disabling verification would be a
//! security regression this module refuses to introduce.  A TLS-only queue
//! can still be shared; its capabilities are then entered from the queue's
//! plain-IPP URL or left empty.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::services::server_config::{is_lan_host, split_url};

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Largest HTTP body accepted from a printer (1 MiB).
pub const MAX_BODY_BYTES: usize = 1 << 20;
/// Largest HTTP header block accepted from a printer.
const MAX_HEADER_BYTES: usize = 16 * 1024;
/// Most attributes decoded from one message; a real printer sends a few hundred.
const MAX_ATTRIBUTES: usize = 4096;
/// Most values decoded for one attribute.
const MAX_VALUES: usize = 512;
/// Socket connect timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Socket read/write timeout.
const IO_TIMEOUT: Duration = Duration::from_secs(4);
/// Default IPP port (RFC 8010 §5).
const IPP_PORT: u16 = 631;

// IPP operation and tag constants (RFC 8010 §3.5 / §3.4).
const OP_GET_PRINTER_ATTRIBUTES: u16 = 0x000B;
const OP_CUPS_GET_PRINTERS: u16 = 0x4002;
const TAG_OPERATION_GROUP: u8 = 0x01;
const TAG_END: u8 = 0x03;
const TAG_PRINTER_GROUP: u8 = 0x04;
const TAG_BOOLEAN: u8 = 0x22;
/// Only the test fixture emits an enum attribute (to prove non-text tags are skipped).
#[cfg(test)]
const TAG_ENUM: u8 = 0x23;
const TAG_TEXT_LANG: u8 = 0x35;
const TAG_NAME_LANG: u8 = 0x36;
const TAG_TEXT: u8 = 0x41;
const TAG_NAME: u8 = 0x42;
const TAG_KEYWORD: u8 = 0x44;
const TAG_URI: u8 = 0x45;
const TAG_CHARSET: u8 = 0x47;
const TAG_LANGUAGE: u8 = 0x48;
/// IPP status codes below this are successes (RFC 8011 appendix B).
const STATUS_OK_MAX: u16 = 0x00FF;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why an IPP operation failed.  Every variant is plain data so it can cross
/// the FFI boundary as a message without leaking anything but the status.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IppError {
    /// The queue URL could not be parsed or uses an unsupported scheme.
    #[error("not a usable printer address")]
    InvalidUrl,
    /// The queue is outside this device and its local network.
    #[error("only printers on this device or your local network can be reached")]
    NotLocal,
    /// `ipps://` / `https://` queues are not probed (see module docs).
    #[error("capabilities can't be read over an encrypted printer link; use the queue's plain ipp:// address")]
    TlsUnsupported,
    /// The socket could not be opened or timed out.
    #[error("the printer didn't answer")]
    Connect,
    /// The printer answered with a non-200 HTTP status.
    #[error("the printer refused the request (HTTP {0})")]
    Http(u16),
    /// The response exceeded a size bound.
    #[error("the printer's reply was too large")]
    TooLarge,
    /// The bytes were not a well-formed IPP message.
    #[error("the printer's reply was malformed: {0}")]
    Malformed(&'static str),
    /// The IPP status code was an error.
    #[error("the printer reported IPP status 0x{0:04x}")]
    Status(u16),
}

// ---------------------------------------------------------------------------
// Wire model
// ---------------------------------------------------------------------------

/// One attribute value: its tag and raw bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IppValue {
    /// RFC 8010 value tag.
    pub tag: u8,
    /// Raw value bytes exactly as sent.
    pub data: Vec<u8>,
}

impl IppValue {
    /// The value as text for the string-like tags (keyword, name, uri...).
    /// `nameWithLanguage` / `textWithLanguage` carry a language prefix that
    /// is stripped here.  Non-text tags yield `None`.
    pub fn as_text(&self) -> Option<String> {
        match self.tag {
            TAG_KEYWORD | TAG_URI | TAG_NAME | TAG_TEXT | TAG_CHARSET | TAG_LANGUAGE => {
                Some(String::from_utf8_lossy(&self.data).into_owned())
            }
            TAG_NAME_LANG | TAG_TEXT_LANG => {
                // 2-byte language length, language, 2-byte text length, text.
                let lang_len = read_u16(&self.data, 0)? as usize;
                let text_off = 2 + lang_len;
                let text_len = read_u16(&self.data, text_off)? as usize;
                let text = self.data.get(text_off + 2..text_off + 2 + text_len)?;
                Some(String::from_utf8_lossy(text).into_owned())
            }
            _ => None,
        }
    }

    /// The value as a boolean (tag 0x22, one byte).
    pub fn as_bool(&self) -> Option<bool> {
        if self.tag == TAG_BOOLEAN {
            self.data.first().map(|b| *b != 0)
        } else {
            None
        }
    }
}

/// One attribute: name plus one or more values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IppAttribute {
    /// Attribute name, e.g. `printer-name`.
    pub name: String,
    /// Values in wire order.
    pub values: Vec<IppValue>,
}

/// One attribute group (operation, printer, job...).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IppGroup {
    /// Begin-attribute-group tag.
    pub tag: u8,
    /// Attributes in wire order.
    pub attributes: Vec<IppAttribute>,
}

impl IppGroup {
    /// First value of the named attribute, as text.
    fn text(&self, name: &str) -> Option<String> {
        self.attributes
            .iter()
            .find(|a| a.name == name)
            .and_then(|a| a.values.first())
            .and_then(IppValue::as_text)
    }

    /// Every value of the named attribute, as text.
    fn texts(&self, name: &str) -> Vec<String> {
        self.attributes
            .iter()
            .find(|a| a.name == name)
            .map(|a| a.values.iter().filter_map(IppValue::as_text).collect())
            .unwrap_or_default()
    }

    /// First value of the named attribute, as a boolean.
    fn boolean(&self, name: &str) -> Option<bool> {
        self.attributes
            .iter()
            .find(|a| a.name == name)
            .and_then(|a| a.values.first())
            .and_then(IppValue::as_bool)
    }
}

/// A decoded IPP request or response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IppMessage {
    /// Protocol version, e.g. (2, 0).
    pub version: (u8, u8),
    /// Operation id (requests) or status code (responses).
    pub op_or_status: u16,
    /// Request id echoed by the responder.
    pub request_id: u32,
    /// Attribute groups in wire order.
    pub groups: Vec<IppGroup>,
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

impl IppMessage {
    /// Serialise to wire bytes (RFC 8010 §3.1).  Names and values longer
    /// than a 16-bit length are truncated, which cannot happen for the
    /// fixed request attributes this module sends.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.push(self.version.0);
        out.push(self.version.1);
        out.extend_from_slice(&self.op_or_status.to_be_bytes());
        out.extend_from_slice(&self.request_id.to_be_bytes());
        for group in &self.groups {
            out.push(group.tag);
            for attr in &group.attributes {
                for (i, value) in attr.values.iter().enumerate() {
                    out.push(value.tag);
                    // Only the first value carries the name; additional
                    // values of the same attribute use an empty name.
                    let name: &[u8] = if i == 0 { attr.name.as_bytes() } else { &[] };
                    let name = &name[..name.len().min(u16::MAX as usize)];
                    out.extend_from_slice(&(name.len() as u16).to_be_bytes());
                    out.extend_from_slice(name);
                    let data = &value.data[..value.data.len().min(u16::MAX as usize)];
                    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
                    out.extend_from_slice(data);
                }
            }
        }
        out.push(TAG_END);
        out
    }
}

/// A text-valued attribute with one value.
fn attr(tag: u8, name: &str, value: &str) -> IppAttribute {
    IppAttribute {
        name: name.to_string(),
        values: vec![IppValue {
            tag,
            data: value.as_bytes().to_vec(),
        }],
    }
}

/// A keyword attribute with several values.
fn keywords(name: &str, values: &[&str]) -> IppAttribute {
    IppAttribute {
        name: name.to_string(),
        values: values
            .iter()
            .map(|v| IppValue {
                tag: TAG_KEYWORD,
                data: v.as_bytes().to_vec(),
            })
            .collect(),
    }
}

/// The attributes the capability chips are derived from.
const REQUESTED: [&str; 6] = [
    "printer-name",
    "printer-uri-supported",
    "printer-info",
    "sides-supported",
    "color-supported",
    "media-supported",
];

/// Build the operation group every request starts with (RFC 8011 §4.1.4).
fn operation_group(extra: Vec<IppAttribute>) -> IppGroup {
    let mut attributes = vec![
        attr(TAG_CHARSET, "attributes-charset", "utf-8"),
        attr(TAG_LANGUAGE, "attributes-natural-language", "en"),
    ];
    attributes.extend(extra);
    attributes.push(keywords("requested-attributes", &REQUESTED));
    IppGroup {
        tag: TAG_OPERATION_GROUP,
        attributes,
    }
}

/// Encode a `Get-Printer-Attributes` request for `printer_uri`.
pub fn get_printer_attributes_request(printer_uri: &str, request_id: u32) -> Vec<u8> {
    IppMessage {
        version: (2, 0),
        op_or_status: OP_GET_PRINTER_ATTRIBUTES,
        request_id,
        groups: vec![operation_group(vec![attr(
            TAG_URI,
            "printer-uri",
            printer_uri,
        )])],
    }
    .encode()
}

/// Encode a `CUPS-Get-Printers` request.
pub fn cups_get_printers_request(request_id: u32) -> Vec<u8> {
    IppMessage {
        version: (2, 0),
        op_or_status: OP_CUPS_GET_PRINTERS,
        request_id,
        groups: vec![operation_group(Vec::new())],
    }
    .encode()
}

// ---------------------------------------------------------------------------
// Decoding (untrusted bytes)
// ---------------------------------------------------------------------------

/// Read a big-endian u16 at `at`, or `None` past the end.
fn read_u16(bytes: &[u8], at: usize) -> Option<u16> {
    let slice = bytes.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([slice[0], slice[1]]))
}

/// Decode an IPP message.  Never panics; every slice is bounds-checked and
/// the attribute and value counts are capped.
pub fn parse_message(bytes: &[u8]) -> Result<IppMessage, IppError> {
    if bytes.len() > MAX_BODY_BYTES {
        return Err(IppError::TooLarge);
    }
    if bytes.len() < 9 {
        return Err(IppError::Malformed("header too short"));
    }
    let version = (bytes[0], bytes[1]);
    let op_or_status = u16::from_be_bytes([bytes[2], bytes[3]]);
    let request_id = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let mut pos = 8;
    let mut groups: Vec<IppGroup> = Vec::new();
    let mut total_attrs = 0usize;

    loop {
        let tag = *bytes
            .get(pos)
            .ok_or(IppError::Malformed("missing end tag"))?;
        pos += 1;
        if tag == TAG_END {
            break;
        }
        // Delimiter tags are 0x00–0x0F; anything else here is an attribute
        // belonging to the current group.
        if tag < 0x10 {
            groups.push(IppGroup {
                tag,
                attributes: Vec::new(),
            });
            continue;
        }
        let name_len =
            read_u16(bytes, pos).ok_or(IppError::Malformed("truncated name length"))? as usize;
        pos += 2;
        let name = bytes
            .get(pos..pos + name_len)
            .ok_or(IppError::Malformed("truncated name"))?;
        pos += name_len;
        let value_len =
            read_u16(bytes, pos).ok_or(IppError::Malformed("truncated value length"))? as usize;
        pos += 2;
        let data = bytes
            .get(pos..pos + value_len)
            .ok_or(IppError::Malformed("truncated value"))?;
        pos += value_len;
        let value = IppValue {
            tag,
            data: data.to_vec(),
        };

        let group = groups
            .last_mut()
            .ok_or(IppError::Malformed("attribute before any group"))?;
        if name_len == 0 {
            // Additional value for the previous attribute.
            let last = group
                .attributes
                .last_mut()
                .ok_or(IppError::Malformed("additional value without attribute"))?;
            if last.values.len() >= MAX_VALUES {
                return Err(IppError::TooLarge);
            }
            last.values.push(value);
        } else {
            total_attrs += 1;
            if total_attrs > MAX_ATTRIBUTES {
                return Err(IppError::TooLarge);
            }
            group.attributes.push(IppAttribute {
                name: String::from_utf8_lossy(name).into_owned(),
                values: vec![value],
            });
        }
    }

    Ok(IppMessage {
        version,
        op_or_status,
        request_id,
        groups,
    })
}

// ---------------------------------------------------------------------------
// Printer model
// ---------------------------------------------------------------------------

/// A queue as the UI shows it: name, URL and capability tags.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IppPrinter {
    /// `printer-name` (falls back to `printer-info`, then the URL).
    pub name: String,
    /// `printer-uri-supported` (first value) or the probed URL.
    pub url: String,
    /// §20.8.1 capability tags: `duplex`, `color`, paper sizes.
    pub capabilities: Vec<String>,
}

/// Map an IPP media keyword to a §20.8.1 paper-size tag.
fn media_tag(keyword: &str) -> Option<&'static str> {
    // PWG 5101.1 self-describing names: `iso_a4_210x297mm`, `na_letter_8.5x11in`.
    let tags: [(&str, &str); 8] = [
        ("iso_a3_", "a3"),
        ("iso_a4_", "a4"),
        ("iso_a5_", "a5"),
        ("iso_a6_", "a6"),
        ("na_letter_", "letter"),
        ("na_legal_", "legal"),
        ("na_ledger_", "ledger"),
        ("na_executive_", "executive"),
    ];
    tags.iter()
        .find(|(prefix, _)| keyword.starts_with(prefix))
        .map(|(_, tag)| *tag)
}

/// Derive the capability list from a printer attribute group.
fn capabilities_of(group: &IppGroup) -> Vec<String> {
    let mut caps = Vec::new();
    let sides = group.texts("sides-supported");
    if sides.iter().any(|s| s.starts_with("two-sided")) {
        caps.push("duplex".to_string());
    }
    if group.boolean("color-supported") == Some(true) {
        caps.push("color".to_string());
    }
    for media in group.texts("media-supported") {
        if let Some(tag) = media_tag(&media) {
            let tag = tag.to_string();
            if !caps.contains(&tag) {
                caps.push(tag);
            }
        }
    }
    caps
}

/// Extract every printer group from a decoded message.
pub fn printers_of(message: &IppMessage, fallback_url: &str) -> Vec<IppPrinter> {
    message
        .groups
        .iter()
        .filter(|g| g.tag == TAG_PRINTER_GROUP)
        .map(|g| {
            let url = g
                .text("printer-uri-supported")
                .unwrap_or_else(|| fallback_url.to_string());
            let name = g
                .text("printer-name")
                .or_else(|| g.text("printer-info"))
                .unwrap_or_else(|| url.clone());
            IppPrinter {
                name,
                url,
                capabilities: capabilities_of(g),
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// HTTP transport
// ---------------------------------------------------------------------------

/// Where a request goes on the wire.
#[derive(Debug)]
struct Endpoint {
    /// Host part of the URL (literal or name).
    host: String,
    /// TCP port.
    port: u16,
    /// Request path.
    path: String,
    /// `ipp://host:port/path` form for the `printer-uri` attribute.
    printer_uri: String,
}

/// Resolve a queue URL into a plaintext endpoint, enforcing the §22.54.9
/// locality rule before any socket is opened.
fn endpoint_for(url: &str, hostname: Option<&str>) -> Result<Endpoint, IppError> {
    let (scheme, host, port, path) = split_url(url.trim()).ok_or(IppError::InvalidUrl)?;
    let port = match scheme.as_str() {
        "ipp" => port.unwrap_or(IPP_PORT),
        "http" => port.unwrap_or(80),
        "ipps" | "https" => return Err(IppError::TlsUnsupported),
        _ => return Err(IppError::InvalidUrl),
    };
    if !is_lan_host(&host, hostname) {
        return Err(IppError::NotLocal);
    }
    let host_part = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.clone()
    };
    Ok(Endpoint {
        printer_uri: format!("ipp://{host_part}:{port}{path}"),
        host,
        port,
        path,
    })
}

/// POST `body` as `application/ipp` and return the response body.
fn post_ipp(endpoint: &Endpoint, body: &[u8]) -> Result<Vec<u8>, IppError> {
    let addr = (endpoint.host.as_str(), endpoint.port)
        .to_socket_addrs()
        .map_err(|_| IppError::Connect)?
        .next()
        .ok_or(IppError::Connect)?;
    let mut stream =
        TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).map_err(|_| IppError::Connect)?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|_| IppError::Connect)?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|_| IppError::Connect)?;

    let host_header = if endpoint.host.contains(':') {
        format!("[{}]:{}", endpoint.host, endpoint.port)
    } else {
        format!("{}:{}", endpoint.host, endpoint.port)
    };
    let head = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/ipp\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        endpoint.path,
        host_header,
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .map_err(|_| IppError::Connect)?;
    stream.write_all(body).map_err(|_| IppError::Connect)?;

    // Read everything the server sends (it closes after the response), with
    // a hard cap so a misbehaving device cannot exhaust memory.
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = stream.read(&mut chunk).map_err(|_| IppError::Connect)?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
        if raw.len() > MAX_BODY_BYTES + MAX_HEADER_BYTES {
            return Err(IppError::TooLarge);
        }
    }
    parse_http_response(&raw)
}

/// Split an HTTP/1.1 response into its body, honouring `Content-Length`
/// and chunked transfer encoding.  Untrusted input; bounds-checked.
pub fn parse_http_response(raw: &[u8]) -> Result<Vec<u8>, IppError> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or(IppError::Malformed("no HTTP header terminator"))?;
    if header_end > MAX_HEADER_BYTES {
        return Err(IppError::TooLarge);
    }
    let header = String::from_utf8_lossy(&raw[..header_end]);
    let mut lines = header.lines();
    let status_line = lines
        .next()
        .ok_or(IppError::Malformed("empty status line"))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or(IppError::Malformed("bad status line"))?;
    if status != 200 {
        return Err(IppError::Http(status));
    }
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "content-length" {
            content_length = value.parse().ok();
        } else if name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked") {
            chunked = true;
        }
    }
    let body = &raw[header_end + 4..];
    let body = if chunked {
        decode_chunked(body)?
    } else if let Some(len) = content_length {
        body.get(..len)
            .ok_or(IppError::Malformed("body shorter than Content-Length"))?
            .to_vec()
    } else {
        body.to_vec()
    };
    if body.len() > MAX_BODY_BYTES {
        return Err(IppError::TooLarge);
    }
    Ok(body)
}

/// Decode a chunked transfer-encoded body (RFC 9112 §7.1).
fn decode_chunked(mut body: &[u8]) -> Result<Vec<u8>, IppError> {
    let mut out = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or(IppError::Malformed("truncated chunk size"))?;
        let size_text = String::from_utf8_lossy(&body[..line_end]);
        // Chunk extensions follow a ';' and are ignored.
        let size_hex = size_text.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| IppError::Malformed("bad chunk size"))?;
        body = &body[line_end + 2..];
        if size == 0 {
            break;
        }
        let data = body
            .get(..size)
            .ok_or(IppError::Malformed("truncated chunk"))?;
        out.extend_from_slice(data);
        if out.len() > MAX_BODY_BYTES {
            return Err(IppError::TooLarge);
        }
        body = body
            .get(size + 2..)
            .ok_or(IppError::Malformed("missing chunk terminator"))?;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Public operations
// ---------------------------------------------------------------------------

/// Decode a response body and check its IPP status.
fn decode_response(body: &[u8]) -> Result<IppMessage, IppError> {
    let message = parse_message(body)?;
    if message.op_or_status > STATUS_OK_MAX {
        return Err(IppError::Status(message.op_or_status));
    }
    Ok(message)
}

/// List the queues the local spooler reports on `127.0.0.1:631`.
///
/// An unreachable spooler is an empty list, not an error: on a machine
/// with no IPP spooler the §22.54.9 picker simply offers "Other…".
pub fn discover_local_queues() -> Vec<IppPrinter> {
    let endpoint = Endpoint {
        host: "127.0.0.1".to_string(),
        port: IPP_PORT,
        path: "/".to_string(),
        printer_uri: format!("ipp://127.0.0.1:{IPP_PORT}/"),
    };
    let body = cups_get_printers_request(1);
    match post_ipp(&endpoint, &body).and_then(|b| decode_response(&b)) {
        Ok(message) => printers_of(&message, &endpoint.printer_uri),
        Err(_) => Vec::new(),
    }
}

/// Read the name and capabilities of the queue at `url`.
pub fn probe_queue(url: &str, hostname: Option<&str>) -> Result<IppPrinter, IppError> {
    let endpoint = endpoint_for(url, hostname)?;
    let body = get_printer_attributes_request(&endpoint.printer_uri, 2);
    let message = post_ipp(&endpoint, &body).and_then(|b| decode_response(&b))?;
    printers_of(&message, url)
        .into_iter()
        .next()
        .map(|mut p| {
            // The caller's URL is what gets shared, not whatever alias the
            // printer advertises for itself.
            p.url = url.trim().to_string();
            p
        })
        .ok_or(IppError::Malformed("no printer attributes in reply"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::invariants::assert_no_panic_on_bytes;

    /// A representative `Get-Printer-Attributes` success response.
    pub(crate) fn sample_response() -> Vec<u8> {
        IppMessage {
            version: (2, 0),
            op_or_status: 0x0000,
            request_id: 2,
            groups: vec![
                IppGroup {
                    tag: TAG_OPERATION_GROUP,
                    attributes: vec![
                        attr(TAG_CHARSET, "attributes-charset", "utf-8"),
                        attr(TAG_LANGUAGE, "attributes-natural-language", "en"),
                    ],
                },
                IppGroup {
                    tag: TAG_PRINTER_GROUP,
                    attributes: vec![
                        attr(TAG_NAME, "printer-name", "Office_Laser"),
                        attr(
                            TAG_URI,
                            "printer-uri-supported",
                            "ipp://127.0.0.1:631/printers/Office_Laser",
                        ),
                        keywords("sides-supported", &["one-sided", "two-sided-long-edge"]),
                        IppAttribute {
                            name: "color-supported".into(),
                            values: vec![IppValue {
                                tag: TAG_BOOLEAN,
                                data: vec![1],
                            }],
                        },
                        keywords(
                            "media-supported",
                            &["iso_a4_210x297mm", "na_letter_8.5x11in", "custom_min_1x1in"],
                        ),
                        IppAttribute {
                            name: "printer-state".into(),
                            values: vec![IppValue {
                                tag: TAG_ENUM,
                                data: vec![0, 0, 0, 3],
                            }],
                        },
                        IppAttribute {
                            name: "printer-info".into(),
                            values: vec![IppValue {
                                tag: TAG_NAME_LANG,
                                data: {
                                    let mut d = Vec::new();
                                    d.extend_from_slice(&2u16.to_be_bytes());
                                    d.extend_from_slice(b"en");
                                    d.extend_from_slice(&5u16.to_be_bytes());
                                    d.extend_from_slice(b"Laser");
                                    d
                                },
                            }],
                        },
                    ],
                },
            ],
        }
        .encode()
    }

    #[test]
    fn request_encodes_and_decodes() {
        let bytes = get_printer_attributes_request("ipp://127.0.0.1:631/printers/x", 7);
        let message = parse_message(&bytes).unwrap();
        assert_eq!(message.op_or_status, OP_GET_PRINTER_ATTRIBUTES);
        assert_eq!(message.request_id, 7);
        assert_eq!(message.groups.len(), 1);
        assert_eq!(
            message.groups[0].text("printer-uri").as_deref(),
            Some("ipp://127.0.0.1:631/printers/x")
        );
        let requested = message.groups[0].texts("requested-attributes");
        assert_eq!(requested.len(), REQUESTED.len());
        let cups = parse_message(&cups_get_printers_request(1)).unwrap();
        assert_eq!(cups.op_or_status, OP_CUPS_GET_PRINTERS);
    }

    #[test]
    fn response_yields_printer_and_capabilities() {
        let message = decode_response(&sample_response()).unwrap();
        let printers = printers_of(&message, "ipp://fallback/");
        assert_eq!(printers.len(), 1);
        let p = &printers[0];
        assert_eq!(p.name, "Office_Laser");
        assert_eq!(p.url, "ipp://127.0.0.1:631/printers/Office_Laser");
        assert_eq!(p.capabilities, vec!["duplex", "color", "a4", "letter"]);
    }

    #[test]
    fn name_with_language_is_decoded() {
        let message = parse_message(&sample_response()).unwrap();
        assert_eq!(
            message.groups[1].text("printer-info").as_deref(),
            Some("Laser")
        );
        assert_eq!(message.groups[1].text("printer-state"), None);
    }

    #[test]
    fn error_status_is_reported() {
        let mut bytes = sample_response();
        bytes[2] = 0x04;
        bytes[3] = 0x00;
        assert_eq!(decode_response(&bytes), Err(IppError::Status(0x0400)));
    }

    #[test]
    fn truncated_and_garbage_inputs_are_typed_errors() {
        assert_eq!(
            parse_message(&[]),
            Err(IppError::Malformed("header too short"))
        );
        let sample = sample_response();
        for cut in [8, 9, 12, 20, sample.len() - 1] {
            assert!(
                matches!(parse_message(&sample[..cut]), Err(IppError::Malformed(_))),
                "cut {cut}"
            );
        }
        // Attribute before any group.
        let mut bad = vec![
            2,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
            TAG_KEYWORD,
            0,
            1,
            b'a',
            0,
            0,
            TAG_END,
        ];
        assert_eq!(
            parse_message(&bad),
            Err(IppError::Malformed("attribute before any group"))
        );
        // Additional value without an attribute.
        bad[8] = TAG_PRINTER_GROUP;
        bad.splice(9..9, [TAG_KEYWORD, 0, 0, 0, 0]);
        assert!(matches!(parse_message(&bad), Err(IppError::Malformed(_))));
        let oversized = vec![0u8; MAX_BODY_BYTES + 1];
        assert_eq!(parse_message(&oversized), Err(IppError::TooLarge));
    }

    #[test]
    fn attribute_flood_is_bounded() {
        let mut bytes = vec![2, 0, 0, 0, 0, 0, 0, 1, TAG_PRINTER_GROUP];
        for _ in 0..=MAX_ATTRIBUTES {
            bytes.extend_from_slice(&[TAG_KEYWORD, 0, 1, b'k', 0, 0]);
        }
        bytes.push(TAG_END);
        assert_eq!(parse_message(&bytes), Err(IppError::TooLarge));
        let mut bytes = vec![
            2,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
            TAG_PRINTER_GROUP,
            TAG_KEYWORD,
            0,
            1,
            b'k',
            0,
            0,
        ];
        for _ in 0..MAX_VALUES {
            bytes.extend_from_slice(&[TAG_KEYWORD, 0, 0, 0, 0]);
        }
        bytes.push(TAG_END);
        assert_eq!(parse_message(&bytes), Err(IppError::TooLarge));
    }

    #[test]
    fn parser_never_panics_on_random_bytes() {
        let mut seed = 0x9e37_79b9_u32;
        for len in [1usize, 5, 9, 16, 64, 300, 1500] {
            let data: Vec<u8> = (0..len)
                .map(|_| {
                    seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    (seed >> 24) as u8
                })
                .collect();
            assert_no_panic_on_bytes("parse_message", &data, parse_message);
        }
    }

    #[test]
    fn http_bodies_are_extracted() {
        let body = b"\x02\x00\x00\x00\x00\x00\x00\x01\x03";
        let plain = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/ipp\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut raw = plain.into_bytes();
        raw.extend_from_slice(body);
        assert_eq!(parse_http_response(&raw).unwrap(), body);

        let mut chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n\x02\x00\x00\x00\r\n5;ext\r\n\x00\x00\x00\x01\x03\r\n0\r\n\r\n".to_vec();
        assert_eq!(parse_http_response(&chunked).unwrap(), body);
        chunked.truncate(chunked.len() - 7);
        assert!(matches!(
            parse_http_response(&chunked),
            Err(IppError::Malformed(_))
        ));

        assert_eq!(
            parse_http_response(b"HTTP/1.1 401 Unauthorized\r\n\r\n"),
            Err(IppError::Http(401))
        );
        assert!(matches!(
            parse_http_response(b"garbage"),
            Err(IppError::Malformed(_))
        ));
        assert!(matches!(
            parse_http_response(b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nshort"),
            Err(IppError::Malformed(_))
        ));
    }

    #[test]
    fn endpoint_rules() {
        let e = endpoint_for("ipp://192.168.1.9/ipp/print", None).unwrap();
        assert_eq!(
            (e.host.as_str(), e.port, e.path.as_str()),
            ("192.168.1.9", 631, "/ipp/print")
        );
        assert_eq!(e.printer_uri, "ipp://192.168.1.9:631/ipp/print");
        let e = endpoint_for("http://[::1]:8631/printers/a", None).unwrap();
        assert_eq!(e.printer_uri, "ipp://[::1]:8631/printers/a");
        assert_eq!(
            endpoint_for("ipps://127.0.0.1/", None).unwrap_err(),
            IppError::TlsUnsupported
        );
        assert_eq!(
            endpoint_for("ipp://8.8.8.8/", None).unwrap_err(),
            IppError::NotLocal
        );
        assert_eq!(
            endpoint_for("ftp://127.0.0.1/", None).unwrap_err(),
            IppError::InvalidUrl
        );
        assert_eq!(
            endpoint_for("nonsense", None).unwrap_err(),
            IppError::InvalidUrl
        );
    }

    #[test]
    fn probe_refuses_remote_hosts_without_connecting() {
        // A public address must be refused by the locality rule, never by a
        // (slow) connection attempt.
        let started = std::time::Instant::now();
        assert_eq!(
            probe_queue("ipp://1.1.1.1/ipp/print", None),
            Err(IppError::NotLocal)
        );
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn corpus_replay_never_panics() {
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus/fuzz_ipp_response");
        crate::testing::corpus::assert_corpus_dir_exists(&dir);
        let entries = crate::testing::corpus::load_corpus_entries(&dir).expect("read corpus");
        assert!(!entries.is_empty(), "corpus must contain seeds");
        for (path, bytes) in entries {
            assert_no_panic_on_bytes(&path.display().to_string(), &bytes, |d| {
                let _ = parse_message(d);
                let _ = parse_http_response(d);
            });
        }
    }

    #[test]
    fn committed_seed_matches_encoder() {
        // The committed seed must be a real response so the fuzzer starts
        // from a valid message rather than only from garbage.
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus/fuzz_ipp_response");
        let seed = std::fs::read(dir.join("seed_01_get_printer_attributes")).expect("seed present");
        assert_eq!(seed, sample_response());
    }
}
