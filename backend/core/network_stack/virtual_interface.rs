//! Virtual interface abstraction (TUN) plus local IP/route utilities.
//!
//! The `VirtualInterface` type wraps a host TUN device and is fully
//! cross-platform.  Platform-specific TUN backends are selected at compile
//! time via the private `TunDevice` trait:
//!
//! - **Unix / Linux / macOS**: `tun-tap` crate (`tun_tap::Iface`)
//! - **Windows**: `wintun` crate (WireGuard's WinTun driver)
//!
//! All other code in the network-stack (VPN service, packet router) depends
//! only on `VirtualInterface` and is therefore unaffected by the platform.

use crate::core::error::{MeshInfinityError, Result};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

// ── Platform-independent TUN trait ───────────────────────────────────────────

trait TunDevice: Send {
    fn recv(&self, buf: &mut [u8]) -> Result<usize>;
    fn send(&self, packet: &[u8]) -> Result<usize>;
    fn name(&self) -> String;
}

// ── Unix backend (tun-tap) ────────────────────────────────────────────────────

#[cfg(unix)]
mod unix_tun {
    use super::{MeshInfinityError, Result, TunDevice};
    use tun_tap::{Iface, Mode};

    pub struct UnixTun(Iface);

    impl UnixTun {
        pub fn open(name: &str) -> Result<Box<dyn TunDevice>> {
            let iface = Iface::new(name, Mode::Tun)
                .map_err(|e| MeshInfinityError::NetworkError(e.to_string()))?;
            Ok(Box::new(Self(iface)))
        }
    }

    impl TunDevice for UnixTun {
        fn recv(&self, buf: &mut [u8]) -> Result<usize> {
            self.0
                .recv(buf)
                .map_err(|e| MeshInfinityError::NetworkError(e.to_string()))
        }

        fn send(&self, packet: &[u8]) -> Result<usize> {
            self.0
                .send(packet)
                .map_err(|e| MeshInfinityError::NetworkError(e.to_string()))
        }

        fn name(&self) -> String {
            self.0.name().to_string()
        }
    }
}

// ── Windows backend (wintun) ──────────────────────────────────────────────────

#[cfg(windows)]
mod windows_tun {
    use super::{MeshInfinityError, Result, TunDevice};
    use std::sync::Arc;
    use wintun;

    pub struct WinTun {
        // _lib must be kept alive for the lifetime of the session.
        _lib: wintun::Wintun,
        session: Arc<wintun::Session>,
        name: String,
    }

    impl WinTun {
        pub fn open(name: &str) -> Result<Box<dyn TunDevice>> {
            // SAFETY: loads wintun.dll from PATH or the executable directory.
            let lib = unsafe {
                wintun::load()
                    .map_err(|e| MeshInfinityError::NetworkError(e.to_string()))?
            };

            let adapter = wintun::Adapter::create(&lib, name, "MeshInfinity", None)
                .map_err(|e| MeshInfinityError::NetworkError(e.to_string()))?;

            let session = Arc::new(
                adapter
                    .start_session(wintun::MAX_RING_CAPACITY)
                    .map_err(|e| MeshInfinityError::NetworkError(e.to_string()))?,
            );

            Ok(Box::new(Self {
                _lib: lib,
                session,
                name: name.to_string(),
            }))
        }
    }

    impl TunDevice for WinTun {
        fn recv(&self, buf: &mut [u8]) -> Result<usize> {
            let packet = self
                .session
                .receive_blocking()
                .map_err(|e| MeshInfinityError::NetworkError(e.to_string()))?;
            let src = packet.bytes();
            let n = src.len().min(buf.len());
            buf[..n].copy_from_slice(&src[..n]);
            Ok(n)
        }

        fn send(&self, packet: &[u8]) -> Result<usize> {
            let mut send_packet = self
                .session
                .allocate_send_packet(packet.len() as u16)
                .map_err(|e| MeshInfinityError::NetworkError(e.to_string()))?;
            send_packet.bytes_mut().copy_from_slice(packet);
            self.session.send_packet(send_packet);
            Ok(packet.len())
        }

        fn name(&self) -> String {
            self.name.clone()
        }
    }
}

// ── Platform dispatch ─────────────────────────────────────────────────────────

fn open_tun(name: &str) -> Result<Box<dyn TunDevice>> {
    #[cfg(unix)]
    return unix_tun::UnixTun::open(name);

    #[cfg(windows)]
    return windows_tun::WinTun::open(name);

    // Compile-time guard: this branch is only reached on unsupported targets
    // (e.g. wasm32).  The cfg attributes above cover all production targets.
    #[cfg(not(any(unix, windows)))]
    return Err(MeshInfinityError::NetworkError(
        "TUN interfaces are not supported on this platform".to_string(),
    ));
}

// ── Public cross-platform VirtualInterface ────────────────────────────────────

pub struct VirtualInterface {
    device: Arc<Mutex<Box<dyn TunDevice>>>,
    ip_allocator: IpAllocator,
    route_table: RouteTable,
    packet_filter: PacketFilter,
}

impl VirtualInterface {
    /// Create and initialize a TUN interface with local allocator and routing.
    pub fn new(interface_name: &str, ip_range: &str) -> Result<Self> {
        let device = open_tun(interface_name)?;
        let ip_allocator = IpAllocator::new(ip_range)?;
        let route_table = RouteTable::new();
        let packet_filter = PacketFilter::new();

        Ok(Self {
            device: Arc::new(Mutex::new(device)),
            ip_allocator,
            route_table,
            packet_filter,
        })
    }

    /// Read one packet from the TUN device and apply the ingress packet filter.
    ///
    /// Returns `Ok(0)` when the packet is dropped by the filter.
    pub fn read_packet(&self, buffer: &mut [u8]) -> Result<usize> {
        let device = self.device.lock().unwrap();
        let bytes_read = device.recv(buffer)?;
        if !self.packet_filter.filter_packet(&buffer[..bytes_read]) {
            return Ok(0);
        }
        Ok(bytes_read)
    }

    /// Write one packet to the TUN device.
    pub fn write_packet(&self, packet: &[u8]) -> Result<usize> {
        let device = self.device.lock().unwrap();
        device.send(packet)
    }

    /// Allocate the next available IP address from the configured local pool.
    pub fn allocate_ip(&mut self) -> Result<IpAddr> {
        self.ip_allocator.allocate()
    }

    /// Add a route entry to the local route table.
    pub fn add_route(
        &mut self,
        destination: IpAddr,
        gateway: Option<IpAddr>,
        interface: &str,
    ) -> Result<()> {
        self.route_table.add_route(destination, gateway, interface)
    }

    /// Return the OS-level interface name of the underlying TUN device.
    pub fn get_interface_name(&self) -> String {
        self.device.lock().unwrap().name()
    }
}

// ── IpAllocator ───────────────────────────────────────────────────────────────

pub struct IpAllocator {
    network: Ipv4Addr,
    netmask: Ipv4Addr,
    next_ip: Ipv4Addr,
    used_ips: Vec<Ipv4Addr>,
}

impl IpAllocator {
    /// Create allocator from a CIDR-like IPv4 range string (e.g. `10.42.0.0/16`).
    pub fn new(ip_range: &str) -> Result<Self> {
        let parts: Vec<&str> = ip_range.split('/').collect();
        if parts.len() != 2 {
            return Err(MeshInfinityError::InvalidConfiguration(format!(
                "Invalid IP range format: {}",
                ip_range
            )));
        }

        let base_ip: Ipv4Addr = parts[0].parse().map_err(|err| {
            MeshInfinityError::InvalidConfiguration(format!("Invalid IP range base: {err}"))
        })?;
        let prefix_len: u8 = parts[1].parse().map_err(|err| {
            MeshInfinityError::InvalidConfiguration(format!("Invalid IP range prefix: {err}"))
        })?;

        let netmask = match prefix_len {
            0..=8 => Ipv4Addr::new(255, 0, 0, 0),
            9..=16 => Ipv4Addr::new(255, 255, 0, 0),
            17..=24 => Ipv4Addr::new(255, 255, 255, 0),
            _ => Ipv4Addr::new(255, 255, 255, 255),
        };

        let mut octets = base_ip.octets();
        octets[3] = 1;
        let next_ip = Ipv4Addr::from(octets);

        Ok(Self {
            network: base_ip,
            netmask,
            next_ip,
            used_ips: vec![base_ip],
        })
    }

    /// Allocate the next sequential IPv4 address in the range.
    pub fn allocate(&mut self) -> Result<IpAddr> {
        let ip = self.next_ip;

        if !self.is_in_range(ip) {
            return Err(MeshInfinityError::InvalidConfiguration(format!(
                "IP allocation exceeded range: {}",
                ip
            )));
        }

        let octets = self.next_ip.octets();
        let mut new_octets = octets;
        new_octets[3] = new_octets[3].wrapping_add(1);
        if new_octets[3] == 0 {
            new_octets[2] = new_octets[2].wrapping_add(1);
            if new_octets[2] == 0 {
                new_octets[1] = new_octets[1].wrapping_add(1);
                if new_octets[1] == 0 {
                    new_octets[0] = new_octets[0].wrapping_add(1);
                }
            }
        }

        let next_ip = Ipv4Addr::from(new_octets);
        if !self.is_in_range(next_ip) {
            return Err(MeshInfinityError::InvalidConfiguration(format!(
                "IP allocation exceeded range: {}",
                next_ip
            )));
        }

        self.next_ip = next_ip;
        self.used_ips.push(ip);

        Ok(IpAddr::V4(ip))
    }

    fn is_in_range(&self, ip: Ipv4Addr) -> bool {
        let net = u32::from(self.network);
        let mask = u32::from(self.netmask);
        (u32::from(ip) & mask) == (net & mask)
    }
}

// ── RouteTable ────────────────────────────────────────────────────────────────

pub struct RouteTable {
    routes: Vec<RouteEntry>,
}

impl Default for RouteTable {
    fn default() -> Self {
        Self::new()
    }
}

impl RouteTable {
    pub fn new() -> Self {
        Self { routes: Vec::new() }
    }

    pub fn add_route(
        &mut self,
        destination: IpAddr,
        gateway: Option<IpAddr>,
        interface: &str,
    ) -> Result<()> {
        self.routes.push(RouteEntry {
            destination,
            gateway,
            interface: interface.to_string(),
        });
        Ok(())
    }

    pub fn find_route(&self, destination: &IpAddr) -> Option<&RouteEntry> {
        self.routes
            .iter()
            .find(|route| &route.destination == destination)
    }
}

pub struct RouteEntry {
    pub destination: IpAddr,
    pub gateway: Option<IpAddr>,
    pub interface: String,
}

// ── PacketFilter ──────────────────────────────────────────────────────────────

pub struct PacketFilter {}

impl Default for PacketFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketFilter {
    pub fn new() -> Self {
        Self {}
    }

    /// Evaluate a packet against current rules.  Currently allows all packets.
    pub fn filter_packet(&self, _packet: &[u8]) -> bool {
        true
    }
}
