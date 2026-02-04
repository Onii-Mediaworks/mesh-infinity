use std::net::IpAddr;

use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;

use crate::core::error::{MeshInfinityError, Result};

pub struct DnsResolver {
    resolver: Resolver,
}

impl DnsResolver {
    pub fn new() -> Result<Self> {
        let resolver = Resolver::from_system_conf()
            .or_else(|_| Resolver::new(ResolverConfig::default(), ResolverOpts::default()))
            .map_err(|err| MeshInfinityError::NetworkError(format!("dns resolver init failed: {err}")))?;

        Ok(Self { resolver })
    }

    pub fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        if let Ok(ip) = hostname.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        let response = self
            .resolver
            .lookup_ip(hostname)
            .map_err(|err| MeshInfinityError::NetworkError(format!("dns lookup failed: {err}")))?;
        Ok(response.iter().collect())
    }
}
