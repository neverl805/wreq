//! DNS resolution via the [hickory-resolver](https://github.com/hickory-dns/hickory-dns) crate

use std::{net::SocketAddr, sync::LazyLock};

use hickory_resolver::{
    TokioResolver,
    config::{LookupIpStrategy, ResolverConfig},
    lookup_ip::LookupIpIntoIter,
    name_server::TokioConnectionProvider,
};

use super::{Addrs, Name, Resolve, Resolving, cache::GLOBAL_DNS_CACHE};

/// Wrapper around an [`TokioResolver`], which implements the `Resolve` trait.
#[derive(Debug, Clone)]
pub struct HickoryDnsResolver {
    /// Shared, lazily-initialized Tokio-based DNS resolver.
    ///
    /// Backed by [`LazyLock`] to guarantee thread-safe, one-time creation.
    /// On initialization, it attempts to load the system's DNS configuration;
    /// if unavailable, it falls back to sensible default settings.
    resolver: &'static LazyLock<TokioResolver>,
}

impl HickoryDnsResolver {
    /// Create a new resolver with the default configuration,
    /// which reads from `/etc/resolve.conf`. The options are
    /// overriden to look up for both IPv4 and IPv6 addresses
    /// to work with "happy eyeballs" algorithm.
    pub fn new() -> HickoryDnsResolver {
        static RESOLVER: LazyLock<TokioResolver> = LazyLock::new(|| {
            let mut builder = match TokioResolver::builder_tokio() {
                Ok(resolver) => {
                    debug!("using system DNS configuration");
                    resolver
                }
                Err(_err) => {
                    debug!("error reading DNS system conf: {}, using defaults", _err);
                    TokioResolver::builder_with_config(
                        ResolverConfig::default(),
                        TokioConnectionProvider::default(),
                    )
                }
            };
            builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
            builder.build()
        });

        HickoryDnsResolver {
            resolver: &RESOLVER,
        }
    }
}

struct SocketAddrs {
    iter: LookupIpIntoIter,
}

/// Wrapper for cached socket addresses
struct CachedSocketAddrs {
    iter: std::vec::IntoIter<std::net::IpAddr>,
}

impl Iterator for CachedSocketAddrs {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|ip_addr| SocketAddr::new(ip_addr, 0))
    }
}

impl Resolve for HickoryDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.clone();
        Box::pin(async move {
            let hostname = name.as_str();

            // Check cache first
            if let Some(cached_addrs) = GLOBAL_DNS_CACHE.get(hostname) {
                trace!("Using cached DNS result for {}", hostname);
                let ip_addrs: Vec<std::net::IpAddr> = cached_addrs.into_iter().map(|addr| addr.ip()).collect();
                let addrs: Addrs = Box::new(CachedSocketAddrs {
                    iter: ip_addrs.into_iter(),
                });
                return Ok(addrs);
            }

            // Cache miss - perform actual DNS lookup
            debug!("DNS cache miss, resolving {}", hostname);
            let lookup = resolver.resolver.lookup_ip(hostname).await?;

            // Collect addresses for caching
            let ip_addrs: Vec<_> = lookup.iter().collect();
            let socket_addrs: Vec<SocketAddr> = ip_addrs.iter()
                .map(|ip| SocketAddr::new(*ip, 0))
                .collect();

            // Cache the result
            if !socket_addrs.is_empty() {
                GLOBAL_DNS_CACHE.insert(hostname.to_string(), socket_addrs);
            }

            let addrs: Addrs = Box::new(SocketAddrs {
                iter: lookup.into_iter(),
            });
            Ok(addrs)
        })
    }
}

impl Iterator for SocketAddrs {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|ip_addr| SocketAddr::new(ip_addr, 0))
    }
}
