/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! Guards for outbound requests to URLs supplied by users or tenants, so they
//! cannot reach loopback, private or link-local services (SSRF).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::redirect::Policy;

/// True for addresses reachable on the public internet.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || a == 0
        // Carrier-grade NAT 100.64.0.0/10
        || (a == 100 && (b & 0xc0) == 64)
        // IETF protocol assignments 192.0.0.0/24, benchmarking 198.18.0.0/15
        || (a == 192 && b == 0 && ip.octets()[2] == 0)
        || (a == 198 && (b & 0xfe) == 18)
        // Reserved 240.0.0.0/4
        || a >= 240)
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_ipv4(v4);
    }
    let segments = ip.segments();
    // NAT64 64:ff9b::/96 embeds an IPv4 address
    if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        let [a, b] = segments[6].to_be_bytes();
        let [c, d] = segments[7].to_be_bytes();
        return is_public_ipv4(Ipv4Addr::new(a, b, c, d));
    }
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        // Unique local fc00::/7
        || (segments[0] & 0xfe00) == 0xfc00
        // Link local fe80::/10
        || (segments[0] & 0xffc0) == 0xfe80
        // Documentation 2001:db8::/32
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}

/// Extracts the host of an `http(s)://` URL, without brackets for IPv6.
pub fn url_host(url: &str) -> Option<&str> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(v6) = host_port.strip_prefix('[') {
        v6.split_once(']')?.0
    } else {
        host_port.split_once(':').map_or(host_port, |(h, _)| h)
    };
    (!host.is_empty()).then_some(host)
}

/// Rejects URLs that are not https or whose host is a non-public IP literal.
/// Host names are checked at connection time by [`public_http_client`].
pub fn is_public_https_url(url: &str) -> bool {
    url.starts_with("https://")
        && url_host(url).is_some_and(|host| {
            !host.eq_ignore_ascii_case("localhost")
                && host.parse::<IpAddr>().map_or(true, is_public_ip)
        })
}

/// Resolver that drops every non-public address, so a host name pointing at
/// an internal service (including via DNS rebinding) cannot be connected to.
struct PublicOnlyResolver;

impl Resolve for PublicOnlyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((name.as_str(), 0))
                .await?
                .filter(|addr| is_public_ip(addr.ip()))
                .collect();
            if addrs.is_empty() {
                return Err(
                    format!("{} does not resolve to a public address", name.as_str()).into(),
                );
            }
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

/// HTTP client for user-supplied URLs: public addresses only, no redirects.
/// Callers must still reject IP-literal URLs with [`is_public_https_url`],
/// since literals bypass the resolver.
pub fn public_http_client(timeout: Duration) -> reqwest::Result<Client> {
    Client::builder()
        .timeout(timeout)
        .redirect(Policy::none())
        .dns_resolver(Arc::new(PublicOnlyResolver))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_internal_addresses() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "64:ff9b::a9fe:a9fe",
        ] {
            assert!(!is_public_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "172.32.0.1", "2606:4700::1111"] {
            assert!(is_public_ip(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn validates_urls() {
        assert!(is_public_https_url("https://push.example.com/abc?x=1"));
        assert!(is_public_https_url("https://1.1.1.1:8443/x"));
        assert!(!is_public_https_url("http://push.example.com/"));
        assert!(!is_public_https_url("https://127.0.0.1:8080/api"));
        assert!(!is_public_https_url("https://[::1]/x"));
        assert!(!is_public_https_url("https://user@169.254.169.254/"));
        assert!(!is_public_https_url("https://localhost/x"));
        assert!(!is_public_https_url("https:///x"));
        assert_eq!(
            url_host("https://[2606:4700::1]:443/x"),
            Some("2606:4700::1")
        );
    }
}
