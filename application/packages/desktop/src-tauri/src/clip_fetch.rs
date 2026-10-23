//! `clip_fetch`: download one web page or one picture for the web clipper, or
//! one calendar file for the calendar import, from this device, with no server
//! of ours in between.
//!
//! The command fetches an address the person typed or a page named, so it is
//! a door from the web view to the network. What keeps it from reaching
//! anything but the public web:
//! - only `http` and `https`, no user name or password in the address;
//! - the host is resolved here, every answer is checked against the private
//!   and local ranges, and the connection goes to the address that was
//!   checked, so a second DNS answer cannot move it;
//! - redirects are followed by hand, at most five, each hop checked the same
//!   way;
//! - an address assigned to this device is refused too, which catches a
//!   global IPv6 address that routes back to it;
//! - the ports browsers refuse (the Fetch standard's bad-port list) are
//!   refused;
//! - certificates are checked offline against the Mozilla root list, so the
//!   check itself never downloads anything;
//! - no proxy, no cookies, no referrer, no stored credentials;
//! - a type and size limit per kind, and one deadline for the whole download.
//!
//! The answer goes back as raw bytes: four bytes of header length (big
//! endian), a JSON header `{ url, contentType }`, then the body. A refusal is
//! an error string of one opaque code, mapped to a message by the web view.
//! Spec: ops/docs/archive/web-clipper-stage1.md (section 3.1)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{CONTENT_LENGTH, CONTENT_TYPE, LOCATION};
use reqwest::Url;

const MAX_REDIRECTS: usize = 5;
const DEADLINE: Duration = Duration::from_secs(20);
/// Spec: ops/docs/archive/web-clipper-stage1.md (section 3.1, page: 5 MB)
const PAGE_MAX_BYTES: usize = 5 * 1024 * 1024;
/// One picture may be as large as the per-clip picture budget.
/// Spec: ops/docs/archive/web-clipper-stage1.md (section 3.3, 10 MB per clip)
const IMAGE_MAX_BYTES: usize = 10_000_000;
/// A public calendar feed of several years is a few MB.
/// Spec: ops/issues/0548.md (Spec, design A)
const CALENDAR_MAX_BYTES: usize = 10_000_000;
const USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15";

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind {
    Page,
    Image,
    Calendar,
}

impl Kind {
    fn parse(kind: &str) -> Result<Self, &'static str> {
        match kind {
            "page" => Ok(Kind::Page),
            "image" => Ok(Kind::Image),
            "calendar" => Ok(Kind::Calendar),
            _ => Err("bad-request"),
        }
    }

    fn max_bytes(self) -> usize {
        match self {
            Kind::Page => PAGE_MAX_BYTES,
            Kind::Image => IMAGE_MAX_BYTES,
            Kind::Calendar => CALENDAR_MAX_BYTES,
        }
    }

    fn accepts(self, content_type: &str) -> bool {
        let essence = content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
        match self {
            Kind::Page => essence == "text/html" || essence == "application/xhtml+xml",
            Kind::Image => essence.starts_with("image/"),
            // Many calendar servers send a generic type; the importer refuses
            // a body that is not a calendar. An HTML page is refused here.
            Kind::Calendar => matches!(
                essence.as_str(),
                "text/calendar" | "application/ics" | "text/plain" | "application/octet-stream" | "application/binary"
            ),
        }
    }

    fn accept_header(self) -> &'static str {
        match self {
            Kind::Calendar => "text/calendar,*/*;q=0.5",
            _ => "text/html,application/xhtml+xml,image/*;q=0.9,*/*;q=0.5",
        }
    }
}

pub struct Fetched {
    pub url: String,
    pub content_type: String,
    pub body: Vec<u8>,
}

/// The one exception a test may make to the address check: a local test
/// server. Production code always passes `Guard::default()`.
#[derive(Default)]
pub struct Guard {
    #[cfg(test)]
    pub allow: Option<SocketAddr>,
}

impl Guard {
    fn permits(&self, addr: SocketAddr) -> bool {
        #[cfg(test)]
        if self.allow == Some(addr) {
            return true;
        }
        !is_blocked(addr.ip()) && !is_own_address(addr.ip()) && !is_bad_port(addr.port())
    }
}

/// Whether `ip` is assigned to one of this device's interfaces: only then
/// can a socket bind to it. A public IPv6 address of the device passes every
/// range check and still reaches services listening on it.
fn is_own_address(ip: IpAddr) -> bool {
    std::net::UdpSocket::bind(SocketAddr::new(ip, 0)).is_ok()
}

/// The ports the Fetch standard blocks, so a page cannot aim a request at a
/// mail, shell or database service. https://fetch.spec.whatwg.org/#port-blocking
fn is_bad_port(port: u16) -> bool {
    const BAD: [u16; 82] = [
        0, 1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79, 87, 95, 101, 102, 103, 104, 109,
        110, 111, 113, 115, 117, 119, 123, 135, 137, 139, 143, 161, 179, 389, 427, 465, 512, 513, 514, 515, 526, 530,
        531, 532, 540, 548, 554, 556, 563, 587, 601, 636, 989, 990, 993, 995, 1719, 1720, 1723, 2049, 3659, 4045, 4190,
        5060, 5061, 6000, 6566, 6665, 6666, 6667, 6668, 6669, 6679, 6697,
    ];
    BAD.contains(&port) || port == 10080
}

/// Whether an address is one the clipper must never connect to: loopback,
/// private, shared (carrier NAT), link-local, unspecified, multicast,
/// broadcast, documentation and reserved ranges, and the IPv6 forms that
/// carry one of those IPv4 addresses inside.
pub fn is_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => is_blocked_v6(v6),
    }
}

fn is_blocked_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || a == 0
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (b == 18 || b == 19))
        || a >= 240
}

fn is_blocked_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = embedded_v4(ip) {
        return is_blocked_v4(v4);
    }
    let first = ip.segments()[0];
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (first & 0xfe00) == 0xfc00 // unique local fc00::/7
        || (first & 0xffc0) == 0xfe80 // link local fe80::/10
        || (first & 0xffc0) == 0xfec0 // site local fec0::/10
        || first == 0x2001 && ip.segments()[1] == 0x0db8 // documentation
        || first == 0x0100 && ip.segments()[1..4] == [0, 0, 0] // discard 100::/64
        || first == 0x0064 && ip.segments()[1] == 0xff9b && ip.segments()[2] == 0x0001 // local NAT64 64:ff9b:1::/48, any layout
}

/// The IPv4 address inside a mapped (`::ffff:a.b.c.d`), translated
/// (`::ffff:0:a.b.c.d`), compatible (`::a.b.c.d`), NAT64 (`64:ff9b::/96`),
/// Teredo
/// (`2001::/32`, the client address inverted in the last two groups) or 6to4
/// (`2002::/16`) address.
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return Some(v4);
    }
    let s = ip.segments();
    let tail = Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8);
    if s[..6] == [0, 0, 0, 0, 0, 0] && !ip.is_loopback() && !ip.is_unspecified() {
        return Some(tail);
    }
    if s[..6] == [0, 0, 0, 0, 0xffff, 0] {
        return Some(tail);
    }
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        return Some(tail);
    }
    if s[0] == 0x2001 && s[1] == 0 {
        let t = [!s[6], !s[7]];
        return Some(Ipv4Addr::new((t[0] >> 8) as u8, t[0] as u8, (t[1] >> 8) as u8, t[1] as u8));
    }
    if s[0] == 0x2002 {
        return Some(Ipv4Addr::new((s[1] >> 8) as u8, s[1] as u8, (s[2] >> 8) as u8, s[2] as u8));
    }
    None
}

/// Parse and check an address the web view sent or a redirect named.
pub fn check_url(raw: &str) -> Result<Url, &'static str> {
    let url = Url::parse(raw.trim()).map_err(|_| "bad-url")?;
    if url.scheme() != "https" && url.scheme() != "http" {
        return Err("bad-url");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("bad-url");
    }
    if url.host().is_none() {
        return Err("bad-url");
    }
    Ok(url)
}

/// Resolve the host of `url` and return the one address to connect to. Every
/// answer must pass, not only the one used: a host that also points inside
/// the network is refused.
async fn resolve(url: &Url, guard: &Guard) -> Result<SocketAddr, &'static str> {
    let port = url.port_or_known_default().ok_or("bad-url")?;
    let addrs: Vec<SocketAddr> = match url.host() {
        Some(url::Host::Ipv4(ip)) => vec![SocketAddr::new(IpAddr::V4(ip), port)],
        Some(url::Host::Ipv6(ip)) => vec![SocketAddr::new(IpAddr::V6(ip), port)],
        Some(url::Host::Domain(name)) => tokio::net::lookup_host((name, port))
            .await
            .map_err(|_| "dns")?
            .collect(),
        None => return Err("bad-url"),
    };
    let first = *addrs.first().ok_or("dns")?;
    if addrs.iter().any(|a| !guard.permits(*a)) {
        return Err("blocked-address");
    }
    Ok(first)
}

/// Certificates are checked offline, against the Mozilla root list, on every
/// platform. A platform verifier may fetch a missing issuer certificate from
/// an address the site's certificate names, outside every check above.
fn tls_config() -> Result<rustls::ClientConfig, &'static str> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| "tls")?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// One request to `url`, connected to `addr` and nowhere else.
async fn request(url: &Url, addr: SocketAddr, kind: Kind) -> Result<reqwest::Response, &'static str> {
    let mut builder = reqwest::Client::builder()
        .tls_backend_preconfigured(tls_config()?)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .referer(false)
        .user_agent(USER_AGENT)
        .connect_timeout(Duration::from_secs(10));
    if let Some(url::Host::Domain(name)) = url.host() {
        builder = builder.resolve(name, addr);
    }
    let client = builder.build().map_err(|_| "network")?;
    client
        .get(url.clone())
        .header("accept", kind.accept_header())
        .send()
        .await
        .map_err(|_| "network")
}

/// Download `raw` as `kind`, following redirects by hand.
pub async fn fetch(raw: &str, kind: Kind, guard: &Guard) -> Result<Fetched, String> {
    match tokio::time::timeout(DEADLINE, fetch_inner(raw, kind, guard)).await {
        Ok(result) => result,
        Err(_) => Err("timeout".into()),
    }
}

async fn fetch_inner(raw: &str, kind: Kind, guard: &Guard) -> Result<Fetched, String> {
    let mut url = check_url(raw)?;
    for hop in 0..=MAX_REDIRECTS {
        let addr = resolve(&url, guard).await?;
        let mut response = request(&url, addr, kind).await?;
        let status = response.status();
        if status.is_redirection() {
            if hop == MAX_REDIRECTS {
                return Err("too-many-redirects".into());
            }
            let location = response
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or("bad-redirect")?;
            let next = url.join(location).map_err(|_| "bad-redirect")?;
            url = check_url(next.as_str())?;
            continue;
        }
        if !status.is_success() {
            return Err(format!("status:{}", status.as_u16()));
        }
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        if !kind.accepts(&content_type) {
            return Err("wrong-type".into());
        }
        let limit = kind.max_bytes();
        let declared = response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        if declared.is_some_and(|n| n > limit as u64) {
            return Err("too-large".into());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| "network")? {
            if body.len() + chunk.len() > limit {
                return Err("too-large".into());
            }
            body.extend_from_slice(&chunk);
        }
        return Ok(Fetched { url: url.to_string(), content_type, body });
    }
    Err("too-many-redirects".into())
}

/// Frame a download for the web view: header length, JSON header, body.
fn frame(fetched: Fetched) -> Vec<u8> {
    let header = serde_json::json!({ "url": fetched.url, "contentType": fetched.content_type }).to_string();
    let mut out = Vec::with_capacity(4 + header.len() + fetched.body.len());
    out.extend_from_slice(&(header.len() as u32).to_be_bytes());
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(&fetched.body);
    out
}

#[tauri::command]
pub async fn clip_fetch(url: String, kind: String) -> Result<tauri::ipc::Response, String> {
    let kind = Kind::parse(&kind)?;
    let fetched = fetch(&url, kind, &Guard::default()).await?;
    Ok(tauri::ipc::Response::new(frame(fetched)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn refuses_private_and_local_ipv4() {
        for s in [
            "127.0.0.1", "127.8.8.8", "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255",
            "192.168.1.1", "169.254.169.254", "100.64.0.1", "100.127.255.255", "0.0.0.0", "0.1.2.3",
            "255.255.255.255", "224.0.0.1", "192.0.2.1", "198.18.0.1", "240.0.0.1",
        ] {
            assert!(is_blocked(ip(s)), "{s} must be refused");
        }
    }

    #[test]
    fn allows_public_ipv4() {
        for s in ["1.1.1.1", "93.184.216.34", "172.15.255.255", "172.32.0.1", "100.63.255.255", "100.128.0.1", "192.169.0.1"] {
            assert!(!is_blocked(ip(s)), "{s} is public");
        }
    }

    #[test]
    fn refuses_private_and_local_ipv6() {
        for s in [
            "::1", "::", "fc00::1", "fd12:3456::1", "fe80::1", "fec0::1", "ff02::1", "2001:db8::1",
            "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "::10.0.0.1",
            "64:ff9b::a00:1", "64:ff9b:1::c0a8:101", "64:ff9b:1:0:c0:a801:100:0", "::ffff:0:c0a8:101", "2001:0:4136:e378:8000:63bf:f5ff:fefe",
            "2002:c0a8:0101::1", "100::1",
        ] {
            assert!(is_blocked(ip(s)), "{s} must be refused");
        }
    }

    #[test]
    fn allows_public_ipv6() {
        for s in ["2606:4700:4700::1111", "2a00:1450:4001::200e", "::ffff:1.1.1.1", "64:ff9b::101:101", "2002:0101:0101::1"] {
            assert!(!is_blocked(ip(s)), "{s} is public");
        }
    }

    #[test]
    fn refuses_bad_ports_and_own_addresses() {
        assert!(is_bad_port(25) && is_bad_port(22) && is_bad_port(6667) && is_bad_port(10080));
        assert!(!is_bad_port(80) && !is_bad_port(443) && !is_bad_port(8080));
        let guard = Guard::default();
        assert!(!guard.permits("1.1.1.1:25".parse().unwrap()));
        assert!(guard.permits("1.1.1.1:443".parse().unwrap()));
        // Every interface address of this machine binds, so each is refused.
        let probe = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        if probe.connect("1.1.1.1:53").is_ok() {
            let own = probe.local_addr().unwrap().ip();
            assert!(is_own_address(own), "{own} is this device");
        }
        assert!(!is_own_address("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn accepts_only_plain_http_addresses() {
        assert!(check_url("https://example.com/a").is_ok());
        assert!(check_url("http://example.com:8080/a").is_ok());
        for bad in [
            "ftp://example.com/", "file:///etc/passwd", "javascript:alert(1)", "data:text/html,x",
            "https://user:pass@example.com/", "https://user@example.com/", "not a url", "https://",
        ] {
            assert_eq!(check_url(bad).unwrap_err(), "bad-url", "{bad}");
        }
    }

    #[test]
    fn checks_the_type_per_kind() {
        assert!(Kind::Page.accepts("text/html; charset=utf-8"));
        assert!(Kind::Page.accepts("application/xhtml+xml"));
        assert!(!Kind::Page.accepts("application/json"));
        assert!(!Kind::Page.accepts("image/png"));
        assert!(Kind::Image.accepts("image/webp"));
        assert!(!Kind::Image.accepts("text/html"));
        assert!(!Kind::Image.accepts(""));
        assert!(Kind::Calendar.accepts("text/calendar; charset=utf-8"));
        assert!(Kind::Calendar.accepts("text/plain"));
        assert!(Kind::Calendar.accepts("application/octet-stream"));
        assert!(!Kind::Calendar.accepts("text/html"));
        assert!(!Kind::Calendar.accepts(""));
        assert_eq!(Kind::parse("calendar"), Ok(Kind::Calendar));
        assert_eq!(Kind::parse("video"), Err("bad-request"));
    }

    fn run<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(f)
    }

    /// A one-connection-at-a-time server answering every request with `reply`.
    async fn serve(reply: String) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { return };
                let mut buf = [0u8; 4096];
                let _ = socket.read(&mut buf).await;
                let _ = socket.write_all(reply.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });
        addr
    }

    fn response(status: &str, headers: &[(&str, &str)], body: &str) -> String {
        let mut out = format!("HTTP/1.1 {status}\r\nconnection: close\r\ncontent-length: {}\r\n", body.len());
        for (k, v) in headers {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        out.push_str("\r\n");
        out.push_str(body);
        out
    }

    #[test]
    fn refuses_a_local_address_before_connecting() {
        run(async {
            let addr = serve(response("200 OK", &[("content-type", "text/html")], "<p>hi</p>")).await;
            let err = fetch(&format!("http://{addr}/"), Kind::Page, &Guard::default()).await.err();
            assert_eq!(err.as_deref(), Some("blocked-address"));
            let err = fetch(&format!("http://localhost:{}/", addr.port()), Kind::Page, &Guard::default()).await.err();
            assert_eq!(err.as_deref(), Some("blocked-address"));
        });
    }

    #[test]
    fn downloads_a_page_from_an_allowed_server() {
        run(async {
            let addr = serve(response("200 OK", &[("content-type", "text/html; charset=utf-8")], "<p>hi</p>")).await;
            let got = fetch(&format!("http://{addr}/a"), Kind::Page, &Guard { allow: Some(addr) }).await.unwrap();
            assert_eq!(got.body, b"<p>hi</p>");
            assert_eq!(got.url, format!("http://{addr}/a"));
            assert!(got.content_type.starts_with("text/html"));
        });
    }

    #[test]
    fn checks_every_redirect_hop() {
        run(async {
            let addr = serve(response("302 Found", &[("location", "http://10.0.0.1/inside")], "")).await;
            let err = fetch(&format!("http://{addr}/"), Kind::Page, &Guard { allow: Some(addr) }).await.err();
            assert_eq!(err.as_deref(), Some("blocked-address"));
        });
    }

    #[test]
    fn refuses_a_redirect_to_another_scheme() {
        run(async {
            let addr = serve(response("301 Moved", &[("location", "file:///etc/passwd")], "")).await;
            let err = fetch(&format!("http://{addr}/"), Kind::Page, &Guard { allow: Some(addr) }).await.err();
            assert_eq!(err.as_deref(), Some("bad-url"));
        });
    }

    #[test]
    fn stops_after_five_redirects() {
        run(async {
            let addr = serve(response("302 Found", &[("location", "/again")], "")).await;
            let err = fetch(&format!("http://{addr}/"), Kind::Page, &Guard { allow: Some(addr) }).await.err();
            assert_eq!(err.as_deref(), Some("too-many-redirects"));
        });
    }

    #[test]
    fn refuses_the_wrong_type() {
        run(async {
            let addr = serve(response("200 OK", &[("content-type", "application/json")], "{}")).await;
            let err = fetch(&format!("http://{addr}/"), Kind::Page, &Guard { allow: Some(addr) }).await.err();
            assert_eq!(err.as_deref(), Some("wrong-type"));
            let err = fetch(&format!("http://{addr}/"), Kind::Image, &Guard { allow: Some(addr) }).await.err();
            assert_eq!(err.as_deref(), Some("wrong-type"));
        });
    }

    #[test]
    fn refuses_a_page_over_the_limit() {
        run(async {
            let big = "x".repeat(PAGE_MAX_BYTES + 1);
            let addr = serve(response("200 OK", &[("content-type", "text/html")], &big)).await;
            let err = fetch(&format!("http://{addr}/"), Kind::Page, &Guard { allow: Some(addr) }).await.err();
            assert_eq!(err.as_deref(), Some("too-large"));
        });
    }

    #[test]
    fn passes_a_refusal_status_through() {
        run(async {
            let addr = serve(response("403 Forbidden", &[("content-type", "text/html")], "blocked")).await;
            let err = fetch(&format!("http://{addr}/"), Kind::Page, &Guard { allow: Some(addr) }).await.err();
            assert_eq!(err.as_deref(), Some("status:403"));
        });
    }

    #[test]
    fn sends_no_cookie_and_no_credentials() {
        run(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let seen = tokio::spawn(async move {
                let mut all = String::new();
                for _ in 0..2 {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let mut buf = vec![0u8; 8192];
                    let n = socket.read(&mut buf).await.unwrap();
                    all.push_str(&String::from_utf8_lossy(&buf[..n]));
                    let reply = if all.matches("GET ").count() == 1 {
                        response("302 Found", &[("location", "/next"), ("set-cookie", "id=secret; Path=/")], "")
                    } else {
                        response("200 OK", &[("content-type", "text/html")], "<p>ok</p>")
                    };
                    socket.write_all(reply.as_bytes()).await.unwrap();
                    let _ = socket.shutdown().await;
                }
                all
            });
            fetch(&format!("http://{addr}/"), Kind::Page, &Guard { allow: Some(addr) }).await.unwrap();
            let requests = seen.await.unwrap().to_ascii_lowercase();
            assert!(!requests.contains("cookie:"), "{requests}");
            assert!(!requests.contains("authorization:"));
            assert!(!requests.contains("referer:"));
        });
    }

    /// Needs the network, so it runs only by hand:
    /// `cargo test clip_fetch -- --ignored`.
    #[test]
    #[ignore]
    fn downloads_a_public_page_over_tls() {
        run(async {
            let got = fetch("https://example.com/", Kind::Page, &Guard::default()).await.unwrap();
            assert!(String::from_utf8_lossy(&got.body).contains("Example Domain"));
        });
    }

    #[test]
    fn frames_the_answer() {
        let framed = frame(Fetched { url: "https://a.example/".into(), content_type: "text/html".into(), body: b"<p>x</p>".to_vec() });
        let len = u32::from_be_bytes(framed[..4].try_into().unwrap()) as usize;
        let header: serde_json::Value = serde_json::from_slice(&framed[4..4 + len]).unwrap();
        assert_eq!(header["url"], "https://a.example/");
        assert_eq!(header["contentType"], "text/html");
        assert_eq!(&framed[4 + len..], b"<p>x</p>");
    }
}
