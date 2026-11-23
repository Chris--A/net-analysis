//! SSDP discovery replies, UPnP device descriptions, and the small slice of
//! HTTP/1.1 needed to fetch them.

use na_model::UpnpInfo;

pub const SSDP_ADDR: &str = "239.255.255.250:1900";

pub fn m_search(st: &str, mx: u8) -> String {
    format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: {SSDP_ADDR}\r\nMAN: \"ssdp:discover\"\r\nMX: {mx}\r\nST: {st}\r\nUSER-AGENT: net-analysis/0.1 UPnP/1.1\r\n\r\n"
    )
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SsdpReply {
    pub location: Option<String>,
    pub server: Option<String>,
    pub st: Option<String>,
    pub usn: Option<String>,
}

/// Parse an M-SEARCH response (or a NOTIFY).
pub fn parse_ssdp(text: &str) -> Option<SsdpReply> {
    let mut lines = text.lines();
    let first = lines.next()?;
    if !(first.starts_with("HTTP/1.1 200") || first.starts_with("NOTIFY")) {
        return None;
    }
    let mut r = SsdpReply::default();
    for line in lines {
        let Some((k, v)) = line.split_once(':') else { continue };
        let v = Some(v.trim().to_owned()).filter(|v| !v.is_empty());
        match k.trim().to_ascii_uppercase().as_str() {
            "LOCATION" => r.location = v,
            "SERVER" => r.server = v,
            "ST" | "NT" => r.st = v,
            "USN" => r.usn = v,
            _ => {}
        }
    }
    Some(r)
}

/// `http://192.168.1.1:5000/rootDesc.xml` → `("192.168.1.1", 5000, "/rootDesc.xml")`. HTTP only.
pub fn split_http_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("http://").or_else(|| url.strip_prefix("HTTP://"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.contains(']') || h.ends_with(']') => (h, p.parse().ok()?),
        _ => (authority, 80),
    };
    Some((host.trim_matches(['[', ']']).to_owned(), port, path.to_owned()))
}

/// Root-device fields from a UPnP description. Embedded devices are ignored.
pub fn parse_description(xml: &str) -> UpnpInfo {
    let root = match xml.find("<device") {
        Some(start) => {
            let body = &xml[start..];
            let end = ["<deviceList", "<serviceList", "</device>"]
                .iter()
                .filter_map(|t| body.find(t))
                .min()
                .unwrap_or(body.len());
            &body[..end]
        }
        None => "",
    };
    UpnpInfo {
        friendly_name: tag(root, "friendlyName"),
        manufacturer: tag(root, "manufacturer"),
        model_name: tag(root, "modelName"),
        model_number: tag(root, "modelNumber"),
        model_description: tag(root, "modelDescription"),
        device_type: tag(root, "deviceType"),
        server: None,
        advertised: Vec::new(),
    }
}

/// Text of the first `<name>…</name>`, entity-decoded and trimmed.
fn tag(xml: &str, name: &str) -> Option<String> {
    let open = format!("<{name}");
    let mut from = 0;
    while let Some(i) = xml[from..].find(&open) {
        let start = from + i + open.len();
        // Must be `<name>` or `<name attr…>`, not `<nameSuffix>`.
        match xml[start..].chars().next() {
            Some('>') | Some(' ') | Some('\t') | Some('\n') | Some('\r') => {
                let gt = start + xml[start..].find('>')? + 1;
                let close = format!("</{name}>");
                let end = gt + xml[gt..].find(&close)?;
                let v = decode_entities(xml[gt..end].trim());
                return (!v.is_empty()).then_some(v);
            }
            _ => from = start,
        }
    }
    None
}

fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let Some(semi) = tail.find(';').filter(|&j| j <= 8) else {
            out.push('&');
            rest = &tail[1..];
            continue;
        };
        let ent = &tail[1..semi];
        let ch = match ent {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ if ent.starts_with("#x") => u32::from_str_radix(&ent[2..], 16).ok().and_then(char::from_u32),
            _ if ent.starts_with('#') => ent[1..].parse().ok().and_then(char::from_u32),
            _ => None,
        };
        match ch {
            Some(c) => out.push(c),
            None => out.push_str(&tail[..=semi]),
        }
        rest = &tail[semi + 1..];
    }
    out.push_str(rest);
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// `<title>` of an HTML body.
    pub fn title(&self) -> Option<String> {
        let text = String::from_utf8_lossy(&self.body);
        let lower = text.to_ascii_lowercase();
        let start = lower.find("<title")?;
        let gt = start + lower[start..].find('>')? + 1;
        let end = gt + lower[gt..].find("</title")?;
        let t = decode_entities(text[gt..end].trim());
        let t: String = t.split_whitespace().collect::<Vec<_>>().join(" ");
        (!t.is_empty()).then_some(t)
    }
}

/// Parse a complete (possibly truncated-body) HTTP/1.x response, de-chunking if needed.
pub fn parse_http(raw: &[u8]) -> Option<HttpResponse> {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&raw[..split]).ok()?;
    let mut lines = head.split("\r\n");
    let status = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();
    let mut body = raw[split + 4..].to_vec();
    let chunked = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked"));
    if chunked {
        body = dechunk(&body);
    }
    Some(HttpResponse { status, headers, body })
}

fn dechunk(mut data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(eol) = data.windows(2).position(|w| w == b"\r\n") {
        let size_text = String::from_utf8_lossy(&data[..eol]);
        let Ok(size) = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16) else { break };
        if size == 0 {
            break;
        }
        let start = eol + 2;
        let end = (start + size).min(data.len());
        out.extend_from_slice(&data[start..end]);
        data = data.get(end + 2..).unwrap_or_default();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssdp_reply_headers() {
        let r = parse_ssdp(
            "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLocation: http://192.168.1.1:5000/rootDesc.xml\r\n\
             SERVER: Linux/3.14 UPnP/1.0 MiniUPnPd/2.1\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
             USN: uuid:abc::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n",
        )
        .unwrap();
        assert_eq!(r.location.as_deref(), Some("http://192.168.1.1:5000/rootDesc.xml"));
        assert!(r.server.unwrap().contains("MiniUPnPd"));
        assert_eq!(parse_ssdp("M-SEARCH * HTTP/1.1\r\n\r\n"), None);
        assert_eq!(
            split_http_url("http://192.168.1.1:5000/rootDesc.xml"),
            Some(("192.168.1.1".into(), 5000, "/rootDesc.xml".into()))
        );
        assert_eq!(split_http_url("http://10.0.0.2"), Some(("10.0.0.2".into(), 80, "/".into())));
        assert_eq!(split_http_url("https://10.0.0.2/x"), None);
    }

    #[test]
    fn description_uses_root_device_only() {
        let xml = r#"<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0">
            <device><deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
            <friendlyName>Living Room &amp; Kitchen</friendlyName><manufacturer>Sonos, Inc.</manufacturer>
            <modelName>Sonos One</modelName><modelNumber>S18</modelNumber>
            <deviceList><device><friendlyName>Embedded</friendlyName><modelName>Other</modelName></device></deviceList>
            </device></root>"#;
        let d = parse_description(xml);
        assert_eq!(d.friendly_name.as_deref(), Some("Living Room & Kitchen"));
        assert_eq!(d.manufacturer.as_deref(), Some("Sonos, Inc."));
        assert_eq!(d.model_name.as_deref(), Some("Sonos One"));
        assert_eq!(d.model_number.as_deref(), Some("S18"));
        assert_eq!(d.device_type.as_deref(), Some("urn:schemas-upnp-org:device:MediaRenderer:1"));
        assert_eq!(decode_entities("a&#x41;&#66;&bogus;&"), "aAB&bogus;&");
    }

    #[test]
    fn http_plain_and_chunked() {
        let r = parse_http(b"HTTP/1.1 200 OK\r\nServer: lighttpd/1.4\r\n\r\n<html><title> Router\n Login </title>").unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.header("server"), Some("lighttpd/1.4"));
        assert_eq!(r.title().as_deref(), Some("Router Login"));
        let c = parse_http(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n").unwrap();
        assert_eq!(c.body, b"hello world");
        assert_eq!(parse_http(b"garbage"), None);
    }
}
