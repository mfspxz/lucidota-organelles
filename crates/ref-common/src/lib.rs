//! Shared helpers for reference organelles: a minimal dependency-free
//! HTTP/1.1 client (http:// only — https is honestly refused) and a small
//! HTML text extractor. Pure std; deterministic.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub struct HttpError(pub String);

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "http: {}", self.0)
    }
}

fn parse_url(url: &str) -> Result<(String, u16, String), HttpError> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| HttpError("only http:// URLs supported in reference build".to_string()))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    if authority.is_empty() {
        return Err(HttpError("empty host".to_string()));
    }
    let (host, port) = match authority.rfind(':') {
        Some(i) => {
            let port: u16 = authority[i + 1..]
                .parse()
                .map_err(|_| HttpError("bad port".to_string()))?;
            (authority[..i].to_string(), port)
        }
        None => (authority.to_string(), 80),
    };
    Ok((host, port, path))
}

fn do_request(
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    timeout_ms: u64,
    max_bytes: usize,
) -> Result<HttpResponse, HttpError> {
    let (host, port, path) = parse_url(url)?;
    let timeout = Duration::from_millis(timeout_ms.max(1).min(30_000));
    let addr = format!("{host}:{port}")
        .to_socket_addrs()
        .map_err(|e| HttpError(format!("dns: {e}")))?
        .next()
        .ok_or_else(|| HttpError("no address".to_string()))?;
    let mut stream = TcpStream::connect_timeout(&addr, timeout)
        .map_err(|e| HttpError(format!("connect: {e}")))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| HttpError(format!("timeout: {e}")))?;

    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    if let Some(b) = body {
        req.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            b.len()
        ));
    }
    req.push_str("\r\n");
    stream
        .write_all(req.as_bytes())
        .map_err(|e| HttpError(format!("write: {e}")))?;
    if let Some(b) = body {
        stream
            .write_all(b)
            .map_err(|e| HttpError(format!("write body: {e}")))?;
    }

    // Read headers first (bounded), then body up to max_bytes+1.
    let mut head = Vec::with_capacity(8192);
    let mut one = [0u8; 1];
    loop {
        if head.len() > 65536 {
            return Err(HttpError("header too large".to_string()));
        }
        match stream.read(&mut one) {
            Ok(0) => break,
            Ok(_) => {
                head.push(one[0]);
                if head.len() >= 4 && &head[head.len() - 4..] == b"\r\n\r\n" {
                    break;
                }
            }
            Err(e) => return Err(HttpError(format!("read head: {e}"))),
        }
    }
    let head_str = String::from_utf8_lossy(&head);
    let mut lines = head_str.lines();
    let status_line = lines.next().ok_or_else(|| HttpError("empty response".to_string()))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| HttpError(format!("bad status line: {status_line}")))?;
    let mut headers = Vec::new();
    let mut content_length: Option<usize> = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_string();
            let v = v.trim().to_string();
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.parse().ok();
            }
            headers.push((k, v));
        }
    }

    let want = content_length.unwrap_or(usize::MAX).min(max_bytes + 1);
    let mut body_out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        if body_out.len() >= want {
            break;
        }
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => body_out.extend_from_slice(&buf[..n]),
            Err(e) => {
                // Timeouts mid-body: return what we have, marked truncated.
                let _ = e;
                break;
            }
        }
    }
    let truncated = body_out.len() > max_bytes;
    if truncated {
        body_out.truncate(max_bytes);
    }
    Ok(HttpResponse { status, headers, body: body_out, truncated })
}

/// Minimal HTTP GET. `max_bytes` caps the body; excess sets `truncated`.
pub fn http_get(url: &str, timeout_ms: u64, max_bytes: usize) -> Result<HttpResponse, HttpError> {
    do_request("GET", url, None, timeout_ms, max_bytes)
}

/// Minimal HTTP POST with a JSON body; parses a JSON response body.
pub fn http_post_json(
    url: &str,
    body: &serde_json::Value,
    timeout_ms: u64,
    max_bytes: usize,
) -> Result<(u16, serde_json::Value), HttpError> {
    let bytes = serde_json::to_vec(body).map_err(|e| HttpError(format!("encode: {e}")))?;
    let r = do_request("POST", url, Some(&bytes), timeout_ms, max_bytes)?;
    let v: serde_json::Value =
        serde_json::from_slice(&r.body).map_err(|e| HttpError(format!("decode: {e}")))?;
    Ok((r.status, v))
}

// ---------------------------------------------------------------------------
// HTML extraction
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Extracted {
    pub title: Option<String>,
    pub text: String,
    pub links: Vec<String>,
}

fn strip_tags(html: &str) -> (String, Option<String>, Vec<String>) {
    let mut text = String::new();
    let mut title: Option<String> = None;
    let mut links = Vec::new();
    let bytes = html.as_bytes();
    let mut i = 0;
    let mut skip_depth: i32 = 0; // inside script/style
    let mut in_title = false;
    let mut title_buf = String::new();
    while i < bytes.len() {
        if bytes[i] == b'<' {
            if let Some(end) = html[i..].find('>') {
                let tag = html[i + 1..i + end].trim().to_ascii_lowercase();
                let tag_name: String =
                    tag.split_whitespace().next().unwrap_or("").trim_start_matches('/').to_string();
                if tag_name == "script" || tag_name == "style" {
                    if tag.starts_with('/') {
                        skip_depth = skip_depth.saturating_sub(1);
                    } else {
                        skip_depth += 1;
                    }
                } else if tag_name == "title" {
                    if tag.starts_with('/') {
                        in_title = false;
                        if title.is_none() {
                            title = Some(title_buf.trim().to_string());
                        }
                    } else {
                        in_title = true;
                        title_buf.clear();
                    }
                } else if tag_name == "a" && !tag.starts_with('/') {
                    if let Some(href) = extract_attr(&tag, "href") {
                        links.push(href);
                    }
                }
                if skip_depth == 0 && !in_title {
                    text.push(' ');
                }
                i += end + 1;
                continue;
            }
        }
        let c = bytes[i] as char;
        if skip_depth == 0 {
            if in_title {
                title_buf.push(c);
            } else {
                text.push(c);
            }
        }
        i += 1;
    }
    // Collapse whitespace.
    let collapsed = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    (collapsed, title, links)
}

fn extract_attr(tag: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=");
    let start = tag.find(&needle)? + needle.len();
    let rest = tag[start..].trim_start();
    let quote = rest.chars().next()?;
    if quote == '"' || quote == '\'' {
        let end = rest[1..].find(quote)?;
        Some(rest[1..1 + end].to_string())
    } else {
        let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
        Some(rest[..end].to_string())
    }
}

/// Extract title, visible text, and links from HTML.
pub fn extract_text(html: &str) -> Extracted {
    let (text, title, links) = strip_tags(html);
    Extracted { title, text, links }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_https_honestly() {
        let e = http_get("https://example.com/", 1000, 1024).unwrap_err();
        assert!(e.0.contains("http://"), "{e}");
    }

    #[test]
    fn get_against_local_server() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let body = b"hello test";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
            let _ = s.write_all(body);
        });
        let r = http_get(&format!("http://127.0.0.1:{port}/x"), 3000, 1024).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"hello test");
        assert!(!r.truncated);
    }

    #[test]
    fn body_truncation_flagged() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let body = vec![b'a'; 5000];
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: 5000\r\nConnection: close\r\n\r\n"
            );
            let _ = s.write_all(resp.as_bytes());
            let _ = s.write_all(&body);
        });
        let r = http_get(&format!("http://127.0.0.1:{port}/"), 3000, 100).unwrap();
        assert!(r.truncated);
        assert_eq!(r.body.len(), 100);
    }

    #[test]
    fn html_extraction() {
        let html = r#"<html><head><title>Hi</title><style>.x{}</style></head>
            <body><h1>Hello <a href="/p">world</a></h1><script>var x=1;</script></body></html>"#;
        let e = extract_text(html);
        assert_eq!(e.title.as_deref(), Some("Hi"));
        assert!(e.text.contains("Hello") && e.text.contains("world"), "{}", e.text);
        assert!(!e.text.contains("var x"), "script leaked: {}", e.text);
        assert_eq!(e.links, vec!["/p".to_string()]);
    }

    #[test]
    fn post_json_roundtrip() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let n = s.read(&mut buf).unwrap_or(0);
            let got = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(got.starts_with("POST /chat"));
            let body = br#"{"reply":"hi"}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
            let _ = s.write_all(body);
        });
        let (status, v) =
            http_post_json(&format!("http://127.0.0.1:{port}/chat"), &serde_json::json!({"m":1}), 3000, 4096)
                .unwrap();
        assert_eq!(status, 200);
        assert_eq!(v["reply"], serde_json::json!("hi"));
    }
}
