#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![deny(rustdoc::all)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![deny(clippy::cargo)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_wrap)]

//! Obtain the HTTP timings for any given URL
//!
//! This crate provides a way to measure the HTTP timings for any given URL.
//! This crate also provides basic and the certificate information for the given URL.
//!
//! Example:
//! ```rust
//! use http_timings::from_string;
//! use std::time::Duration;
//!
//! let url = "https://www.example.com";
//! let timeout = Some(Duration::from_secs(5)); // Set a timeout of 5 seconds
//! match from_string(url, timeout) {
//!     Ok(response) => {
//!         println!("Response Status: {}", response.status);
//!         println!("Response Body: {}", response.body);
//!         if let Some(cert_info) = response.certificate_information {
//!             println!("Certificate Subject: {:?}", cert_info.subject);
//!             println!("Certificate Issued At: {:?}", cert_info.issued_at);
//!             println!("Certificate Expires At: {:?}", cert_info.expires_at);
//!             println!("Is Certificate Active: {:?}", cert_info.is_active);
//!         } else {
//!             println!("No certificate information available.");
//!         }
//!     },
//!     Err(e) => {
//!         eprintln!("Error occurred: {:?}", e);
//!     }
//! }
//! ```

use std::{
    fmt::Debug,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    time::{Duration, SystemTime, UNIX_EPOCH},
    vec::IntoIter,
};

use flate2::read::{DeflateDecoder, GzDecoder};
use openssl::{
    asn1::{Asn1Time, Asn1TimeRef},
    error::ErrorStack,
    ssl::{SslConnector, SslMethod, SslVerifyMode},
    x509::X509,
};
use url::Url;

extern crate openssl;

/// `ReadWrite` trait
///
/// This trait is implemented for types that implement the `Read` and `Write` traits.
/// This is mainly used to make socket streams compatible with both [`TcpStream`] and [`openssl::ssl::SslStream`].
pub trait ReadWrite: Read + Write + Debug {}
impl<T: Read + Write + Debug> ReadWrite for T {}

/// Error types
///
/// This module contains the error types for the http-timings crate.
///
/// The errors are defined using the `thiserror` crate.
pub mod error {
    use thiserror::Error;

    use crate::ReadWrite;

    #[derive(Error, Debug)]
    /// Error types
    ///
    /// This enum contains the error types for the http-timings crate.
    pub enum Error {
        #[error("io error")]
        /// IO error, derived from [`std::io::Error`]
        Io(#[from] std::io::Error),
        #[error("ssl error")]
        /// SSL error, derived from [`openssl::error::ErrorStack`]
        Ssl(#[from] openssl::error::ErrorStack),
        #[error("ssl handshake error")]
        /// SSL handshake error, derived from [`openssl::ssl::HandshakeError`]
        SslHandshake(#[from] openssl::ssl::HandshakeError<Box<dyn ReadWrite + Send + Sync>>),
        #[error("ssl certificate not found")]
        /// SSL certificate not found
        SslCertificateNotFound,
        #[error("system time error")]
        /// System time error, derived from [`std::time::SystemTimeError`]
        SystemTime(#[from] std::time::SystemTimeError),
    }
}

#[derive(Debug)]
/// A pair of durations, one total and one relative
///
/// The total duration is the sum of the relative duration and the previous duration.
pub struct DurationPair {
    total: Duration,
    relative: Duration,
}

impl DurationPair {
    /// Returns the total duration
    #[must_use]
    pub fn total(&self) -> Duration {
        self.total
    }

    /// Returns the relative duration
    #[must_use]
    pub fn relative(&self) -> Duration {
        self.relative
    }
}

#[derive(Debug)]
/// The response timings for any given request. The response timings can be found
/// [here](https://developer.chrome.com/docs/devtools/network/reference/?utm_source=devtools#timing-explanation).
pub struct ResponseTimings {
    /// DNS resolution time
    pub dns: DurationPair,
    /// TCP connection time
    pub tcp: DurationPair,
    /// TLS handshake time
    pub tls: Option<DurationPair>,
    /// HTTP request send time
    pub http_send: DurationPair,
    /// Time To First Byte
    pub ttfb: DurationPair,
    /// Content download time
    pub content_download: DurationPair,
}

impl ResponseTimings {
    fn new(
        dns: Duration,
        tcp: Duration,
        tls: Option<Duration>,
        http_send: Duration,
        ttfb: Duration,
        content_download: Duration,
    ) -> Self {
        let dns = DurationPair {
            total: dns,
            relative: dns,
        };

        let tcp = DurationPair {
            total: dns.total + tcp,
            relative: tcp,
        };

        let tls = tls.map(|tls| DurationPair {
            total: tcp.total + tls,
            relative: tls,
        });

        let http_send = DurationPair {
            total: match &tls {
                Some(tls) => tls.total + http_send,
                None => tcp.total + http_send,
            },
            relative: http_send,
        };

        let ttfb = DurationPair {
            total: http_send.total + ttfb,
            relative: ttfb,
        };

        let content_download = DurationPair {
            total: ttfb.total + content_download,
            relative: content_download,
        };

        Self {
            dns,
            tcp,
            tls,
            http_send,
            ttfb,
            content_download,
        }
    }
}

#[derive(Debug)]
/// Basic information about an SSL certificate
pub struct CertificateInformation {
    /// Issued at
    pub issued_at: SystemTime,
    /// Expires at
    pub expires_at: SystemTime,
    /// Subject
    pub subject: String,
    /// Is active
    pub is_active: bool,
}

#[derive(Debug)]
/// The response from a given request
pub struct Response {
    /// The timings of the response
    pub timings: ResponseTimings,
    /// The certificate information
    pub certificate_information: Option<CertificateInformation>,
    /// The raw certificate
    pub certificate: Option<X509>,
    /// The status of the response
    pub status: u16,
    /// The body of the response
    pub body: String,
}

fn asn1_time_to_system_time(time: &Asn1TimeRef) -> Result<SystemTime, ErrorStack> {
    let unix_time = Asn1Time::from_unix(0)?.diff(time)?;
    Ok(SystemTime::UNIX_EPOCH
        + Duration::from_secs((unix_time.days as u64) * 86400 + unix_time.secs as u64))
}

fn get_dns_timing(url: &Url) -> Result<(Duration, IntoIter<SocketAddr>), error::Error> {
    let Some(domain) = url.host_str() else {
        return Err(error::Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid url",
        )));
    };
    let port = url.port().unwrap_or(match url.scheme() {
        "http" => 80,
        "https" => 443,
        _ => {
            return Err(error::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid url scheme",
            )))
        }
    });
    let start = std::time::Instant::now();
    match format!("{domain}:{port}").to_socket_addrs() {
        Ok(addrs) => Ok((start.elapsed(), addrs)),
        Err(e) => Err(error::Error::Io(e)),
    }
}

fn get_tcp_timing(
    addr: &SocketAddr,
    timeout: Option<Duration>,
) -> Result<(Duration, Box<dyn ReadWrite + Send + Sync>), error::Error> {
    let now = std::time::Instant::now();
    let stream = match TcpStream::connect_timeout(addr, timeout.unwrap_or(Duration::from_secs(5))) {
        Ok(stream) => stream,
        Err(e) => return Err(error::Error::Io(e)),
    };
    Ok((now.elapsed(), Box::new(stream)))
}

struct TlsTimingResponse {
    timing: Duration,
    stream: Box<dyn ReadWrite + Send + Sync>,
    certificate_information: Option<CertificateInformation>,
    certificate: Option<X509>,
}

fn get_tls_timing(
    url: &Url,
    stream: Box<dyn ReadWrite + Send + Sync>,
) -> Result<TlsTimingResponse, error::Error> {
    let now = std::time::Instant::now();
    let connector = {
        let mut context = match SslConnector::builder(SslMethod::tls()) {
            Ok(context) => context,
            Err(e) => return Err(error::Error::Ssl(e)),
        };
        context.set_verify(SslVerifyMode::NONE);
        context.build()
    };
    let stream = match connector.connect(
        match url.host_str() {
            Some(host) => host,
            None => {
                return Err(error::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid url host",
                )))
            }
        },
        stream,
    ) {
        Ok(stream) => stream,
        Err(e) => return Err(error::Error::SslHandshake(e)),
    };
    let Some(raw_certificate) = stream.ssl().peer_certificate() else {
        return Err(error::Error::SslCertificateNotFound);
    };
    let time_elapsed = now.elapsed();

    let current_asn1_time =
        Asn1Time::from_unix(match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs() as i64,
            Err(e) => return Err(error::Error::SystemTime(e)),
        })?;
    let certificate_information = CertificateInformation {
        issued_at: asn1_time_to_system_time(raw_certificate.not_before())?,
        expires_at: asn1_time_to_system_time(raw_certificate.not_after())?,
        subject: raw_certificate
            .subject_name()
            .entries()
            .map(|entry| entry.data().as_slice().to_ascii_lowercase())
            .map(|entry| String::from_utf8_lossy(entry.as_slice()).into_owned())
            .collect(),
        is_active: raw_certificate.not_after() > current_asn1_time,
    };

    Ok(TlsTimingResponse {
        timing: time_elapsed,
        stream: Box::new(stream),
        certificate_information: Some(certificate_information),
        certificate: Some(raw_certificate),
    })
}

fn get_http_send_timing(
    url: &Url,
    stream: &mut Box<dyn ReadWrite + Send + Sync>,
) -> Result<Duration, error::Error> {
    let now = std::time::Instant::now();
    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nAccept-Encoding: gzip, deflate, br\r\nUser-Agent: http-timings/0.2\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n",
        url.path(),
        match url.host_str() {
            Some(host) => host,
            None => return Err(error::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid url host",
            ))),
        }
    );
    if let Err(err) = stream.write_all(request.as_bytes()) {
        return Err(error::Error::Io(err));
    }
    Ok(now.elapsed())
}

fn get_ttfb_timing(
    stream: &mut Box<dyn ReadWrite + Send + Sync>,
) -> Result<Duration, error::Error> {
    let mut one_byte = vec![0_u8];
    let now = std::time::Instant::now();
    if let Err(err) = stream.read_exact(&mut one_byte) {
        return Err(error::Error::Io(err));
    }
    Ok(now.elapsed())
}

fn get_content_download_timing(
    stream: &mut Box<dyn ReadWrite + Send + Sync>,
) -> Result<(Duration, u16, String), error::Error> {
    let mut reader = BufReader::new(stream);
    let mut header_buf = String::new();
    let now = std::time::Instant::now();
    loop {
        let bytes_read = match reader.read_line(&mut header_buf) {
            Ok(bytes_read) => bytes_read,
            Err(err) => return Err(error::Error::Io(err)),
        };
        if bytes_read == 2 {
            break;
        }
    }
    let headers = header_buf.split('\n');
    let content_length = match headers
        .clone()
        .filter(|line| line.to_ascii_lowercase().starts_with("content-length"))
        .collect::<Vec<_>>()
        .first()
    {
        Some(content_length) => content_length.split(':').collect::<Vec<_>>()[1]
            .trim()
            .parse()
            .unwrap_or(0),
        None => 0,
    };

    let status = match headers
        .clone()
        .filter(|line| line.starts_with("TTP"))
        .collect::<Vec<_>>()
        .first()
    {
        Some(status) => status.split(' ').collect::<Vec<_>>()[1]
            .parse::<u16>()
            .unwrap_or(0),
        None => {
            return Err(error::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid http status",
            )))
        }
    };

    let mut body_buf;
    if content_length == 0 {
        body_buf = vec![];
        if let Err(err) = reader.read_to_end(&mut body_buf) {
            return Err(error::Error::Io(err));
        }
    } else {
        body_buf = vec![0_u8; content_length];
        if let Err(err) = reader.read_exact(&mut body_buf) {
            return Err(error::Error::Io(err));
        }
    }

    let content_encoding = match headers
        .filter(|line| line.to_ascii_lowercase().starts_with("content-encoding"))
        .collect::<Vec<_>>()
        .first()
    {
        Some(content_encoding) => content_encoding.split(':').collect::<Vec<_>>()[1].trim(),
        None => "",
    };

    let body = match content_encoding {
        "gzip" => {
            let decoder = GzDecoder::new(&body_buf[..]);
            let mut decode_reader = BufReader::new(decoder);
            let mut buf = vec![];
            let _ = decode_reader.read_to_end(&mut buf);
            String::from_utf8_lossy(&buf).into_owned()
        }
        "deflate" => {
            let mut decoder = DeflateDecoder::new(&body_buf[..]);
            let mut string = String::new();
            if let Err(err) = decoder.read_to_string(&mut string) {
                return Err(error::Error::Io(err));
            }
            string
        }
        "br" => {
            let mut decoder = brotli::Decompressor::new(&body_buf[..], 4096);
            let mut buf = vec![];
            if let Err(err) = decoder.read_to_end(&mut buf) {
                return Err(error::Error::Io(err));
            }
            String::from_utf8_lossy(&buf).into_owned()
        }
        _ => String::from_utf8_lossy(&body_buf).into_owned(),
    };

    Ok((now.elapsed(), status, body))
}

/// Measures the HTTP timings from the given URL
///
/// # Errors
///
/// This function will return an error if the URL is invalid or the URL is not reachable.
/// It could also error under any scenario in the [`error::Error`] enum.
pub fn from_url(url: &Url, timeout: Option<Duration>) -> Result<Response, error::Error> {
    let (dns_timing, mut socket_addrs) = get_dns_timing(url)?;
    let Some(url_ip) = socket_addrs.next() else {
        return Err(error::Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid url ip",
        )));
    };
    let (tcp_timing, mut stream) = get_tcp_timing(&url_ip, timeout)?;
    let mut ssl_certificate = None;
    let mut ssl_certificate_information = None;
    let mut tls_timing = None;
    if url.scheme() == "https" {
        let timing_response = get_tls_timing(url, stream)?;
        tls_timing = Some(timing_response.timing);
        ssl_certificate = timing_response.certificate;
        ssl_certificate_information = timing_response.certificate_information;
        stream = timing_response.stream;
    }
    let http_send_timing = get_http_send_timing(url, &mut stream)?;
    let ttfb_timing = get_ttfb_timing(&mut stream)?;
    let (content_download_timing, status, body) = get_content_download_timing(&mut stream)?;

    Ok(Response {
        timings: ResponseTimings::new(
            dns_timing,
            tcp_timing,
            tls_timing,
            http_send_timing,
            ttfb_timing,
            content_download_timing,
        ),
        certificate_information: ssl_certificate_information,
        certificate: ssl_certificate,
        status,
        body,
    })
}

/// Given a string, it will be parsed as a URL and the HTTP timings will be measured
///
/// # Errors
///
/// This function will return an error if the URL is invalid or the URL is not reachable.
/// It could also error under any scenario in the [`error::Error`] enum.
pub fn from_string(url: &str, timeout: Option<Duration>) -> Result<Response, error::Error> {
    let input = if !url.starts_with("http://") && !url.starts_with("https://") {
        format!("http://{url}")
    } else {
        url.to_string()
    };

    let url = Url::parse(&input).map_err(|e| {
        error::Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid url: {e}"),
        ))
    })?;
    from_url(&url, timeout)
}

#[cfg(test)]
mod tests {
    use super::*;
    const TIMEOUT: Duration = Duration::from_secs(5);

    #[test]
    fn test_non_tls_connection() {
        let url = "neverssl.com";
        let result = from_string(url, Some(TIMEOUT));
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, 200);
        assert!(response.body.contains("Follow @neverssl"));
        assert!(response.timings.dns.total.as_secs() < 1);
        assert!(response.timings.content_download.total.as_secs() < 5);
    }

    #[test]
    fn test_popular_tls_connection() {
        let url = "https://www.google.com";
        let result = from_string(url, Some(TIMEOUT));
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, 200);
        assert!(response.body.contains("Google Search"));
        assert!(response.timings.dns.total.as_secs() < 1);
        assert!(response.timings.content_download.total.as_secs() < 5);
    }

    #[test]
    fn test_ip() {
        let url = "1.1.1.1";
        let result = from_string(url, Some(TIMEOUT));
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, 301);
        assert!(!response.body.is_empty());
        assert!(response.timings.dns.total.as_secs() < 1);
        assert!(response.timings.content_download.total.as_secs() < 5);
    }
}
