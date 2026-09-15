//! Establish the KVM socket. The exact endpoint/transport varies by firmware, so
//! we try a small ladder of rungs and validate each by the RFB banner (a plaintext
//! connect to a TLS port succeeds at the TCP layer but never yields a banner).

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use log::info;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};

use crate::jnlp::KvmParams;
use crate::rfb;

/// Object-safe read+write+send handle to the connected socket.
pub trait ReadWrite: Read + Write + Send {}
impl<T: Read + Write + Send> ReadWrite for T {}

pub struct Connection {
    pub stream: Box<dyn ReadWrite>,
    pub server_banner: [u8; 12],
    pub endpoint: String,
}

/// How long to wait for the TCP connect and the banner on each rung before
/// giving up and trying the next one.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(6);
const BANNER_TIMEOUT: Duration = Duration::from_secs(6);

struct Rung {
    host: String,
    port: u16,
    tls: bool,
}

pub fn connect(p: &KvmParams) -> Result<Connection> {
    let ladder = build_ladder(p);

    let mut last_err: Option<anyhow::Error> = None;
    for rung in ladder {
        let label = format!(
            "{}://{}:{}",
            if rung.tls { "tls" } else { "tcp" },
            rung.host,
            rung.port
        );
        info!("trying {label}");
        match try_rung(&rung) {
            Ok(conn) => {
                info!("connected via {}", conn.endpoint);
                return Ok(conn);
            }
            Err(e) => {
                info!("rung {label} failed: {e:#}");
                last_err = Some(e);
            }
        }
    }

    match last_err {
        Some(e) => Err(e.context("all connection attempts failed")),
        None => bail!("no connection endpoints to try"),
    }
}

/// Rungs to try, in order. `p.tls` is arg[8] of the JNLP — the vendor's own
/// declaration of whether this BMC speaks TLS on the KVM port — so it decides
/// which transport is attempted first. Ordering only: every rung is still
/// validated by the RFB banner, so a wrong flag costs one BANNER_TIMEOUT
/// rather than a failed session.
fn build_ladder(p: &KvmParams) -> Vec<Rung> {
    let rung = |host: &String, tls: bool| Rung { host: host.clone(), port: p.kvm_port, tls };
    let (first, second) = if p.tls { (true, false) } else { (false, true) };
    vec![
        rung(&p.bmc_ip, first),
        rung(&p.bmc_ip, second),
        rung(&p.codebase_host, first),
        rung(&p.codebase_host, second),
    ]
}

fn try_rung(rung: &Rung) -> Result<Connection> {
    let addr = (rung.host.as_str(), rung.port)
        .to_socket_addrs()
        .with_context(|| format!("resolving {}:{}", rung.host, rung.port))?
        .next()
        .with_context(|| format!("no addresses for {}:{}", rung.host, rung.port))?;

    let tcp = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .with_context(|| format!("connecting to {addr}"))?;
    // Bound the banner read so a wrong (silent) rung doesn't hang the ladder.
    tcp.set_read_timeout(Some(BANNER_TIMEOUT)).ok();
    // Control handle to clear the timeout once we've committed to this rung.
    let ctl = tcp.try_clone().context("cloning socket handle")?;

    let label = format!(
        "{}://{}:{}",
        if rung.tls { "tls" } else { "tcp" },
        rung.host,
        rung.port
    );

    let mut stream: Box<dyn ReadWrite> = if rung.tls {
        Box::new(tls_wrap(tcp, &rung.host)?)
    } else {
        Box::new(tcp)
    };

    let banner = rfb::read_banner(&mut stream).context("reading RFB banner")?;
    if !rfb::banner_is_rfb(&banner) {
        bail!("no RFB banner (got {:02x?})", banner);
    }

    // Committed: switch to blocking reads for the rest of the session.
    ctl.set_read_timeout(None).ok();

    Ok(Connection {
        stream,
        server_banner: banner,
        endpoint: label,
    })
}

fn tls_wrap(tcp: TcpStream, host: &str) -> Result<StreamOwned<ClientConnection, TcpStream>> {
    // No client certificate. The credential ATEN shipped in `res/client.crt`
    // expired 2026-05-17, and firmware that predates the mutual-TLS scheme (e.g.
    // V1.69.21) never shipped one at all. A BMC that does demand one now fails
    // this handshake and the ladder falls through to a plaintext rung.
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth();

    // SNI: use the hostname when we have one; an IP literal produces an IP-typed
    // ServerName (no SNI sent), which is fine.
    let server_name = ServerName::try_from(host.to_string())
        .with_context(|| format!("invalid server name {host}"))?;
    let conn = ClientConnection::new(Arc::new(config), server_name)
        .context("starting TLS session")?;
    Ok(StreamOwned::new(conn, tcp))
}

/// Accept any server certificate. The OVH proxy / BMC presents a cert that won't
/// chain-validate; we still set SNI so the proxy routes correctly, but we do not
/// verify the chain (this is a console tunnel, not a web login).
#[derive(Debug)]
struct AcceptAny;

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn params(tls: bool) -> KvmParams {
        KvmParams {
            codebase_host: "proxy.example".into(),
            bmc_ip: "10.0.0.1".into(),
            username: "u".into(),
            password: "p".into(),
            tls,
            kvm_port: 5900,
        }
    }

    /// The JNLP's arg[8] decides which transport is tried first. A plaintext BMC
    /// must not spend a BANNER_TIMEOUT on a TLS rung that can never answer.
    #[test]
    fn ladder_order_follows_jnlp_tls_flag() {
        let shape = |p: &KvmParams| {
            build_ladder(p)
                .iter()
                .map(|r| (r.host.clone(), r.tls))
                .collect::<Vec<_>>()
        };

        assert_eq!(
            shape(&params(false)),
            vec![
                ("10.0.0.1".to_string(), false),
                ("10.0.0.1".to_string(), true),
                ("proxy.example".to_string(), false),
                ("proxy.example".to_string(), true),
            ],
            "tls=0 must try plaintext to the BMC first"
        );

        assert_eq!(
            shape(&params(true)),
            vec![
                ("10.0.0.1".to_string(), true),
                ("10.0.0.1".to_string(), false),
                ("proxy.example".to_string(), true),
                ("proxy.example".to_string(), false),
            ],
            "tls=1 must try TLS to the BMC first"
        );

        // Both orderings cover the same four endpoints; only the order differs.
        let mut a = shape(&params(false));
        let mut b = shape(&params(true));
        a.sort();
        b.sort();
        assert_eq!(a, b);
    }

    /// A mock BMC that speaks the plaintext ATEN handshake, exercising the
    /// banner-validated ladder + `rfb::handshake` over a real TCP socket.
    #[test]
    fn ladder_selects_plaintext_rung_and_completes_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut out = Vec::new();
            out.extend_from_slice(b"RFB 003.008\n"); // banner
            out.push(1); // one security type
            out.push(0x10); // ATEN
            out.extend_from_slice(&[0u8; 24]); // opaque blob
            out.extend_from_slice(&0u32.to_be_bytes()); // SecurityResult OK
            // ServerInit 800x600, name "T", + 12-byte trailer.
            out.extend_from_slice(&800u16.to_be_bytes());
            out.extend_from_slice(&600u16.to_be_bytes());
            out.extend_from_slice(&[0u8; 16]);
            out.extend_from_slice(&1u32.to_be_bytes());
            out.extend_from_slice(b"T");
            out.extend_from_slice(&[0u8; 12]);
            sock.write_all(&out).unwrap();
            // Drain the client's full handshake output (banner echo 12 + sec-type
            // 1 + auth 48 + ClientInit 1 = 62 bytes) so there's no unread data at
            // close — otherwise the OS sends an RST that aborts the client's still
            // -buffered reads. A real BMC keeps the socket open, so this only bites
            // the mock.
            let mut buf = [0u8; 62];
            let _ = sock.read_exact(&mut buf);
        });

        let params = KvmParams {
            codebase_host: "127.0.0.1".into(),
            bmc_ip: "127.0.0.1".into(),
            username: "u".into(),
            password: "p".into(),
            tls: false,
            kvm_port: port,
        };

        let conn = connect(&params).unwrap();
        assert!(conn.endpoint.starts_with("tcp://127.0.0.1"));
        let mut stream = conn.stream;
        let si = rfb::handshake(&mut stream, conn.server_banner, &params.username, &params.password)
            .unwrap();
        assert_eq!((si.width, si.height), (800, 600));
        assert_eq!(si.name, "T");

        server.join().unwrap();
    }
}
