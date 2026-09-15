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
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};

/// The iKVM client certificate + key, extracted from the ATEN `iKVM__*.jar`
/// (`res/client.crt`, `res/client.key`). The BMC requires mutual TLS on the KVM
/// port and only accepts a client cert signed by the Supermicro IPMI CA — this is
/// that fixed, shipped-with-the-client credential, identical across BMCs.
const CLIENT_CERT_PEM: &str = include_str!("../certs/client.crt");
const CLIENT_KEY_PEM: &str = include_str!("../certs/client.key");

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
    // Order: TLS to the BMC IP first — confirmed live to be mutual-TLS RFB on
    // 5900. Plaintext + proxy-host variants remain as fallbacks for other
    // firmware. Edit/trim once the live winner is known.
    let ladder = vec![
        Rung { host: p.bmc_ip.clone(), port: p.kvm_port, tls: true },
        Rung { host: p.bmc_ip.clone(), port: p.kvm_port, tls: false },
        Rung { host: p.codebase_host.clone(), port: p.kvm_port, tls: true },
        Rung { host: p.codebase_host.clone(), port: p.kvm_port, tls: false },
    ];

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

fn client_auth() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certs = rustls_pemfile::certs(&mut CLIENT_CERT_PEM.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .context("parsing embedded client.crt")?;
    let key = rustls_pemfile::private_key(&mut CLIENT_KEY_PEM.as_bytes())
        .context("parsing embedded client.key")?
        .context("no private key found in embedded client.key")?;
    Ok((certs, key))
}

fn tls_wrap(tcp: TcpStream, host: &str) -> Result<StreamOwned<ClientConnection, TcpStream>> {
    let (cert_chain, key) = client_auth()?;
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        // Present the iKVM client cert; the BMC requires it (mutual TLS).
        .with_client_auth_cert(cert_chain, key)
        .context("installing client certificate")?;

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
