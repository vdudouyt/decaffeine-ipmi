//! Parse an ATEN iKVM `.jnlp` file into the parameters we need to open a KVM session.
//!
//! We only care about two things in the XML: the `codebase` attribute on the root
//! `<jnlp>` element (the OVH session-proxy host, used for TLS SNI on the fallback
//! rungs) and the ordered `<argument>` list under `<application-desc>`, which the
//! ATEN `KVMMain` class is invoked with:
//!
//! ```text
//! [0] BMC/KVM host      [1] username token   [2] password token   [3] "null"
//! [4] local KVM port    [5] 623 (RMCP)       [6] company id       [7] board id
//! [8] TLS flag          [9] remote KVM/RFB port
//! ```

use std::path::Path;

use anyhow::{Context, Result, bail};
use quick_xml::events::Event;
use quick_xml::reader::Reader;

#[derive(Debug, Clone)]
pub struct KvmParams {
    /// Session-proxy host from `codebase` (e.g. `35f5….ipmi.ovh.net`), no scheme/path.
    pub codebase_host: String,
    /// arg[0] — the BMC/KVM host we connect to.
    pub bmc_ip: String,
    /// arg[1] — session username token.
    pub username: String,
    /// arg[2] — session password token.
    pub password: String,
    /// arg[8] == "1".
    pub tls: bool,
    /// arg[9] — remote KVM/RFB port (falls back to 5900).
    pub kvm_port: u16,
}

pub fn parse(path: &Path) -> Result<KvmParams> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    parse_str(&content)
}

/// Split out so it is unit-testable without touching the filesystem.
pub fn parse_str(content: &str) -> Result<KvmParams> {
    let mut reader = Reader::from_str(content);

    let mut codebase = String::new();
    let mut args: Vec<String> = Vec::new();
    let mut in_argument = false;

    loop {
        match reader.read_event().context("malformed JNLP XML")? {
            Event::Start(e) => {
                let name = e.name();
                match name.as_ref() {
                    b"jnlp" => {
                        for attr in e.attributes() {
                            let attr = attr.context("bad attribute in <jnlp>")?;
                            if attr.key.as_ref() == b"codebase" {
                                codebase = attr.unescape_value()?.to_string();
                            }
                        }
                    }
                    b"argument" => {
                        in_argument = true;
                        // Push a slot even if the text event is empty/whitespace so
                        // positional indices stay aligned.
                        args.push(String::new());
                    }
                    _ => {}
                }
            }
            Event::Text(t) => {
                if in_argument {
                    let text = t.unescape()?;
                    if let Some(last) = args.last_mut() {
                        last.push_str(text.trim());
                    }
                }
            }
            Event::End(e) => {
                if e.name().as_ref() == b"argument" {
                    in_argument = false;
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }

    if args.len() < 3 {
        bail!(
            "JNLP has {} <argument> elements, need at least 3 (host, user, pass)",
            args.len()
        );
    }

    let codebase_host = host_from_codebase(&codebase);

    Ok(KvmParams {
        codebase_host,
        bmc_ip: args[0].clone(),
        username: args[1].clone(),
        password: args[2].clone(),
        tls: args.get(8).map(|s| s == "1").unwrap_or(false),
        kvm_port: args.get(9).and_then(|s| s.parse().ok()).unwrap_or(5900),
    })
}

/// `https://host.example/` -> `host.example`.
fn host_from_codebase(codebase: &str) -> String {
    let no_scheme = codebase
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(codebase);
    no_scheme
        .split(['/', ':'])
        .next()
        .unwrap_or(no_scheme)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<jnlp spec="1.0+" codebase="https://35f5b0d8bb5b442bb9f52c5caabecaa1.bhs6-1.ipmi.ovh.net/">
      <information><title>ATEN Java iKVM Viewer</title></information>
      <resources><jar href="iKVM.jar" main="true"/></resources>
      <application-desc main-class="tw.com.aten.ikvm.KVMMain">
        <argument>142.44.189.192</argument>
        <argument>Cl8xFRaBRZTRMIR</argument>
        <argument>jwGwerg==</argument>
        <argument>null</argument>
        <argument>63630</argument>
        <argument>623</argument>
        <argument>0</argument>
        <argument>0</argument>
        <argument>1</argument>
        <argument>5900</argument>
      </application-desc>
    </jnlp>"#;

    #[test]
    fn parses_sample() {
        let p = parse_str(SAMPLE).unwrap();
        assert_eq!(p.codebase_host, "35f5b0d8bb5b442bb9f52c5caabecaa1.bhs6-1.ipmi.ovh.net");
        assert_eq!(p.bmc_ip, "142.44.189.192");
        assert_eq!(p.username, "Cl8xFRaBRZTRMIR");
        assert_eq!(p.password, "jwGwerg==");
        assert!(p.tls);
        assert_eq!(p.kvm_port, 5900);
    }

    #[test]
    fn host_stripping() {
        assert_eq!(host_from_codebase("https://a.b.c/"), "a.b.c");
        assert_eq!(host_from_codebase("https://a.b.c:8443/x"), "a.b.c");
        assert_eq!(host_from_codebase("a.b.c"), "a.b.c");
    }
}
