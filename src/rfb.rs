//! The modified RFB 3.8 ("ATEN iKVM") wire protocol.
//!
//! All multi-byte RFB fields are big-endian; RGB555 pixel data is little-endian.
//! Everything here reads with `read_exact` so a short read surfaces as an error
//! rather than a silent desync.

use std::io::{self, Read, Write};
use std::sync::mpsc::Sender;

use anyhow::{Result, bail};
use log::info;

use crate::frame::{Frame, Shared};

/// Screen-off sentinel: a rect whose width/height are these values carries no
/// pixel data (the guest video output is disabled).
const SENTINEL_W: u16 = 0xFD80;
const SENTINEL_H: u16 = 0xFE20;

pub struct ServerInit {
    pub width: usize,
    pub height: usize,
    pub name: String,
}

#[derive(Debug, Clone, Copy)]
pub struct KeyEvent {
    pub down: bool,
    pub usage: u16,
}

// --- big-endian read helpers -------------------------------------------------

fn read_u8<S: Read + ?Sized>(s: &mut S) -> io::Result<u8> {
    let mut b = [0u8; 1];
    s.read_exact(&mut b)?;
    Ok(b[0])
}

fn read_u16<S: Read + ?Sized>(s: &mut S) -> io::Result<u16> {
    let mut b = [0u8; 2];
    s.read_exact(&mut b)?;
    Ok(u16::from_be_bytes(b))
}

fn read_u32<S: Read + ?Sized>(s: &mut S) -> io::Result<u32> {
    let mut b = [0u8; 4];
    s.read_exact(&mut b)?;
    Ok(u32::from_be_bytes(b))
}

fn skip<S: Read + ?Sized>(s: &mut S, n: usize) -> io::Result<()> {
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf)
}

// --- handshake / auth / server init -----------------------------------------

/// Read the 12-byte RFB banner and validate it. Returned so the caller (the
/// transport fallback ladder) can use it to decide a rung is really speaking RFB.
pub fn read_banner<S: Read + ?Sized>(s: &mut S) -> io::Result<[u8; 12]> {
    let mut banner = [0u8; 12];
    s.read_exact(&mut banner)?;
    Ok(banner)
}

pub fn banner_is_rfb(banner: &[u8; 12]) -> bool {
    banner.starts_with(b"RFB ")
}

/// Drive the handshake from just after the banner has been read: echo the
/// banner, negotiate the ATEN security type, authenticate, and read ServerInit.
pub fn handshake<S: Read + Write + ?Sized>(
    s: &mut S,
    banner: [u8; 12],
    username: &str,
    password: &str,
) -> Result<ServerInit> {
    // 1. Echo the server's protocol version back.
    s.write_all(&banner)?;

    // 2. Security types: u8 count, then that many type bytes.
    let count = read_u8(s)?;
    if count == 0 {
        // RFB failure: u32 reason length + reason string.
        let len = read_u32(s)? as usize;
        let mut reason = vec![0u8; len];
        s.read_exact(&mut reason)?;
        bail!("server rejected connection: {}", String::from_utf8_lossy(&reason));
    }
    let mut types = vec![0u8; count as usize];
    s.read_exact(&mut types)?;
    if !types.contains(&0x10) {
        bail!("server did not offer ATEN security type 16, offered {:?}", types);
    }
    s.write_all(&[0x10])?;

    // 3. Opaque 24-byte blob after security selection — discard.
    skip(s, 24)?;

    // 4. Auth: username[24] + password[24], each zero-padded.
    let mut auth = [0u8; 48];
    let ub = username.as_bytes();
    let un = ub.len().min(24);
    auth[..un].copy_from_slice(&ub[..un]);
    let pb = password.as_bytes();
    let pn = pb.len().min(24);
    auth[24..24 + pn].copy_from_slice(&pb[..pn]);
    s.write_all(&auth)?;

    // 5. SecurityResult: u32, 0 = OK.
    let result = read_u32(s)?;
    if result != 0 {
        bail!("authentication failed (SecurityResult = {result})");
    }

    // 6. ClientInit: 1 byte shared-flag.
    s.write_all(&[0u8])?;

    // 7. ServerInit.
    let width = read_u16(s)? as usize;
    let height = read_u16(s)? as usize;
    skip(s, 16)?; // pixel format — ignored, real pixels are RGB555
    let name_len = read_u32(s)? as usize;
    let mut name = vec![0u8; name_len];
    s.read_exact(&mut name)?;
    skip(s, 12)?; // ATEN trailer

    Ok(ServerInit {
        width,
        height,
        name: String::from_utf8_lossy(&name).into_owned(),
    })
}

// --- client -> server messages ----------------------------------------------

pub fn send_fbur<S: Write + ?Sized>(s: &mut S, incremental: bool) -> io::Result<()> {
    let mut b = [0u8; 10];
    b[0] = 3; // FramebufferUpdateRequest
    b[1] = incremental as u8;
    // x/y/w/h all zero — the BMC ignores the rect and sends the whole screen.
    s.write_all(&b)
}

pub fn encode_key(k: &KeyEvent) -> [u8; 18] {
    let mut b = [0u8; 18];
    b[0] = 4; // KeyEvent
    b[2] = k.down as u8;
    // key: u32 big-endian HID usage code at offset 5..9
    b[5..9].copy_from_slice(&(k.usage as u32).to_be_bytes());
    b
}

pub fn send_key<S: Write + ?Sized>(s: &mut S, k: &KeyEvent) -> io::Result<()> {
    s.write_all(&encode_key(k))
}

// --- server -> client messages ----------------------------------------------

/// Read and process one server message. Returns `Ok(true)` if it was a
/// FramebufferUpdate (so the caller re-requests an incremental update).
pub fn read_message<S: Read + ?Sized>(
    s: &mut S,
    shared: &Shared,
    dim_tx: &Sender<(usize, usize)>,
) -> io::Result<bool> {
    let msg_type = read_u8(s)?;
    match msg_type {
        0x00 => {
            handle_fb_update(s, shared, dim_tx)?;
            Ok(true)
        }
        0x04 => {
            skip(s, 20)?;
            Ok(false)
        }
        0x16 => {
            skip(s, 1)?;
            Ok(false)
        }
        0x37 => {
            skip(s, 2)?;
            Ok(false)
        }
        0x39 => {
            skip(s, 264)?;
            Ok(false)
        }
        0x3c => {
            skip(s, 8)?;
            Ok(false)
        }
        other => {
            // Unknown types have no known length — we can't reliably resync.
            // Log and let the next read either recover or fail cleanly.
            info!("unknown server message type {other:#04x}");
            Ok(false)
        }
    }
}

fn handle_fb_update<S: Read + ?Sized>(
    s: &mut S,
    shared: &Shared,
    dim_tx: &Sender<(usize, usize)>,
) -> io::Result<()> {
    let _pad = read_u8(s)?;
    let n_rects = read_u16(s)?;

    for _ in 0..n_rects {
        let x = read_u16(s)? as usize;
        let y = read_u16(s)? as usize;
        let w = read_u16(s)?;
        let h = read_u16(s)?;
        let _encoding = read_u32(s)?; // unreliable (0x00 on older BMCs) — do not dispatch on it
        let _unknown = read_u32(s)?;
        let data_len = read_u32(s)? as usize;

        if w == SENTINEL_W && h == SENTINEL_H {
            // Screen off: no payload for this rect.
            if let Ok(mut g) = shared.lock() {
                if let Some(f) = g.as_mut() {
                    f.fill_black();
                }
            }
            continue;
        }

        // Read the whole rect payload up front so the stream stays in sync even
        // if our inner parse is off.
        let mut payload = vec![0u8; data_len];
        s.read_exact(&mut payload)?;
        if payload.len() < 10 {
            info!("framebuffer rect payload too short ({} bytes)", payload.len());
            continue;
        }

        // 10-byte ATEN sub-header.
        let sub_type = payload[0];
        let field1 = u32::from_be_bytes([payload[2], payload[3], payload[4], payload[5]]);
        let _field2 = u32::from_be_bytes([payload[6], payload[7], payload[8], payload[9]]);
        let body = &payload[10..];

        let mut g = match shared.lock() {
            Ok(g) => g,
            Err(_) => continue,
        };
        let frame = match g.as_mut() {
            Some(f) => f,
            None => continue,
        };

        match sub_type {
            0 => decode_subrects(frame, field1 as usize, body),
            1 => decode_raw(frame, x, y, w as usize, h as usize, body, dim_tx),
            other => info!("unknown ATEN sub-encoding {other}"),
        }
    }

    Ok(())
}

/// type 0: `count` fixed 518-byte segments, each `[4 skip][u8 y][u8 x][512 tile]`.
fn decode_subrects(frame: &mut Frame, count: usize, body: &[u8]) {
    const SEG: usize = 518;
    for i in 0..count {
        let off = i * SEG;
        if off + SEG > body.len() {
            info!("subrect stream truncated at segment {i}/{count}");
            break;
        }
        let seg = &body[off..off + SEG];
        let ty = seg[4] as usize;
        let tx = seg[5] as usize;
        frame.blit_tile(tx, ty, &seg[6..6 + 512]);
    }
}

/// type 1: raw RGB555 block for the rect. When it covers the whole screen at a
/// new size, treat it as a resolution change.
fn decode_raw(
    frame: &mut Frame,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    body: &[u8],
    dim_tx: &Sender<(usize, usize)>,
) {
    let full_screen = x == 0 && y == 0;
    let sane = w > 0 && h > 0 && w <= 8192 && h <= 8192;
    if full_screen && sane && (w != frame.width || h != frame.height) {
        info!("resolution change: {}x{} -> {}x{}", frame.width, frame.height, w, h);
        frame.resize(w, h);
        let _ = dim_tx.send((w, h));
    }
    frame.blit_raw(x, y, w, h, body);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};

    /// A stream whose reads come from a scripted buffer and whose writes go to a
    /// separate sink — so a client that reads and writes doesn't clobber its own
    /// unread input (which a single `Cursor` would).
    struct MockStream {
        rx: Cursor<Vec<u8>>,
        tx: Vec<u8>,
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.rx.read(buf)
        }
    }

    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.tx.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn keyevent_encoding() {
        // 'a' pressed: type 4, down 1, usage 0x04 big-endian at bytes 5..9.
        let ev = KeyEvent { down: true, usage: 0x04 };
        let expected = [4u8, 0, 1, 0, 0, 0, 0, 0, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(encode_key(&ev), expected);

        let up = KeyEvent { down: false, usage: 0xe1 };
        let mut want = [0u8; 18];
        want[0] = 4;
        want[8] = 0xe1;
        assert_eq!(encode_key(&up), want);
    }

    fn build_server_init() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&640u16.to_be_bytes());
        v.extend_from_slice(&480u16.to_be_bytes());
        v.extend_from_slice(&[0u8; 16]); // pixel format
        let name = b"iKVM";
        v.extend_from_slice(&(name.len() as u32).to_be_bytes());
        v.extend_from_slice(name);
        v.extend_from_slice(&[0u8; 12]); // ATEN trailer
        v
    }

    #[test]
    fn handshake_flow() {
        // Server-side script the client will read.
        let mut server = Vec::new();
        server.extend_from_slice(b"RFB 003.008\n"); // banner
        server.push(1); // one security type
        server.push(0x10); // ATEN
        server.extend_from_slice(&[0u8; 24]); // opaque blob
        server.extend_from_slice(&0u32.to_be_bytes()); // SecurityResult OK
        server.extend_from_slice(&build_server_init());

        let mut stream = MockStream { rx: Cursor::new(server), tx: Vec::new() };
        let banner = read_banner(&mut stream).unwrap();
        assert!(banner_is_rfb(&banner));
        let si = handshake(&mut stream, banner, "user", "pass").unwrap();
        assert_eq!((si.width, si.height), (640, 480));
        assert_eq!(si.name, "iKVM");

        // The client should have echoed the banner, selected security type 0x10,
        // and sent 48 auth bytes + a 1-byte ClientInit.
        assert!(stream.tx.starts_with(b"RFB 003.008\n"));
        assert!(stream.tx.contains(&0x10));
        // "user"/"pass" zero-padded into two 24-byte fields.
        assert!(stream.tx.windows(4).any(|w| w == b"user"));
        assert!(stream.tx.windows(4).any(|w| w == b"pass"));
    }

    #[test]
    fn subrect_framebuffer_update() {
        let shared: Shared = Arc::new(Mutex::new(Some(Frame::new(32, 32))));
        let (tx, _rx) = mpsc::channel();

        // one 16x16 pure-red tile at grid (0,0)
        let mut tile = vec![0u8; 512];
        for px in tile.chunks_exact_mut(2) {
            px[0] = 0x00;
            px[1] = 0x7c;
        }
        let mut seg = vec![0u8; 6];
        seg[4] = 0; // ty
        seg[5] = 0; // tx
        seg.extend_from_slice(&tile); // 518 total

        let mut sub = Vec::new();
        sub.push(0u8); // sub_type 0 = subrects
        sub.push(0u8); // pad
        sub.extend_from_slice(&1u32.to_be_bytes()); // field1 = 1 segment
        sub.extend_from_slice(&(seg.len() as u32 + 10).to_be_bytes()); // field2
        sub.extend_from_slice(&seg);

        let mut msg = Vec::new();
        msg.push(0u8); // FramebufferUpdate
        msg.push(0u8); // pad
        msg.extend_from_slice(&1u16.to_be_bytes()); // nRects
        // rect header
        msg.extend_from_slice(&0u16.to_be_bytes()); // x
        msg.extend_from_slice(&0u16.to_be_bytes()); // y
        msg.extend_from_slice(&16u16.to_be_bytes()); // w
        msg.extend_from_slice(&16u16.to_be_bytes()); // h
        msg.extend_from_slice(&0u32.to_be_bytes()); // encoding
        msg.extend_from_slice(&0u32.to_be_bytes()); // unknown
        msg.extend_from_slice(&(sub.len() as u32).to_be_bytes()); // dataLength
        msg.extend_from_slice(&sub);

        let mut cur = Cursor::new(msg);
        let was_fb = read_message(&mut cur, &shared, &tx).unwrap();
        assert!(was_fb);

        let g = shared.lock().unwrap();
        let f = g.as_ref().unwrap();
        assert_eq!(f.pixels[0], 0xff0000);
        assert_eq!(f.pixels[15 * 32 + 15], 0xff0000);
        assert_eq!(f.pixels[16 * 32 + 16], 0x000000); // outside the tile
    }

    #[test]
    fn screen_off_sentinel_fills_black() {
        let mut frame = Frame::new(4, 4);
        frame.pixels.iter_mut().for_each(|p| *p = 0xffffff);
        let shared: Shared = Arc::new(Mutex::new(Some(frame)));
        let (tx, _rx) = mpsc::channel();

        let mut msg = Vec::new();
        msg.push(0u8); // FramebufferUpdate
        msg.push(0u8); // pad
        msg.extend_from_slice(&1u16.to_be_bytes()); // nRects
        msg.extend_from_slice(&0u16.to_be_bytes()); // x
        msg.extend_from_slice(&0u16.to_be_bytes()); // y
        msg.extend_from_slice(&SENTINEL_W.to_be_bytes());
        msg.extend_from_slice(&SENTINEL_H.to_be_bytes());
        msg.extend_from_slice(&0u32.to_be_bytes()); // encoding
        msg.extend_from_slice(&0u32.to_be_bytes()); // unknown
        msg.extend_from_slice(&0u32.to_be_bytes()); // dataLength (no payload)

        let mut cur = Cursor::new(msg);
        read_message(&mut cur, &shared, &tx).unwrap();

        let g = shared.lock().unwrap();
        assert!(g.as_ref().unwrap().pixels.iter().all(|&p| p == 0));
    }
}
