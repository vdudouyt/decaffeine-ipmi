//! decaffeine-ipmi — a Java-free ATEN iKVM client (screen + keyboard).
//!
//! Usage: `ipmi kvm.jnlp`

mod frame;
mod jnlp;
mod keymap;
mod rfb;
mod transport;

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

use anyhow::{Context, Result, anyhow};
use log::{error, info};
use minifb::{Key, Window, WindowOptions};

use frame::{Frame, Shared};
use jnlp::KvmParams;
use rfb::KeyEvent;

fn main() -> Result<()> {
    logsy::set_echo(true);
    logsy::set_level(log::LevelFilter::Info);

    // rustls needs a process-wide crypto provider; we built with `ring`.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let path = std::env::args_os()
        .nth(1)
        .ok_or_else(|| anyhow!("usage: decaffeine <file.jnlp>"))?;
    let params = jnlp::parse(Path::new(&path))
        .with_context(|| format!("parsing JNLP {}", Path::new(&path).display()))?;
    info!(
        "target {}:{} (user={}, tls_flag={}, proxy={})",
        params.bmc_ip, params.kvm_port, params.username, params.tls, params.codebase_host
    );

    let title = format!("decaffeine-ipmi — {}", params.bmc_ip);

    let shared: Shared = Arc::new(Mutex::new(None));
    let (dim_tx, dim_rx) = mpsc::channel::<(usize, usize)>();
    let (key_tx, key_rx) = mpsc::channel::<KeyEvent>();
    let shutdown = Arc::new(AtomicBool::new(false));

    // I/O thread owns the socket and all RFB state.
    let io_shared = shared.clone();
    let io_shutdown = shutdown.clone();
    let io_handle = thread::spawn(move || {
        match io_main(params, io_shared, dim_tx, key_rx, io_shutdown.clone()) {
            // A connection-phase error: log and let main exit (dim_rx closes).
            Err(e) => error!("KVM connection failed: {e:#}"),
            // Clean end of session (EOF / window closed).
            Ok(()) => info!("session ended"),
        }
        io_shutdown.store(true, Ordering::Relaxed);
    });

    // Block until the I/O thread reports the initial screen dimensions. If it
    // failed to connect it drops dim_tx, so recv() errors and we exit non-zero.
    let (mut w, mut h) = match dim_rx.recv() {
        Ok(dims) => dims,
        Err(_) => {
            // The I/O thread already logged the specific error via error!().
            let _ = io_handle.join();
            std::process::exit(1);
        }
    };
    info!("initial framebuffer {w}x{h}");

    let mut window = Window::new(&title, w, h, WindowOptions::default())
        .context("creating window")?;
    window.set_target_fps(60);

    let mut local = vec![0u32; w * h];
    let mut prev_keys: HashSet<Key> = HashSet::new();

    while window.is_open()
        && !window.is_key_down(Key::Escape)
        && !shutdown.load(Ordering::Relaxed)
    {
        // Resolution change → recreate the window for a crisp 1:1 view.
        while let Ok((nw, nh)) = dim_rx.try_recv() {
            if nw != w || nh != h {
                info!("recreating window for {nw}x{nh}");
                match Window::new(&title, nw, nh, WindowOptions::default()) {
                    Ok(new_win) => {
                        window = new_win;
                        window.set_target_fps(60);
                        w = nw;
                        h = nh;
                        local = vec![0u32; w * h];
                    }
                    Err(e) => info!("failed to recreate window: {e:#}"),
                }
            }
        }

        // Copy the latest pixels. If dimensions don't match yet (a resize race),
        // adopt the frame's own size and wait for the dim event to recreate.
        if let Ok(g) = shared.lock() {
            if let Some(f) = g.as_ref() {
                if f.width == w && f.height == h {
                    local.copy_from_slice(&f.pixels);
                } else {
                    w = f.width;
                    h = f.height;
                    local = f.pixels.clone();
                }
            }
        }

        if let Err(e) = window.update_with_buffer(&local, w, h) {
            info!("display update error: {e:#}");
        }

        pump_keys(&window, &mut prev_keys, &key_tx);
    }

    // Release any keys still held so the guest doesn't see them stuck down.
    for key in prev_keys.drain() {
        if let Some(usage) = keymap::hid_usage(key) {
            let _ = key_tx.send(KeyEvent { down: false, usage });
        }
    }

    shutdown.store(true, Ordering::Relaxed);
    let _ = io_handle.join();
    Ok(())
}

/// HID usages 0xE0..=0xE7 are the modifier keys (ctrl/shift/alt/super).
fn is_modifier(usage: u16) -> bool {
    (0xe0..=0xe7).contains(&usage)
}

/// Usages newly present in `a` but not `b`, sorted for deterministic output.
fn usages_added(a: &HashSet<Key>, b: &HashSet<Key>) -> Vec<u16> {
    let mut v: Vec<u16> = a.difference(b).filter_map(|k| keymap::hid_usage(*k)).collect();
    v.sort_unstable();
    v
}

/// Diff the currently-held keys against last frame and emit down/up KeyEvents.
///
/// Ordering matters and `HashSet` iteration order does not provide it: the ATEN
/// KeyEvent carries only a keycode and a down flag (confirmed against the vendor
/// library's `RFBKeyboard::Sendkey`), so there is no modifier bitmask and the BMC
/// infers modifier state from the order events arrive in. A shifted character
/// typed inside one 60Hz frame therefore has to go out as Shift-down, key-down,
/// key-up, Shift-up — emit the key first and the guest sees the unshifted
/// character instead.
fn pump_keys(window: &Window, prev: &mut HashSet<Key>, tx: &Sender<KeyEvent>) {
    let cur: HashSet<Key> = window.get_keys().into_iter().collect();
    for ev in key_events(prev, &cur) {
        let _ = tx.send(ev);
    }
    *prev = cur;
}

/// The ordered event sequence for one frame's transition from `prev` to `cur`.
fn key_events(prev: &HashSet<Key>, cur: &HashSet<Key>) -> Vec<KeyEvent> {
    let mut out = Vec::new();

    // Press: modifiers first, so they are already held when the key lands.
    let downs = usages_added(cur, prev);
    for usage in downs.iter().copied().filter(|u| is_modifier(*u)) {
        out.push(KeyEvent { down: true, usage });
    }
    for usage in downs.iter().copied().filter(|u| !is_modifier(*u)) {
        out.push(KeyEvent { down: true, usage });
    }

    // Release: modifiers last, so they outlive the key they modified.
    let ups = usages_added(prev, cur);
    for usage in ups.iter().copied().filter(|u| !is_modifier(*u)) {
        out.push(KeyEvent { down: false, usage });
    }
    for usage in ups.iter().copied().filter(|u| is_modifier(*u)) {
        out.push(KeyEvent { down: false, usage });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(keys: &[Key]) -> HashSet<Key> {
        keys.iter().copied().collect()
    }

    fn seq(evs: &[KeyEvent]) -> Vec<(bool, u16)> {
        evs.iter().map(|e| (e.down, e.usage)).collect()
    }

    /// Typing '#' is Shift+3. The ATEN KeyEvent has no modifier bitmask, so the
    /// BMC infers modifier state from arrival order: Shift must go down before
    /// '3' and come up after it. Both land in the same frame when typed at speed.
    #[test]
    fn shifted_character_orders_modifier_around_the_key() {
        // Shift and '3' pressed within one frame.
        let down = key_events(&set(&[]), &set(&[Key::LeftShift, Key::Key3]));
        assert_eq!(seq(&down), vec![(true, 0xe1), (true, 0x20)],
                   "Shift (0xe1) must be pressed before '3' (0x20)");

        // Both released within one frame.
        let up = key_events(&set(&[Key::LeftShift, Key::Key3]), &set(&[]));
        assert_eq!(seq(&up), vec![(false, 0x20), (false, 0xe1)],
                   "'3' must be released before Shift");
    }

    /// The whole set is re-derived each frame, so ordering must hold no matter
    /// how the underlying HashSet happens to iterate.
    #[test]
    fn modifier_ordering_is_stable_across_hashset_iteration() {
        let keys = [Key::LeftShift, Key::RightShift, Key::A, Key::B, Key::LeftCtrl];
        let expected = seq(&key_events(&set(&[]), &set(&keys)));

        for _ in 0..64 {
            let got = seq(&key_events(&set(&[]), &set(&keys)));
            assert_eq!(got, expected, "event order must not vary between runs");
        }

        // Every modifier precedes every non-modifier on the way down.
        let last_mod = expected.iter().rposition(|(_, u)| is_modifier(*u)).unwrap();
        let first_key = expected.iter().position(|(_, u)| !is_modifier(*u)).unwrap();
        assert!(last_mod < first_key, "all modifiers must precede all plain keys");
    }

    /// Keys with no HID mapping are dropped rather than sent as garbage.
    #[test]
    fn unmapped_keys_are_skipped() {
        assert!(key_events(&set(&[]), &set(&[Key::Unknown])).is_empty());
    }
}

/// Connect, authenticate, then pump framebuffer updates into `shared` and drain
/// queued keystrokes onto the wire. Returns `Err` only for connection-phase
/// failures; once the session is live, runtime errors end the loop cleanly.
fn io_main(
    params: KvmParams,
    shared: Shared,
    dim_tx: Sender<(usize, usize)>,
    key_rx: Receiver<KeyEvent>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    let conn = transport::connect(&params)?;
    let mut stream = conn.stream;

    let si = rfb::handshake(&mut stream, conn.server_banner, &params.username, &params.password)
        .context("RFB handshake/auth")?;
    info!("server init: {}x{} \"{}\"", si.width, si.height, si.name);

    {
        let mut g = shared.lock().unwrap();
        *g = Some(Frame::new(si.width, si.height));
    }
    // Unblocks the main thread and creates the window.
    dim_tx
        .send((si.width, si.height))
        .map_err(|_| anyhow!("UI thread gone"))?;

    // Kick off with a full (non-incremental) update request.
    rfb::send_fbur(&mut stream, false).context("initial update request")?;

    while !shutdown.load(Ordering::Relaxed) {
        match rfb::read_message(&mut stream, &shared, &dim_tx) {
            Ok(was_fb_update) => {
                // Flush any pending keystrokes.
                for ev in key_rx.try_iter() {
                    if let Err(e) = rfb::send_key(&mut stream, &ev) {
                        info!("failed to send key: {e:#}");
                        return Ok(());
                    }
                }
                if was_fb_update {
                    if let Err(e) = rfb::send_fbur(&mut stream, true) {
                        info!("failed to request update: {e:#}");
                        return Ok(());
                    }
                }
            }
            Err(e) => {
                info!("stream ended: {e:#}");
                return Ok(());
            }
        }
    }

    Ok(())
}
