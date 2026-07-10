//! Map `minifb::Key` values to USB HID keyboard/keypad usage codes.
//!
//! The ATEN KeyEvent carries a HID usage code, not an X11 keysym. Modifiers are
//! sent as ordinary key down/up events using their own usage (0xE0..=0xE6); the
//! BMC tracks the modifier state. Keys we can't map return `None` and are dropped.

use minifb::Key;

pub fn hid_usage(key: Key) -> Option<u16> {
    let code: u16 = match key {
        // Letters: a..z -> 0x04..0x1d
        Key::A => 0x04, Key::B => 0x05, Key::C => 0x06, Key::D => 0x07,
        Key::E => 0x08, Key::F => 0x09, Key::G => 0x0a, Key::H => 0x0b,
        Key::I => 0x0c, Key::J => 0x0d, Key::K => 0x0e, Key::L => 0x0f,
        Key::M => 0x10, Key::N => 0x11, Key::O => 0x12, Key::P => 0x13,
        Key::Q => 0x14, Key::R => 0x15, Key::S => 0x16, Key::T => 0x17,
        Key::U => 0x18, Key::V => 0x19, Key::W => 0x1a, Key::X => 0x1b,
        Key::Y => 0x1c, Key::Z => 0x1d,

        // Digit row: 1..9 -> 0x1e..0x26, 0 -> 0x27
        Key::Key1 => 0x1e, Key::Key2 => 0x1f, Key::Key3 => 0x20, Key::Key4 => 0x21,
        Key::Key5 => 0x22, Key::Key6 => 0x23, Key::Key7 => 0x24, Key::Key8 => 0x25,
        Key::Key9 => 0x26, Key::Key0 => 0x27,

        Key::Enter => 0x28,
        Key::Escape => 0x29,
        Key::Backspace => 0x2a,
        Key::Tab => 0x2b,
        Key::Space => 0x2c,
        Key::Minus => 0x2d,
        Key::Equal => 0x2e,
        Key::LeftBracket => 0x2f,
        Key::RightBracket => 0x30,
        Key::Backslash => 0x31,
        Key::Semicolon => 0x33,
        Key::Apostrophe => 0x34,
        Key::Backquote => 0x35,
        Key::Comma => 0x36,
        Key::Period => 0x37,
        Key::Slash => 0x38,
        Key::CapsLock => 0x39,

        // Function keys F1..F12 -> 0x3a..0x45
        Key::F1 => 0x3a, Key::F2 => 0x3b, Key::F3 => 0x3c, Key::F4 => 0x3d,
        Key::F5 => 0x3e, Key::F6 => 0x3f, Key::F7 => 0x40, Key::F8 => 0x41,
        Key::F9 => 0x42, Key::F10 => 0x43, Key::F11 => 0x44, Key::F12 => 0x45,

        Key::Pause => 0x48,
        Key::Insert => 0x49,
        Key::Home => 0x4a,
        Key::PageUp => 0x4b,
        Key::Delete => 0x4c,
        Key::End => 0x4d,
        Key::PageDown => 0x4e,

        // Arrows
        Key::Right => 0x4f,
        Key::Left => 0x50,
        Key::Down => 0x51,
        Key::Up => 0x52,

        // Keypad
        Key::NumLock => 0x53,
        Key::NumPadSlash => 0x54,
        Key::NumPadAsterisk => 0x55,
        Key::NumPadMinus => 0x56,
        Key::NumPadPlus => 0x57,
        Key::NumPadEnter => 0x58,
        Key::NumPad1 => 0x59, Key::NumPad2 => 0x5a, Key::NumPad3 => 0x5b,
        Key::NumPad4 => 0x5c, Key::NumPad5 => 0x5d, Key::NumPad6 => 0x5e,
        Key::NumPad7 => 0x5f, Key::NumPad8 => 0x60, Key::NumPad9 => 0x61,
        Key::NumPad0 => 0x62,
        Key::NumPadDot => 0x63,

        Key::Menu => 0x65,
        Key::ScrollLock => 0x47,

        // Modifiers -> 0xE0..=0xE7
        Key::LeftCtrl => 0xe0,
        Key::LeftShift => 0xe1,
        Key::LeftAlt => 0xe2,
        Key::LeftSuper => 0xe3,
        Key::RightCtrl => 0xe4,
        Key::RightShift => 0xe5,
        Key::RightAlt => 0xe6,
        Key::RightSuper => 0xe7,

        _ => return None,
    };
    Some(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_keys() {
        assert_eq!(hid_usage(Key::A), Some(0x04));
        assert_eq!(hid_usage(Key::Z), Some(0x1d));
        assert_eq!(hid_usage(Key::Key0), Some(0x27));
        assert_eq!(hid_usage(Key::Enter), Some(0x28));
        assert_eq!(hid_usage(Key::LeftCtrl), Some(0xe0));
        assert_eq!(hid_usage(Key::F12), Some(0x45));
        assert_eq!(hid_usage(Key::Up), Some(0x52));
    }

    #[test]
    fn unmapped_is_none() {
        assert_eq!(hid_usage(Key::Unknown), None);
    }
}
