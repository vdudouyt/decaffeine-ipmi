//! Shared framebuffer state written by the I/O thread and read by the UI thread.
//!
//! Pixels are stored in minifb's `0x00RRGGBB` layout. The BMC sends RGB555
//! little-endian pixels, either as 16x16 tiles (subrect encoding) or as a raw
//! row-major block (raw encoding).

use std::sync::{Arc, Mutex};

pub type Shared = Arc<Mutex<Option<Frame>>>;

pub struct Frame {
    pub width: usize,
    pub height: usize,
    pub pixels: Vec<u32>,
    /// Bumped on every resolution change so the UI thread can notice re-allocations.
    pub generation: u64,
}

impl Frame {
    pub fn new(width: usize, height: usize) -> Self {
        Frame {
            width,
            height,
            pixels: vec![0u32; width * height],
            generation: 0,
        }
    }

    pub fn resize(&mut self, width: usize, height: usize) {
        self.width = width;
        self.height = height;
        self.pixels = vec![0u32; width * height];
        self.generation = self.generation.wrapping_add(1);
    }

    pub fn fill_black(&mut self) {
        self.pixels.iter_mut().for_each(|p| *p = 0);
    }

    /// Blit one 16x16 RGB555 tile at tile-grid position (tx, ty), i.e. pixel
    /// origin (tx*16, ty*16). `tile` must be 512 bytes (256 px * 2 bytes).
    pub fn blit_tile(&mut self, tx: usize, ty: usize, tile: &[u8]) {
        if tile.len() < 512 {
            return;
        }
        let x0 = tx * 16;
        let y0 = ty * 16;
        for row in 0..16 {
            let py = y0 + row;
            if py >= self.height {
                break;
            }
            let dst_row = py * self.width;
            for col in 0..16 {
                let px = x0 + col;
                if px >= self.width {
                    continue;
                }
                let idx = (row * 16 + col) * 2;
                let v = u16::from_le_bytes([tile[idx], tile[idx + 1]]);
                self.pixels[dst_row + px] = rgb555_to_argb(v);
            }
        }
    }

    /// Blit a raw w*h RGB555 block (row-major) at pixel origin (x, y).
    pub fn blit_raw(&mut self, x: usize, y: usize, w: usize, h: usize, body: &[u8]) {
        for row in 0..h {
            let py = y + row;
            if py >= self.height {
                break;
            }
            let dst_row = py * self.width;
            for col in 0..w {
                let px = x + col;
                if px >= self.width {
                    continue;
                }
                let idx = (row * w + col) * 2;
                if idx + 2 > body.len() {
                    return;
                }
                let v = u16::from_le_bytes([body[idx], body[idx + 1]]);
                self.pixels[dst_row + px] = rgb555_to_argb(v);
            }
        }
    }
}

/// RGB555 (little-endian `0RRRRRGGGGGBBBBB`) -> `0x00RRGGBB`, scaling each
/// 5-bit channel to 8 bits.
pub fn rgb555_to_argb(v: u16) -> u32 {
    let r = ((v >> 10) & 0x1f) as u32;
    let g = ((v >> 5) & 0x1f) as u32;
    let b = (v & 0x1f) as u32;
    let r = (r << 3) | (r >> 2);
    let g = (g << 3) | (g >> 2);
    let b = (b << 3) | (b >> 2);
    (r << 16) | (g << 8) | b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rgb555_extremes() {
        assert_eq!(rgb555_to_argb(0x0000), 0x000000);
        // all bits set in 15-bit color -> white
        assert_eq!(rgb555_to_argb(0x7fff), 0xffffff);
        // pure red: r=31 -> 0xff0000
        assert_eq!(rgb555_to_argb(0b0_11111_00000_00000), 0xff0000);
        // pure blue: b=31 -> 0x0000ff
        assert_eq!(rgb555_to_argb(0b0_00000_00000_11111), 0x0000ff);
    }

    #[test]
    fn tile_lands_at_grid_origin() {
        let mut f = Frame::new(32, 32);
        // A tile full of pure-red pixels (0x7c00 little-endian = [0x00, 0x7c]).
        let mut tile = vec![0u8; 512];
        for px in tile.chunks_exact_mut(2) {
            px[0] = 0x00;
            px[1] = 0x7c;
        }
        f.blit_tile(1, 1, &tile); // origin (16,16)
        assert_eq!(f.pixels[0], 0x000000); // untouched
        assert_eq!(f.pixels[16 * 32 + 16], 0xff0000); // tile corner
        assert_eq!(f.pixels[31 * 32 + 31], 0xff0000); // tile far corner
    }
}
