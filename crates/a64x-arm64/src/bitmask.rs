//! ARMv8 "bitmask immediate" decoding, straight from the ARM ARM
//! `DecodeBitMasks` pseudocode. Used by logical-immediate and bitfield
//! instructions.

/// Highest set bit index of a 7-bit value (`N:~imms`), or None when zero.
fn highest_set_bit(v: u32) -> Option<u32> {
    if v == 0 {
        None
    } else {
        Some(31 - v.leading_zeros())
    }
}

/// Rotate `x` right by `r` *within a lane of `esize` bits*.
fn ror_within(x: u64, r: u64, esize: u64) -> u64 {
    debug_assert!(esize.is_power_of_two() && esize <= 64);
    let lane_mask = if esize == 64 { u64::MAX } else { (1u64 << esize) - 1 };
    let r = r % esize;
    let x = x & lane_mask;
    if r == 0 {
        x
    } else {
        ((x >> r) | (x << (esize - r))) & lane_mask
    }
}

/// Replicate a lane of `esize` bits across a 64-bit value.
fn replicate(x: u64, esize: u64) -> u64 {
    let lane_mask = if esize == 64 { u64::MAX } else { (1u64 << esize) - 1 };
    let x = x & lane_mask;
    let mut out = 0u64;
    let mut shift = 0u64;
    while shift < 64 {
        out |= x << shift;
        shift += esize;
    }
    out
}

/// Decode a *logical* ("bitmask") immediate (N, immr, imms) to its mask.
///
/// Returns `None` for unallocated encodings.
/// `imm_size` is 32 or 64; the returned mask is zero-extended to 64 bits.
pub fn decode_logical_imm(n: bool, immr: u8, imms: u8, width: u8) -> Option<u64> {
    let n_immr_imms = ((n as u32) << 6) | ((!imms as u32) & 0x3F);
    let len = highest_set_bit(n_immr_imms)?;
    if len < 1 || (1u32 << len) > width as u32 {
        return None;
    }
    let levels = (1u64 << len) - 1;
    let s = (imms as u64) & levels;
    let r = (immr as u64) & levels;
    // For logical immediates, S == levels is an unallocated encoding.
    if s == levels {
        return None;
    }
    let esize = 1u64 << len;
    let welem = if s + 1 >= esize {
        // ones(esize)
        if esize == 64 {
            u64::MAX
        } else {
            (1u64 << esize) - 1
        }
    } else {
        (1u64 << (s + 1)) - 1
    };
    let mask = replicate(ror_within(welem, r, esize), esize);
    Some(if width == 64 { mask } else { mask & 0xFFFF_FFFF })
}

/// Decode the (wmask, tmask) pair of a *bitfield* instruction operand.
///
/// Follows `DecodeBitMasks(N, imms, immr, /*immediate=*/FALSE)`.
pub fn decode_bitfield_masks(n: bool, immr: u8, imms: u8, width: u8) -> Option<(u64, u64)> {
    let n_immr_imms = ((n as u32) << 6) | ((!imms as u32) & 0x3F);
    let len = highest_set_bit(n_immr_imms)?;
    if len < 1 || (1u32 << len) > width as u32 {
        return None;
    }
    let levels = (1u64 << len) - 1;
    let esize = 1u64 << len;
    let s = (imms as u64) & levels;
    let r = (immr as u64) & levels;
    let diff = s.wrapping_sub(r) & levels;
    let lane = if esize == 64 { u64::MAX } else { (1u64 << esize) - 1 };
    let welem = if s + 1 >= esize { lane } else { (1u64 << (s + 1)) - 1 };
    let telem = if diff + 1 >= esize { lane } else { (1u64 << (diff + 1)) - 1 };
    let wmask = replicate(ror_within(welem, r, esize), esize);
    let tmask = replicate(telem & lane, esize);
    let (wmask, tmask) = if width == 64 {
        (wmask, tmask)
    } else {
        (wmask & 0xFFFF_FFFF, tmask & 0xFFFF_FFFF)
    };
    Some((wmask, tmask))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_logical_masks() {
        // AND x0, x1, #0x3
        assert_eq!(decode_logical_imm(true, 0, 1, 64), Some(0x3));
        // ORR w1, wzr, #0xFF00FF00  (esize=16: ror32(ones(8), 8) = 0xFF00, x2)
        assert_eq!(decode_logical_imm(false, 8, 39, 32), Some(0xFF00_FF00));
        // ORR x0, xzr, #0xFF000000FF000000 (esize=32: ror32(ones(8), 8) x2)
        assert_eq!(decode_logical_imm(false, 8, 7, 64), Some(0xFF00_0000_FF00_0000));
        // AND w0, w1, #0xFF
        assert_eq!(decode_logical_imm(false, 0, 7, 32), Some(0xFF));
        // AND w0, w1, #0xFF000000 (esize=32: ror32(ones(8), 8))
        assert_eq!(decode_logical_imm(false, 8, 7, 32), Some(0xFF00_0000));
        // imms all-ones within levels is unallocated for logical
        assert_eq!(decode_logical_imm(true, 0, 63, 64), None);
        // TST x0, #0x8000000000000000 (esize=64: ror64(ones(1), 1))
        assert_eq!(decode_logical_imm(true, 1, 0, 64), Some(1u64 << 63));
        // AND x0, x1, #0x7FFFFFFFFFFFFFFF (ones(63), no rotation)
        assert_eq!(decode_logical_imm(true, 0, 62, 64), Some(0x7FFF_FFFF_FFFF_FFFF));
        // AND x0, x1, #0xFFFFFFFFFFFFFFFE (ones(63) rotated right by 63)
        assert_eq!(decode_logical_imm(true, 63, 62, 64), Some(u64::MAX - 1));
    }

    #[test]
    fn known_bitfield_masks() {
        // LSL x0, x1, #3  =>  immr=61, imms=60: wmask keeps the shifted-out
        // window (rotate-right of ones(61) by 61 == 0xFFFF...FFF8)
        let (w, t) = decode_bitfield_masks(true, 61, 60, 64).unwrap();
        assert_eq!(w, 0xFFFF_FFFF_FFFF_FFF8);
        assert_eq!(t, u64::MAX);
        // LSR x0, x1, #5  =>  immr=5, imms=63
        let (w, t) = decode_bitfield_masks(true, 5, 63, 64).unwrap();
        assert_eq!(w, u64::MAX);
        assert_eq!(t, u64::MAX >> 5);
        // UXTB w0, w1  => immr=0, imms=7 (32-bit)
        let (w, t) = decode_bitfield_masks(false, 0, 7, 32).unwrap();
        assert_eq!(w, 0xFF);
        assert_eq!(t, 0xFF);
        // SXTW x0, w1 => immr=0, imms=31 (64-bit)
        let (w, t) = decode_bitfield_masks(true, 0, 31, 64).unwrap();
        assert_eq!(w, 0xFFFF_FFFF);
        assert_eq!(t, 0xFFFF_FFFF);
        // SBFX x0, x1, #8, #16 => immr=8, imms=23
        // wmask = ror64(ones(24), 8), tmask = ones(16)
        let (w, t) = decode_bitfield_masks(true, 8, 23, 64).unwrap();
        assert_eq!(w, 0xFF00_0000_0000_FFFF);
        assert_eq!(t, 0xFFFF);
    }
}
