//! Infallible width conversions used across the Mach-O codec.
//!
//! These centralize the few casts the codec needs. Callers must guarantee the value fits the
//! destination (the reader bounds-checks offsets against the buffer length in `u64` space before
//! narrowing, and the writer only narrows lengths that cannot exceed `u32::MAX` for any
//! constructible module). Centralizing them keeps the lossy-cast lint expectation in one place.

/// Widens a `u32` to `usize` (lossless on every supported pointer width).
#[inline]
pub(crate) const fn usize_from_u32(value: u32) -> usize {
    value as usize
}

/// Narrows a `u64` to `usize`. The caller must have verified the value is in range.
#[inline]
#[expect(
    clippy::cast_possible_truncation,
    reason = "callers bounds-check the value against the buffer length before narrowing"
)]
pub(crate) const fn usize_from_u64(value: u64) -> usize {
    value as usize
}

/// Widens a `usize` to `u64` (lossless on every supported pointer width).
#[inline]
pub(crate) const fn u64_from_usize(value: usize) -> u64 {
    value as u64
}

/// Narrows a `usize` to `u32`. The caller must have verified the value fits 32 bits.
#[inline]
#[expect(
    clippy::cast_possible_truncation,
    reason = "callers only narrow lengths that cannot exceed u32::MAX for a constructible module"
)]
pub(crate) const fn u32_from_usize(value: usize) -> u32 {
    value as u32
}

/// Narrows a `u64` to `u32`. The caller must have verified the value fits 32 bits.
#[inline]
#[expect(
    clippy::cast_possible_truncation,
    reason = "callers only narrow offsets/sizes that cannot exceed u32::MAX for a constructible module"
)]
pub(crate) const fn u32_from_u64(value: u64) -> u32 {
    value as u32
}

/// Narrows a `u32` to `u8`. The caller must have verified the value fits 8 bits.
#[inline]
#[expect(
    clippy::cast_possible_truncation,
    reason = "callers bound the value to 8 bits before narrowing"
)]
pub(crate) const fn u8_from_u32(value: u32) -> u8 {
    value as u8
}

/// Narrows a `usize` to `u16`. The caller must have verified the value fits 16 bits.
#[inline]
#[expect(
    clippy::cast_possible_truncation,
    reason = "callers only narrow ordinals that cannot exceed u16::MAX for a constructible module"
)]
pub(crate) const fn u16_from_usize(value: usize) -> u16 {
    value as u16
}
