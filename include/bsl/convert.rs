//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
use crate::Integer;
use crate::IntoSafeIntegral;
use crate::SafeI16;
use crate::SafeI32;
use crate::SafeI64;
use crate::SafeI8;
use crate::SafeIdx;
use crate::SafeIntegral;
use crate::SafeU16;
use crate::SafeU32;
use crate::SafeU64;
use crate::SafeU8;
use crate::SafeUMx;
use crate::UnsignedInteger;

// -------------------------------------------------------------------------
// predefined conversion functions
// -------------------------------------------------------------------------

fn safe_integral_to_i8<T>(other: SafeIntegral<T>) -> SafeI8
where
    T: Integer,
{
    let val = other.cdata_as_ref().into_i8();
    return SafeI8::new_from_option_with_flags_from(val, other);
}

fn safe_integral_to_i16<T>(other: SafeIntegral<T>) -> SafeI16
where
    T: Integer,
{
    let val = other.cdata_as_ref().into_i16();
    return SafeI16::new_from_option_with_flags_from(val, other);
}

fn safe_integral_to_i32<T>(other: SafeIntegral<T>) -> SafeI32
where
    T: Integer,
{
    let val = other.cdata_as_ref().into_i32();
    return SafeI32::new_from_option_with_flags_from(val, other);
}

fn safe_integral_to_i64<T>(other: SafeIntegral<T>) -> SafeI64
where
    T: Integer,
{
    let val = other.cdata_as_ref().into_i64();
    return SafeI64::new_from_option_with_flags_from(val, other);
}

fn safe_integral_to_u8<T>(other: SafeIntegral<T>) -> SafeU8
where
    T: Integer,
{
    let val = other.cdata_as_ref().into_u8();
    return SafeU8::new_from_option_with_flags_from(val, other);
}

fn safe_integral_to_u8_unsafe<T>(other: SafeIntegral<T>) -> SafeU8
where
    T: UnsignedInteger,
{
    let val = other.cdata_as_ref().into_u8_unsafe();
    return SafeU8::new_with_flags_from(val, other);
}

fn safe_integral_to_u16<T>(other: SafeIntegral<T>) -> SafeU16
where
    T: Integer,
{
    let val = other.cdata_as_ref().into_u16();
    return SafeU16::new_from_option_with_flags_from(val, other);
}

fn safe_integral_to_u16_unsafe<T>(other: SafeIntegral<T>) -> SafeU16
where
    T: UnsignedInteger,
{
    let val = other.cdata_as_ref().into_u16_unsafe();
    return SafeU16::new_with_flags_from(val, other);
}

fn safe_integral_to_u32<T>(other: SafeIntegral<T>) -> SafeU32
where
    T: Integer,
{
    let val = other.cdata_as_ref().into_u32();
    return SafeU32::new_from_option_with_flags_from(val, other);
}

fn safe_integral_to_u32_unsafe<T>(other: SafeIntegral<T>) -> SafeU32
where
    T: UnsignedInteger,
{
    let val = other.cdata_as_ref().into_u32_unsafe();
    return SafeU32::new_with_flags_from(val, other);
}

fn safe_integral_to_u64<T>(other: SafeIntegral<T>) -> SafeU64
where
    T: Integer,
{
    let val = other.cdata_as_ref().into_u64();
    return SafeU64::new_from_option_with_flags_from(val, other);
}

fn safe_integral_to_u64_unsafe<T>(other: SafeIntegral<T>) -> SafeU64
where
    T: UnsignedInteger,
{
    let val = other.cdata_as_ref().into_u64_unsafe();
    return SafeU64::new_with_flags_from(val, other);
}

fn safe_integral_to_umx<T>(other: SafeIntegral<T>) -> SafeUMx
where
    T: Integer,
{
    let val = other.cdata_as_ref().into_usize();
    return SafeUMx::new_from_option_with_flags_from(val, other);
}

fn safe_integral_to_umx_unsafe<T>(other: SafeIntegral<T>) -> SafeUMx
where
    T: UnsignedInteger,
{
    let val = other.cdata_as_ref().into_usize_unsafe();
    return SafeUMx::new_with_flags_from(val, other);
}

// -------------------------------------------------------------------------
// public conversion functions
// -------------------------------------------------------------------------

/// <!-- description -->
///   @brief Returns other converted to a SafeI8
///
/// <!-- inputs/outputs -->
///   @tparam P the type of integral to convert
///   @param other the integral to convert
///   @return Returns other converted to a SafeI8
///
pub fn to_i8<P, T>(other: P) -> SafeI8
where
    P: IntoSafeIntegral<Output = SafeIntegral<T>>,
    T: Integer,
{
    return safe_integral_to_i8(other.into_safe_integral());
}

/// <!-- description -->
///   @brief Returns other converted to a SafeI16
///
/// <!-- inputs/outputs -->
///   @tparam P the type of integral to convert
///   @param other the integral to convert
///   @return Returns other converted to a SafeI16
///
pub fn to_i16<P, T>(other: P) -> SafeI16
where
    P: IntoSafeIntegral<Output = SafeIntegral<T>>,
    T: Integer,
{
    return safe_integral_to_i16(other.into_safe_integral());
}

/// <!-- description -->
///   @brief Returns other converted to a SafeI32
///
/// <!-- inputs/outputs -->
///   @tparam P the type of integral to convert
///   @param other the integral to convert
///   @return Returns other converted to a SafeI32
///
pub fn to_i32<P, T>(other: P) -> SafeI32
where
    P: IntoSafeIntegral<Output = SafeIntegral<T>>,
    T: Integer,
{
    return safe_integral_to_i32(other.into_safe_integral());
}

/// <!-- description -->
///   @brief Returns other converted to a SafeI64
///
/// <!-- inputs/outputs -->
///   @tparam P the type of integral to convert
///   @param other the integral to convert
///   @return Returns other converted to a SafeI64
///
pub fn to_i64<P, T>(other: P) -> SafeI64
where
    P: IntoSafeIntegral<Output = SafeIntegral<T>>,
    T: Integer,
{
    return safe_integral_to_i64(other.into_safe_integral());
}

/// <!-- description -->
///   @brief Returns other converted to a SafeU8
///
/// <!-- inputs/outputs -->
///   @tparam P the type of integral to convert
///   @param other the integral to convert
///   @return Returns other converted to a SafeU8
///
pub fn to_u8<P, T>(other: P) -> SafeU8
where
    P: IntoSafeIntegral<Output = SafeIntegral<T>>,
    T: Integer,
{
    return safe_integral_to_u8(other.into_safe_integral());
}

/// <!-- description -->
///   @brief Returns other converted to a SafeU8
///     without checking for data loss.
///
/// <!-- inputs/outputs -->
///   @tparam P the type of integral to convert
///   @param other the integral to convert
///   @return Returns other converted to a SafeU8
///
pub fn to_u8_unsafe<P, T>(other: P) -> SafeU8
where
    P: IntoSafeIntegral<Output = SafeIntegral<T>>,
    T: UnsignedInteger,
{
    return safe_integral_to_u8_unsafe(other.into_safe_integral());
}

/// <!-- description -->
///   @brief Returns other converted to a SafeU16
///
/// <!-- inputs/outputs -->
///   @tparam P the type of integral to convert
///   @param other the integral to convert
///   @return Returns other converted to a SafeU16
///
pub fn to_u16<P, T>(other: P) -> SafeU16
where
    P: IntoSafeIntegral<Output = SafeIntegral<T>>,
    T: Integer,
{
    return safe_integral_to_u16(other.into_safe_integral());
}

/// <!-- description -->
///   @brief Returns other converted to a SafeU16
///     without checking for data loss.
///
/// <!-- inputs/outputs -->
///   @tparam P the type of integral to convert
///   @param other the integral to convert
///   @return Returns other converted to a SafeU16
///
pub fn to_u16_unsafe<P, T>(other: P) -> SafeU16
where
    P: IntoSafeIntegral<Output = SafeIntegral<T>>,
    T: UnsignedInteger,
{
    return safe_integral_to_u16_unsafe(other.into_safe_integral());
}

/// <!-- description -->
///   @brief Returns other converted to a SafeU32
///
/// <!-- inputs/outputs -->
///   @tparam P the type of integral to convert
///   @param other the integral to convert
///   @return Returns other converted to a SafeU32
///
pub fn to_u32<P, T>(other: P) -> SafeU32
where
    P: IntoSafeIntegral<Output = SafeIntegral<T>>,
    T: Integer,
{
    return safe_integral_to_u32(other.into_safe_integral());
}

/// <!-- description -->
///   @brief Returns other converted to a SafeU32
///     without checking for data loss.
///
/// <!-- inputs/outputs -->
///   @tparam P the type of integral to convert
///   @param other the integral to convert
///   @return Returns other converted to a SafeU32
///
pub fn to_u32_unsafe<P, T>(other: P) -> SafeU32
where
    P: IntoSafeIntegral<Output = SafeIntegral<T>>,
    T: UnsignedInteger,
{
    return safe_integral_to_u32_unsafe(other.into_safe_integral());
}

/// <!-- description -->
///   @brief Returns other converted to a SafeU64
///
/// <!-- inputs/outputs -->
///   @tparam P the type of integral to convert
///   @param other the integral to convert
///   @return Returns other converted to a SafeU64
///
pub fn to_u64<P, T>(other: P) -> SafeU64
where
    P: IntoSafeIntegral<Output = SafeIntegral<T>>,
    T: Integer,
{
    return safe_integral_to_u64(other.into_safe_integral());
}

/// <!-- description -->
///   @brief Returns other converted to a SafeU64
///     without checking for data loss.
///
/// <!-- inputs/outputs -->
///   @tparam P the type of integral to convert
///   @param other the integral to convert
///   @return Returns other converted to a SafeU64
///
pub fn to_u64_unsafe<P, T>(other: P) -> SafeU64
where
    P: IntoSafeIntegral<Output = SafeIntegral<T>>,
    T: UnsignedInteger,
{
    return safe_integral_to_u64_unsafe(other.into_safe_integral());
}

/// <!-- description -->
///   @brief Returns other converted to a SafeUMx
///
/// <!-- inputs/outputs -->
///   @tparam P the type of integral to convert
///   @param other the integral to convert
///   @return Returns other converted to a SafeUMx
///
pub fn to_umx<P, T>(other: P) -> SafeUMx
where
    P: IntoSafeIntegral<Output = SafeIntegral<T>>,
    T: Integer,
{
    return safe_integral_to_umx(other.into_safe_integral());
}

/// <!-- description -->
///   @brief Returns other converted to a SafeUMx
///     without checking for data loss.
///
/// <!-- inputs/outputs -->
///   @tparam P the type of integral to convert
///   @param other the integral to convert
///   @return Returns other converted to a SafeUMx
///
pub fn to_umx_unsafe<P, T>(other: P) -> SafeUMx
where
    P: IntoSafeIntegral<Output = SafeIntegral<T>>,
    T: UnsignedInteger,
{
    return safe_integral_to_umx_unsafe(other.into_safe_integral());
}

/// <!-- description -->
///   @brief Returns other converted to a SafeIdx
///
/// <!-- inputs/outputs -->
///   @tparam P the type of integral to convert
///   @param other the integral to convert
///   @return Returns other converted to a SafeIdx
///
#[track_caller]
pub fn to_idx<P, T>(other: P) -> SafeIdx
where
    P: IntoSafeIntegral<Output = SafeIntegral<T>>,
    T: Integer,
{
    return SafeIdx::new_from(to_umx(other), crate::here());
}

// -------------------------------------------------------------------------
// upper/lower conversion
// -------------------------------------------------------------------------

/// <!-- description -->
///   @brief Returns (upper & 0xFFFFFFFFFFFFFF00) | to_umx(lower)
///
/// <!-- inputs/outputs -->
///   @param upper the integral to merge with lower
///   @param lower the integral to merge with upper
///   @return Returns (upper & 0xFFFFFFFFFFFFFF00) | to_umx(lower)
///
pub fn merge_umx_with_u8<P1, P2>(upper: P1, lower: P2) -> SafeUMx
where
    P1: IntoSafeIntegral<Output = SafeIntegral<usize>>,
    P2: IntoSafeIntegral<Output = SafeIntegral<u8>>,
{
    let mask = to_umx(0xFFFFFFFFFFFFFF00 as usize);
    return (upper.into_safe_integral() & mask) | to_umx(lower);
}

/// <!-- description -->
///   @brief Returns (upper & 0xFFFFFFFFFFFF0000) | to_umx(lower)
///
/// <!-- inputs/outputs -->
///   @param upper the integral to merge with lower
///   @param lower the integral to merge with upper
///   @return Returns (upper & 0xFFFFFFFFFFFF0000) | to_umx(lower)
///
pub fn merge_umx_with_u16<P1, P2>(upper: P1, lower: P2) -> SafeUMx
where
    P1: IntoSafeIntegral<Output = SafeIntegral<usize>>,
    P2: IntoSafeIntegral<Output = SafeIntegral<u16>>,
{
    let mask = to_umx(0xFFFFFFFFFFFF0000 as usize);
    return (upper.into_safe_integral() & mask) | to_umx(lower);
}

/// <!-- description -->
///   @brief Returns (upper & 0xFFFFFFFF00000000) | to_umx(lower)
///
/// <!-- inputs/outputs -->
///   @param upper the integral to merge with lower
///   @param lower the integral to merge with upper
///   @return Returns (upper & 0xFFFFFFFF00000000) | to_umx(lower)
///
pub fn merge_umx_with_u32<P1, P2>(upper: P1, lower: P2) -> SafeUMx
where
    P1: IntoSafeIntegral<Output = SafeIntegral<usize>>,
    P2: IntoSafeIntegral<Output = SafeIntegral<u32>>,
{
    let mask = to_umx(0xFFFFFFFF00000000 as usize);
    return (upper.into_safe_integral() & mask) | to_umx(lower);
}

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod test_convert {
    use super::*;
    use crate::*;

    #[test]
    fn convert_from_sfe_i8() {
        assert!(to_i8(SafeI8::failure()).is_invalid());
        assert!(to_i16(SafeI8::failure()).is_invalid());
        assert!(to_i32(SafeI8::failure()).is_invalid());
        assert!(to_i64(SafeI8::failure()).is_invalid());
        assert!(to_u8(SafeI8::failure()).is_invalid());
        assert!(to_u16(SafeI8::failure()).is_invalid());
        assert!(to_u32(SafeI8::failure()).is_invalid());
        assert!(to_u64(SafeI8::failure()).is_invalid());
        assert!(to_umx(SafeI8::failure()).is_invalid());
        assert_panics!(to_idx(SafeI8::failure()));

        assert!(to_i8(SafeI8::magic_neg_1()) == i8::magic_neg_1());
        assert!(to_i16(SafeI8::magic_neg_1()) == i16::magic_neg_1());
        assert!(to_i32(SafeI8::magic_neg_1()) == i32::magic_neg_1());
        assert!(to_i64(SafeI8::magic_neg_1()) == i64::magic_neg_1());
        assert!(to_u8(SafeI8::magic_neg_1()).is_invalid());
        assert!(to_u16(SafeI8::magic_neg_1()).is_invalid());
        assert!(to_u32(SafeI8::magic_neg_1()).is_invalid());
        assert!(to_u64(SafeI8::magic_neg_1()).is_invalid());
        assert!(to_umx(SafeI8::magic_neg_1()).is_invalid());

        assert!(to_i8(SafeI8::magic_neg_2()) == i8::magic_neg_2());
        assert!(to_i16(SafeI8::magic_neg_2()) == i16::magic_neg_2());
        assert!(to_i32(SafeI8::magic_neg_2()) == i32::magic_neg_2());
        assert!(to_i64(SafeI8::magic_neg_2()) == i64::magic_neg_2());
        assert!(to_u8(SafeI8::magic_neg_2()).is_invalid());
        assert!(to_u16(SafeI8::magic_neg_2()).is_invalid());
        assert!(to_u32(SafeI8::magic_neg_2()).is_invalid());
        assert!(to_u64(SafeI8::magic_neg_2()).is_invalid());
        assert!(to_umx(SafeI8::magic_neg_2()).is_invalid());

        assert!(to_i8(SafeI8::magic_neg_3()) == i8::magic_neg_3());
        assert!(to_i16(SafeI8::magic_neg_3()) == i16::magic_neg_3());
        assert!(to_i32(SafeI8::magic_neg_3()) == i32::magic_neg_3());
        assert!(to_i64(SafeI8::magic_neg_3()) == i64::magic_neg_3());
        assert!(to_u8(SafeI8::magic_neg_3()).is_invalid());
        assert!(to_u16(SafeI8::magic_neg_3()).is_invalid());
        assert!(to_u32(SafeI8::magic_neg_3()).is_invalid());
        assert!(to_u64(SafeI8::magic_neg_3()).is_invalid());
        assert!(to_umx(SafeI8::magic_neg_3()).is_invalid());

        assert!(to_i8(SafeI8::magic_0()) == i8::magic_0());
        assert!(to_i16(SafeI8::magic_0()) == i16::magic_0());
        assert!(to_i32(SafeI8::magic_0()) == i32::magic_0());
        assert!(to_i64(SafeI8::magic_0()) == i64::magic_0());
        assert!(to_u8(SafeI8::magic_0()) == u8::magic_0());
        assert!(to_u16(SafeI8::magic_0()) == u16::magic_0());
        assert!(to_u32(SafeI8::magic_0()) == u32::magic_0());
        assert!(to_u64(SafeI8::magic_0()) == u64::magic_0());
        assert!(to_umx(SafeI8::magic_0()) == usize::magic_0());
        assert!(to_idx(SafeI8::magic_0()) == usize::magic_0());

        assert!(to_i8(SafeI8::magic_1()) == i8::magic_1());
        assert!(to_i16(SafeI8::magic_1()) == i16::magic_1());
        assert!(to_i32(SafeI8::magic_1()) == i32::magic_1());
        assert!(to_i64(SafeI8::magic_1()) == i64::magic_1());
        assert!(to_u8(SafeI8::magic_1()) == u8::magic_1());
        assert!(to_u16(SafeI8::magic_1()) == u16::magic_1());
        assert!(to_u32(SafeI8::magic_1()) == u32::magic_1());
        assert!(to_u64(SafeI8::magic_1()) == u64::magic_1());
        assert!(to_umx(SafeI8::magic_1()) == usize::magic_1());
        assert!(to_idx(SafeI8::magic_1()) == usize::magic_1());

        assert!(to_i8(SafeI8::max_value()) == (i8::max_value() as i8));
        assert!(to_i16(SafeI8::max_value()) == (i8::max_value() as i16));
        assert!(to_i32(SafeI8::max_value()) == (i8::max_value() as i32));
        assert!(to_i64(SafeI8::max_value()) == (i8::max_value() as i64));
        assert!(to_u8(SafeI8::max_value()) == (i8::max_value() as u8));
        assert!(to_u16(SafeI8::max_value()) == (i8::max_value() as u16));
        assert!(to_u32(SafeI8::max_value()) == (i8::max_value() as u32));
        assert!(to_u64(SafeI8::max_value()) == (i8::max_value() as u64));
        assert!(to_umx(SafeI8::max_value()) == (i8::max_value() as usize));
        assert!(to_idx(SafeI8::max_value()) == (i8::max_value() as usize));

        assert!(to_i8(SafeI8::min_value()) == (i8::min_value() as i8));
        assert!(to_i16(SafeI8::min_value()) == (i8::min_value() as i16));
        assert!(to_i32(SafeI8::min_value()) == (i8::min_value() as i32));
        assert!(to_i64(SafeI8::min_value()) == (i8::min_value() as i64));
        assert!(to_u8(SafeI8::min_value()).is_invalid());
        assert!(to_u16(SafeI8::min_value()).is_invalid());
        assert!(to_u32(SafeI8::min_value()).is_invalid());
        assert!(to_u64(SafeI8::min_value()).is_invalid());
        assert!(to_umx(SafeI8::min_value()).is_invalid());
    }

    #[test]
    fn convert_from_raw_i8() {
        assert!(to_i8(i8::magic_neg_1()) == i8::magic_neg_1());
        assert!(to_i16(i8::magic_neg_1()) == i16::magic_neg_1());
        assert!(to_i32(i8::magic_neg_1()) == i32::magic_neg_1());
        assert!(to_i64(i8::magic_neg_1()) == i64::magic_neg_1());
        assert!(to_u8(i8::magic_neg_1()).is_invalid());
        assert!(to_u16(i8::magic_neg_1()).is_invalid());
        assert!(to_u32(i8::magic_neg_1()).is_invalid());
        assert!(to_u64(i8::magic_neg_1()).is_invalid());
        assert!(to_umx(i8::magic_neg_1()).is_invalid());
        assert_panics!(to_idx(i8::magic_neg_1()));

        assert!(to_i8(i8::magic_0()) == i8::magic_0());
        assert!(to_i16(i8::magic_0()) == i16::magic_0());
        assert!(to_i32(i8::magic_0()) == i32::magic_0());
        assert!(to_i64(i8::magic_0()) == i64::magic_0());
        assert!(to_u8(i8::magic_0()) == u8::magic_0());
        assert!(to_u16(i8::magic_0()) == u16::magic_0());
        assert!(to_u32(i8::magic_0()) == u32::magic_0());
        assert!(to_u64(i8::magic_0()) == u64::magic_0());
        assert!(to_umx(i8::magic_0()) == usize::magic_0());
        assert!(to_idx(i8::magic_0()) == usize::magic_0());

        assert!(to_i8(i8::magic_1()) == i8::magic_1());
        assert!(to_i16(i8::magic_1()) == i16::magic_1());
        assert!(to_i32(i8::magic_1()) == i32::magic_1());
        assert!(to_i64(i8::magic_1()) == i64::magic_1());
        assert!(to_u8(i8::magic_1()) == u8::magic_1());
        assert!(to_u16(i8::magic_1()) == u16::magic_1());
        assert!(to_u32(i8::magic_1()) == u32::magic_1());
        assert!(to_u64(i8::magic_1()) == u64::magic_1());
        assert!(to_umx(i8::magic_1()) == usize::magic_1());
        assert!(to_idx(i8::magic_1()) == usize::magic_1());

        assert!(to_i8(i8::max_value()) == (i8::max_value() as i8));
        assert!(to_i16(i8::max_value()) == (i8::max_value() as i16));
        assert!(to_i32(i8::max_value()) == (i8::max_value() as i32));
        assert!(to_i64(i8::max_value()) == (i8::max_value() as i64));
        assert!(to_u8(i8::max_value()) == (i8::max_value() as u8));
        assert!(to_u16(i8::max_value()) == (i8::max_value() as u16));
        assert!(to_u32(i8::max_value()) == (i8::max_value() as u32));
        assert!(to_u64(i8::max_value()) == (i8::max_value() as u64));
        assert!(to_umx(i8::max_value()) == (i8::max_value() as usize));
        assert!(to_idx(i8::max_value()) == (i8::max_value() as usize));

        assert!(to_i8(i8::min_value()) == (i8::min_value() as i8));
        assert!(to_i16(i8::min_value()) == (i8::min_value() as i16));
        assert!(to_i32(i8::min_value()) == (i8::min_value() as i32));
        assert!(to_i64(i8::min_value()) == (i8::min_value() as i64));
        assert!(to_u8(i8::min_value()).is_invalid());
        assert!(to_u16(i8::min_value()).is_invalid());
        assert!(to_u32(i8::min_value()).is_invalid());
        assert!(to_u64(i8::min_value()).is_invalid());
        assert!(to_umx(i8::min_value()).is_invalid());
    }

    #[test]
    fn convert_from_sfe_i16() {
        assert!(to_i8(SafeI16::failure()).is_invalid());
        assert!(to_i16(SafeI16::failure()).is_invalid());
        assert!(to_i32(SafeI16::failure()).is_invalid());
        assert!(to_i64(SafeI16::failure()).is_invalid());
        assert!(to_u8(SafeI16::failure()).is_invalid());
        assert!(to_u16(SafeI16::failure()).is_invalid());
        assert!(to_u32(SafeI16::failure()).is_invalid());
        assert!(to_u64(SafeI16::failure()).is_invalid());
        assert!(to_umx(SafeI16::failure()).is_invalid());
        assert_panics!(to_idx(SafeI16::failure()));

        assert!(to_i8(SafeI16::magic_neg_1()) == i8::magic_neg_1());
        assert!(to_i16(SafeI16::magic_neg_1()) == i16::magic_neg_1());
        assert!(to_i32(SafeI16::magic_neg_1()) == i32::magic_neg_1());
        assert!(to_i64(SafeI16::magic_neg_1()) == i64::magic_neg_1());
        assert!(to_u8(SafeI16::magic_neg_1()).is_invalid());
        assert!(to_u16(SafeI16::magic_neg_1()).is_invalid());
        assert!(to_u32(SafeI16::magic_neg_1()).is_invalid());
        assert!(to_u64(SafeI16::magic_neg_1()).is_invalid());
        assert!(to_umx(SafeI16::magic_neg_1()).is_invalid());

        assert!(to_i8(SafeI16::magic_0()) == i8::magic_0());
        assert!(to_i16(SafeI16::magic_0()) == i16::magic_0());
        assert!(to_i32(SafeI16::magic_0()) == i32::magic_0());
        assert!(to_i64(SafeI16::magic_0()) == i64::magic_0());
        assert!(to_u8(SafeI16::magic_0()) == u8::magic_0());
        assert!(to_u16(SafeI16::magic_0()) == u16::magic_0());
        assert!(to_u32(SafeI16::magic_0()) == u32::magic_0());
        assert!(to_u64(SafeI16::magic_0()) == u64::magic_0());
        assert!(to_umx(SafeI16::magic_0()) == usize::magic_0());
        assert!(to_idx(SafeI16::magic_0()) == usize::magic_0());

        assert!(to_i8(SafeI16::magic_1()) == i8::magic_1());
        assert!(to_i16(SafeI16::magic_1()) == i16::magic_1());
        assert!(to_i32(SafeI16::magic_1()) == i32::magic_1());
        assert!(to_i64(SafeI16::magic_1()) == i64::magic_1());
        assert!(to_u8(SafeI16::magic_1()) == u8::magic_1());
        assert!(to_u16(SafeI16::magic_1()) == u16::magic_1());
        assert!(to_u32(SafeI16::magic_1()) == u32::magic_1());
        assert!(to_u64(SafeI16::magic_1()) == u64::magic_1());
        assert!(to_umx(SafeI16::magic_1()) == usize::magic_1());
        assert!(to_idx(SafeI16::magic_1()) == usize::magic_1());

        assert!(to_i8(SafeI16::max_value()).is_invalid());
        assert!(to_i16(SafeI16::max_value()) == (i16::max_value() as i16));
        assert!(to_i32(SafeI16::max_value()) == (i16::max_value() as i32));
        assert!(to_i64(SafeI16::max_value()) == (i16::max_value() as i64));
        assert!(to_u8(SafeI16::max_value()).is_invalid());
        assert!(to_u16(SafeI16::max_value()) == (i16::max_value() as u16));
        assert!(to_u32(SafeI16::max_value()) == (i16::max_value() as u32));
        assert!(to_u64(SafeI16::max_value()) == (i16::max_value() as u64));
        assert!(to_umx(SafeI16::max_value()) == (i16::max_value() as usize));
        assert!(to_idx(SafeI16::max_value()) == (i16::max_value() as usize));

        assert!(to_i8(SafeI16::min_value()).is_invalid());
        assert!(to_i16(SafeI16::min_value()) == (i16::min_value() as i16));
        assert!(to_i32(SafeI16::min_value()) == (i16::min_value() as i32));
        assert!(to_i64(SafeI16::min_value()) == (i16::min_value() as i64));
        assert!(to_u8(SafeI16::min_value()).is_invalid());
        assert!(to_u16(SafeI16::min_value()).is_invalid());
        assert!(to_u32(SafeI16::min_value()).is_invalid());
        assert!(to_u64(SafeI16::min_value()).is_invalid());
        assert!(to_umx(SafeI16::min_value()).is_invalid());
    }

    #[test]
    fn convert_from_raw_i16() {
        assert!(to_i8(i16::magic_neg_1()) == i8::magic_neg_1());
        assert!(to_i16(i16::magic_neg_1()) == i16::magic_neg_1());
        assert!(to_i32(i16::magic_neg_1()) == i32::magic_neg_1());
        assert!(to_i64(i16::magic_neg_1()) == i64::magic_neg_1());
        assert!(to_u8(i16::magic_neg_1()).is_invalid());
        assert!(to_u16(i16::magic_neg_1()).is_invalid());
        assert!(to_u32(i16::magic_neg_1()).is_invalid());
        assert!(to_u64(i16::magic_neg_1()).is_invalid());
        assert!(to_umx(i16::magic_neg_1()).is_invalid());
        assert_panics!(to_idx(i16::magic_neg_1()));

        assert!(to_i8(i16::magic_0()) == i8::magic_0());
        assert!(to_i16(i16::magic_0()) == i16::magic_0());
        assert!(to_i32(i16::magic_0()) == i32::magic_0());
        assert!(to_i64(i16::magic_0()) == i64::magic_0());
        assert!(to_u8(i16::magic_0()) == u8::magic_0());
        assert!(to_u16(i16::magic_0()) == u16::magic_0());
        assert!(to_u32(i16::magic_0()) == u32::magic_0());
        assert!(to_u64(i16::magic_0()) == u64::magic_0());
        assert!(to_umx(i16::magic_0()) == usize::magic_0());
        assert!(to_idx(i16::magic_0()) == usize::magic_0());

        assert!(to_i8(i16::magic_1()) == i8::magic_1());
        assert!(to_i16(i16::magic_1()) == i16::magic_1());
        assert!(to_i32(i16::magic_1()) == i32::magic_1());
        assert!(to_i64(i16::magic_1()) == i64::magic_1());
        assert!(to_u8(i16::magic_1()) == u8::magic_1());
        assert!(to_u16(i16::magic_1()) == u16::magic_1());
        assert!(to_u32(i16::magic_1()) == u32::magic_1());
        assert!(to_u64(i16::magic_1()) == u64::magic_1());
        assert!(to_umx(i16::magic_1()) == usize::magic_1());
        assert!(to_idx(i16::magic_1()) == usize::magic_1());

        assert!(to_i8(i16::max_value()).is_invalid());
        assert!(to_i16(i16::max_value()) == (i16::max_value() as i16));
        assert!(to_i32(i16::max_value()) == (i16::max_value() as i32));
        assert!(to_i64(i16::max_value()) == (i16::max_value() as i64));
        assert!(to_u8(i16::max_value()).is_invalid());
        assert!(to_u16(i16::max_value()) == (i16::max_value() as u16));
        assert!(to_u32(i16::max_value()) == (i16::max_value() as u32));
        assert!(to_u64(i16::max_value()) == (i16::max_value() as u64));
        assert!(to_umx(i16::max_value()) == (i16::max_value() as usize));
        assert!(to_idx(i16::max_value()) == (i16::max_value() as usize));

        assert!(to_i8(i16::min_value()).is_invalid());
        assert!(to_i16(i16::min_value()) == (i16::min_value() as i16));
        assert!(to_i32(i16::min_value()) == (i16::min_value() as i32));
        assert!(to_i64(i16::min_value()) == (i16::min_value() as i64));
        assert!(to_u8(i16::min_value()).is_invalid());
        assert!(to_u16(i16::min_value()).is_invalid());
        assert!(to_u32(i16::min_value()).is_invalid());
        assert!(to_u64(i16::min_value()).is_invalid());
        assert!(to_umx(i16::min_value()).is_invalid());
    }

    #[test]
    fn convert_from_sfe_i32() {
        assert!(to_i8(SafeI32::failure()).is_invalid());
        assert!(to_i16(SafeI32::failure()).is_invalid());
        assert!(to_i32(SafeI32::failure()).is_invalid());
        assert!(to_i64(SafeI32::failure()).is_invalid());
        assert!(to_u8(SafeI32::failure()).is_invalid());
        assert!(to_u16(SafeI32::failure()).is_invalid());
        assert!(to_u32(SafeI32::failure()).is_invalid());
        assert!(to_u64(SafeI32::failure()).is_invalid());
        assert!(to_umx(SafeI32::failure()).is_invalid());
        assert_panics!(to_idx(SafeI32::failure()));

        assert!(to_i8(SafeI32::magic_neg_1()) == i8::magic_neg_1());
        assert!(to_i16(SafeI32::magic_neg_1()) == i16::magic_neg_1());
        assert!(to_i32(SafeI32::magic_neg_1()) == i32::magic_neg_1());
        assert!(to_i64(SafeI32::magic_neg_1()) == i64::magic_neg_1());
        assert!(to_u8(SafeI32::magic_neg_1()).is_invalid());
        assert!(to_u16(SafeI32::magic_neg_1()).is_invalid());
        assert!(to_u32(SafeI32::magic_neg_1()).is_invalid());
        assert!(to_u64(SafeI32::magic_neg_1()).is_invalid());
        assert!(to_umx(SafeI32::magic_neg_1()).is_invalid());

        assert!(to_i8(SafeI32::magic_0()) == i8::magic_0());
        assert!(to_i16(SafeI32::magic_0()) == i16::magic_0());
        assert!(to_i32(SafeI32::magic_0()) == i32::magic_0());
        assert!(to_i64(SafeI32::magic_0()) == i64::magic_0());
        assert!(to_u8(SafeI32::magic_0()) == u8::magic_0());
        assert!(to_u16(SafeI32::magic_0()) == u16::magic_0());
        assert!(to_u32(SafeI32::magic_0()) == u32::magic_0());
        assert!(to_u64(SafeI32::magic_0()) == u64::magic_0());
        assert!(to_umx(SafeI32::magic_0()) == usize::magic_0());
        assert!(to_idx(SafeI32::magic_0()) == usize::magic_0());

        assert!(to_i8(SafeI32::magic_1()) == i8::magic_1());
        assert!(to_i16(SafeI32::magic_1()) == i16::magic_1());
        assert!(to_i32(SafeI32::magic_1()) == i32::magic_1());
        assert!(to_i64(SafeI32::magic_1()) == i64::magic_1());
        assert!(to_u8(SafeI32::magic_1()) == u8::magic_1());
        assert!(to_u16(SafeI32::magic_1()) == u16::magic_1());
        assert!(to_u32(SafeI32::magic_1()) == u32::magic_1());
        assert!(to_u64(SafeI32::magic_1()) == u64::magic_1());
        assert!(to_umx(SafeI32::magic_1()) == usize::magic_1());
        assert!(to_idx(SafeI32::magic_1()) == usize::magic_1());

        assert!(to_i8(SafeI32::max_value()).is_invalid());
        assert!(to_i16(SafeI32::max_value()).is_invalid());
        assert!(to_i32(SafeI32::max_value()) == (i32::max_value() as i32));
        assert!(to_i64(SafeI32::max_value()) == (i32::max_value() as i64));
        assert!(to_u8(SafeI32::max_value()).is_invalid());
        assert!(to_u16(SafeI32::max_value()).is_invalid());
        assert!(to_u32(SafeI32::max_value()) == (i32::max_value() as u32));
        assert!(to_u64(SafeI32::max_value()) == (i32::max_value() as u64));
        assert!(to_umx(SafeI32::max_value()) == (i32::max_value() as usize));
        assert!(to_idx(SafeI32::max_value()) == (i32::max_value() as usize));

        assert!(to_i8(SafeI32::min_value()).is_invalid());
        assert!(to_i16(SafeI32::min_value()).is_invalid());
        assert!(to_i32(SafeI32::min_value()) == (i32::min_value() as i32));
        assert!(to_i64(SafeI32::min_value()) == (i32::min_value() as i64));
        assert!(to_u8(SafeI32::min_value()).is_invalid());
        assert!(to_u16(SafeI32::min_value()).is_invalid());
        assert!(to_u32(SafeI32::min_value()).is_invalid());
        assert!(to_u64(SafeI32::min_value()).is_invalid());
        assert!(to_umx(SafeI32::min_value()).is_invalid());
    }

    #[test]
    fn convert_from_raw_i32() {
        assert!(to_i8(i32::magic_neg_1()) == i8::magic_neg_1());
        assert!(to_i16(i32::magic_neg_1()) == i16::magic_neg_1());
        assert!(to_i32(i32::magic_neg_1()) == i32::magic_neg_1());
        assert!(to_i64(i32::magic_neg_1()) == i64::magic_neg_1());
        assert!(to_u8(i32::magic_neg_1()).is_invalid());
        assert!(to_u16(i32::magic_neg_1()).is_invalid());
        assert!(to_u32(i32::magic_neg_1()).is_invalid());
        assert!(to_u64(i32::magic_neg_1()).is_invalid());
        assert!(to_umx(i32::magic_neg_1()).is_invalid());
        assert_panics!(to_idx(i32::magic_neg_1()));

        assert!(to_i8(i32::magic_0()) == i8::magic_0());
        assert!(to_i16(i32::magic_0()) == i16::magic_0());
        assert!(to_i32(i32::magic_0()) == i32::magic_0());
        assert!(to_i64(i32::magic_0()) == i64::magic_0());
        assert!(to_u8(i32::magic_0()) == u8::magic_0());
        assert!(to_u16(i32::magic_0()) == u16::magic_0());
        assert!(to_u32(i32::magic_0()) == u32::magic_0());
        assert!(to_u64(i32::magic_0()) == u64::magic_0());
        assert!(to_umx(i32::magic_0()) == usize::magic_0());
        assert!(to_idx(i32::magic_0()) == usize::magic_0());

        assert!(to_i8(i32::magic_1()) == i8::magic_1());
        assert!(to_i16(i32::magic_1()) == i16::magic_1());
        assert!(to_i32(i32::magic_1()) == i32::magic_1());
        assert!(to_i64(i32::magic_1()) == i64::magic_1());
        assert!(to_u8(i32::magic_1()) == u8::magic_1());
        assert!(to_u16(i32::magic_1()) == u16::magic_1());
        assert!(to_u32(i32::magic_1()) == u32::magic_1());
        assert!(to_u64(i32::magic_1()) == u64::magic_1());
        assert!(to_umx(i32::magic_1()) == usize::magic_1());
        assert!(to_idx(i32::magic_1()) == usize::magic_1());

        assert!(to_i8(i32::max_value()).is_invalid());
        assert!(to_i16(i32::max_value()).is_invalid());
        assert!(to_i32(i32::max_value()) == (i32::max_value() as i32));
        assert!(to_i64(i32::max_value()) == (i32::max_value() as i64));
        assert!(to_u8(i32::max_value()).is_invalid());
        assert!(to_u16(i32::max_value()).is_invalid());
        assert!(to_u32(i32::max_value()) == (i32::max_value() as u32));
        assert!(to_u64(i32::max_value()) == (i32::max_value() as u64));
        assert!(to_umx(i32::max_value()) == (i32::max_value() as usize));
        assert!(to_idx(i32::max_value()) == (i32::max_value() as usize));

        assert!(to_i8(i32::min_value()).is_invalid());
        assert!(to_i16(i32::min_value()).is_invalid());
        assert!(to_i32(i32::min_value()) == (i32::min_value() as i32));
        assert!(to_i64(i32::min_value()) == (i32::min_value() as i64));
        assert!(to_u8(i32::min_value()).is_invalid());
        assert!(to_u16(i32::min_value()).is_invalid());
        assert!(to_u32(i32::min_value()).is_invalid());
        assert!(to_u64(i32::min_value()).is_invalid());
        assert!(to_umx(i32::min_value()).is_invalid());
    }

    #[test]
    fn convert_from_sfe_i64() {
        assert!(to_i8(SafeI64::failure()).is_invalid());
        assert!(to_i16(SafeI64::failure()).is_invalid());
        assert!(to_i32(SafeI64::failure()).is_invalid());
        assert!(to_i64(SafeI64::failure()).is_invalid());
        assert!(to_u8(SafeI64::failure()).is_invalid());
        assert!(to_u16(SafeI64::failure()).is_invalid());
        assert!(to_u32(SafeI64::failure()).is_invalid());
        assert!(to_u64(SafeI64::failure()).is_invalid());
        assert!(to_umx(SafeI64::failure()).is_invalid());
        assert_panics!(to_idx(SafeI64::failure()));

        assert!(to_i8(SafeI64::magic_neg_1()) == i8::magic_neg_1());
        assert!(to_i16(SafeI64::magic_neg_1()) == i16::magic_neg_1());
        assert!(to_i32(SafeI64::magic_neg_1()) == i32::magic_neg_1());
        assert!(to_i64(SafeI64::magic_neg_1()) == i64::magic_neg_1());
        assert!(to_u8(SafeI64::magic_neg_1()).is_invalid());
        assert!(to_u16(SafeI64::magic_neg_1()).is_invalid());
        assert!(to_u32(SafeI64::magic_neg_1()).is_invalid());
        assert!(to_u64(SafeI64::magic_neg_1()).is_invalid());
        assert!(to_umx(SafeI64::magic_neg_1()).is_invalid());

        assert!(to_i8(SafeI64::magic_0()) == i8::magic_0());
        assert!(to_i16(SafeI64::magic_0()) == i16::magic_0());
        assert!(to_i32(SafeI64::magic_0()) == i32::magic_0());
        assert!(to_i64(SafeI64::magic_0()) == i64::magic_0());
        assert!(to_u8(SafeI64::magic_0()) == u8::magic_0());
        assert!(to_u16(SafeI64::magic_0()) == u16::magic_0());
        assert!(to_u32(SafeI64::magic_0()) == u32::magic_0());
        assert!(to_u64(SafeI64::magic_0()) == u64::magic_0());
        assert!(to_umx(SafeI64::magic_0()) == usize::magic_0());
        assert!(to_idx(SafeI64::magic_0()) == usize::magic_0());

        assert!(to_i8(SafeI64::magic_1()) == i8::magic_1());
        assert!(to_i16(SafeI64::magic_1()) == i16::magic_1());
        assert!(to_i32(SafeI64::magic_1()) == i32::magic_1());
        assert!(to_i64(SafeI64::magic_1()) == i64::magic_1());
        assert!(to_u8(SafeI64::magic_1()) == u8::magic_1());
        assert!(to_u16(SafeI64::magic_1()) == u16::magic_1());
        assert!(to_u32(SafeI64::magic_1()) == u32::magic_1());
        assert!(to_u64(SafeI64::magic_1()) == u64::magic_1());
        assert!(to_umx(SafeI64::magic_1()) == usize::magic_1());
        assert!(to_idx(SafeI64::magic_1()) == usize::magic_1());

        assert!(to_i8(SafeI64::max_value()).is_invalid());
        assert!(to_i16(SafeI64::max_value()).is_invalid());
        assert!(to_i32(SafeI64::max_value()).is_invalid());
        assert!(to_i64(SafeI64::max_value()) == (i64::max_value() as i64));
        assert!(to_u8(SafeI64::max_value()).is_invalid());
        assert!(to_u16(SafeI64::max_value()).is_invalid());
        assert!(to_u32(SafeI64::max_value()).is_invalid());
        assert!(to_u64(SafeI64::max_value()) == (i64::max_value() as u64));
        assert!(to_umx(SafeI64::max_value()) == (i64::max_value() as usize));
        assert!(to_idx(SafeI64::max_value()) == (i64::max_value() as usize));

        assert!(to_i8(SafeI64::min_value()).is_invalid());
        assert!(to_i16(SafeI64::min_value()).is_invalid());
        assert!(to_i32(SafeI64::min_value()).is_invalid());
        assert!(to_i64(SafeI64::min_value()) == (i64::min_value() as i64));
        assert!(to_u8(SafeI64::min_value()).is_invalid());
        assert!(to_u16(SafeI64::min_value()).is_invalid());
        assert!(to_u32(SafeI64::min_value()).is_invalid());
        assert!(to_u64(SafeI64::min_value()).is_invalid());
        assert!(to_umx(SafeI64::min_value()).is_invalid());
    }

    #[test]
    fn convert_from_raw_i64() {
        assert!(to_i8(i64::magic_neg_1()) == i8::magic_neg_1());
        assert!(to_i16(i64::magic_neg_1()) == i16::magic_neg_1());
        assert!(to_i32(i64::magic_neg_1()) == i32::magic_neg_1());
        assert!(to_i64(i64::magic_neg_1()) == i64::magic_neg_1());
        assert!(to_u8(i64::magic_neg_1()).is_invalid());
        assert!(to_u16(i64::magic_neg_1()).is_invalid());
        assert!(to_u32(i64::magic_neg_1()).is_invalid());
        assert!(to_u64(i64::magic_neg_1()).is_invalid());
        assert!(to_umx(i64::magic_neg_1()).is_invalid());
        assert_panics!(to_idx(i64::magic_neg_1()));

        assert!(to_i8(i64::magic_0()) == i8::magic_0());
        assert!(to_i16(i64::magic_0()) == i16::magic_0());
        assert!(to_i32(i64::magic_0()) == i32::magic_0());
        assert!(to_i64(i64::magic_0()) == i64::magic_0());
        assert!(to_u8(i64::magic_0()) == u8::magic_0());
        assert!(to_u16(i64::magic_0()) == u16::magic_0());
        assert!(to_u32(i64::magic_0()) == u32::magic_0());
        assert!(to_u64(i64::magic_0()) == u64::magic_0());
        assert!(to_umx(i64::magic_0()) == usize::magic_0());
        assert!(to_idx(i64::magic_0()) == usize::magic_0());

        assert!(to_i8(i64::magic_1()) == i8::magic_1());
        assert!(to_i16(i64::magic_1()) == i16::magic_1());
        assert!(to_i32(i64::magic_1()) == i32::magic_1());
        assert!(to_i64(i64::magic_1()) == i64::magic_1());
        assert!(to_u8(i64::magic_1()) == u8::magic_1());
        assert!(to_u16(i64::magic_1()) == u16::magic_1());
        assert!(to_u32(i64::magic_1()) == u32::magic_1());
        assert!(to_u64(i64::magic_1()) == u64::magic_1());
        assert!(to_umx(i64::magic_1()) == usize::magic_1());
        assert!(to_idx(i64::magic_1()) == usize::magic_1());

        assert!(to_i8(i64::max_value()).is_invalid());
        assert!(to_i16(i64::max_value()).is_invalid());
        assert!(to_i32(i64::max_value()).is_invalid());
        assert!(to_i64(i64::max_value()) == (i64::max_value() as i64));
        assert!(to_u8(i64::max_value()).is_invalid());
        assert!(to_u16(i64::max_value()).is_invalid());
        assert!(to_u32(i64::max_value()).is_invalid());
        assert!(to_u64(i64::max_value()) == (i64::max_value() as u64));
        assert!(to_umx(i64::max_value()) == (i64::max_value() as usize));
        assert!(to_idx(i64::max_value()) == (i64::max_value() as usize));

        assert!(to_i8(i64::min_value()).is_invalid());
        assert!(to_i16(i64::min_value()).is_invalid());
        assert!(to_i32(i64::min_value()).is_invalid());
        assert!(to_i64(i64::min_value()) == (i64::min_value() as i64));
        assert!(to_u8(i64::min_value()).is_invalid());
        assert!(to_u16(i64::min_value()).is_invalid());
        assert!(to_u32(i64::min_value()).is_invalid());
        assert!(to_u64(i64::min_value()).is_invalid());
        assert!(to_umx(i64::min_value()).is_invalid());
    }

    #[test]
    fn convert_from_sfe_u8() {
        assert!(to_i8(SafeU8::failure()).is_invalid());
        assert!(to_i16(SafeU8::failure()).is_invalid());
        assert!(to_i32(SafeU8::failure()).is_invalid());
        assert!(to_i64(SafeU8::failure()).is_invalid());
        assert!(to_u8(SafeU8::failure()).is_invalid());
        assert!(to_u16(SafeU8::failure()).is_invalid());
        assert!(to_u32(SafeU8::failure()).is_invalid());
        assert!(to_u64(SafeU8::failure()).is_invalid());
        assert!(to_umx(SafeU8::failure()).is_invalid());
        assert_panics!(to_idx(SafeU8::failure()));

        assert!(to_i8(SafeU8::magic_0()) == i8::magic_0());
        assert!(to_i16(SafeU8::magic_0()) == i16::magic_0());
        assert!(to_i32(SafeU8::magic_0()) == i32::magic_0());
        assert!(to_i64(SafeU8::magic_0()) == i64::magic_0());
        assert!(to_u8(SafeU8::magic_0()) == u8::magic_0());
        assert!(to_u16(SafeU8::magic_0()) == u16::magic_0());
        assert!(to_u32(SafeU8::magic_0()) == u32::magic_0());
        assert!(to_u64(SafeU8::magic_0()) == u64::magic_0());
        assert!(to_umx(SafeU8::magic_0()) == usize::magic_0());
        assert!(to_idx(SafeU8::magic_0()) == usize::magic_0());

        assert!(to_i8(SafeU8::magic_1()) == i8::magic_1());
        assert!(to_i16(SafeU8::magic_1()) == i16::magic_1());
        assert!(to_i32(SafeU8::magic_1()) == i32::magic_1());
        assert!(to_i64(SafeU8::magic_1()) == i64::magic_1());
        assert!(to_u8(SafeU8::magic_1()) == u8::magic_1());
        assert!(to_u16(SafeU8::magic_1()) == u16::magic_1());
        assert!(to_u32(SafeU8::magic_1()) == u32::magic_1());
        assert!(to_u64(SafeU8::magic_1()) == u64::magic_1());
        assert!(to_umx(SafeU8::magic_1()) == usize::magic_1());
        assert!(to_idx(SafeU8::magic_1()) == usize::magic_1());

        assert!(to_i8(SafeU8::max_value()).is_invalid());
        assert!(to_i16(SafeU8::max_value()) == (u8::max_value() as i16));
        assert!(to_i32(SafeU8::max_value()) == (u8::max_value() as i32));
        assert!(to_i64(SafeU8::max_value()) == (u8::max_value() as i64));
        assert!(to_u8(SafeU8::max_value()) == (u8::max_value() as u8));
        assert!(to_u16(SafeU8::max_value()) == (u8::max_value() as u16));
        assert!(to_u32(SafeU8::max_value()) == (u8::max_value() as u32));
        assert!(to_u64(SafeU8::max_value()) == (u8::max_value() as u64));
        assert!(to_umx(SafeU8::max_value()) == (u8::max_value() as usize));
        assert!(to_idx(SafeU8::max_value()) == (u8::max_value() as usize));

        assert!(to_i8(SafeU8::min_value()) == (u8::min_value() as i8));
        assert!(to_i16(SafeU8::min_value()) == (u8::min_value() as i16));
        assert!(to_i32(SafeU8::min_value()) == (u8::min_value() as i32));
        assert!(to_i64(SafeU8::min_value()) == (u8::min_value() as i64));
        assert!(to_u8(SafeU8::min_value()) == (u8::min_value() as u8));
        assert!(to_u16(SafeU8::min_value()) == (u8::min_value() as u16));
        assert!(to_u32(SafeU8::min_value()) == (u8::min_value() as u32));
        assert!(to_u64(SafeU8::min_value()) == (u8::min_value() as u64));
        assert!(to_umx(SafeU8::min_value()) == (u8::min_value() as usize));
        assert!(to_idx(SafeU8::min_value()) == (u8::min_value() as usize));
    }

    #[test]
    fn convert_from_raw_u8() {
        assert!(to_i8(u8::magic_0()) == i8::magic_0());
        assert!(to_i16(u8::magic_0()) == i16::magic_0());
        assert!(to_i32(u8::magic_0()) == i32::magic_0());
        assert!(to_i64(u8::magic_0()) == i64::magic_0());
        assert!(to_u8(u8::magic_0()) == u8::magic_0());
        assert!(to_u16(u8::magic_0()) == u16::magic_0());
        assert!(to_u32(u8::magic_0()) == u32::magic_0());
        assert!(to_u64(u8::magic_0()) == u64::magic_0());
        assert!(to_umx(u8::magic_0()) == usize::magic_0());
        assert!(to_idx(u8::magic_0()) == usize::magic_0());

        assert!(to_i8(u8::magic_1()) == i8::magic_1());
        assert!(to_i16(u8::magic_1()) == i16::magic_1());
        assert!(to_i32(u8::magic_1()) == i32::magic_1());
        assert!(to_i64(u8::magic_1()) == i64::magic_1());
        assert!(to_u8(u8::magic_1()) == u8::magic_1());
        assert!(to_u16(u8::magic_1()) == u16::magic_1());
        assert!(to_u32(u8::magic_1()) == u32::magic_1());
        assert!(to_u64(u8::magic_1()) == u64::magic_1());
        assert!(to_umx(u8::magic_1()) == usize::magic_1());
        assert!(to_idx(u8::magic_1()) == usize::magic_1());

        assert!(to_i8(u8::max_value()).is_invalid());
        assert!(to_i16(u8::max_value()) == (u8::max_value() as i16));
        assert!(to_i32(u8::max_value()) == (u8::max_value() as i32));
        assert!(to_i64(u8::max_value()) == (u8::max_value() as i64));
        assert!(to_u8(u8::max_value()) == (u8::max_value() as u8));
        assert!(to_u16(u8::max_value()) == (u8::max_value() as u16));
        assert!(to_u32(u8::max_value()) == (u8::max_value() as u32));
        assert!(to_u64(u8::max_value()) == (u8::max_value() as u64));
        assert!(to_umx(u8::max_value()) == (u8::max_value() as usize));
        assert!(to_idx(u8::max_value()) == (u8::max_value() as usize));

        assert!(to_i8(u8::min_value()) == (u8::min_value() as i8));
        assert!(to_i16(u8::min_value()) == (u8::min_value() as i16));
        assert!(to_i32(u8::min_value()) == (u8::min_value() as i32));
        assert!(to_i64(u8::min_value()) == (u8::min_value() as i64));
        assert!(to_u8(u8::min_value()) == (u8::min_value() as u8));
        assert!(to_u16(u8::min_value()) == (u8::min_value() as u16));
        assert!(to_u32(u8::min_value()) == (u8::min_value() as u32));
        assert!(to_u64(u8::min_value()) == (u8::min_value() as u64));
        assert!(to_umx(u8::min_value()) == (u8::min_value() as usize));
        assert!(to_idx(u8::min_value()) == (u8::min_value() as usize));
    }

    #[test]
    fn convert_from_sfe_u16() {
        assert!(to_i8(SafeU16::failure()).is_invalid());
        assert!(to_i16(SafeU16::failure()).is_invalid());
        assert!(to_i32(SafeU16::failure()).is_invalid());
        assert!(to_i64(SafeU16::failure()).is_invalid());
        assert!(to_u8(SafeU16::failure()).is_invalid());
        assert!(to_u16(SafeU16::failure()).is_invalid());
        assert!(to_u32(SafeU16::failure()).is_invalid());
        assert!(to_u64(SafeU16::failure()).is_invalid());
        assert!(to_umx(SafeU16::failure()).is_invalid());
        assert_panics!(to_idx(SafeU16::failure()));

        assert!(to_i8(SafeU16::magic_0()) == i8::magic_0());
        assert!(to_i16(SafeU16::magic_0()) == i16::magic_0());
        assert!(to_i32(SafeU16::magic_0()) == i32::magic_0());
        assert!(to_i64(SafeU16::magic_0()) == i64::magic_0());
        assert!(to_u8(SafeU16::magic_0()) == u8::magic_0());
        assert!(to_u16(SafeU16::magic_0()) == u16::magic_0());
        assert!(to_u32(SafeU16::magic_0()) == u32::magic_0());
        assert!(to_u64(SafeU16::magic_0()) == u64::magic_0());
        assert!(to_umx(SafeU16::magic_0()) == usize::magic_0());
        assert!(to_idx(SafeU16::magic_0()) == usize::magic_0());

        assert!(to_i8(SafeU16::magic_1()) == i8::magic_1());
        assert!(to_i16(SafeU16::magic_1()) == i16::magic_1());
        assert!(to_i32(SafeU16::magic_1()) == i32::magic_1());
        assert!(to_i64(SafeU16::magic_1()) == i64::magic_1());
        assert!(to_u8(SafeU16::magic_1()) == u8::magic_1());
        assert!(to_u16(SafeU16::magic_1()) == u16::magic_1());
        assert!(to_u32(SafeU16::magic_1()) == u32::magic_1());
        assert!(to_u64(SafeU16::magic_1()) == u64::magic_1());
        assert!(to_umx(SafeU16::magic_1()) == usize::magic_1());
        assert!(to_idx(SafeU16::magic_1()) == usize::magic_1());

        assert!(to_i8(SafeU16::max_value()).is_invalid());
        assert!(to_i16(SafeU16::max_value()).is_invalid());
        assert!(to_i32(SafeU16::max_value()) == (u16::max_value() as i32));
        assert!(to_i64(SafeU16::max_value()) == (u16::max_value() as i64));
        assert!(to_u8(SafeU16::max_value()).is_invalid());
        assert!(to_u16(SafeU16::max_value()) == (u16::max_value() as u16));
        assert!(to_u32(SafeU16::max_value()) == (u16::max_value() as u32));
        assert!(to_u64(SafeU16::max_value()) == (u16::max_value() as u64));
        assert!(to_umx(SafeU16::max_value()) == (u16::max_value() as usize));
        assert!(to_idx(SafeU16::max_value()) == (u16::max_value() as usize));

        assert!(to_i8(SafeU16::min_value()) == (u16::min_value() as i8));
        assert!(to_i16(SafeU16::min_value()) == (u16::min_value() as i16));
        assert!(to_i32(SafeU16::min_value()) == (u16::min_value() as i32));
        assert!(to_i64(SafeU16::min_value()) == (u16::min_value() as i64));
        assert!(to_u8(SafeU16::min_value()) == (u16::min_value() as u8));
        assert!(to_u16(SafeU16::min_value()) == (u16::min_value() as u16));
        assert!(to_u32(SafeU16::min_value()) == (u16::min_value() as u32));
        assert!(to_u64(SafeU16::min_value()) == (u16::min_value() as u64));
        assert!(to_umx(SafeU16::min_value()) == (u16::min_value() as usize));
        assert!(to_idx(SafeU16::min_value()) == (u16::min_value() as usize));
    }

    #[test]
    fn convert_from_raw_u16() {
        assert!(to_i8(u16::magic_0()) == i8::magic_0());
        assert!(to_i16(u16::magic_0()) == i16::magic_0());
        assert!(to_i32(u16::magic_0()) == i32::magic_0());
        assert!(to_i64(u16::magic_0()) == i64::magic_0());
        assert!(to_u8(u16::magic_0()) == u8::magic_0());
        assert!(to_u16(u16::magic_0()) == u16::magic_0());
        assert!(to_u32(u16::magic_0()) == u32::magic_0());
        assert!(to_u64(u16::magic_0()) == u64::magic_0());
        assert!(to_umx(u16::magic_0()) == usize::magic_0());
        assert!(to_idx(u16::magic_0()) == usize::magic_0());

        assert!(to_i8(u16::magic_1()) == i8::magic_1());
        assert!(to_i16(u16::magic_1()) == i16::magic_1());
        assert!(to_i32(u16::magic_1()) == i32::magic_1());
        assert!(to_i64(u16::magic_1()) == i64::magic_1());
        assert!(to_u8(u16::magic_1()) == u8::magic_1());
        assert!(to_u16(u16::magic_1()) == u16::magic_1());
        assert!(to_u32(u16::magic_1()) == u32::magic_1());
        assert!(to_u64(u16::magic_1()) == u64::magic_1());
        assert!(to_umx(u16::magic_1()) == usize::magic_1());
        assert!(to_idx(u16::magic_1()) == usize::magic_1());

        assert!(to_i8(u16::max_value()).is_invalid());
        assert!(to_i16(u16::max_value()).is_invalid());
        assert!(to_i32(u16::max_value()) == (u16::max_value() as i32));
        assert!(to_i64(u16::max_value()) == (u16::max_value() as i64));
        assert!(to_u8(u16::max_value()).is_invalid());
        assert!(to_u16(u16::max_value()) == (u16::max_value() as u16));
        assert!(to_u32(u16::max_value()) == (u16::max_value() as u32));
        assert!(to_u64(u16::max_value()) == (u16::max_value() as u64));
        assert!(to_umx(u16::max_value()) == (u16::max_value() as usize));
        assert!(to_idx(u16::max_value()) == (u16::max_value() as usize));

        assert!(to_i8(u16::min_value()) == (u16::min_value() as i8));
        assert!(to_i16(u16::min_value()) == (u16::min_value() as i16));
        assert!(to_i32(u16::min_value()) == (u16::min_value() as i32));
        assert!(to_i64(u16::min_value()) == (u16::min_value() as i64));
        assert!(to_u8(u16::min_value()) == (u16::min_value() as u8));
        assert!(to_u16(u16::min_value()) == (u16::min_value() as u16));
        assert!(to_u32(u16::min_value()) == (u16::min_value() as u32));
        assert!(to_u64(u16::min_value()) == (u16::min_value() as u64));
        assert!(to_umx(u16::min_value()) == (u16::min_value() as usize));
        assert!(to_idx(u16::min_value()) == (u16::min_value() as usize));
    }

    #[test]
    fn convert_from_sfe_u32() {
        assert!(to_i8(SafeU32::failure()).is_invalid());
        assert!(to_i16(SafeU32::failure()).is_invalid());
        assert!(to_i32(SafeU32::failure()).is_invalid());
        assert!(to_i64(SafeU32::failure()).is_invalid());
        assert!(to_u8(SafeU32::failure()).is_invalid());
        assert!(to_u16(SafeU32::failure()).is_invalid());
        assert!(to_u32(SafeU32::failure()).is_invalid());
        assert!(to_u64(SafeU32::failure()).is_invalid());
        assert!(to_umx(SafeU32::failure()).is_invalid());
        assert_panics!(to_idx(SafeU32::failure()));

        assert!(to_i8(SafeU32::magic_0()) == i8::magic_0());
        assert!(to_i16(SafeU32::magic_0()) == i16::magic_0());
        assert!(to_i32(SafeU32::magic_0()) == i32::magic_0());
        assert!(to_i64(SafeU32::magic_0()) == i64::magic_0());
        assert!(to_u8(SafeU32::magic_0()) == u8::magic_0());
        assert!(to_u16(SafeU32::magic_0()) == u16::magic_0());
        assert!(to_u32(SafeU32::magic_0()) == u32::magic_0());
        assert!(to_u64(SafeU32::magic_0()) == u64::magic_0());
        assert!(to_umx(SafeU32::magic_0()) == usize::magic_0());
        assert!(to_idx(SafeU32::magic_0()) == usize::magic_0());

        assert!(to_i8(SafeU32::magic_1()) == i8::magic_1());
        assert!(to_i16(SafeU32::magic_1()) == i16::magic_1());
        assert!(to_i32(SafeU32::magic_1()) == i32::magic_1());
        assert!(to_i64(SafeU32::magic_1()) == i64::magic_1());
        assert!(to_u8(SafeU32::magic_1()) == u8::magic_1());
        assert!(to_u16(SafeU32::magic_1()) == u16::magic_1());
        assert!(to_u32(SafeU32::magic_1()) == u32::magic_1());
        assert!(to_u64(SafeU32::magic_1()) == u64::magic_1());
        assert!(to_umx(SafeU32::magic_1()) == usize::magic_1());
        assert!(to_idx(SafeU32::magic_1()) == usize::magic_1());

        assert!(to_i8(SafeU32::max_value()).is_invalid());
        assert!(to_i16(SafeU32::max_value()).is_invalid());
        assert!(to_i32(SafeU32::max_value()).is_invalid());
        assert!(to_i64(SafeU32::max_value()) == (u32::max_value() as i64));
        assert!(to_u8(SafeU32::max_value()).is_invalid());
        assert!(to_u16(SafeU32::max_value()).is_invalid());
        assert!(to_u32(SafeU32::max_value()) == (u32::max_value() as u32));
        assert!(to_u64(SafeU32::max_value()) == (u32::max_value() as u64));
        assert!(to_umx(SafeU32::max_value()) == (u32::max_value() as usize));
        assert!(to_idx(SafeU32::max_value()) == (u32::max_value() as usize));

        assert!(to_i8(SafeU32::min_value()) == (u32::min_value() as i8));
        assert!(to_i16(SafeU32::min_value()) == (u32::min_value() as i16));
        assert!(to_i32(SafeU32::min_value()) == (u32::min_value() as i32));
        assert!(to_i64(SafeU32::min_value()) == (u32::min_value() as i64));
        assert!(to_u8(SafeU32::min_value()) == (u32::min_value() as u8));
        assert!(to_u16(SafeU32::min_value()) == (u32::min_value() as u16));
        assert!(to_u32(SafeU32::min_value()) == (u32::min_value() as u32));
        assert!(to_u64(SafeU32::min_value()) == (u32::min_value() as u64));
        assert!(to_umx(SafeU32::min_value()) == (u32::min_value() as usize));
        assert!(to_idx(SafeU32::min_value()) == (u32::min_value() as usize));
    }

    #[test]
    fn convert_from_raw_u32() {
        assert!(to_i8(u32::magic_0()) == i8::magic_0());
        assert!(to_i16(u32::magic_0()) == i16::magic_0());
        assert!(to_i32(u32::magic_0()) == i32::magic_0());
        assert!(to_i64(u32::magic_0()) == i64::magic_0());
        assert!(to_u8(u32::magic_0()) == u8::magic_0());
        assert!(to_u16(u32::magic_0()) == u16::magic_0());
        assert!(to_u32(u32::magic_0()) == u32::magic_0());
        assert!(to_u64(u32::magic_0()) == u64::magic_0());
        assert!(to_umx(u32::magic_0()) == usize::magic_0());
        assert!(to_idx(u32::magic_0()) == usize::magic_0());

        assert!(to_i8(u32::magic_1()) == i8::magic_1());
        assert!(to_i16(u32::magic_1()) == i16::magic_1());
        assert!(to_i32(u32::magic_1()) == i32::magic_1());
        assert!(to_i64(u32::magic_1()) == i64::magic_1());
        assert!(to_u8(u32::magic_1()) == u8::magic_1());
        assert!(to_u16(u32::magic_1()) == u16::magic_1());
        assert!(to_u32(u32::magic_1()) == u32::magic_1());
        assert!(to_u64(u32::magic_1()) == u64::magic_1());
        assert!(to_umx(u32::magic_1()) == usize::magic_1());
        assert!(to_idx(u32::magic_1()) == usize::magic_1());

        assert!(to_i8(u32::max_value()).is_invalid());
        assert!(to_i16(u32::max_value()).is_invalid());
        assert!(to_i32(u32::max_value()).is_invalid());
        assert!(to_i64(u32::max_value()) == (u32::max_value() as i64));
        assert!(to_u8(u32::max_value()).is_invalid());
        assert!(to_u16(u32::max_value()).is_invalid());
        assert!(to_u32(u32::max_value()) == (u32::max_value() as u32));
        assert!(to_u64(u32::max_value()) == (u32::max_value() as u64));
        assert!(to_umx(u32::max_value()) == (u32::max_value() as usize));
        assert!(to_idx(u32::max_value()) == (u32::max_value() as usize));

        assert!(to_i8(u32::min_value()) == (u32::min_value() as i8));
        assert!(to_i16(u32::min_value()) == (u32::min_value() as i16));
        assert!(to_i32(u32::min_value()) == (u32::min_value() as i32));
        assert!(to_i64(u32::min_value()) == (u32::min_value() as i64));
        assert!(to_u8(u32::min_value()) == (u32::min_value() as u8));
        assert!(to_u16(u32::min_value()) == (u32::min_value() as u16));
        assert!(to_u32(u32::min_value()) == (u32::min_value() as u32));
        assert!(to_u64(u32::min_value()) == (u32::min_value() as u64));
        assert!(to_umx(u32::min_value()) == (u32::min_value() as usize));
        assert!(to_idx(u32::min_value()) == (u32::min_value() as usize));
    }

    #[test]
    fn convert_from_sfe_u64() {
        assert!(to_i8(SafeU64::failure()).is_invalid());
        assert!(to_i16(SafeU64::failure()).is_invalid());
        assert!(to_i32(SafeU64::failure()).is_invalid());
        assert!(to_i64(SafeU64::failure()).is_invalid());
        assert!(to_u8(SafeU64::failure()).is_invalid());
        assert!(to_u16(SafeU64::failure()).is_invalid());
        assert!(to_u32(SafeU64::failure()).is_invalid());
        assert!(to_u64(SafeU64::failure()).is_invalid());
        assert!(to_umx(SafeU64::failure()).is_invalid());
        assert_panics!(to_idx(SafeU64::failure()));

        assert!(to_i8(SafeU64::magic_0()) == i8::magic_0());
        assert!(to_i16(SafeU64::magic_0()) == i16::magic_0());
        assert!(to_i32(SafeU64::magic_0()) == i32::magic_0());
        assert!(to_i64(SafeU64::magic_0()) == i64::magic_0());
        assert!(to_u8(SafeU64::magic_0()) == u8::magic_0());
        assert!(to_u16(SafeU64::magic_0()) == u16::magic_0());
        assert!(to_u32(SafeU64::magic_0()) == u32::magic_0());
        assert!(to_u64(SafeU64::magic_0()) == u64::magic_0());
        assert!(to_umx(SafeU64::magic_0()) == usize::magic_0());
        assert!(to_idx(SafeU64::magic_0()) == usize::magic_0());

        assert!(to_i8(SafeU64::magic_1()) == i8::magic_1());
        assert!(to_i16(SafeU64::magic_1()) == i16::magic_1());
        assert!(to_i32(SafeU64::magic_1()) == i32::magic_1());
        assert!(to_i64(SafeU64::magic_1()) == i64::magic_1());
        assert!(to_u8(SafeU64::magic_1()) == u8::magic_1());
        assert!(to_u16(SafeU64::magic_1()) == u16::magic_1());
        assert!(to_u32(SafeU64::magic_1()) == u32::magic_1());
        assert!(to_u64(SafeU64::magic_1()) == u64::magic_1());
        assert!(to_umx(SafeU64::magic_1()) == usize::magic_1());
        assert!(to_idx(SafeU64::magic_1()) == usize::magic_1());

        assert!(to_i8(SafeU64::max_value()).is_invalid());
        assert!(to_i16(SafeU64::max_value()).is_invalid());
        assert!(to_i32(SafeU64::max_value()).is_invalid());
        assert!(to_i64(SafeU64::max_value()).is_invalid());
        assert!(to_u8(SafeU64::max_value()).is_invalid());
        assert!(to_u16(SafeU64::max_value()).is_invalid());
        assert!(to_u32(SafeU64::max_value()).is_invalid());
        assert!(to_u64(SafeU64::max_value()) == (u64::max_value() as u64));
        assert!(to_umx(SafeU64::max_value()) == (u64::max_value() as usize));
        assert!(to_idx(SafeU64::max_value()) == (u64::max_value() as usize));

        assert!(to_i8(SafeU64::min_value()) == (u64::min_value() as i8));
        assert!(to_i16(SafeU64::min_value()) == (u64::min_value() as i16));
        assert!(to_i32(SafeU64::min_value()) == (u64::min_value() as i32));
        assert!(to_i64(SafeU64::min_value()) == (u64::min_value() as i64));
        assert!(to_u8(SafeU64::min_value()) == (u64::min_value() as u8));
        assert!(to_u16(SafeU64::min_value()) == (u64::min_value() as u16));
        assert!(to_u32(SafeU64::min_value()) == (u64::min_value() as u32));
        assert!(to_u64(SafeU64::min_value()) == (u64::min_value() as u64));
        assert!(to_umx(SafeU64::min_value()) == (u64::min_value() as usize));
        assert!(to_idx(SafeU64::min_value()) == (u64::min_value() as usize));
    }

    #[test]
    fn convert_from_raw_u64() {
        assert!(to_i8(u64::magic_0()) == i8::magic_0());
        assert!(to_i16(u64::magic_0()) == i16::magic_0());
        assert!(to_i32(u64::magic_0()) == i32::magic_0());
        assert!(to_i64(u64::magic_0()) == i64::magic_0());
        assert!(to_u8(u64::magic_0()) == u8::magic_0());
        assert!(to_u16(u64::magic_0()) == u16::magic_0());
        assert!(to_u32(u64::magic_0()) == u32::magic_0());
        assert!(to_u64(u64::magic_0()) == u64::magic_0());
        assert!(to_umx(u64::magic_0()) == usize::magic_0());
        assert!(to_idx(u64::magic_0()) == usize::magic_0());

        assert!(to_i8(u64::magic_1()) == i8::magic_1());
        assert!(to_i16(u64::magic_1()) == i16::magic_1());
        assert!(to_i32(u64::magic_1()) == i32::magic_1());
        assert!(to_i64(u64::magic_1()) == i64::magic_1());
        assert!(to_u8(u64::magic_1()) == u8::magic_1());
        assert!(to_u16(u64::magic_1()) == u16::magic_1());
        assert!(to_u32(u64::magic_1()) == u32::magic_1());
        assert!(to_u64(u64::magic_1()) == u64::magic_1());
        assert!(to_umx(u64::magic_1()) == usize::magic_1());
        assert!(to_idx(u64::magic_1()) == usize::magic_1());

        assert!(to_i8(u64::max_value()).is_invalid());
        assert!(to_i16(u64::max_value()).is_invalid());
        assert!(to_i32(u64::max_value()).is_invalid());
        assert!(to_i64(u64::max_value()).is_invalid());
        assert!(to_u8(u64::max_value()).is_invalid());
        assert!(to_u16(u64::max_value()).is_invalid());
        assert!(to_u32(u64::max_value()).is_invalid());
        assert!(to_u64(u64::max_value()) == (u64::max_value() as u64));
        assert!(to_umx(u64::max_value()) == (u64::max_value() as usize));
        assert!(to_idx(u64::max_value()) == (u64::max_value() as usize));

        assert!(to_i8(u64::min_value()) == (u64::min_value() as i8));
        assert!(to_i16(u64::min_value()) == (u64::min_value() as i16));
        assert!(to_i32(u64::min_value()) == (u64::min_value() as i32));
        assert!(to_i64(u64::min_value()) == (u64::min_value() as i64));
        assert!(to_u8(u64::min_value()) == (u64::min_value() as u8));
        assert!(to_u16(u64::min_value()) == (u64::min_value() as u16));
        assert!(to_u32(u64::min_value()) == (u64::min_value() as u32));
        assert!(to_u64(u64::min_value()) == (u64::min_value() as u64));
        assert!(to_umx(u64::min_value()) == (u64::min_value() as usize));
        assert!(to_idx(u64::min_value()) == (u64::min_value() as usize));
    }

    #[test]
    fn convert_from_sfe_umx() {
        assert!(to_i8(SafeUMx::failure()).is_invalid());
        assert!(to_i16(SafeUMx::failure()).is_invalid());
        assert!(to_i32(SafeUMx::failure()).is_invalid());
        assert!(to_i64(SafeUMx::failure()).is_invalid());
        assert!(to_u8(SafeUMx::failure()).is_invalid());
        assert!(to_u16(SafeUMx::failure()).is_invalid());
        assert!(to_u32(SafeUMx::failure()).is_invalid());
        assert!(to_u64(SafeUMx::failure()).is_invalid());
        assert!(to_umx(SafeUMx::failure()).is_invalid());
        assert_panics!(to_idx(SafeUMx::failure()));

        assert!(to_i8(SafeUMx::magic_0()) == i8::magic_0());
        assert!(to_i16(SafeUMx::magic_0()) == i16::magic_0());
        assert!(to_i32(SafeUMx::magic_0()) == i32::magic_0());
        assert!(to_i64(SafeUMx::magic_0()) == i64::magic_0());
        assert!(to_u8(SafeUMx::magic_0()) == u8::magic_0());
        assert!(to_u16(SafeUMx::magic_0()) == u16::magic_0());
        assert!(to_u32(SafeUMx::magic_0()) == u32::magic_0());
        assert!(to_u64(SafeUMx::magic_0()) == u64::magic_0());
        assert!(to_umx(SafeUMx::magic_0()) == usize::magic_0());
        assert!(to_idx(SafeUMx::magic_0()) == usize::magic_0());

        assert!(to_i8(SafeUMx::magic_1()) == i8::magic_1());
        assert!(to_i16(SafeUMx::magic_1()) == i16::magic_1());
        assert!(to_i32(SafeUMx::magic_1()) == i32::magic_1());
        assert!(to_i64(SafeUMx::magic_1()) == i64::magic_1());
        assert!(to_u8(SafeUMx::magic_1()) == u8::magic_1());
        assert!(to_u16(SafeUMx::magic_1()) == u16::magic_1());
        assert!(to_u32(SafeUMx::magic_1()) == u32::magic_1());
        assert!(to_u64(SafeUMx::magic_1()) == u64::magic_1());
        assert!(to_umx(SafeUMx::magic_1()) == usize::magic_1());
        assert!(to_idx(SafeUMx::magic_1()) == usize::magic_1());

        assert!(to_i8(SafeUMx::max_value()).is_invalid());
        assert!(to_i16(SafeUMx::max_value()).is_invalid());
        assert!(to_i32(SafeUMx::max_value()).is_invalid());
        assert!(to_i64(SafeUMx::max_value()).is_invalid());
        assert!(to_u8(SafeUMx::max_value()).is_invalid());
        assert!(to_u16(SafeUMx::max_value()).is_invalid());
        assert!(to_u32(SafeUMx::max_value()).is_invalid());
        assert!(to_u64(SafeUMx::max_value()) == (usize::max_value() as u64));
        assert!(to_umx(SafeUMx::max_value()) == (usize::max_value() as usize));
        assert!(to_idx(SafeUMx::max_value()) == (usize::max_value() as usize));

        assert!(to_i8(SafeUMx::min_value()) == (usize::min_value() as i8));
        assert!(to_i16(SafeUMx::min_value()) == (usize::min_value() as i16));
        assert!(to_i32(SafeUMx::min_value()) == (usize::min_value() as i32));
        assert!(to_i64(SafeUMx::min_value()) == (usize::min_value() as i64));
        assert!(to_u8(SafeUMx::min_value()) == (usize::min_value() as u8));
        assert!(to_u16(SafeUMx::min_value()) == (usize::min_value() as u16));
        assert!(to_u32(SafeUMx::min_value()) == (usize::min_value() as u32));
        assert!(to_u64(SafeUMx::min_value()) == (usize::min_value() as u64));
        assert!(to_umx(SafeUMx::min_value()) == (usize::min_value() as usize));
        assert!(to_idx(SafeUMx::min_value()) == (usize::min_value() as usize));
    }

    #[test]
    fn convert_from_raw_usize() {
        assert!(to_i8(usize::magic_0()) == i8::magic_0());
        assert!(to_i16(usize::magic_0()) == i16::magic_0());
        assert!(to_i32(usize::magic_0()) == i32::magic_0());
        assert!(to_i64(usize::magic_0()) == i64::magic_0());
        assert!(to_u8(usize::magic_0()) == u8::magic_0());
        assert!(to_u16(usize::magic_0()) == u16::magic_0());
        assert!(to_u32(usize::magic_0()) == u32::magic_0());
        assert!(to_u64(usize::magic_0()) == u64::magic_0());
        assert!(to_umx(usize::magic_0()) == usize::magic_0());
        assert!(to_idx(usize::magic_0()) == usize::magic_0());

        assert!(to_i8(usize::magic_1()) == i8::magic_1());
        assert!(to_i16(usize::magic_1()) == i16::magic_1());
        assert!(to_i32(usize::magic_1()) == i32::magic_1());
        assert!(to_i64(usize::magic_1()) == i64::magic_1());
        assert!(to_u8(usize::magic_1()) == u8::magic_1());
        assert!(to_u16(usize::magic_1()) == u16::magic_1());
        assert!(to_u32(usize::magic_1()) == u32::magic_1());
        assert!(to_u64(usize::magic_1()) == u64::magic_1());
        assert!(to_umx(usize::magic_1()) == usize::magic_1());
        assert!(to_idx(usize::magic_1()) == usize::magic_1());

        assert!(to_i8(usize::max_value()).is_invalid());
        assert!(to_i16(usize::max_value()).is_invalid());
        assert!(to_i32(usize::max_value()).is_invalid());
        assert!(to_i64(usize::max_value()).is_invalid());
        assert!(to_u8(usize::max_value()).is_invalid());
        assert!(to_u16(usize::max_value()).is_invalid());
        assert!(to_u32(usize::max_value()).is_invalid());
        assert!(to_u64(usize::max_value()) == (usize::max_value() as u64));
        assert!(to_umx(usize::max_value()) == (usize::max_value() as usize));
        assert!(to_idx(usize::max_value()) == (usize::max_value() as usize));

        assert!(to_i8(usize::min_value()) == (usize::min_value() as i8));
        assert!(to_i16(usize::min_value()) == (usize::min_value() as i16));
        assert!(to_i32(usize::min_value()) == (usize::min_value() as i32));
        assert!(to_i64(usize::min_value()) == (usize::min_value() as i64));
        assert!(to_u8(usize::min_value()) == (usize::min_value() as u8));
        assert!(to_u16(usize::min_value()) == (usize::min_value() as u16));
        assert!(to_u32(usize::min_value()) == (usize::min_value() as u32));
        assert!(to_u64(usize::min_value()) == (usize::min_value() as u64));
        assert!(to_umx(usize::min_value()) == (usize::min_value() as usize));
        assert!(to_idx(usize::min_value()) == (usize::min_value() as usize));
    }

    #[test]
    fn convert_from_sfe_idx() {
        assert!(to_i8(SafeIdx::magic_0()) == i8::magic_0());
        assert!(to_i16(SafeIdx::magic_0()) == i16::magic_0());
        assert!(to_i32(SafeIdx::magic_0()) == i32::magic_0());
        assert!(to_i64(SafeIdx::magic_0()) == i64::magic_0());
        assert!(to_u8(SafeIdx::magic_0()) == u8::magic_0());
        assert!(to_u16(SafeIdx::magic_0()) == u16::magic_0());
        assert!(to_u32(SafeIdx::magic_0()) == u32::magic_0());
        assert!(to_u64(SafeIdx::magic_0()) == u64::magic_0());
        assert!(to_umx(SafeIdx::magic_0()) == usize::magic_0());
        assert!(to_idx(SafeIdx::magic_0()) == usize::magic_0());

        assert!(to_i8(SafeIdx::magic_1()) == i8::magic_1());
        assert!(to_i16(SafeIdx::magic_1()) == i16::magic_1());
        assert!(to_i32(SafeIdx::magic_1()) == i32::magic_1());
        assert!(to_i64(SafeIdx::magic_1()) == i64::magic_1());
        assert!(to_u8(SafeIdx::magic_1()) == u8::magic_1());
        assert!(to_u16(SafeIdx::magic_1()) == u16::magic_1());
        assert!(to_u32(SafeIdx::magic_1()) == u32::magic_1());
        assert!(to_u64(SafeIdx::magic_1()) == u64::magic_1());
        assert!(to_umx(SafeIdx::magic_1()) == usize::magic_1());
        assert!(to_idx(SafeIdx::magic_1()) == usize::magic_1());

        assert!(to_i8(SafeIdx::max_value()).is_invalid());
        assert!(to_i16(SafeIdx::max_value()).is_invalid());
        assert!(to_i32(SafeIdx::max_value()).is_invalid());
        assert!(to_i64(SafeIdx::max_value()).is_invalid());
        assert!(to_u8(SafeIdx::max_value()).is_invalid());
        assert!(to_u16(SafeIdx::max_value()).is_invalid());
        assert!(to_u32(SafeIdx::max_value()).is_invalid());
        assert!(to_u64(SafeIdx::max_value()) == (usize::max_value() as u64));
        assert!(to_umx(SafeIdx::max_value()) == (usize::max_value() as usize));
        assert!(to_idx(SafeIdx::max_value()) == (usize::max_value() as usize));

        assert!(to_i8(SafeIdx::min_value()) == (usize::min_value() as i8));
        assert!(to_i16(SafeIdx::min_value()) == (usize::min_value() as i16));
        assert!(to_i32(SafeIdx::min_value()) == (usize::min_value() as i32));
        assert!(to_i64(SafeIdx::min_value()) == (usize::min_value() as i64));
        assert!(to_u8(SafeIdx::min_value()) == (usize::min_value() as u8));
        assert!(to_u16(SafeIdx::min_value()) == (usize::min_value() as u16));
        assert!(to_u32(SafeIdx::min_value()) == (usize::min_value() as u32));
        assert!(to_u64(SafeIdx::min_value()) == (usize::min_value() as u64));
        assert!(to_umx(SafeIdx::min_value()) == (usize::min_value() as usize));
        assert!(to_idx(SafeIdx::min_value()) == (usize::min_value() as usize));
    }

    #[test]
    fn convert_to_idx_from_poisoned() {
        let mut idx = SafeIdx::max_value();
        idx = idx + 1;
        assert_panics!(to_idx(idx));

        assert_panics!(to_idx(SafeI8::failure()));
        assert_panics!(to_idx(SafeI16::failure()));
        assert_panics!(to_idx(SafeI32::failure()));
        assert_panics!(to_idx(SafeI64::failure()));
        assert_panics!(to_idx(SafeU8::failure()));
        assert_panics!(to_idx(SafeU16::failure()));
        assert_panics!(to_idx(SafeU32::failure()));
        assert_panics!(to_idx(SafeU64::failure()));
        assert_panics!(to_idx(SafeUMx::failure()));
    }

    #[test]
    fn convert_from_sfe_u8_to_unsafe() {
        assert!(to_u8_unsafe(SafeU8::max_value()) == (u8::max_value() as u8));
        assert!(to_u16_unsafe(SafeU8::max_value()) == (u8::max_value() as u16));
        assert!(to_u32_unsafe(SafeU8::max_value()) == (u8::max_value() as u32));
        assert!(to_u64_unsafe(SafeU8::max_value()) == (u8::max_value() as u64));
        assert!(to_umx_unsafe(SafeU8::max_value()) == (u8::max_value() as usize));

        assert!(to_u8_unsafe(SafeU8::min_value()) == (u8::min_value() as u8));
        assert!(to_u16_unsafe(SafeU8::min_value()) == (u8::min_value() as u16));
        assert!(to_u32_unsafe(SafeU8::min_value()) == (u8::min_value() as u32));
        assert!(to_u64_unsafe(SafeU8::min_value()) == (u8::min_value() as u64));
        assert!(to_umx_unsafe(SafeU8::min_value()) == (u8::min_value() as usize));
    }

    #[test]
    fn convert_from_raw_u8_to_unsafe() {
        assert!(to_u8_unsafe(u8::max_value()) == (u8::max_value() as u8));
        assert!(to_u16_unsafe(u8::max_value()) == (u8::max_value() as u16));
        assert!(to_u32_unsafe(u8::max_value()) == (u8::max_value() as u32));
        assert!(to_u64_unsafe(u8::max_value()) == (u8::max_value() as u64));
        assert!(to_umx_unsafe(u8::max_value()) == (u8::max_value() as usize));

        assert!(to_u8_unsafe(u8::min_value()) == (u8::min_value() as u8));
        assert!(to_u16_unsafe(u8::min_value()) == (u8::min_value() as u16));
        assert!(to_u32_unsafe(u8::min_value()) == (u8::min_value() as u32));
        assert!(to_u64_unsafe(u8::min_value()) == (u8::min_value() as u64));
        assert!(to_umx_unsafe(u8::min_value()) == (u8::min_value() as usize));
    }

    #[test]
    fn convert_from_sfe_u16_to_unsafe() {
        assert!(to_u8_unsafe(SafeU16::max_value()) == (u16::max_value() as u8));
        assert!(to_u16_unsafe(SafeU16::max_value()) == (u16::max_value() as u16));
        assert!(to_u32_unsafe(SafeU16::max_value()) == (u16::max_value() as u32));
        assert!(to_u64_unsafe(SafeU16::max_value()) == (u16::max_value() as u64));
        assert!(to_umx_unsafe(SafeU16::max_value()) == (u16::max_value() as usize));

        assert!(to_u8_unsafe(SafeU16::min_value()) == (u16::min_value() as u8));
        assert!(to_u16_unsafe(SafeU16::min_value()) == (u16::min_value() as u16));
        assert!(to_u32_unsafe(SafeU16::min_value()) == (u16::min_value() as u32));
        assert!(to_u64_unsafe(SafeU16::min_value()) == (u16::min_value() as u64));
        assert!(to_umx_unsafe(SafeU16::min_value()) == (u16::min_value() as usize));
    }

    #[test]
    fn convert_from_raw_u16_to_unsafe() {
        assert!(to_u8_unsafe(u16::max_value()) == (u16::max_value() as u8));
        assert!(to_u16_unsafe(u16::max_value()) == (u16::max_value() as u16));
        assert!(to_u32_unsafe(u16::max_value()) == (u16::max_value() as u32));
        assert!(to_u64_unsafe(u16::max_value()) == (u16::max_value() as u64));
        assert!(to_umx_unsafe(u16::max_value()) == (u16::max_value() as usize));

        assert!(to_u8_unsafe(u16::min_value()) == (u16::min_value() as u8));
        assert!(to_u16_unsafe(u16::min_value()) == (u16::min_value() as u16));
        assert!(to_u32_unsafe(u16::min_value()) == (u16::min_value() as u32));
        assert!(to_u64_unsafe(u16::min_value()) == (u16::min_value() as u64));
        assert!(to_umx_unsafe(u16::min_value()) == (u16::min_value() as usize));
    }

    #[test]
    fn convert_from_sfe_u32_to_unsafe() {
        assert!(to_u8_unsafe(SafeU32::max_value()) == (u32::max_value() as u8));
        assert!(to_u16_unsafe(SafeU32::max_value()) == (u32::max_value() as u16));
        assert!(to_u32_unsafe(SafeU32::max_value()) == (u32::max_value() as u32));
        assert!(to_u64_unsafe(SafeU32::max_value()) == (u32::max_value() as u64));
        assert!(to_umx_unsafe(SafeU32::max_value()) == (u32::max_value() as usize));

        assert!(to_u8_unsafe(SafeU32::min_value()) == (u32::min_value() as u8));
        assert!(to_u16_unsafe(SafeU32::min_value()) == (u32::min_value() as u16));
        assert!(to_u32_unsafe(SafeU32::min_value()) == (u32::min_value() as u32));
        assert!(to_u64_unsafe(SafeU32::min_value()) == (u32::min_value() as u64));
        assert!(to_umx_unsafe(SafeU32::min_value()) == (u32::min_value() as usize));
    }

    #[test]
    fn convert_from_raw_u32_to_unsafe() {
        assert!(to_u8_unsafe(u32::max_value()) == (u32::max_value() as u8));
        assert!(to_u16_unsafe(u32::max_value()) == (u32::max_value() as u16));
        assert!(to_u32_unsafe(u32::max_value()) == (u32::max_value() as u32));
        assert!(to_u64_unsafe(u32::max_value()) == (u32::max_value() as u64));
        assert!(to_umx_unsafe(u32::max_value()) == (u32::max_value() as usize));

        assert!(to_u8_unsafe(u32::min_value()) == (u32::min_value() as u8));
        assert!(to_u16_unsafe(u32::min_value()) == (u32::min_value() as u16));
        assert!(to_u32_unsafe(u32::min_value()) == (u32::min_value() as u32));
        assert!(to_u64_unsafe(u32::min_value()) == (u32::min_value() as u64));
        assert!(to_umx_unsafe(u32::min_value()) == (u32::min_value() as usize));
    }

    #[test]
    fn convert_from_sfe_u64_to_unsafe() {
        assert!(to_u8_unsafe(SafeU64::max_value()) == (u64::max_value() as u8));
        assert!(to_u16_unsafe(SafeU64::max_value()) == (u64::max_value() as u16));
        assert!(to_u32_unsafe(SafeU64::max_value()) == (u64::max_value() as u32));
        assert!(to_u64_unsafe(SafeU64::max_value()) == (u64::max_value() as u64));
        assert!(to_umx_unsafe(SafeU64::max_value()) == (u64::max_value() as usize));

        assert!(to_u8_unsafe(SafeU64::min_value()) == (u64::min_value() as u8));
        assert!(to_u16_unsafe(SafeU64::min_value()) == (u64::min_value() as u16));
        assert!(to_u32_unsafe(SafeU64::min_value()) == (u64::min_value() as u32));
        assert!(to_u64_unsafe(SafeU64::min_value()) == (u64::min_value() as u64));
        assert!(to_umx_unsafe(SafeU64::min_value()) == (u64::min_value() as usize));
    }

    #[test]
    fn convert_from_raw_u64_to_unsafe() {
        assert!(to_u8_unsafe(u64::max_value()) == (u64::max_value() as u8));
        assert!(to_u16_unsafe(u64::max_value()) == (u64::max_value() as u16));
        assert!(to_u32_unsafe(u64::max_value()) == (u64::max_value() as u32));
        assert!(to_u64_unsafe(u64::max_value()) == (u64::max_value() as u64));
        assert!(to_umx_unsafe(u64::max_value()) == (u64::max_value() as usize));

        assert!(to_u8_unsafe(u64::min_value()) == (u64::min_value() as u8));
        assert!(to_u16_unsafe(u64::min_value()) == (u64::min_value() as u16));
        assert!(to_u32_unsafe(u64::min_value()) == (u64::min_value() as u32));
        assert!(to_u64_unsafe(u64::min_value()) == (u64::min_value() as u64));
        assert!(to_umx_unsafe(u64::min_value()) == (u64::min_value() as usize));
    }

    #[test]
    fn convert_from_sfe_umx_to_unsafe() {
        assert!(to_u8_unsafe(SafeUMx::max_value()) == (usize::max_value() as u8));
        assert!(to_u16_unsafe(SafeUMx::max_value()) == (usize::max_value() as u16));
        assert!(to_u32_unsafe(SafeUMx::max_value()) == (usize::max_value() as u32));
        assert!(to_u64_unsafe(SafeUMx::max_value()) == (usize::max_value() as u64));
        assert!(to_umx_unsafe(SafeUMx::max_value()) == (usize::max_value() as usize));

        assert!(to_u8_unsafe(SafeUMx::min_value()) == (usize::min_value() as u8));
        assert!(to_u16_unsafe(SafeUMx::min_value()) == (usize::min_value() as u16));
        assert!(to_u32_unsafe(SafeUMx::min_value()) == (usize::min_value() as u32));
        assert!(to_u64_unsafe(SafeUMx::min_value()) == (usize::min_value() as u64));
        assert!(to_umx_unsafe(SafeUMx::min_value()) == (usize::min_value() as usize));
    }

    #[test]
    fn convert_from_raw_umx_to_unsafe() {
        assert!(to_u8_unsafe(usize::max_value()) == (usize::max_value() as u8));
        assert!(to_u16_unsafe(usize::max_value()) == (usize::max_value() as u16));
        assert!(to_u32_unsafe(usize::max_value()) == (usize::max_value() as u32));
        assert!(to_u64_unsafe(usize::max_value()) == (usize::max_value() as u64));
        assert!(to_umx_unsafe(usize::max_value()) == (usize::max_value() as usize));

        assert!(to_u8_unsafe(usize::min_value()) == (usize::min_value() as u8));
        assert!(to_u16_unsafe(usize::min_value()) == (usize::min_value() as u16));
        assert!(to_u32_unsafe(usize::min_value()) == (usize::min_value() as u32));
        assert!(to_u64_unsafe(usize::min_value()) == (usize::min_value() as u64));
        assert!(to_umx_unsafe(usize::min_value()) == (usize::min_value() as usize));
    }

    #[test]
    fn convert_merge_umx_t() {
        let uppermx = to_umx(0x1234567890ABCDEF as usize);
        let lower08 = 0xFF as u8;
        let lower16 = 0xFFFF as u16;
        let lower32 = 0xFFFFFFFF as u32;
        assert!(merge_umx_with_u8(uppermx, lower08) == 0x1234567890ABCDFF);
        assert!(merge_umx_with_u16(uppermx, lower16) == 0x1234567890ABFFFF);
        assert!(merge_umx_with_u32(uppermx, lower32) == 0x12345678FFFFFFFF);
    }
}
