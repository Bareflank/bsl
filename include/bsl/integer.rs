// @copyright
// Copyright (C) 2019 Assured Information Security, Inc.
//
// @copyright
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// @copyright
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// @copyright
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

const_assert!(usize::MAX >= (u64::MAX as usize));

// TODO:
// - The to_xxx code assumes that usize is always larger than any other type
//   on the system. This will not work on systems whose register size is
//   smaller than 64 bit based on the way this is done. This will need to be
//   updated to work better on 8, 16 and 32bit systems.
//

// -----------------------------------------------------------------------------
// Traits
// -----------------------------------------------------------------------------

pub trait Integer:
    Sized
    + core::fmt::Binary
    + core::fmt::Debug
    + core::fmt::LowerExp
    + core::fmt::LowerHex
    + core::fmt::Octal
    + core::fmt::UpperExp
    + core::fmt::UpperHex
    + Default
    + Copy
    + Clone
    + Eq
    + Ord
    + PartialEq
    + PartialOrd
    + core::ops::Add<Output = Self>
    + core::ops::AddAssign
    + core::ops::Sub<Output = Self>
    + core::ops::SubAssign
    + core::ops::Mul<Output = Self>
    + core::ops::MulAssign
    + core::ops::Div<Output = Self>
    + core::ops::DivAssign
    + core::ops::Rem<Output = Self>
    + core::ops::RemAssign
{
    fn max_value() -> Self;
    fn min_value() -> Self;

    fn magic_0() -> Self;
    fn magic_1() -> Self;
    fn magic_2() -> Self;
    fn magic_3() -> Self;

    fn add_checked(self, rhs: Self) -> Option<Self>;
    fn sub_checked(self, rhs: Self) -> Option<Self>;
    fn mul_checked(self, rhs: Self) -> Option<Self>;
    fn div_checked(self, rhs: Self) -> Option<Self>;
    fn rem_checked(self, rhs: Self) -> Option<Self>;

    fn into_i8(self) -> Option<i8>;
    fn into_i16(self) -> Option<i16>;
    fn into_i32(self) -> Option<i32>;
    fn into_i64(self) -> Option<i64>;
    fn into_u8(self) -> Option<u8>;
    fn into_u16(self) -> Option<u16>;
    fn into_u32(self) -> Option<u32>;
    fn into_u64(self) -> Option<u64>;
    fn into_usize(self) -> Option<usize>;
}

pub trait SignedInteger: Integer + core::ops::Neg<Output = Self> {
    fn magic_neg_1() -> Self;
    fn neg_checked(self) -> Option<Self>;
}

pub trait UnsignedInteger:
    Integer
    + core::ops::Shl<Output = Self>
    + core::ops::ShlAssign
    + core::ops::Shr<Output = Self>
    + core::ops::ShrAssign
    + core::ops::BitAnd<Output = Self>
    + core::ops::BitAndAssign
    + core::ops::BitOr<Output = Self>
    + core::ops::BitOrAssign
    + core::ops::BitXor<Output = Self>
    + core::ops::BitXorAssign
    + core::ops::Not<Output = Self>
{
    fn shl_wrapping(self, rhs: u32) -> Self;
    fn shr_wrapping(self, rhs: u32) -> Self;

    fn into_u8_unsafe(self) -> u8;
    fn into_u16_unsafe(self) -> u16;
    fn into_u32_unsafe(self) -> u32;
    fn into_u64_unsafe(self) -> u64;
    fn into_usize_unsafe(self) -> usize;
}

// -----------------------------------------------------------------------------
// Trait Implementations
// -----------------------------------------------------------------------------

impl Integer for i8 {
    fn max_value() -> Self {
        return i8::MAX;
    }
    fn min_value() -> Self {
        return i8::MIN;
    }

    fn magic_0() -> Self {
        return 0;
    }
    fn magic_1() -> Self {
        return 1;
    }
    fn magic_2() -> Self {
        return 2;
    }
    fn magic_3() -> Self {
        return 3;
    }

    fn add_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_add(rhs);
    }
    fn sub_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_sub(rhs);
    }
    fn mul_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_mul(rhs);
    }
    fn div_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_div(rhs);
    }
    fn rem_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_rem(rhs);
    }

    fn into_i8(self) -> Option<i8> {
        return Some(self as i8);
    }
    fn into_i16(self) -> Option<i16> {
        return Some(self as i16);
    }
    fn into_i32(self) -> Option<i32> {
        return Some(self as i32);
    }
    fn into_i64(self) -> Option<i64> {
        return Some(self as i64);
    }
    fn into_u8(self) -> Option<u8> {
        if self < 0 {
            return None;
        }
        return Some(self as u8);
    }
    fn into_u16(self) -> Option<u16> {
        if self < 0 {
            return None;
        }
        return Some(self as u16);
    }
    fn into_u32(self) -> Option<u32> {
        if self < 0 {
            return None;
        }
        return Some(self as u32);
    }
    fn into_u64(self) -> Option<u64> {
        if self < 0 {
            return None;
        }
        return Some(self as u64);
    }
    fn into_usize(self) -> Option<usize> {
        if self < 0 {
            return None;
        }
        return Some(self as usize);
    }
}

impl SignedInteger for i8 {
    fn magic_neg_1() -> Self {
        return -1;
    }
    fn neg_checked(self) -> Option<Self> {
        return self.checked_neg();
    }
}

impl Integer for i16 {
    fn max_value() -> Self {
        return i16::MAX;
    }
    fn min_value() -> Self {
        return i16::MIN;
    }

    fn magic_0() -> Self {
        return 0;
    }
    fn magic_1() -> Self {
        return 1;
    }
    fn magic_2() -> Self {
        return 2;
    }
    fn magic_3() -> Self {
        return 3;
    }

    fn add_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_add(rhs);
    }
    fn sub_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_sub(rhs);
    }
    fn mul_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_mul(rhs);
    }
    fn div_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_div(rhs);
    }
    fn rem_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_rem(rhs);
    }

    fn into_i8(self) -> Option<i8> {
        if (self as i64) < (i8::min_value() as i64) {
            return None;
        }
        if (self as i64) > (i8::max_value() as i64) {
            return None;
        }
        return Some(self as i8);
    }
    fn into_i16(self) -> Option<i16> {
        return Some(self as i16);
    }
    fn into_i32(self) -> Option<i32> {
        return Some(self as i32);
    }
    fn into_i64(self) -> Option<i64> {
        return Some(self as i64);
    }
    fn into_u8(self) -> Option<u8> {
        if self < 0 {
            return None;
        }
        if (self as usize) > (u8::max_value() as usize) {
            return None;
        }
        return Some(self as u8);
    }
    fn into_u16(self) -> Option<u16> {
        if self < 0 {
            return None;
        }
        return Some(self as u16);
    }
    fn into_u32(self) -> Option<u32> {
        if self < 0 {
            return None;
        }
        return Some(self as u32);
    }
    fn into_u64(self) -> Option<u64> {
        if self < 0 {
            return None;
        }
        return Some(self as u64);
    }
    fn into_usize(self) -> Option<usize> {
        if self < 0 {
            return None;
        }
        return Some(self as usize);
    }
}

impl SignedInteger for i16 {
    fn magic_neg_1() -> Self {
        return -1;
    }
    fn neg_checked(self) -> Option<Self> {
        return self.checked_neg();
    }
}

impl Integer for i32 {
    fn max_value() -> Self {
        return i32::MAX;
    }
    fn min_value() -> Self {
        return i32::MIN;
    }

    fn magic_0() -> Self {
        return 0;
    }
    fn magic_1() -> Self {
        return 1;
    }
    fn magic_2() -> Self {
        return 2;
    }
    fn magic_3() -> Self {
        return 3;
    }

    fn add_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_add(rhs);
    }
    fn sub_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_sub(rhs);
    }
    fn mul_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_mul(rhs);
    }
    fn div_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_div(rhs);
    }
    fn rem_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_rem(rhs);
    }

    fn into_i8(self) -> Option<i8> {
        if (self as i64) < (i8::min_value() as i64) {
            return None;
        }
        if (self as i64) > (i8::max_value() as i64) {
            return None;
        }
        return Some(self as i8);
    }
    fn into_i16(self) -> Option<i16> {
        if (self as i64) < (i16::min_value() as i64) {
            return None;
        }
        if (self as i64) > (i16::max_value() as i64) {
            return None;
        }
        return Some(self as i16);
    }
    fn into_i32(self) -> Option<i32> {
        return Some(self as i32);
    }
    fn into_i64(self) -> Option<i64> {
        return Some(self as i64);
    }
    fn into_u8(self) -> Option<u8> {
        if self < 0 {
            return None;
        }
        if (self as usize) > (u8::max_value() as usize) {
            return None;
        }
        return Some(self as u8);
    }
    fn into_u16(self) -> Option<u16> {
        if self < 0 {
            return None;
        }
        if (self as usize) > (u16::max_value() as usize) {
            return None;
        }
        return Some(self as u16);
    }
    fn into_u32(self) -> Option<u32> {
        if self < 0 {
            return None;
        }
        return Some(self as u32);
    }
    fn into_u64(self) -> Option<u64> {
        if self < 0 {
            return None;
        }
        return Some(self as u64);
    }
    fn into_usize(self) -> Option<usize> {
        if self < 0 {
            return None;
        }
        return Some(self as usize);
    }
}

impl SignedInteger for i32 {
    fn magic_neg_1() -> Self {
        return -1;
    }
    fn neg_checked(self) -> Option<Self> {
        return self.checked_neg();
    }
}

impl Integer for i64 {
    fn max_value() -> Self {
        return i64::MAX;
    }
    fn min_value() -> Self {
        return i64::MIN;
    }

    fn magic_0() -> Self {
        return 0;
    }
    fn magic_1() -> Self {
        return 1;
    }
    fn magic_2() -> Self {
        return 2;
    }
    fn magic_3() -> Self {
        return 3;
    }

    fn add_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_add(rhs);
    }
    fn sub_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_sub(rhs);
    }
    fn mul_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_mul(rhs);
    }
    fn div_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_div(rhs);
    }
    fn rem_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_rem(rhs);
    }

    fn into_i8(self) -> Option<i8> {
        if (self as i64) < (i8::min_value() as i64) {
            return None;
        }
        if (self as i64) > (i8::max_value() as i64) {
            return None;
        }
        return Some(self as i8);
    }
    fn into_i16(self) -> Option<i16> {
        if (self as i64) < (i16::min_value() as i64) {
            return None;
        }
        if (self as i64) > (i16::max_value() as i64) {
            return None;
        }
        return Some(self as i16);
    }
    fn into_i32(self) -> Option<i32> {
        if (self as i64) < (i32::min_value() as i64) {
            return None;
        }
        if (self as i64) > (i32::max_value() as i64) {
            return None;
        }
        return Some(self as i32);
    }
    fn into_i64(self) -> Option<i64> {
        return Some(self as i64);
    }
    fn into_u8(self) -> Option<u8> {
        if self < 0 {
            return None;
        }
        if (self as usize) > (u8::max_value() as usize) {
            return None;
        }
        return Some(self as u8);
    }
    fn into_u16(self) -> Option<u16> {
        if self < 0 {
            return None;
        }
        if (self as usize) > (u16::max_value() as usize) {
            return None;
        }
        return Some(self as u16);
    }
    fn into_u32(self) -> Option<u32> {
        if self < 0 {
            return None;
        }
        if (self as usize) > (u32::max_value() as usize) {
            return None;
        }
        return Some(self as u32);
    }
    fn into_u64(self) -> Option<u64> {
        if self < 0 {
            return None;
        }
        return Some(self as u64);
    }
    fn into_usize(self) -> Option<usize> {
        if self < 0 {
            return None;
        }
        return Some(self as usize);
    }
}

impl SignedInteger for i64 {
    fn magic_neg_1() -> Self {
        return -1;
    }
    fn neg_checked(self) -> Option<Self> {
        return self.checked_neg();
    }
}

impl Integer for u8 {
    fn max_value() -> Self {
        return u8::MAX;
    }
    fn min_value() -> Self {
        return u8::MIN;
    }

    fn magic_0() -> Self {
        return 0;
    }
    fn magic_1() -> Self {
        return 1;
    }
    fn magic_2() -> Self {
        return 2;
    }
    fn magic_3() -> Self {
        return 3;
    }

    fn add_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_add(rhs);
    }
    fn sub_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_sub(rhs);
    }
    fn mul_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_mul(rhs);
    }
    fn div_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_div(rhs);
    }
    fn rem_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_rem(rhs);
    }

    fn into_i8(self) -> Option<i8> {
        if (self as usize) > (i8::max_value() as usize) {
            return None;
        }
        return Some(self as i8);
    }
    fn into_i16(self) -> Option<i16> {
        return Some(self as i16);
    }
    fn into_i32(self) -> Option<i32> {
        return Some(self as i32);
    }
    fn into_i64(self) -> Option<i64> {
        return Some(self as i64);
    }
    fn into_u8(self) -> Option<u8> {
        return Some(self as u8);
    }
    fn into_u16(self) -> Option<u16> {
        return Some(self as u16);
    }
    fn into_u32(self) -> Option<u32> {
        return Some(self as u32);
    }
    fn into_u64(self) -> Option<u64> {
        return Some(self as u64);
    }
    fn into_usize(self) -> Option<usize> {
        return Some(self as usize);
    }
}

impl UnsignedInteger for u8 {
    fn shl_wrapping(self, rhs: u32) -> Self {
        return self.wrapping_shl(rhs);
    }
    fn shr_wrapping(self, rhs: u32) -> Self {
        return self.wrapping_shr(rhs);
    }

    fn into_u8_unsafe(self) -> u8 {
        return self as u8;
    }
    fn into_u16_unsafe(self) -> u16 {
        return self as u16;
    }
    fn into_u32_unsafe(self) -> u32 {
        return self as u32;
    }
    fn into_u64_unsafe(self) -> u64 {
        return self as u64;
    }
    fn into_usize_unsafe(self) -> usize {
        return self as usize;
    }
}

impl Integer for u16 {
    fn max_value() -> Self {
        return u16::MAX;
    }
    fn min_value() -> Self {
        return u16::MIN;
    }

    fn magic_0() -> Self {
        return 0;
    }
    fn magic_1() -> Self {
        return 1;
    }
    fn magic_2() -> Self {
        return 2;
    }
    fn magic_3() -> Self {
        return 3;
    }

    fn add_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_add(rhs);
    }
    fn sub_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_sub(rhs);
    }
    fn mul_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_mul(rhs);
    }
    fn div_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_div(rhs);
    }
    fn rem_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_rem(rhs);
    }

    fn into_i8(self) -> Option<i8> {
        if (self as usize) > (i8::max_value() as usize) {
            return None;
        }
        return Some(self as i8);
    }
    fn into_i16(self) -> Option<i16> {
        if (self as usize) > (i16::max_value() as usize) {
            return None;
        }
        return Some(self as i16);
    }
    fn into_i32(self) -> Option<i32> {
        return Some(self as i32);
    }
    fn into_i64(self) -> Option<i64> {
        return Some(self as i64);
    }
    fn into_u8(self) -> Option<u8> {
        if (self as usize) > (u8::max_value() as usize) {
            return None;
        }
        return Some(self as u8);
    }
    fn into_u16(self) -> Option<u16> {
        return Some(self as u16);
    }
    fn into_u32(self) -> Option<u32> {
        return Some(self as u32);
    }
    fn into_u64(self) -> Option<u64> {
        return Some(self as u64);
    }
    fn into_usize(self) -> Option<usize> {
        return Some(self as usize);
    }
}

impl UnsignedInteger for u16 {
    fn shl_wrapping(self, rhs: u32) -> Self {
        return self.wrapping_shl(rhs);
    }
    fn shr_wrapping(self, rhs: u32) -> Self {
        return self.wrapping_shr(rhs);
    }

    fn into_u8_unsafe(self) -> u8 {
        return self as u8;
    }
    fn into_u16_unsafe(self) -> u16 {
        return self as u16;
    }
    fn into_u32_unsafe(self) -> u32 {
        return self as u32;
    }
    fn into_u64_unsafe(self) -> u64 {
        return self as u64;
    }
    fn into_usize_unsafe(self) -> usize {
        return self as usize;
    }
}

impl Integer for u32 {
    fn max_value() -> Self {
        return u32::MAX;
    }
    fn min_value() -> Self {
        return u32::MIN;
    }

    fn magic_0() -> Self {
        return 0;
    }
    fn magic_1() -> Self {
        return 1;
    }
    fn magic_2() -> Self {
        return 2;
    }
    fn magic_3() -> Self {
        return 3;
    }

    fn add_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_add(rhs);
    }
    fn sub_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_sub(rhs);
    }
    fn mul_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_mul(rhs);
    }
    fn div_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_div(rhs);
    }
    fn rem_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_rem(rhs);
    }

    fn into_i8(self) -> Option<i8> {
        if (self as usize) > (i8::max_value() as usize) {
            return None;
        }
        return Some(self as i8);
    }
    fn into_i16(self) -> Option<i16> {
        if (self as usize) > (i16::max_value() as usize) {
            return None;
        }
        return Some(self as i16);
    }
    fn into_i32(self) -> Option<i32> {
        if (self as usize) > (i32::max_value() as usize) {
            return None;
        }
        return Some(self as i32);
    }
    fn into_i64(self) -> Option<i64> {
        return Some(self as i64);
    }
    fn into_u8(self) -> Option<u8> {
        if (self as usize) > (u8::max_value() as usize) {
            return None;
        }
        return Some(self as u8);
    }
    fn into_u16(self) -> Option<u16> {
        if (self as usize) > (u16::max_value() as usize) {
            return None;
        }
        return Some(self as u16);
    }
    fn into_u32(self) -> Option<u32> {
        return Some(self as u32);
    }
    fn into_u64(self) -> Option<u64> {
        return Some(self as u64);
    }
    fn into_usize(self) -> Option<usize> {
        return Some(self as usize);
    }
}

impl UnsignedInteger for u32 {
    fn shl_wrapping(self, rhs: u32) -> Self {
        return self.wrapping_shl(rhs);
    }
    fn shr_wrapping(self, rhs: u32) -> Self {
        return self.wrapping_shr(rhs);
    }

    fn into_u8_unsafe(self) -> u8 {
        return self as u8;
    }
    fn into_u16_unsafe(self) -> u16 {
        return self as u16;
    }
    fn into_u32_unsafe(self) -> u32 {
        return self as u32;
    }
    fn into_u64_unsafe(self) -> u64 {
        return self as u64;
    }
    fn into_usize_unsafe(self) -> usize {
        return self as usize;
    }
}

impl Integer for u64 {
    fn max_value() -> Self {
        return u64::MAX;
    }
    fn min_value() -> Self {
        return u64::MIN;
    }

    fn magic_0() -> Self {
        return 0;
    }
    fn magic_1() -> Self {
        return 1;
    }
    fn magic_2() -> Self {
        return 2;
    }
    fn magic_3() -> Self {
        return 3;
    }

    fn add_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_add(rhs);
    }
    fn sub_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_sub(rhs);
    }
    fn mul_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_mul(rhs);
    }
    fn div_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_div(rhs);
    }
    fn rem_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_rem(rhs);
    }

    fn into_i8(self) -> Option<i8> {
        if (self as usize) > (i8::max_value() as usize) {
            return None;
        }
        return Some(self as i8);
    }
    fn into_i16(self) -> Option<i16> {
        if (self as usize) > (i16::max_value() as usize) {
            return None;
        }
        return Some(self as i16);
    }
    fn into_i32(self) -> Option<i32> {
        if (self as usize) > (i32::max_value() as usize) {
            return None;
        }
        return Some(self as i32);
    }
    fn into_i64(self) -> Option<i64> {
        if (self as usize) > (i64::max_value() as usize) {
            return None;
        }
        return Some(self as i64);
    }
    fn into_u8(self) -> Option<u8> {
        if (self as usize) > (u8::max_value() as usize) {
            return None;
        }
        return Some(self as u8);
    }
    fn into_u16(self) -> Option<u16> {
        if (self as usize) > (u16::max_value() as usize) {
            return None;
        }
        return Some(self as u16);
    }
    fn into_u32(self) -> Option<u32> {
        if (self as usize) > (u32::max_value() as usize) {
            return None;
        }
        return Some(self as u32);
    }
    fn into_u64(self) -> Option<u64> {
        return Some(self as u64);
    }
    fn into_usize(self) -> Option<usize> {
        return Some(self as usize);
    }
}

impl UnsignedInteger for u64 {
    fn shl_wrapping(self, rhs: u32) -> Self {
        return self.wrapping_shl(rhs);
    }
    fn shr_wrapping(self, rhs: u32) -> Self {
        return self.wrapping_shr(rhs);
    }

    fn into_u8_unsafe(self) -> u8 {
        return self as u8;
    }
    fn into_u16_unsafe(self) -> u16 {
        return self as u16;
    }
    fn into_u32_unsafe(self) -> u32 {
        return self as u32;
    }
    fn into_u64_unsafe(self) -> u64 {
        return self as u64;
    }
    fn into_usize_unsafe(self) -> usize {
        return self as usize;
    }
}

impl Integer for usize {
    fn max_value() -> Self {
        return usize::MAX;
    }
    fn min_value() -> Self {
        return usize::MIN;
    }

    fn magic_0() -> Self {
        return 0;
    }
    fn magic_1() -> Self {
        return 1;
    }
    fn magic_2() -> Self {
        return 2;
    }
    fn magic_3() -> Self {
        return 3;
    }

    fn add_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_add(rhs);
    }
    fn sub_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_sub(rhs);
    }
    fn mul_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_mul(rhs);
    }
    fn div_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_div(rhs);
    }
    fn rem_checked(self, rhs: Self) -> Option<Self> {
        return self.checked_rem(rhs);
    }

    fn into_i8(self) -> Option<i8> {
        if (self as usize) > (i8::max_value() as usize) {
            return None;
        }
        return Some(self as i8);
    }
    fn into_i16(self) -> Option<i16> {
        if (self as usize) > (i16::max_value() as usize) {
            return None;
        }
        return Some(self as i16);
    }
    fn into_i32(self) -> Option<i32> {
        if (self as usize) > (i32::max_value() as usize) {
            return None;
        }
        return Some(self as i32);
    }
    fn into_i64(self) -> Option<i64> {
        if (self as usize) > (i64::max_value() as usize) {
            return None;
        }
        return Some(self as i64);
    }
    fn into_u8(self) -> Option<u8> {
        if (self as usize) > (u8::max_value() as usize) {
            return None;
        }
        return Some(self as u8);
    }
    fn into_u16(self) -> Option<u16> {
        if (self as usize) > (u16::max_value() as usize) {
            return None;
        }
        return Some(self as u16);
    }
    fn into_u32(self) -> Option<u32> {
        if (self as usize) > (u32::max_value() as usize) {
            return None;
        }
        return Some(self as u32);
    }
    fn into_u64(self) -> Option<u64> {
        return Some(self as u64);
    }
    fn into_usize(self) -> Option<usize> {
        return Some(self as usize);
    }
}

impl UnsignedInteger for usize {
    fn shl_wrapping(self, rhs: u32) -> Self {
        return self.wrapping_shl(rhs);
    }
    fn shr_wrapping(self, rhs: u32) -> Self {
        return self.wrapping_shr(rhs);
    }

    fn into_u8_unsafe(self) -> u8 {
        return self as u8;
    }
    fn into_u16_unsafe(self) -> u16 {
        return self as u16;
    }
    fn into_u32_unsafe(self) -> u32 {
        return self as u32;
    }
    fn into_u64_unsafe(self) -> u64 {
        return self as u64;
    }
    fn into_usize_unsafe(self) -> usize {
        return self as usize;
    }
}
