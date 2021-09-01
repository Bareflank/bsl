// @copyright
// Copyright (C) 2020 Assured Information Security, Inc.
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
use crate::Integer;
use crate::SafeIntegral;
use crate::SafeIdx;
use crate::SafeUMx;

pub trait IntoSafeIntegral {
    type Output;
    fn into_safe_integral(self) -> Self::Output;
}

impl<T> IntoSafeIntegral for T
where
    T: Integer,
{
    type Output = SafeIntegral<T>;
    fn into_safe_integral(self) -> Self::Output {
        return SafeIntegral::<T>::new(self);
    }
}

impl<T> IntoSafeIntegral for SafeIntegral<T>
where
    T: Integer,
{
    type Output = SafeIntegral<T>;
    fn into_safe_integral(self) -> Self::Output {
        return self;
    }
}

impl IntoSafeIntegral for SafeIdx
{
    type Output = SafeUMx;
    fn into_safe_integral(self) -> Self::Output {
        if self.is_invalid() {
            return SafeUMx::failure();
        }

        return SafeUMx::new(*self.cdata_as_ref());
    }
}

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod test_into_safe_integral {
    use super::*;

    fn into_safe_integral_general_for_t<T>()
    where
        T: Integer,
    {
        let val = T::magic_1();
        assert!(val.into_safe_integral().is_valid());
        let val = SafeIntegral::<T>::magic_1();
        assert!(val.into_safe_integral().is_valid());
    }

    #[test]
    fn into_safe_integral_general() {
        into_safe_integral_general_for_t::<i8>();
        into_safe_integral_general_for_t::<i16>();
        into_safe_integral_general_for_t::<i32>();
        into_safe_integral_general_for_t::<i64>();
        into_safe_integral_general_for_t::<u8>();
        into_safe_integral_general_for_t::<u16>();
        into_safe_integral_general_for_t::<u32>();
        into_safe_integral_general_for_t::<u64>();
        into_safe_integral_general_for_t::<usize>();
    }
}
