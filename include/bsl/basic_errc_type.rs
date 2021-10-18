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
use core::fmt;
use core::ops;

// -----------------------------------------------------------------------------
// BasicErrcType<T>
// -----------------------------------------------------------------------------

#[derive(Debug, Default, Copy, Clone, PartialEq, PartialOrd)]
pub struct BasicErrcType<T>(T);

impl<T> BasicErrcType<T>
where
    T: Sized,
{
    /// <!-- description -->
    ///   @brief Value initialization constructor
    ///
    /// <!-- inputs/outputs -->
    ///   @param val the error code to store
    ///
    pub const fn new(val: T) -> Self {
        Self { 0: val }
    }
}

impl<T> BasicErrcType<T>
where
    T: Integer,
{
    /// <!-- description -->
    ///   @brief Returns the integer value that represents the error code.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the integer value that represents the error code.
    ///
    pub fn get(&self) -> T {
        return self.0;
    }

    /// <!-- description -->
    ///   @brief Returns true if the error code contains T{},
    ///     otherwise, if the error code contains an error code,
    ///     returns false.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the error code contains T{},
    ///     otherwise, if the error code contains an error code,
    ///     returns false.
    ///
    pub fn success(&self) -> bool {
        return self.0 >= Default::default();
    }

    /// <!-- description -->
    ///   @brief Returns true if the error code contains an error code,
    ///     otherwise, if the error code contains T{},
    ///     returns false.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the error code contains an error code,
    ///     otherwise, if the error code contains T{},
    ///     returns false.
    ///
    pub fn failure(&self) -> bool {
        return self.0 < Default::default();
    }
}

// -----------------------------------------------------------------------------
// Conversions
// -----------------------------------------------------------------------------

impl<T> ops::Not for BasicErrcType<T>
where
    T: Integer,
{
    type Output = bool;
    fn not(self) -> bool {
        return self.failure();
    }
}

impl<T> From<BasicErrcType<T>> for bool
where
    T: Integer,
{
    fn from(errc: BasicErrcType<T>) -> Self {
        return errc.success();
    }
}

// -----------------------------------------------------------------------------
// Output
// -----------------------------------------------------------------------------

impl<T> fmt::Display for BasicErrcType<T>
where
    T: Integer,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let val = self.0;
        return write!(f, "{:?}", &val);
    }
}

impl<T> fmt::Binary for BasicErrcType<T>
where
    T: Integer,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let val = self.0;
        return fmt::Binary::fmt(&val, f);
    }
}

impl<T> fmt::LowerExp for BasicErrcType<T>
where
    T: Integer,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let val = self.0;
        return fmt::LowerExp::fmt(&val, f);
    }
}

impl<T> fmt::LowerHex for BasicErrcType<T>
where
    T: Integer,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let val = self.0;
        return fmt::LowerHex::fmt(&val, f);
    }
}

impl<T> fmt::Octal for BasicErrcType<T>
where
    T: Integer,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let val = self.0;
        return fmt::Octal::fmt(&val, f);
    }
}

impl<T> fmt::UpperExp for BasicErrcType<T>
where
    T: Integer,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let val = self.0;
        return fmt::UpperExp::fmt(&val, f);
    }
}

impl<T> fmt::UpperHex for BasicErrcType<T>
where
    T: Integer,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let val = self.0;
        return fmt::UpperHex::fmt(&val, f);
    }
}

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod test_basic_errc_type {
    use super::*;
    use crate::*;

    #[test]
    fn safe_integral_debug() {
        print!("{}\n", BasicErrcType::<i32>::new(0));
        print!("{:?}\n", BasicErrcType::<i32>::new(0));
        print!("{:x?}\n", BasicErrcType::<i32>::new(0));
        print!("{:X?}\n", BasicErrcType::<i32>::new(0));
        print!("{:o}\n", BasicErrcType::<i32>::new(0));
        print!("{:x}\n", BasicErrcType::<i32>::new(0));
        print!("{:X}\n", BasicErrcType::<i32>::new(0));
        print!("{:b}\n", BasicErrcType::<i32>::new(0));
        print!("{:e}\n", BasicErrcType::<i32>::new(0));
        print!("{:E}\n", BasicErrcType::<i32>::new(0));
    }

    #[test]
    fn basic_errc_type_default_construction() {
        let ret: BasicErrcType<i32> = Default::default();
        assert!(ret.success());
    }

    #[test]
    fn basic_errc_type_copy() {
        let ret1 = BasicErrcType::<i32>::new(0);
        let ret2 = ret1;
        assert!(ret1.success());
        assert!(ret2.success());
    }

    #[test]
    fn basic_errc_type_clone() {
        let ret1 = BasicErrcType::<i32>::new(0);
        let ret2 = ret1.clone();
        assert!(ret1.success());
        assert!(ret2.success());
    }

    #[test]
    fn basic_errc_type_partialeq() {
        let ret1 = BasicErrcType::<i32>::new(42);
        let ret2 = BasicErrcType::<i32>::new(42);
        let ret3 = BasicErrcType::<i32>::new(0);
        assert!(ret1 == ret2);
        assert!(ret1 != ret3);
    }

    #[test]
    fn basic_errc_type_partialord() {
        let ret1 = BasicErrcType::<i32>::new(0);
        let ret2 = BasicErrcType::<i32>::new(0);
        let ret3 = BasicErrcType::<i32>::new(42);
        assert!(ret1 < ret3);
        assert!(ret2 <= ret2);
        assert!(ret3 > ret2);
        assert!(ret3 >= ret3);
    }

    #[test]
    fn basic_errc_type_new_construction() {
        let ret1 = BasicErrcType::<i32>::new(42);
        let ret2 = BasicErrcType::<i32>::new(0);
        let ret3 = BasicErrcType::<i32>::new(-42);
        assert!(ret1.success());
        assert!(ret2.success());
        assert!(ret3.failure());
    }

    #[test]
    fn basic_errc_type_get() {
        let ret1 = BasicErrcType::<i32>::new(42);
        let ret2 = BasicErrcType::<i32>::new(0);
        let ret3 = BasicErrcType::<i32>::new(-42);
        assert!(ret1.get() == 42);
        assert!(ret2.get() == 0);
        assert!(ret3.get() == -42);
    }

    #[test]
    fn basic_errc_type_success() {
        let ret1 = BasicErrcType::<i32>::new(42);
        let ret2 = BasicErrcType::<i32>::new(0);
        let ret3 = BasicErrcType::<i32>::new(-42);
        assert!(ret1.success());
        assert!(ret2.success());
        assert!(!ret3.success());
    }

    #[test]
    fn basic_errc_type_failure() {
        let ret1 = BasicErrcType::<i32>::new(42);
        let ret2 = BasicErrcType::<i32>::new(0);
        let ret3 = BasicErrcType::<i32>::new(-42);
        assert!(!ret1.failure());
        assert!(!ret2.failure());
        assert!(ret3.failure());
    }

    #[test]
    fn basic_errc_type_not() {
        let ret = BasicErrcType::<i32>::new(-42);
        assert!(!ret);

        let ret = BasicErrcType::<i32>::new(0);
        assert!(!!ret);
    }

    #[test]
    fn basic_errc_type_into() {
        let ret: bool = BasicErrcType::<i32>::new(0).into();
        assert!(ret == true);

        let ret: bool = BasicErrcType::<i32>::new(-42).into();
        assert!(ret == false);
    }

    #[test]
    fn basic_errc_type_into_bool() {
        let ret = BasicErrcType::<i32>::new(0);
        assert!(ret.into_bool() == true);

        let ret = BasicErrcType::<i32>::new(-42);
        assert!(ret.into_bool() == false);
    }
}
