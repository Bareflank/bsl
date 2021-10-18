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
use crate::SafeUMx;
use crate::SourceLocation;
use core::cmp;
use core::fmt;
use core::ops;

#[derive(Debug, Default, Copy, Clone)]
pub struct SafeIdx {
    m_val: usize,
    m_poisoned: bool,
}

impl SafeIdx {
    fn update_poisoned(&mut self, poisoned: bool) {
        self.m_poisoned |= poisoned;
    }
}

impl SafeIdx {
    /// <!-- description -->
    ///   @brief Value initialization constructor
    ///
    /// <!-- inputs/outputs -->
    ///   @param val the value to set the SafeIdx to
    ///
    pub const fn new(val: usize) -> Self {
        Self {
            m_val: val,
            m_poisoned: false,
        }
    }

    /// <!-- description -->
    ///   @brief Returns a new SafeIdx given a value and flags
    ///     from a SafeUMx.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val the value to set the new SafeIdx to
    ///   @param flags the SafeUMx to get the flags from
    ///   @return Returns a new SafeIdx given a value and flags
    ///     from a SafeUMx.
    ///
    pub fn new_from(val: SafeUMx, sloc: SourceLocation) -> Self {
        if val.is_invalid() {
            crate::assert("a safe_idx was poisoned", sloc);
        } else {
            crate::touch();
        }

        Self {
            m_val: *val.cdata_as_ref(),
            m_poisoned: val.is_invalid(),
        }
    }

    /// <!-- description -->
    ///   @brief Returns the max value the bsl::SafeIdx can store.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the max value the bsl::SafeIdx can store.
    ///
    pub fn max_value() -> Self {
        return Self::new(usize::max_value());
    }

    /// <!-- description -->
    ///   @brief Returns the min value the bsl::SafeIdx can store.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the min value the bsl::SafeIdx can store.
    ///
    pub fn min_value() -> Self {
        return Self::new(usize::min_value());
    }

    /// <!-- description -->
    ///   @brief Returns Self::new(0);
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns Self::new(0);
    ///
    pub fn magic_0() -> Self {
        return Self::new(0);
    }

    /// <!-- description -->
    ///   @brief Returns Self::new(1);
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns Self::new(1);
    ///
    pub fn magic_1() -> Self {
        return Self::new(1);
    }

    /// <!-- description -->
    ///   @brief Returns Self::new(2);
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns Self::new(2);
    ///
    pub fn magic_2() -> Self {
        return Self::new(2);
    }

    /// <!-- description -->
    ///   @brief Returns Self::new(3);
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns Self::new(3);
    ///
    pub fn magic_3() -> Self {
        return Self::new(3);
    }

    /// <!-- description -->
    ///   @brief Returns a reference to the internal integral being managed
    ///     by this class, providing a means to directly read/write the
    ///     integral's value.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns a reference to the internal integral being managed
    ///     by this class, providing a means to directly read/write the
    ///     integral's value.
    ///
    pub fn data_as_ref(&mut self) -> &mut usize {
        return &mut self.m_val;
    }

    /// <!-- description -->
    ///   @brief Returns a reference to the internal integral being managed
    ///     by this class, providing a means to directly read the
    ///     integral's value.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns a reference to the internal integral being managed
    ///     by this class, providing a means to directly read the
    ///     integral's value.
    ///
    pub fn cdata_as_ref(&self) -> &usize {
        return &self.m_val;
    }

    /// <!-- description -->
    ///   @brief Returns a pointer to the internal integral being managed
    ///     by this class, providing a means to directly read/write the
    ///     integral's value.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns a pointer to the internal integral being managed
    ///     by this class, providing a means to directly read/write the
    ///     integral's value.
    ///
    pub fn data(&mut self) -> *mut usize {
        return &mut self.m_val;
    }

    /// <!-- description -->
    ///   @brief Returns a pointer to the internal integral being managed
    ///     by this class, providing a means to directly read the
    ///     integral's value.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns a pointer to the internal integral being managed
    ///     by this class, providing a means to directly read the
    ///     integral's value.
    ///
    pub fn cdata(&mut self) -> *const usize {
        return &self.m_val;
    }

    /// <!-- description -->
    ///   @brief Returns the value stored by the bsl::SafeIntegral.
    ///     Attempting to get the value of an invalid SafeIntegral
    ///     results in undefined behavior.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the value stored by the bsl::SafeIntegral.
    ///     Attempting to get the value of an invalid SafeIntegral
    ///     results in undefined behavior.
    ///
    pub fn get_with_sloc(&self, sloc: SourceLocation) -> usize {
        if self.m_poisoned {
            crate::assert("a poisoned SafeIntegral was read", sloc);
        } else {
            crate::touch();
        }

        return self.m_val;
    }

    /// <!-- description -->
    ///   @brief Returns the value stored by the bsl::SafeIntegral.
    ///     Attempting to get the value of an invalid SafeIntegral
    ///     results in undefined behavior.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the value stored by the bsl::SafeIntegral.
    ///     Attempting to get the value of an invalid SafeIntegral
    ///     results in undefined behavior.
    ///
    #[track_caller]
    pub fn get(&self) -> usize {
        return self.get_with_sloc(crate::here());
    }

    /// <!-- description -->
    ///   @brief Returns true if the SafeIdx is positive.
    ///     Attempting to run is_pos on an invalid SafeIdx
    ///     results in undefined behavior.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the SafeIdx is positive
    ///
    #[track_caller]
    pub fn is_pos(&self) -> bool {
        if self.m_poisoned {
            crate::assert("a poisoned SafeIdx was read", crate::here());
        } else {
            crate::touch();
        }

        return self.m_val > 0;
    }

    /// <!-- description -->
    ///   @brief Returns true if the SafeIdx is 0.
    ///     Attempting to run is_zero on an invalid SafeIdx
    ///     results in undefined behavior.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the SafeIdx is 0
    ///
    #[track_caller]
    pub fn is_zero(&self) -> bool {
        if self.m_poisoned {
            crate::assert("a poisoned SafeIdx was read", crate::here());
        } else {
            crate::touch();
        }

        return self.m_val == 0;
    }

    /// <!-- description -->
    ///   @brief Returns true if the SafeIdx has encountered and
    ///     error, false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the SafeIdx has encountered and
    ///     error, false otherwise.
    ///
    pub fn is_invalid(&self) -> bool {
        return self.m_poisoned;
    }

    /// <!-- description -->
    ///   @brief Returns !self.is_invalid().
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns !self.is_invalid()
    ///
    pub fn is_valid(&self) -> bool {
        return !self.is_invalid();
    }
}

// -----------------------------------------------------------------------------
// Rational
// -----------------------------------------------------------------------------

impl PartialEq for SafeIdx {
    #[track_caller]
    fn eq(&self, rhs: &Self) -> bool {
        let sloc = crate::here();
        return self.get_with_sloc(sloc) == rhs.get_with_sloc(sloc);
    }
}

impl PartialEq<usize> for SafeIdx {
    #[track_caller]
    fn eq(&self, rhs: &usize) -> bool {
        let sloc = crate::here();
        return self.get_with_sloc(sloc) == *rhs;
    }
}

impl PartialEq<SafeUMx> for SafeIdx {
    #[track_caller]
    fn eq(&self, rhs: &SafeUMx) -> bool {
        let sloc = crate::here();
        return self.get_with_sloc(sloc) == rhs.get_with_sloc(sloc);
    }
}

impl PartialOrd for SafeIdx {
    #[track_caller]
    fn partial_cmp(&self, rhs: &Self) -> Option<cmp::Ordering> {
        let sloc = crate::here();
        return Some(self.get_with_sloc(sloc).cmp(&rhs.get_with_sloc(sloc)));
    }
}

impl PartialOrd<usize> for SafeIdx {
    #[track_caller]
    fn partial_cmp(&self, rhs: &usize) -> Option<cmp::Ordering> {
        let sloc = crate::here();
        return Some(self.get_with_sloc(sloc).cmp(rhs));
    }
}

impl PartialOrd<SafeUMx> for SafeIdx {
    #[track_caller]
    fn partial_cmp(&self, rhs: &SafeUMx) -> Option<cmp::Ordering> {
        let sloc = crate::here();
        return Some(self.get_with_sloc(sloc).cmp(&rhs.get_with_sloc(sloc)));
    }
}

// -----------------------------------------------------------------------------
// Arithmetic
// -----------------------------------------------------------------------------

impl ops::AddAssign for SafeIdx {
    fn add_assign(&mut self, rhs: SafeIdx) {
        match self.m_val.checked_add(rhs.m_val) {
            Some(val) => {
                self.m_val = val;
                self.update_poisoned(rhs.is_invalid());
            }
            None => {
                self.update_poisoned(true);
            }
        }
    }
}

impl ops::AddAssign<usize> for SafeIdx {
    fn add_assign(&mut self, rhs: usize) {
        match self.m_val.checked_add(rhs) {
            Some(val) => {
                self.m_val = val;
            }
            None => {
                self.update_poisoned(true);
            }
        }
    }
}

impl ops::Add<SafeIdx> for SafeIdx {
    type Output = SafeIdx;
    fn add(self, rhs: SafeIdx) -> Self::Output {
        let mut ret = self.clone();
        ret += rhs;
        return ret;
    }
}

impl ops::Add<usize> for SafeIdx {
    type Output = SafeIdx;
    fn add(self, rhs: usize) -> Self::Output {
        let mut ret = self.clone();
        ret += rhs;
        return ret;
    }
}

impl ops::SubAssign for SafeIdx {
    fn sub_assign(&mut self, rhs: SafeIdx) {
        match self.m_val.checked_sub(rhs.m_val) {
            Some(val) => {
                self.m_val = val;
                self.update_poisoned(rhs.is_invalid());
            }
            None => {
                self.update_poisoned(true);
            }
        }
    }
}

impl ops::SubAssign<usize> for SafeIdx {
    fn sub_assign(&mut self, rhs: usize) {
        match self.m_val.checked_sub(rhs) {
            Some(val) => {
                self.m_val = val;
            }
            None => {
                self.update_poisoned(true);
            }
        }
    }
}

impl ops::Sub<SafeIdx> for SafeIdx {
    type Output = SafeIdx;
    fn sub(self, rhs: SafeIdx) -> Self::Output {
        let mut ret = self.clone();
        ret -= rhs;
        return ret;
    }
}

impl ops::Sub<usize> for SafeIdx {
    type Output = SafeIdx;
    fn sub(self, rhs: usize) -> Self::Output {
        let mut ret = self.clone();
        ret -= rhs;
        return ret;
    }
}

// -----------------------------------------------------------------------------
// Output
// -----------------------------------------------------------------------------

impl fmt::Display for SafeIdx {
    #[track_caller]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_invalid() {
            return write!(f, "[error]");
        } else {
            let val = self.get_with_sloc(crate::here());
            return write!(f, "{:?}", &val);
        }
    }
}

impl fmt::Binary for SafeIdx {
    #[track_caller]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_invalid() {
            return write!(f, "[error]");
        } else {
            let val = self.get_with_sloc(crate::here());
            return fmt::Binary::fmt(&val, f);
        }
    }
}

impl fmt::LowerExp for SafeIdx {
    #[track_caller]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_invalid() {
            return write!(f, "[error]");
        } else {
            let val = self.get_with_sloc(crate::here());
            return fmt::LowerExp::fmt(&val, f);
        }
    }
}

impl fmt::LowerHex for SafeIdx {
    #[track_caller]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_invalid() {
            return write!(f, "[error]");
        } else {
            let val = self.get_with_sloc(crate::here());
            return fmt::LowerHex::fmt(&val, f);
        }
    }
}

impl fmt::Octal for SafeIdx {
    #[track_caller]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_invalid() {
            return write!(f, "[error]");
        } else {
            let val = self.get_with_sloc(crate::here());
            return fmt::Octal::fmt(&val, f);
        }
    }
}

impl fmt::UpperExp for SafeIdx {
    #[track_caller]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_invalid() {
            return write!(f, "[error]");
        } else {
            let val = self.get_with_sloc(crate::here());
            return fmt::UpperExp::fmt(&val, f);
        }
    }
}

impl fmt::UpperHex for SafeIdx {
    #[track_caller]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_invalid() {
            return write!(f, "[error]");
        } else {
            let val = self.get_with_sloc(crate::here());
            return fmt::UpperHex::fmt(&val, f);
        }
    }
}

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod safe_idx_tests {
    use super::*;
    use crate::*;

    #[test]
    fn safe_idx_constructors() {
        assert!(SafeIdx::default().is_valid());
        assert!(SafeIdx::new(1).is_valid());

        let val = SafeUMx::default();
        assert!(SafeIdx::new_from(val, here()).is_valid());
        let val = SafeUMx::failure();
        assert_panics!(SafeIdx::new_from(val, here()));
    }

    #[test]
    fn safe_idx_debug() {
        print!("{}\n", SafeIdx::magic_1());
        print!("{}\n", SafeIdx::max_value() + SafeIdx::magic_1());
        print!("{:?}\n", SafeIdx::magic_1());
        print!("{:?}\n", SafeIdx::max_value() + SafeIdx::magic_1());
        print!("{:x?}\n", SafeIdx::magic_1());
        print!("{:x?}\n", SafeIdx::max_value() + SafeIdx::magic_1());
        print!("{:X?}\n", SafeIdx::magic_1());
        print!("{:X?}\n", SafeIdx::max_value() + SafeIdx::magic_1());
        print!("{:o}\n", SafeIdx::magic_1());
        print!("{:o}\n", SafeIdx::max_value() + SafeIdx::magic_1());
        print!("{:x}\n", SafeIdx::magic_1());
        print!("{:x}\n", SafeIdx::max_value() + SafeIdx::magic_1());
        print!("{:X}\n", SafeIdx::magic_1());
        print!("{:X}\n", SafeIdx::max_value() + SafeIdx::magic_1());
        print!("{:b}\n", SafeIdx::magic_1());
        print!("{:b}\n", SafeIdx::max_value() + SafeIdx::magic_1());
        print!("{:e}\n", SafeIdx::magic_1());
        print!("{:e}\n", SafeIdx::max_value() + SafeIdx::magic_1());
        print!("{:E}\n", SafeIdx::magic_1());
        print!("{:E}\n", SafeIdx::max_value() + SafeIdx::magic_1());
    }

    #[test]
    fn safe_idx_max_min() {
        assert!(SafeIdx::max_value() == usize::max_value());
        assert!(SafeIdx::min_value() == usize::min_value());
    }

    #[test]
    fn safe_idx_magic() {
        assert!(SafeIdx::magic_0() == 0);
        assert!(SafeIdx::magic_1() == 1);
        assert!(SafeIdx::magic_2() == 2);
        assert!(SafeIdx::magic_3() == 3);
    }

    #[test]
    fn safe_idx_data() {
        let mut val = SafeIdx::new(1);

        unsafe {
            *val.data_as_ref() = usize::magic_1();
            assert!(*val.data_as_ref() == usize::magic_1());
            assert!(*val.cdata_as_ref() == usize::magic_1());
            *val.data_as_ref() = usize::magic_2();
            assert!(*val.data_as_ref() == usize::magic_2());
            assert!(*val.cdata_as_ref() == usize::magic_2());

            *val.data() = usize::magic_1();
            assert!(*val.data() == usize::magic_1());
            assert!(*val.cdata() == usize::magic_1());
            *val.data() = usize::magic_2();
            assert!(*val.data() == usize::magic_2());
            assert!(*val.cdata() == usize::magic_2());
        }
    }

    #[test]
    fn safe_idx_get() {
        let val = SafeIdx::new(1);
        assert!(val.get() == 1);
        let val = SafeIdx::max_value() + SafeIdx::magic_1();
        assert_panics!(val.get());
    }

    #[test]
    fn safe_idx_is_queries() {
        assert_eq!(SafeIdx::magic_0().is_zero(), true);
        assert_eq!(SafeIdx::magic_0().is_pos(), false);
        assert_eq!(SafeIdx::magic_1().is_zero(), false);
        assert_eq!(SafeIdx::magic_1().is_pos(), true);

        let val = SafeIdx::max_value() + SafeIdx::magic_1();
        assert_panics!(val.is_zero());
        assert_panics!(val.is_pos());
    }

    #[test]
    fn safe_idx_failure() {
        assert_eq!(SafeIdx::magic_0().is_invalid(), false);
        assert_eq!(SafeIdx::magic_0().is_valid(), true);

        assert_eq!(SafeIdx::magic_1().is_invalid(), false);
        assert_eq!(SafeIdx::magic_1().is_valid(), true);

        let val = SafeIdx::max_value() + SafeIdx::magic_1();
        assert_eq!(val.is_invalid(), true);
        assert_eq!(val.is_valid(), false);
    }

    #[test]
    fn safe_idx_rational() {
        assert!(SafeIdx::magic_1() == SafeIdx::magic_1());
        assert!(SafeIdx::magic_1() != SafeIdx::magic_2());
        assert!(SafeIdx::magic_1() < SafeIdx::magic_2());
        assert!(SafeIdx::magic_1() <= SafeIdx::magic_2());
        assert!(SafeIdx::magic_1() <= SafeIdx::magic_1());
        assert!(SafeIdx::magic_1() > SafeIdx::magic_0());
        assert!(SafeIdx::magic_1() >= SafeIdx::magic_0());
        assert!(SafeIdx::magic_1() >= SafeIdx::magic_1());

        assert!(SafeIdx::magic_1() == SafeIdx::magic_1().get());
        assert!(SafeIdx::magic_1() != SafeIdx::magic_2().get());
        assert!(SafeIdx::magic_1() < SafeIdx::magic_2().get());
        assert!(SafeIdx::magic_1() <= SafeIdx::magic_2().get());
        assert!(SafeIdx::magic_1() <= SafeIdx::magic_1().get());
        assert!(SafeIdx::magic_1() > SafeIdx::magic_0().get());
        assert!(SafeIdx::magic_1() >= SafeIdx::magic_0().get());
        assert!(SafeIdx::magic_1() >= SafeIdx::magic_1().get());

        assert!(SafeIdx::magic_1() == SafeUMx::magic_1());
        assert!(SafeIdx::magic_1() != SafeUMx::magic_2());
        assert!(SafeIdx::magic_1() < SafeUMx::magic_2());
        assert!(SafeIdx::magic_1() <= SafeUMx::magic_2());
        assert!(SafeIdx::magic_1() <= SafeUMx::magic_1());
        assert!(SafeIdx::magic_1() > SafeUMx::magic_0());
        assert!(SafeIdx::magic_1() >= SafeUMx::magic_0());
        assert!(SafeIdx::magic_1() >= SafeUMx::magic_1());
    }

    #[test]
    fn safe_idx_add() {
        let mut val = SafeIdx::magic_1();
        val += SafeIdx::magic_1();
        assert!(val == 2);

        let mut val = SafeIdx::magic_1();
        val += SafeIdx::max_value();
        assert!(val.is_invalid());

        let val = SafeIdx::magic_1();
        assert!((val + SafeIdx::magic_1()) == 2);

        let val = SafeIdx::magic_1();
        assert!((val + SafeIdx::max_value()).is_invalid());

        let mut val = SafeIdx::magic_1();
        val += 1;
        assert!(val == 2);

        let mut val = SafeIdx::magic_1();
        val += usize::max_value();
        assert!(val.is_invalid());

        let val = SafeIdx::magic_1();
        assert!((val + 1) == 2);

        let val = SafeIdx::magic_1();
        assert!((val + usize::max_value()).is_invalid());
    }

    #[test]
    fn safe_idx_sub() {
        let mut val = SafeIdx::magic_1();
        val -= SafeIdx::magic_1();
        assert!(val == 0);

        let mut val = SafeIdx::min_value();
        val -= SafeIdx::magic_1();
        assert!(val.is_invalid());

        let val = SafeIdx::magic_1();
        assert!((val - SafeIdx::magic_1()) == 0);

        let val = SafeIdx::min_value();
        assert!((val - SafeIdx::magic_1()).is_invalid());

        let mut val = SafeIdx::magic_1();
        val -= 1;
        assert!(val == 0);

        let mut val = SafeIdx::min_value();
        val -= 1;
        assert!(val.is_invalid());

        let val = SafeIdx::magic_1();
        assert!((val - 1) == 0);

        let val = SafeIdx::min_value();
        assert!((val - 1).is_invalid());
    }
}
