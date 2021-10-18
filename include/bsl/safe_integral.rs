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
use crate::Integer;
use crate::SignedInteger;
use crate::SourceLocation;
use crate::UnsignedInteger;
use core::cmp;
use core::fmt;
use core::ops;

/// @class bsl::safe_integral
///
/// <!-- description -->
///   @brief Please see safe_integral.hpp for a complete set of details as to
///     what this class is, and how to use it. The C++ description still
///     applies for Rust.
///
/// <!-- template parameters -->
///   @tparam T the integral type to encapsulate.
///
#[derive(Debug, Default, Copy, Clone)]
pub struct SafeIntegral<T> {
    m_val: T,
    m_poisoned: bool,
    m_unchecked: bool,
}

impl<T> SafeIntegral<T>
where
    T: Integer,
{
    #[cfg(debug_assertions)]
    fn update_poisoned(&mut self, poisoned: bool) {
        self.m_poisoned |= poisoned;
        self.m_unchecked = true;
    }

    #[cfg(not(debug_assertions))]
    fn update_poisoned(&mut self, poisoned: bool) {
        self.m_poisoned |= poisoned;
    }

    #[cfg(debug_assertions)]
    fn verify_poison_has_been_checked(&self, sloc: SourceLocation) {
        if self.m_unchecked {
            crate::assert("SafeIntegrals must be checked before use", sloc);
        } else {
            crate::touch();
        }
    }

    #[cfg(not(debug_assertions))]
    fn verify_poison_has_been_checked(&self, _sloc: SourceLocation) {
        crate::discard(self);
    }

    #[cfg(debug_assertions)]
    fn mark_as_unchecked(&mut self) {
        self.m_unchecked = true;
    }

    #[cfg(not(debug_assertions))]
    fn mark_as_unchecked(&mut self) {
        crate::discard(self);
    }

    #[cfg(debug_assertions)]
    fn mark_as_checked_if_valid(&mut self) {
        self.m_unchecked = self.m_poisoned;
    }

    #[cfg(not(debug_assertions))]
    fn mark_as_checked_if_valid(&mut self) {
        crate::discard(self);
    }
}

impl<T> SafeIntegral<T>
where
    T: Sized,
{
    /// <!-- description -->
    ///   @brief Value initialization constructor
    ///
    /// <!-- inputs/outputs -->
    ///   @param val the value to set the SafeIntegral to
    ///
    pub const fn new(val: T) -> Self {
        Self {
            m_val: val,
            m_poisoned: false,
            m_unchecked: false,
        }
    }
}

impl<T> SafeIntegral<T>
where
    T: Integer,
{
    /// <!-- description -->
    ///   @brief Returns a new SafeIntegral given a value and flags
    ///     from another SafeIntegral of a different type.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val the value to set the new SafeIntegral to
    ///   @param flags the SafeIntegral to get the flags from
    ///   @return Returns a new SafeIntegral given a value and flags
    ///     from another SafeIntegral of a different type.
    ///
    pub fn new_with_flags_from<U>(val: T, flags: SafeIntegral<U>) -> Self
    where
        U: Integer,
    {
        Self {
            m_val: val,
            m_poisoned: flags.m_poisoned,
            m_unchecked: flags.m_unchecked,
        }
    }

    /// <!-- description -->
    ///   @brief Returns a new SafeIntegral given an optional value and flags
    ///     from another SafeIntegral of a different type. If the optional
    ///     value is None, SafeIntegral::failure() is returned.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val the optional value to set the new SafeIntegral to
    ///   @param flags the SafeIntegral to get the flags from
    ///   @return Returns a new SafeIntegral given an optional value and flags
    ///     from another SafeIntegral of a different type. If the optional
    ///     value is None, SafeIntegral::failure() is returned.
    ///
    pub fn new_from_option_with_flags_from<U>(val: Option<T>, flags: SafeIntegral<U>) -> Self
    where
        U: Integer,
    {
        match val {
            Some(v) => Self {
                m_val: v,
                m_poisoned: flags.m_poisoned,
                m_unchecked: flags.m_unchecked,
            },
            None => Self {
                m_val: T::default(),
                m_poisoned: true,
                m_unchecked: true,
            },
        }
    }

    /// <!-- description -->
    ///   @brief Returns the max value the bsl::SafeIntegral can store.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the max value the bsl::SafeIntegral can store.
    ///
    pub fn max_value() -> Self {
        return Self::new(T::max_value());
    }

    /// <!-- description -->
    ///   @brief Returns the min value the bsl::SafeIntegral can store.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the min value the bsl::SafeIntegral can store.
    ///
    pub fn min_value() -> Self {
        return Self::new(T::min_value());
    }
}

impl<T> SafeIntegral<T>
where
    T: SignedInteger,
{
    /// <!-- description -->
    ///   @brief Returns Self::new(T::magic_neg_1());
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns Self::new(T::magic_neg_1());
    ///
    pub fn magic_neg_1() -> Self {
        return Self::new(T::magic_neg_1());
    }

    /// <!-- description -->
    ///   @brief Returns Self::new(T::magic_neg_1());
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns Self::new(T::magic_neg_1());
    ///
    pub fn magic_neg_2() -> Self {
        return Self::new(T::magic_neg_2());
    }

    /// <!-- description -->
    ///   @brief Returns Self::new(T::magic_neg_1());
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns Self::new(T::magic_neg_1());
    ///
    pub fn magic_neg_3() -> Self {
        return Self::new(T::magic_neg_3());
    }
}

impl<T> SafeIntegral<T>
where
    T: Integer,
{
    /// <!-- description -->
    ///   @brief Returns Self::new(T::magic_0());
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns Self::new(T::magic_0());
    ///
    pub fn magic_0() -> Self {
        return Self::new(T::magic_0());
    }

    /// <!-- description -->
    ///   @brief Returns Self::new(T::magic_1());
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns Self::new(T::magic_1());
    ///
    pub fn magic_1() -> Self {
        return Self::new(T::magic_1());
    }

    /// <!-- description -->
    ///   @brief Returns Self::new(T::magic_2());
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns Self::new(T::magic_2());
    ///
    pub fn magic_2() -> Self {
        return Self::new(T::magic_2());
    }

    /// <!-- description -->
    ///   @brief Returns Self::new(T::magic_3());
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns Self::new(T::magic_3());
    ///
    pub fn magic_3() -> Self {
        return Self::new(T::magic_3());
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
    pub fn data_as_ref(&mut self) -> &mut T {
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
    pub fn cdata_as_ref(&self) -> &T {
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
    pub fn data(&mut self) -> *mut T {
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
    pub fn cdata(&mut self) -> *const T {
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
    pub fn get_with_sloc(&self, sloc: SourceLocation) -> T {
        if self.m_poisoned {
            crate::assert("a poisoned SafeIntegral was read", sloc);
        } else {
            crate::touch();
        }

        self.verify_poison_has_been_checked(sloc);
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
    pub fn get(&self) -> T {
        return self.get_with_sloc(crate::here());
    }
}

impl<T> SafeIntegral<T>
where
    T: Sized,
{
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
    pub const fn get_unsafe(&self) -> &T {
        return &self.m_val;
    }
}

impl<T> SafeIntegral<T>
where
    T: Integer,
{
    /// <!-- description -->
    ///   @brief Returns true if the SafeIntegral is positive.
    ///     Attempting to run is_pos on an invalid SafeIntegral
    ///     results in undefined behavior.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the SafeIntegral is positive
    ///
    #[track_caller]
    pub fn is_pos(&self) -> bool {
        let sloc = crate::here();
        if self.m_poisoned {
            crate::assert("a poisoned SafeIntegral was read", sloc);
        } else {
            crate::touch();
        }

        self.verify_poison_has_been_checked(sloc);
        return self.m_val > T::magic_0();
    }
}

impl<T> SafeIntegral<T>
where
    T: SignedInteger,
{
    /// <!-- description -->
    ///   @brief Returns true if the SafeIntegral is negative.
    ///     Attempting to run is_neg on an invalid SafeIntegral
    ///     results in undefined behavior.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the SafeIntegral is negative
    ///
    #[track_caller]
    pub fn is_neg(&self) -> bool {
        let sloc = crate::here();
        if self.m_poisoned {
            crate::assert("a poisoned SafeIntegral was read", sloc);
        } else {
            crate::touch();
        }

        self.verify_poison_has_been_checked(sloc);
        return self.m_val < T::magic_0();
    }
}

impl<T> SafeIntegral<T>
where
    T: Integer,
{
    /// <!-- description -->
    ///   @brief Returns true if the SafeIntegral is 0.
    ///     Attempting to run is_zero on an invalid SafeIntegral
    ///     results in undefined behavior.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the SafeIntegral is 0
    ///
    #[track_caller]
    pub fn is_zero(&self) -> bool {
        let sloc = crate::here();
        if self.m_poisoned {
            crate::assert("a poisoned SafeIntegral was read", sloc);
        } else {
            crate::touch();
        }

        self.verify_poison_has_been_checked(sloc);
        return self.m_val == T::magic_0();
    }

    /// <!-- description -->
    ///   @brief Returns true if the SafeIntegral has encountered and
    ///     error, false otherwise. This function WILL mark the
    ///     SafeIntegral as checked.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the SafeIntegral has encountered and
    ///     error, false otherwise. This function WILL mark the
    ///     SafeIntegral as checked.
    ///
    pub fn is_poisoned(&mut self) -> bool {
        self.mark_as_checked_if_valid();
        return self.m_poisoned;
    }

    /// <!-- description -->
    ///   @brief Returns true if the SafeIntegral has encountered and
    ///     error, false otherwise. This function DOES NOT marked the
    ///     SafeIntegral as checked.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the SafeIntegral has encountered and
    ///     error, false otherwise. This function DOES NOT marked the
    ///     SafeIntegral as checked.
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

    /// <!-- description -->
    ///   @brief Returns true if the SafeIntegral is 0. Will
    ///     always return true if an error has been encountered. This
    ///     function WILL mark the SafeIntegral as checked.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the SafeIntegral is 0. Will
    ///     always return true if an error has been encountered. This
    ///     function WILL mark the SafeIntegral as checked.
    ///
    pub fn is_zero_or_poisoned(&mut self) -> bool {
        if self.is_poisoned() {
            return true;
        }

        return self.m_val == T::magic_0();
    }

    /// <!-- description -->
    ///   @brief Returns true if the SafeIntegral is 0. Will
    ///     always return true if an error has been encountered. This
    ///     function DOES NOT marked the SafeIntegral as checked.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the SafeIntegral is 0. Will
    ///     always return true if an error has been encountered. This
    ///     function DOES NOT marked the SafeIntegral as checked.
    ///
    pub fn is_zero_or_invalid(&self) -> bool {
        if self.is_invalid() {
            return true;
        }

        return self.m_val == T::magic_0();
    }

    /// <!-- description -->
    ///   @brief Returns the checked version of the SafeIntegral. This
    ///     should only be used if the SafeIntegral has actually been
    ///     checked, or unit testing has proven that it is impossible for
    ///     the SafeIntegral to become poisoned (because all of the
    ///     possible ways the integral could become poisoned have been
    ///     verified external to the SafeIntegral).
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the checked version of the SafeIntegral.
    ///
    #[cfg(debug_assertions)]
    #[track_caller]
    pub fn checked(&self) -> Self {
        if self.m_poisoned {
            crate::assert("a poisoned SafeIntegral was read", crate::here());
        }

        return Self {
            m_val: self.m_val,
            m_poisoned: self.m_poisoned,
            m_unchecked: false,
        };
    }

    /// <!-- description -->
    ///   @brief Returns the checked version of the SafeIntegral. This
    ///     should only be used if the SafeIntegral has actually been
    ///     checked, or unit testing has proven that it is impossible for
    ///     the SafeIntegral to become poisoned (because all of the
    ///     possible ways the integral could become poisoned have been
    ///     verified external to the SafeIntegral).
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the checked version of the SafeIntegral.
    ///
    #[cfg(not(debug_assertions))]
    pub fn checked(&self) -> Self {
        return *self;
    }

    /// <!-- description -->
    ///   @brief Returns true if the SafeIntegral must be checked using
    ///     ! or is_poisoned() prior to using get(), or any helper that
    ///     uses get(). In release mode, this function always returns
    ///     false.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the SafeIntegral must be checked using
    ///     ! or is_poisoned() prior to using get(), or any helper that
    ///     uses get(). In release mode, this function always returns
    ///     false.
    ///
    #[cfg(debug_assertions)]
    pub fn is_unchecked(&self) -> bool {
        return self.m_unchecked;
    }

    /// <!-- description -->
    ///   @brief Returns true if the SafeIntegral must be checked using
    ///     ! or is_poisoned() prior to using get(), or any helper that
    ///     uses get(). In release mode, this function always returns
    ///     false.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the SafeIntegral must be checked using
    ///     ! or is_poisoned() prior to using get(), or any helper that
    ///     uses get(). In release mode, this function always returns
    ///     false.
    ///
    #[cfg(not(debug_assertions))]
    pub fn is_unchecked(&self) -> bool {
        return false;
    }

    /// <!-- description -->
    ///   @brief Returns !self.is_unchecked().
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns !self.is_unchecked()
    ///
    pub fn is_checked(&self) -> bool {
        return !self.is_unchecked();
    }

    /// <!-- description -->
    ///   @brief Returns self.is_valid() && self.is_checked()
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns self.is_valid() && self.is_checked()
    ///
    #[cfg(debug_assertions)]
    pub fn is_valid_and_checked(&self) -> bool {
        if self.is_invalid() {
            return false;
        }

        if self.is_unchecked() {
            return false;
        }

        return true;
    }

    /// <!-- description -->
    ///   @brief Returns self.is_valid() && self.is_checked()
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns self.is_valid() && self.is_checked()
    ///
    #[cfg(not(debug_assertions))]
    pub fn is_valid_and_checked(&self) -> bool {
        return self.is_valid();
    }

    /// <!-- description -->
    ///   @brief Returns a SafeIntegral with the poisoned flag set
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns a SafeIntegral with the poisoned flag set
    ///
    pub fn failure() -> Self {
        return Self {
            m_val: T::default(),
            m_poisoned: true,
            m_unchecked: true,
        };
    }

    /// <!-- description -->
    ///   @brief Returns *self if lhs.get() > rhs.get(). Otherwise
    ///     returns rhs.
    ///
    /// <!-- inputs/outputs -->
    ///   @param rhs the other integral to compare with
    ///   @return Returns *self if lhs.get() > rhs.get(). Otherwise
    ///     returns rhs.
    ///
    pub fn max(&self, rhs: Self) -> Self {
        if self.is_invalid() {
            return SafeIntegral::<T>::failure();
        }

        if rhs.is_invalid() {
            return SafeIntegral::<T>::failure();
        }

        if *self > rhs {
            return *self;
        }

        return rhs;
    }

    /// <!-- description -->
    ///   @brief Returns *self if lhs.get() < rhs.get(). Otherwise
    ///     returns rhs.
    ///
    /// <!-- inputs/outputs -->
    ///   @param rhs the other integral to compare with
    ///   @return Returns *self if lhs.get() < rhs.get(). Otherwise
    ///     returns rhs.
    ///
    pub fn min(&self, rhs: Self) -> Self {
        if self.is_invalid() {
            return SafeIntegral::<T>::failure();
        }

        if rhs.is_invalid() {
            return SafeIntegral::<T>::failure();
        }

        if *self < rhs {
            return *self;
        }

        return rhs;
    }
}

// -----------------------------------------------------------------------------
// Rational
// -----------------------------------------------------------------------------

impl<T> PartialEq for SafeIntegral<T>
where
    T: Integer,
{
    #[track_caller]
    fn eq(&self, rhs: &Self) -> bool {
        let sloc = crate::here();
        return self.get_with_sloc(sloc) == rhs.get_with_sloc(sloc);
    }
}

impl<T> PartialEq<T> for SafeIntegral<T>
where
    T: Integer,
{
    #[track_caller]
    fn eq(&self, rhs: &T) -> bool {
        let sloc = crate::here();
        return self.get_with_sloc(sloc) == *rhs;
    }
}

impl<T> PartialOrd for SafeIntegral<T>
where
    T: Integer,
{
    #[track_caller]
    fn partial_cmp(&self, rhs: &Self) -> Option<cmp::Ordering> {
        let sloc = crate::here();
        return Some(self.get_with_sloc(sloc).cmp(&rhs.get_with_sloc(sloc)));
    }
}

impl<T> PartialOrd<T> for SafeIntegral<T>
where
    T: Integer,
{
    #[track_caller]
    fn partial_cmp(&self, rhs: &T) -> Option<cmp::Ordering> {
        let sloc = crate::here();
        return Some(self.get_with_sloc(sloc).cmp(rhs));
    }
}

// -----------------------------------------------------------------------------
// Arithmetic
// -----------------------------------------------------------------------------

impl<T> ops::AddAssign for SafeIntegral<T>
where
    T: Integer,
{
    fn add_assign(&mut self, rhs: SafeIntegral<T>) {
        match self.m_val.add_checked(rhs.m_val) {
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

impl<T> ops::AddAssign<T> for SafeIntegral<T>
where
    T: Integer,
{
    fn add_assign(&mut self, rhs: T) {
        match self.m_val.add_checked(rhs) {
            Some(val) => {
                self.m_val = val;
                self.mark_as_unchecked();
            }
            None => {
                self.update_poisoned(true);
            }
        }
    }
}

impl<T> ops::Add<SafeIntegral<T>> for SafeIntegral<T>
where
    T: Integer,
{
    type Output = SafeIntegral<T>;
    fn add(self, rhs: SafeIntegral<T>) -> Self::Output {
        let mut ret = self.clone();
        ret += rhs;
        return ret;
    }
}

impl<T> ops::Add<T> for SafeIntegral<T>
where
    T: Integer,
{
    type Output = SafeIntegral<T>;
    fn add(self, rhs: T) -> Self::Output {
        let mut ret = self.clone();
        ret += rhs;
        return ret;
    }
}

impl<T> ops::SubAssign for SafeIntegral<T>
where
    T: Integer,
{
    fn sub_assign(&mut self, rhs: SafeIntegral<T>) {
        match self.m_val.sub_checked(rhs.m_val) {
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

impl<T> ops::SubAssign<T> for SafeIntegral<T>
where
    T: Integer,
{
    fn sub_assign(&mut self, rhs: T) {
        match self.m_val.sub_checked(rhs) {
            Some(val) => {
                self.m_val = val;
                self.mark_as_unchecked();
            }
            None => {
                self.update_poisoned(true);
            }
        }
    }
}

impl<T> ops::Sub<SafeIntegral<T>> for SafeIntegral<T>
where
    T: Integer,
{
    type Output = SafeIntegral<T>;
    fn sub(self, rhs: SafeIntegral<T>) -> Self::Output {
        let mut ret = self.clone();
        ret -= rhs;
        return ret;
    }
}

impl<T> ops::Sub<T> for SafeIntegral<T>
where
    T: Integer,
{
    type Output = SafeIntegral<T>;
    fn sub(self, rhs: T) -> Self::Output {
        let mut ret = self.clone();
        ret -= rhs;
        return ret;
    }
}

impl<T> ops::MulAssign for SafeIntegral<T>
where
    T: Integer,
{
    fn mul_assign(&mut self, rhs: SafeIntegral<T>) {
        match self.m_val.mul_checked(rhs.m_val) {
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

impl<T> ops::MulAssign<T> for SafeIntegral<T>
where
    T: Integer,
{
    fn mul_assign(&mut self, rhs: T) {
        match self.m_val.mul_checked(rhs) {
            Some(val) => {
                self.m_val = val;
                self.mark_as_unchecked();
            }
            None => {
                self.update_poisoned(true);
            }
        }
    }
}

impl<T> ops::Mul<SafeIntegral<T>> for SafeIntegral<T>
where
    T: Integer,
{
    type Output = SafeIntegral<T>;
    fn mul(self, rhs: SafeIntegral<T>) -> Self::Output {
        let mut ret = self.clone();
        ret *= rhs;
        return ret;
    }
}

impl<T> ops::Mul<T> for SafeIntegral<T>
where
    T: Integer,
{
    type Output = SafeIntegral<T>;
    fn mul(self, rhs: T) -> Self::Output {
        let mut ret = self.clone();
        ret *= rhs;
        return ret;
    }
}

impl<T> ops::DivAssign for SafeIntegral<T>
where
    T: Integer,
{
    fn div_assign(&mut self, rhs: SafeIntegral<T>) {
        match self.m_val.div_checked(rhs.m_val) {
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

impl<T> ops::DivAssign<T> for SafeIntegral<T>
where
    T: Integer,
{
    fn div_assign(&mut self, rhs: T) {
        match self.m_val.div_checked(rhs) {
            Some(val) => {
                self.m_val = val;
                self.mark_as_unchecked();
            }
            None => {
                self.update_poisoned(true);
            }
        }
    }
}

impl<T> ops::Div<SafeIntegral<T>> for SafeIntegral<T>
where
    T: Integer,
{
    type Output = SafeIntegral<T>;
    fn div(self, rhs: SafeIntegral<T>) -> Self::Output {
        let mut ret = self.clone();
        ret /= rhs;
        return ret;
    }
}

impl<T> ops::Div<T> for SafeIntegral<T>
where
    T: Integer,
{
    type Output = SafeIntegral<T>;
    fn div(self, rhs: T) -> Self::Output {
        let mut ret = self.clone();
        ret /= rhs;
        return ret;
    }
}

impl<T> ops::RemAssign for SafeIntegral<T>
where
    T: Integer,
{
    fn rem_assign(&mut self, rhs: SafeIntegral<T>) {
        match self.m_val.rem_checked(rhs.m_val) {
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

impl<T> ops::RemAssign<T> for SafeIntegral<T>
where
    T: Integer,
{
    fn rem_assign(&mut self, rhs: T) {
        match self.m_val.rem_checked(rhs) {
            Some(val) => {
                self.m_val = val;
                self.mark_as_unchecked();
            }
            None => {
                self.update_poisoned(true);
            }
        }
    }
}

impl<T> ops::Rem<SafeIntegral<T>> for SafeIntegral<T>
where
    T: Integer,
{
    type Output = SafeIntegral<T>;
    fn rem(self, rhs: SafeIntegral<T>) -> Self::Output {
        let mut ret = self.clone();
        ret %= rhs;
        return ret;
    }
}

impl<T> ops::Rem<T> for SafeIntegral<T>
where
    T: Integer,
{
    type Output = SafeIntegral<T>;
    fn rem(self, rhs: T) -> Self::Output {
        let mut ret = self.clone();
        ret %= rhs;
        return ret;
    }
}

// -----------------------------------------------------------------------------
// Shift
// -----------------------------------------------------------------------------

impl<T> ops::ShlAssign<SafeIntegral<T>> for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    fn shl_assign(&mut self, rhs: SafeIntegral<T>) {
        match rhs.m_val.into_u32() {
            Some(v) => self.m_val = self.m_val.shl_wrapping(v),
            None => *self = SafeIntegral::<T>::default(),
        }

        self.update_poisoned(rhs.is_invalid());
        self.mark_as_checked_if_valid();
    }
}

impl<T> ops::ShlAssign<T> for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    fn shl_assign(&mut self, rhs: T) {
        match rhs.into_u32() {
            Some(v) => self.m_val = self.m_val.shl_wrapping(v),
            None => *self = SafeIntegral::<T>::default(),
        }

        self.mark_as_checked_if_valid();
    }
}

impl<T> ops::Shl<SafeIntegral<T>> for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    type Output = SafeIntegral<T>;
    fn shl(self, rhs: SafeIntegral<T>) -> Self::Output {
        let mut ret = self.clone();
        ret <<= rhs;
        return ret;
    }
}

impl<T> ops::Shl<T> for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    type Output = SafeIntegral<T>;
    fn shl(self, rhs: T) -> Self::Output {
        let mut ret = self.clone();
        ret <<= rhs;
        return ret;
    }
}

impl<T> ops::ShrAssign<SafeIntegral<T>> for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    fn shr_assign(&mut self, rhs: SafeIntegral<T>) {
        match rhs.m_val.into_u32() {
            Some(v) => self.m_val = self.m_val.shr_wrapping(v),
            None => *self = SafeIntegral::<T>::default(),
        }

        self.update_poisoned(rhs.is_invalid());
        self.mark_as_checked_if_valid();
    }
}

impl<T> ops::ShrAssign<T> for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    fn shr_assign(&mut self, rhs: T) {
        match rhs.into_u32() {
            Some(v) => self.m_val = self.m_val.shr_wrapping(v),
            None => *self = SafeIntegral::<T>::default(),
        }

        self.mark_as_checked_if_valid();
    }
}

impl<T> ops::Shr<SafeIntegral<T>> for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    type Output = SafeIntegral<T>;
    fn shr(self, rhs: SafeIntegral<T>) -> Self::Output {
        let mut ret = self.clone();
        ret >>= rhs;
        return ret;
    }
}

impl<T> ops::Shr<T> for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    type Output = SafeIntegral<T>;
    fn shr(self, rhs: T) -> Self::Output {
        let mut ret = self.clone();
        ret >>= rhs;
        return ret;
    }
}

// -----------------------------------------------------------------------------
// Binary
// -----------------------------------------------------------------------------

impl<T> ops::BitAndAssign for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    fn bitand_assign(&mut self, rhs: Self) {
        self.m_val &= rhs.m_val;
        self.update_poisoned(rhs.is_invalid());
        self.mark_as_checked_if_valid();
    }
}

impl<T> ops::BitAndAssign<T> for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    fn bitand_assign(&mut self, rhs: T) {
        self.m_val &= rhs;
    }
}

impl<T> ops::BitAnd for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    type Output = SafeIntegral<T>;
    fn bitand(self, rhs: SafeIntegral<T>) -> Self::Output {
        let mut ret = self.clone();
        ret &= rhs;
        return ret;
    }
}

impl<T> ops::BitAnd<T> for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    type Output = SafeIntegral<T>;
    fn bitand(self, rhs: T) -> Self::Output {
        let mut ret = self.clone();
        ret &= rhs;
        return ret;
    }
}

impl<T> ops::BitOrAssign for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    fn bitor_assign(&mut self, rhs: Self) {
        self.m_val |= rhs.m_val;
        self.update_poisoned(rhs.is_invalid());
        self.mark_as_checked_if_valid();
    }
}

impl<T> ops::BitOrAssign<T> for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    fn bitor_assign(&mut self, rhs: T) {
        self.m_val |= rhs;
    }
}

impl<T> ops::BitOr for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    type Output = SafeIntegral<T>;
    fn bitor(self, rhs: SafeIntegral<T>) -> Self::Output {
        let mut ret = self.clone();
        ret |= rhs;
        return ret;
    }
}

impl<T> ops::BitOr<T> for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    type Output = SafeIntegral<T>;
    fn bitor(self, rhs: T) -> Self::Output {
        let mut ret = self.clone();
        ret |= rhs;
        return ret;
    }
}

impl<T> ops::BitXorAssign for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    fn bitxor_assign(&mut self, rhs: Self) {
        self.m_val ^= rhs.m_val;
        self.update_poisoned(rhs.is_invalid());
        self.mark_as_checked_if_valid();
    }
}

impl<T> ops::BitXorAssign<T> for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    fn bitxor_assign(&mut self, rhs: T) {
        self.m_val ^= rhs;
    }
}

impl<T> ops::BitXor for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    type Output = SafeIntegral<T>;
    fn bitxor(self, rhs: SafeIntegral<T>) -> Self::Output {
        let mut ret = self.clone();
        ret ^= rhs;
        return ret;
    }
}

impl<T> ops::BitXor<T> for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    type Output = SafeIntegral<T>;
    fn bitxor(self, rhs: T) -> Self::Output {
        let mut ret = self.clone();
        ret ^= rhs;
        return ret;
    }
}

// -----------------------------------------------------------------------------
// Complement
// -----------------------------------------------------------------------------

impl<T> ops::Not for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    type Output = Self;
    fn not(self) -> Self::Output {
        let mut ret = self.clone();
        ret.m_val = !ret.m_val;
        return ret;
    }
}

// -----------------------------------------------------------------------------
// Negation
// -----------------------------------------------------------------------------

impl<T> ops::Neg for SafeIntegral<T>
where
    T: SignedInteger,
{
    type Output = Self;
    fn neg(self) -> Self::Output {
        let mut ret = self.clone();
        match self.m_val.neg_checked() {
            Some(val) => {
                ret.m_val = val;
            }
            None => {
                ret.update_poisoned(true);
            }
        }

        return ret;
    }
}

// -----------------------------------------------------------------------------
// Output
// -----------------------------------------------------------------------------

impl<T> fmt::Display for SafeIntegral<T>
where
    T: Integer,
{
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

impl<T> fmt::Binary for SafeIntegral<T>
where
    T: Integer,
{
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

impl<T> fmt::LowerExp for SafeIntegral<T>
where
    T: Integer,
{
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

impl<T> fmt::LowerHex for SafeIntegral<T>
where
    T: Integer,
{
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

impl<T> fmt::Octal for SafeIntegral<T>
where
    T: Integer,
{
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

impl<T> fmt::UpperExp for SafeIntegral<T>
where
    T: Integer,
{
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

impl<T> fmt::UpperHex for SafeIntegral<T>
where
    T: Integer,
{
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
// Helpers
// -----------------------------------------------------------------------------

/// <!-- description -->
///   @brief Returns SafeIntegral<T>{val}
///
/// <!-- inputs/outputs -->
///   @tparam T the integral type to make safe.
///   @param val the integral to make safe
///   @return Returns SafeIntegral<T>{val}
///
pub const fn make_safe<T>(val: T) -> SafeIntegral<T> {
    return SafeIntegral::<T>::new(val);
}

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

/// @brief provides the bsl::SafeIntegral version of i8
pub type SafeI8 = SafeIntegral<i8>;
/// @brief provides the bsl::SafeIntegral version of i16
pub type SafeI16 = SafeIntegral<i16>;
/// @brief provides the bsl::SafeIntegral version of i32
pub type SafeI32 = SafeIntegral<i32>;
/// @brief provides the bsl::SafeIntegral version of i64
pub type SafeI64 = SafeIntegral<i64>;

/// @brief provides the bsl::SafeIntegral version of u8
pub type SafeU8 = SafeIntegral<u8>;
/// @brief provides the bsl::SafeIntegral version of u16
pub type SafeU16 = SafeIntegral<u16>;
/// @brief provides the bsl::SafeIntegral version of u32
pub type SafeU32 = SafeIntegral<u32>;
/// @brief provides the bsl::SafeIntegral version of u64
pub type SafeU64 = SafeIntegral<u64>;
/// @brief provides the bsl::SafeIntegral version of usize
pub type SafeUMx = SafeIntegral<usize>;

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod safe_integral_tests {
    use super::*;

    fn safe_integral_constructors_for_t<T>()
    where
        T: Integer,
    {
        assert!(SafeIntegral::<T>::default().is_valid());
        assert!(SafeIntegral::<T>::new(T::magic_1()).is_valid());

        let val = SafeIntegral::<T>::default();
        assert!(SafeIntegral::<T>::new_with_flags_from(val.get(), val).is_valid());
        let val = SafeIntegral::<T>::failure();
        assert!(SafeIntegral::<T>::new_with_flags_from(*val.cdata_as_ref(), val).is_invalid());

        let val = SafeIntegral::<T>::default();
        let opt = Some(*val.cdata_as_ref());
        assert!(SafeIntegral::<T>::new_from_option_with_flags_from(opt, val).is_valid());
        let val = SafeIntegral::<T>::failure();
        let opt = Some(*val.cdata_as_ref());
        assert!(SafeIntegral::<T>::new_from_option_with_flags_from(opt, val).is_invalid());
    }

    #[test]
    fn safe_integral_constructors() {
        safe_integral_constructors_for_t::<i8>();
        safe_integral_constructors_for_t::<i16>();
        safe_integral_constructors_for_t::<i32>();
        safe_integral_constructors_for_t::<i64>();
        safe_integral_constructors_for_t::<u8>();
        safe_integral_constructors_for_t::<u16>();
        safe_integral_constructors_for_t::<u32>();
        safe_integral_constructors_for_t::<u64>();
        safe_integral_constructors_for_t::<usize>();
    }

    fn safe_integral_debug_for_t<T>()
    where
        T: Integer,
    {
        print!("{}\n", SafeIntegral::<T>::magic_1());
        print!("{}\n", SafeIntegral::<T>::failure());
        print!("{:?}\n", SafeIntegral::<T>::magic_1());
        print!("{:?}\n", SafeIntegral::<T>::failure());
        print!("{:x?}\n", SafeIntegral::<T>::magic_1());
        print!("{:x?}\n", SafeIntegral::<T>::failure());
        print!("{:X?}\n", SafeIntegral::<T>::magic_1());
        print!("{:X?}\n", SafeIntegral::<T>::failure());
        print!("{:o}\n", SafeIntegral::<T>::magic_1());
        print!("{:o}\n", SafeIntegral::<T>::failure());
        print!("{:x}\n", SafeIntegral::<T>::magic_1());
        print!("{:x}\n", SafeIntegral::<T>::failure());
        print!("{:X}\n", SafeIntegral::<T>::magic_1());
        print!("{:X}\n", SafeIntegral::<T>::failure());
        print!("{:b}\n", SafeIntegral::<T>::magic_1());
        print!("{:b}\n", SafeIntegral::<T>::failure());
        print!("{:e}\n", SafeIntegral::<T>::magic_1());
        print!("{:e}\n", SafeIntegral::<T>::failure());
        print!("{:E}\n", SafeIntegral::<T>::magic_1());
        print!("{:E}\n", SafeIntegral::<T>::failure());
    }

    #[test]
    fn safe_integral_debug() {
        safe_integral_debug_for_t::<i8>();
        safe_integral_debug_for_t::<i16>();
        safe_integral_debug_for_t::<i32>();
        safe_integral_debug_for_t::<i64>();
        safe_integral_debug_for_t::<u8>();
        safe_integral_debug_for_t::<u16>();
        safe_integral_debug_for_t::<u32>();
        safe_integral_debug_for_t::<u64>();
        safe_integral_debug_for_t::<usize>();
    }

    fn safe_integral_max_min_for_t<T>()
    where
        T: Integer,
    {
        assert!(SafeIntegral::<T>::max_value() == T::max_value());
        assert!(SafeIntegral::<T>::min_value() == T::min_value());
    }

    #[test]
    fn safe_integral_max_min() {
        safe_integral_max_min_for_t::<i8>();
        safe_integral_max_min_for_t::<i16>();
        safe_integral_max_min_for_t::<i32>();
        safe_integral_max_min_for_t::<i64>();
        safe_integral_max_min_for_t::<u8>();
        safe_integral_max_min_for_t::<u16>();
        safe_integral_max_min_for_t::<u32>();
        safe_integral_max_min_for_t::<u64>();
        safe_integral_max_min_for_t::<usize>();
    }

    fn safe_integral_magic_for_t<T>()
    where
        T: Integer,
    {
        assert!(SafeIntegral::<T>::magic_0() == T::magic_0());
        assert!(SafeIntegral::<T>::magic_1() == T::magic_1());
        assert!(SafeIntegral::<T>::magic_2() == T::magic_2());
        assert!(SafeIntegral::<T>::magic_3() == T::magic_3());
    }

    fn safe_integral_magic_for_signed_t<T>()
    where
        T: SignedInteger,
    {
        assert!(SafeIntegral::<T>::magic_neg_1() == T::magic_neg_1());
    }

    #[test]
    fn safe_integral_magic() {
        safe_integral_magic_for_t::<i8>();
        safe_integral_magic_for_t::<i16>();
        safe_integral_magic_for_t::<i32>();
        safe_integral_magic_for_t::<i64>();
        safe_integral_magic_for_t::<u8>();
        safe_integral_magic_for_t::<u16>();
        safe_integral_magic_for_t::<u32>();
        safe_integral_magic_for_t::<u64>();
        safe_integral_magic_for_t::<usize>();

        safe_integral_magic_for_signed_t::<i8>();
        safe_integral_magic_for_signed_t::<i16>();
        safe_integral_magic_for_signed_t::<i32>();
        safe_integral_magic_for_signed_t::<i64>();
    }

    fn safe_integral_data_for_t<T>()
    where
        T: Integer,
    {
        let mut val = SafeIntegral::<T>::default();

        unsafe {
            *val.data_as_ref() = T::magic_1();
            assert!(*val.data_as_ref() == T::magic_1());
            assert!(*val.cdata_as_ref() == T::magic_1());
            *val.data_as_ref() = T::magic_2();
            assert!(*val.data_as_ref() == T::magic_2());
            assert!(*val.cdata_as_ref() == T::magic_2());

            *val.data() = T::magic_1();
            assert!(*val.data() == T::magic_1());
            assert!(*val.cdata() == T::magic_1());
            *val.data() = T::magic_2();
            assert!(*val.data() == T::magic_2());
            assert!(*val.cdata() == T::magic_2());
        }
    }

    #[test]
    fn safe_integral_data() {
        safe_integral_data_for_t::<i8>();
        safe_integral_data_for_t::<i16>();
        safe_integral_data_for_t::<i32>();
        safe_integral_data_for_t::<i64>();
        safe_integral_data_for_t::<u8>();
        safe_integral_data_for_t::<u16>();
        safe_integral_data_for_t::<u32>();
        safe_integral_data_for_t::<u64>();
        safe_integral_data_for_t::<usize>();
    }

    fn safe_integral_get_for_t<T>()
    where
        T: Integer,
    {
        let val = SafeIntegral::new(T::magic_1());
        assert!(val.get() == T::magic_1());
    }

    #[test]
    fn safe_integral_get() {
        safe_integral_get_for_t::<i8>();
        safe_integral_get_for_t::<i16>();
        safe_integral_get_for_t::<i32>();
        safe_integral_get_for_t::<i64>();
        safe_integral_get_for_t::<u8>();
        safe_integral_get_for_t::<u16>();
        safe_integral_get_for_t::<u32>();
        safe_integral_get_for_t::<u64>();
        safe_integral_get_for_t::<usize>();
    }

    fn safe_integral_get_unsafe_for_t<T>()
    where
        T: Integer,
    {
        let val = SafeIntegral::new(T::magic_1());
        assert!(*val.get_unsafe() == T::magic_1());
    }

    #[test]
    fn safe_integral_get_unsafe() {
        safe_integral_get_unsafe_for_t::<i8>();
        safe_integral_get_unsafe_for_t::<i16>();
        safe_integral_get_unsafe_for_t::<i32>();
        safe_integral_get_unsafe_for_t::<i64>();
        safe_integral_get_unsafe_for_t::<u8>();
        safe_integral_get_unsafe_for_t::<u16>();
        safe_integral_get_unsafe_for_t::<u32>();
        safe_integral_get_unsafe_for_t::<u64>();
        safe_integral_get_unsafe_for_t::<usize>();
    }

    fn safe_integral_is_queries_for_t<T>()
    where
        T: Integer,
    {
        assert_eq!(SafeIntegral::<T>::magic_0().is_zero(), true);
        assert_eq!(SafeIntegral::<T>::magic_0().is_pos(), false);
        assert_eq!(SafeIntegral::<T>::magic_1().is_zero(), false);
        assert_eq!(SafeIntegral::<T>::magic_1().is_pos(), true);
    }

    fn safe_integral_is_queries_for_signed_t<T>()
    where
        T: SignedInteger,
    {
        assert_eq!(SafeIntegral::<T>::magic_0().is_neg(), false);
        assert_eq!(SafeIntegral::<T>::magic_1().is_neg(), false);
        assert_eq!(SafeIntegral::<T>::magic_neg_1().is_neg(), true);
    }

    #[test]
    fn safe_integral_is_queries() {
        safe_integral_is_queries_for_t::<i8>();
        safe_integral_is_queries_for_t::<i16>();
        safe_integral_is_queries_for_t::<i32>();
        safe_integral_is_queries_for_t::<i64>();
        safe_integral_is_queries_for_t::<u8>();
        safe_integral_is_queries_for_t::<u16>();
        safe_integral_is_queries_for_t::<u32>();
        safe_integral_is_queries_for_t::<u64>();
        safe_integral_is_queries_for_t::<usize>();

        safe_integral_is_queries_for_signed_t::<i8>();
        safe_integral_is_queries_for_signed_t::<i16>();
        safe_integral_is_queries_for_signed_t::<i32>();
        safe_integral_is_queries_for_signed_t::<i64>();
    }

    fn safe_integral_failure_for_t<T>()
    where
        T: Integer,
    {
        assert_eq!(SafeIntegral::<T>::magic_0().is_poisoned(), false);
        assert_eq!(SafeIntegral::<T>::magic_0().is_invalid(), false);
        assert_eq!(SafeIntegral::<T>::magic_0().is_valid(), true);
        assert_eq!(SafeIntegral::<T>::magic_0().is_zero_or_poisoned(), true);
        assert_eq!(SafeIntegral::<T>::magic_0().is_zero_or_invalid(), true);
        assert_eq!(SafeIntegral::<T>::magic_0().is_unchecked(), false);
        assert_eq!(SafeIntegral::<T>::magic_0().is_checked(), true);
        assert_eq!(SafeIntegral::<T>::magic_0().is_valid_and_checked(), true);

        assert_eq!(SafeIntegral::<T>::magic_1().is_poisoned(), false);
        assert_eq!(SafeIntegral::<T>::magic_1().is_invalid(), false);
        assert_eq!(SafeIntegral::<T>::magic_1().is_valid(), true);
        assert_eq!(SafeIntegral::<T>::magic_1().is_zero_or_poisoned(), false);
        assert_eq!(SafeIntegral::<T>::magic_1().is_zero_or_invalid(), false);
        assert_eq!(SafeIntegral::<T>::magic_1().is_unchecked(), false);
        assert_eq!(SafeIntegral::<T>::magic_1().is_checked(), true);
        assert_eq!(SafeIntegral::<T>::magic_1().is_valid_and_checked(), true);

        assert_eq!(SafeIntegral::<T>::failure().is_poisoned(), true);
        assert_eq!(SafeIntegral::<T>::failure().is_invalid(), true);
        assert_eq!(SafeIntegral::<T>::failure().is_valid(), false);
        assert_eq!(SafeIntegral::<T>::failure().is_zero_or_poisoned(), true);
        assert_eq!(SafeIntegral::<T>::failure().is_zero_or_invalid(), true);
        assert_eq!(SafeIntegral::<T>::failure().is_unchecked(), true);
        assert_eq!(SafeIntegral::<T>::failure().is_checked(), false);
        assert_eq!(SafeIntegral::<T>::failure().is_valid_and_checked(), false);

        let val = SafeIntegral::<T>::magic_1() + SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_invalid(), false);
        assert_eq!(val.is_valid(), true);
        assert_eq!(val.is_zero_or_invalid(), false);
        assert_eq!(val.is_unchecked(), true);
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid_and_checked(), false);
    }

    #[test]
    fn safe_integral_failure() {
        safe_integral_failure_for_t::<i8>();
        safe_integral_failure_for_t::<i16>();
        safe_integral_failure_for_t::<i32>();
        safe_integral_failure_for_t::<i64>();
        safe_integral_failure_for_t::<u8>();
        safe_integral_failure_for_t::<u16>();
        safe_integral_failure_for_t::<u32>();
        safe_integral_failure_for_t::<u64>();
        safe_integral_failure_for_t::<usize>();
    }

    fn safe_integral_max_for_t<T>()
    where
        T: Integer,
    {
        let val1 = super::SafeIntegral::<T>::magic_1();
        let val2 = super::SafeIntegral::<T>::magic_2();
        let fail = super::SafeIntegral::<T>::failure();

        assert!(val1.max(val2) == val2);
        assert!(val2.max(val1) == val2);

        assert!(val1.max(fail).is_invalid());
        assert!(fail.max(val1).is_invalid());
    }

    #[test]
    fn safe_integral_max() {
        safe_integral_max_for_t::<i8>();
        safe_integral_max_for_t::<i16>();
        safe_integral_max_for_t::<i32>();
        safe_integral_max_for_t::<i64>();
        safe_integral_max_for_t::<u8>();
        safe_integral_max_for_t::<u16>();
        safe_integral_max_for_t::<u32>();
        safe_integral_max_for_t::<u64>();
        safe_integral_max_for_t::<usize>();
    }

    fn safe_integral_min_for_t<T>()
    where
        T: Integer,
    {
        let val1 = super::SafeIntegral::<T>::magic_1();
        let val2 = super::SafeIntegral::<T>::magic_2();
        let fail = super::SafeIntegral::<T>::failure();

        assert!(val1.min(val2) == val1);
        assert!(val2.min(val1) == val1);

        assert!(val1.min(fail).is_invalid());
        assert!(fail.min(val1).is_invalid());
    }

    #[test]
    fn safe_integral_min() {
        safe_integral_min_for_t::<i8>();
        safe_integral_min_for_t::<i16>();
        safe_integral_min_for_t::<i32>();
        safe_integral_min_for_t::<i64>();
        safe_integral_min_for_t::<u8>();
        safe_integral_min_for_t::<u16>();
        safe_integral_min_for_t::<u32>();
        safe_integral_min_for_t::<u64>();
        safe_integral_min_for_t::<usize>();
    }

    fn safe_integral_rational_for_t<T>()
    where
        T: Integer,
    {
        assert!(SafeIntegral::<T>::magic_1() == SafeIntegral::<T>::magic_1());
        assert!(SafeIntegral::<T>::magic_1() != SafeIntegral::<T>::magic_2());
        assert!(SafeIntegral::<T>::magic_1() < SafeIntegral::<T>::magic_2());
        assert!(SafeIntegral::<T>::magic_1() <= SafeIntegral::<T>::magic_2());
        assert!(SafeIntegral::<T>::magic_1() <= SafeIntegral::<T>::magic_1());
        assert!(SafeIntegral::<T>::magic_1() > SafeIntegral::<T>::magic_0());
        assert!(SafeIntegral::<T>::magic_1() >= SafeIntegral::<T>::magic_0());
        assert!(SafeIntegral::<T>::magic_1() >= SafeIntegral::<T>::magic_1());

        assert!(SafeIntegral::<T>::magic_1() == SafeIntegral::<T>::magic_1().get());
        assert!(SafeIntegral::<T>::magic_1() != SafeIntegral::<T>::magic_2().get());
        assert!(SafeIntegral::<T>::magic_1() < SafeIntegral::<T>::magic_2().get());
        assert!(SafeIntegral::<T>::magic_1() <= SafeIntegral::<T>::magic_2().get());
        assert!(SafeIntegral::<T>::magic_1() <= SafeIntegral::<T>::magic_1().get());
        assert!(SafeIntegral::<T>::magic_1() > SafeIntegral::<T>::magic_0().get());
        assert!(SafeIntegral::<T>::magic_1() >= SafeIntegral::<T>::magic_0().get());
        assert!(SafeIntegral::<T>::magic_1() >= SafeIntegral::<T>::magic_1().get());
    }

    #[test]
    fn safe_integral_rational() {
        safe_integral_rational_for_t::<i8>();
        safe_integral_rational_for_t::<i16>();
        safe_integral_rational_for_t::<i32>();
        safe_integral_rational_for_t::<i64>();
        safe_integral_rational_for_t::<u8>();
        safe_integral_rational_for_t::<u16>();
        safe_integral_rational_for_t::<u32>();
        safe_integral_rational_for_t::<u64>();
        safe_integral_rational_for_t::<usize>();
    }

    fn safe_integral_add_for_t<T>()
    where
        T: Integer,
    {
        let mut val = SafeIntegral::<T>::magic_1();
        val += SafeIntegral::<T>::magic_1();
        assert!(val.checked() == T::magic_2());

        let mut val = SafeIntegral::<T>::magic_1();
        val += SafeIntegral::<T>::max_value();
        assert!(val.is_invalid());

        let val = SafeIntegral::<T>::magic_1();
        assert!((val + SafeIntegral::<T>::magic_1()).checked() == T::magic_2());

        let val = SafeIntegral::<T>::magic_1();
        assert!((val + SafeIntegral::<T>::max_value()).is_invalid());

        let mut val = SafeIntegral::<T>::magic_1();
        val += T::magic_1();
        assert!(val.checked() == T::magic_2());

        let mut val = SafeIntegral::<T>::magic_1();
        val += T::max_value();
        assert!(val.is_invalid());

        let val = SafeIntegral::<T>::magic_1();
        assert!((val + T::magic_1()).checked() == T::magic_2());

        let val = SafeIntegral::<T>::magic_1();
        assert!((val + T::max_value()).is_invalid());
    }

    fn safe_integral_add_for_signed_t<T>()
    where
        T: SignedInteger,
    {
        let mut val = SafeIntegral::<T>::new(T::magic_neg_1());
        val += SafeIntegral::<T>::min_value();
        assert!(val.is_invalid());

        let val = SafeIntegral::<T>::new(T::magic_neg_1());
        assert!((val + SafeIntegral::<T>::min_value()).is_invalid());

        let mut val = SafeIntegral::<T>::new(T::magic_neg_1());
        val += T::min_value();
        assert!(val.is_invalid());

        let val = SafeIntegral::<T>::new(T::magic_neg_1());
        assert!((val + T::min_value()).is_invalid());
    }

    #[test]
    fn safe_integral_add() {
        safe_integral_add_for_t::<i8>();
        safe_integral_add_for_t::<i16>();
        safe_integral_add_for_t::<i32>();
        safe_integral_add_for_t::<i64>();
        safe_integral_add_for_t::<u8>();
        safe_integral_add_for_t::<u16>();
        safe_integral_add_for_t::<u32>();
        safe_integral_add_for_t::<u64>();
        safe_integral_add_for_t::<usize>();

        safe_integral_add_for_signed_t::<i8>();
        safe_integral_add_for_signed_t::<i16>();
        safe_integral_add_for_signed_t::<i32>();
        safe_integral_add_for_signed_t::<i64>();
    }

    fn safe_integral_sub_for_t<T>()
    where
        T: Integer,
    {
        let mut val = SafeIntegral::<T>::magic_1();
        val -= SafeIntegral::<T>::magic_1();
        assert!(val.checked() == T::magic_0());

        let mut val = SafeIntegral::<T>::min_value();
        val -= SafeIntegral::<T>::magic_1();
        assert!(val.is_invalid());

        let val = SafeIntegral::<T>::magic_1();
        assert!((val - SafeIntegral::<T>::magic_1()).checked() == T::magic_0());

        let val = SafeIntegral::<T>::min_value();
        assert!((val - SafeIntegral::<T>::magic_1()).is_invalid());

        let mut val = SafeIntegral::<T>::magic_1();
        val -= T::magic_1();
        assert!(val.checked() == T::magic_0());

        let mut val = SafeIntegral::<T>::min_value();
        val -= T::magic_1();
        assert!(val.is_invalid());

        let val = SafeIntegral::<T>::magic_1();
        assert!((val - T::magic_1()).checked() == T::magic_0());

        let val = SafeIntegral::<T>::min_value();
        assert!((val - T::magic_1()).is_invalid());
    }

    fn safe_integral_sub_for_signed_t<T>()
    where
        T: SignedInteger,
    {
        let mut val = SafeIntegral::<T>::max_value();
        val -= SafeIntegral::<T>::new(T::magic_neg_1());
        assert!(val.is_invalid());

        let val = SafeIntegral::<T>::max_value();
        assert!((val - SafeIntegral::<T>::new(T::magic_neg_1())).is_invalid());

        let mut val = SafeIntegral::<T>::max_value();
        val -= T::magic_neg_1();
        assert!(val.is_invalid());

        let val = SafeIntegral::<T>::max_value();
        assert!((val - T::magic_neg_1()).is_invalid());
    }

    #[test]
    fn safe_integral_sub() {
        safe_integral_sub_for_t::<i8>();
        safe_integral_sub_for_t::<i16>();
        safe_integral_sub_for_t::<i32>();
        safe_integral_sub_for_t::<i64>();
        safe_integral_sub_for_t::<u8>();
        safe_integral_sub_for_t::<u16>();
        safe_integral_sub_for_t::<u32>();
        safe_integral_sub_for_t::<u64>();
        safe_integral_sub_for_t::<usize>();

        safe_integral_sub_for_signed_t::<i8>();
        safe_integral_sub_for_signed_t::<i16>();
        safe_integral_sub_for_signed_t::<i32>();
        safe_integral_sub_for_signed_t::<i64>();
    }

    fn safe_integral_mul_for_t<T>()
    where
        T: Integer,
    {
        let mut val = SafeIntegral::<T>::magic_1();
        val *= SafeIntegral::<T>::magic_1();
        assert!(val.checked() == T::magic_1());

        let mut val = SafeIntegral::<T>::magic_2();
        val *= SafeIntegral::<T>::max_value();
        assert!(val.is_invalid());

        let val = SafeIntegral::<T>::magic_1();
        assert!((val * SafeIntegral::<T>::magic_1()).checked() == T::magic_1());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val * SafeIntegral::<T>::max_value()).is_invalid());

        let mut val = SafeIntegral::<T>::magic_1();
        val *= T::magic_1();
        assert!(val.checked() == T::magic_1());

        let mut val = SafeIntegral::<T>::magic_2();
        val *= T::max_value();
        assert!(val.is_invalid());

        let val = SafeIntegral::<T>::magic_1();
        assert!((val * T::magic_1()).checked() == T::magic_1());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val * T::max_value()).is_invalid());
    }

    #[test]
    fn safe_integral_mul() {
        safe_integral_mul_for_t::<i8>();
        safe_integral_mul_for_t::<i16>();
        safe_integral_mul_for_t::<i32>();
        safe_integral_mul_for_t::<i64>();
        safe_integral_mul_for_t::<u8>();
        safe_integral_mul_for_t::<u16>();
        safe_integral_mul_for_t::<u32>();
        safe_integral_mul_for_t::<u64>();
        safe_integral_mul_for_t::<usize>();
    }

    fn safe_integral_div_for_t<T>()
    where
        T: Integer,
    {
        let mut val = SafeIntegral::<T>::magic_2();
        val /= SafeIntegral::<T>::magic_2();
        assert!(val.checked() == T::magic_1());

        let mut val = SafeIntegral::<T>::magic_2();
        val /= SafeIntegral::<T>::magic_0();
        assert!(val.is_invalid());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val / SafeIntegral::<T>::magic_2()).checked() == T::magic_1());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val / SafeIntegral::<T>::magic_0()).is_invalid());

        let mut val = SafeIntegral::<T>::magic_2();
        val /= T::magic_2();
        assert!(val.checked() == T::magic_1());

        let mut val = SafeIntegral::<T>::magic_2();
        val /= T::magic_0();
        assert!(val.is_invalid());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val / T::magic_2()).checked() == T::magic_1());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val / T::magic_0()).is_invalid());
    }

    #[test]
    fn safe_integral_div() {
        safe_integral_div_for_t::<i8>();
        safe_integral_div_for_t::<i16>();
        safe_integral_div_for_t::<i32>();
        safe_integral_div_for_t::<i64>();
        safe_integral_div_for_t::<u8>();
        safe_integral_div_for_t::<u16>();
        safe_integral_div_for_t::<u32>();
        safe_integral_div_for_t::<u64>();
        safe_integral_div_for_t::<usize>();
    }

    fn safe_integral_rem_for_t<T>()
    where
        T: Integer,
    {
        let mut val = SafeIntegral::<T>::magic_3();
        val %= SafeIntegral::<T>::magic_2();
        assert!(val.checked() == T::magic_1());

        let mut val = SafeIntegral::<T>::magic_2();
        val %= SafeIntegral::<T>::magic_0();
        assert!(val.is_invalid());

        let val = SafeIntegral::<T>::magic_3();
        assert!((val % SafeIntegral::<T>::magic_2()).checked() == T::magic_1());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val % SafeIntegral::<T>::magic_0()).is_invalid());

        let mut val = SafeIntegral::<T>::magic_3();
        val %= T::magic_2();
        assert!(val.checked() == T::magic_1());

        let mut val = SafeIntegral::<T>::magic_2();
        val %= T::magic_0();
        assert!(val.is_invalid());

        let val = SafeIntegral::<T>::magic_3();
        assert!((val % T::magic_2()).checked() == T::magic_1());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val % T::magic_0()).is_invalid());
    }

    #[test]
    fn safe_integral_rem() {
        safe_integral_rem_for_t::<i8>();
        safe_integral_rem_for_t::<i16>();
        safe_integral_rem_for_t::<i32>();
        safe_integral_rem_for_t::<i64>();
        safe_integral_rem_for_t::<u8>();
        safe_integral_rem_for_t::<u16>();
        safe_integral_rem_for_t::<u32>();
        safe_integral_rem_for_t::<u64>();
        safe_integral_rem_for_t::<usize>();
    }

    fn safe_integral_shl_for_t<T>()
    where
        T: UnsignedInteger,
    {
        let mut val = SafeIntegral::<T>::magic_1();
        val <<= SafeIntegral::<T>::magic_1();
        assert!(val == T::magic_2());

        let mut val = SafeIntegral::<T>::magic_1();
        val <<= SafeIntegral::<T>::max_value();
        assert!(val.is_valid_and_checked());

        let val = SafeIntegral::<T>::magic_1();
        assert!((val << SafeIntegral::<T>::magic_1()) == T::magic_2());

        let val = SafeIntegral::<T>::magic_1();
        assert!((val << SafeIntegral::<T>::max_value()).is_valid_and_checked());

        let mut val = SafeIntegral::<T>::magic_1();
        val <<= T::magic_1();
        assert!(val == T::magic_2());

        let mut val = SafeIntegral::<T>::magic_2();
        val <<= T::max_value();
        assert!(val.is_valid_and_checked());

        let val = SafeIntegral::<T>::magic_1();
        assert!((val << T::magic_1()) == T::magic_2());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val << T::max_value()).is_valid_and_checked());
    }

    #[test]
    fn safe_integral_shl() {
        safe_integral_shl_for_t::<u8>();
        safe_integral_shl_for_t::<u16>();
        safe_integral_shl_for_t::<u32>();
        safe_integral_shl_for_t::<u64>();
        safe_integral_shl_for_t::<usize>();
    }

    fn safe_integral_shr_for_t<T>()
    where
        T: UnsignedInteger,
    {
        let mut val = SafeIntegral::<T>::magic_2();
        val >>= SafeIntegral::<T>::magic_1();
        assert!(val == T::magic_1());

        let mut val = SafeIntegral::<T>::magic_2();
        val >>= SafeIntegral::<T>::max_value();
        assert!(val.is_valid_and_checked());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val >> SafeIntegral::<T>::magic_1()) == T::magic_1());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val >> SafeIntegral::<T>::max_value()).is_valid_and_checked());

        let mut val = SafeIntegral::<T>::magic_2();
        val >>= T::magic_1();
        assert!(val == T::magic_1());

        let mut val = SafeIntegral::<T>::magic_2();
        val >>= T::max_value();
        assert!(val.is_valid_and_checked());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val >> T::magic_1()) == T::magic_1());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val >> T::max_value()).is_valid_and_checked());
    }

    #[test]
    fn safe_integral_shr() {
        safe_integral_shr_for_t::<u8>();
        safe_integral_shr_for_t::<u16>();
        safe_integral_shr_for_t::<u32>();
        safe_integral_shr_for_t::<u64>();
        safe_integral_shr_for_t::<usize>();
    }

    fn safe_integral_and_for_t<T>()
    where
        T: UnsignedInteger,
    {
        let mut val = SafeIntegral::<T>::magic_2();
        val &= SafeIntegral::<T>::magic_1();
        assert!(val == T::magic_0());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val & SafeIntegral::<T>::magic_1()) == T::magic_0());

        let mut val = SafeIntegral::<T>::magic_2();
        val &= T::magic_1();
        assert!(val == T::magic_0());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val & T::magic_1()) == T::magic_0());
    }

    #[test]
    fn safe_integral_and() {
        safe_integral_and_for_t::<u8>();
        safe_integral_and_for_t::<u16>();
        safe_integral_and_for_t::<u32>();
        safe_integral_and_for_t::<u64>();
        safe_integral_and_for_t::<usize>();
    }

    fn safe_integral_or_for_t<T>()
    where
        T: UnsignedInteger,
    {
        let mut val = SafeIntegral::<T>::magic_2();
        val |= SafeIntegral::<T>::magic_1();
        assert!(val == T::magic_3());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val | SafeIntegral::<T>::magic_1()) == T::magic_3());

        let mut val = SafeIntegral::<T>::magic_2();
        val |= T::magic_1();
        assert!(val == T::magic_3());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val | T::magic_1()) == T::magic_3());
    }

    #[test]
    fn safe_integral_or() {
        safe_integral_or_for_t::<u8>();
        safe_integral_or_for_t::<u16>();
        safe_integral_or_for_t::<u32>();
        safe_integral_or_for_t::<u64>();
        safe_integral_or_for_t::<usize>();
    }

    fn safe_integral_xor_for_t<T>()
    where
        T: UnsignedInteger,
    {
        let mut val = SafeIntegral::<T>::magic_2();
        val ^= SafeIntegral::<T>::magic_2();
        assert!(val == T::magic_0());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val ^ SafeIntegral::<T>::magic_2()) == T::magic_0());

        let mut val = SafeIntegral::<T>::magic_2();
        val ^= T::magic_2();
        assert!(val == T::magic_0());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val ^ T::magic_2()) == T::magic_0());
    }

    #[test]
    fn safe_integral_xor() {
        safe_integral_xor_for_t::<u8>();
        safe_integral_xor_for_t::<u16>();
        safe_integral_xor_for_t::<u32>();
        safe_integral_xor_for_t::<u64>();
        safe_integral_xor_for_t::<usize>();
    }

    fn safe_integral_not_for_t<T>()
    where
        T: UnsignedInteger,
    {
        assert!(!SafeIntegral::<T>::magic_1() == !T::magic_1());
    }

    #[test]
    fn safe_integral_not() {
        safe_integral_not_for_t::<u8>();
        safe_integral_not_for_t::<u16>();
        safe_integral_not_for_t::<u32>();
        safe_integral_not_for_t::<u64>();
        safe_integral_not_for_t::<usize>();
    }

    fn safe_integral_neg_for_t<T>()
    where
        T: SignedInteger,
    {
        assert!(-SafeIntegral::<T>::magic_1() == -T::magic_1());
    }

    #[test]
    fn safe_integral_neg() {
        safe_integral_neg_for_t::<i8>();
        safe_integral_neg_for_t::<i16>();
        safe_integral_neg_for_t::<i32>();
        safe_integral_neg_for_t::<i64>();
    }

    #[test]
    fn safe_integral_make_safe() {
        assert!(super::make_safe::<i8>(0).is_zero());
        assert!(super::make_safe::<i16>(0).is_zero());
        assert!(super::make_safe::<i32>(0).is_zero());
        assert!(super::make_safe::<i64>(0).is_zero());
        assert!(super::make_safe::<u8>(0).is_zero());
        assert!(super::make_safe::<u16>(0).is_zero());
        assert!(super::make_safe::<u32>(0).is_zero());
        assert!(super::make_safe::<u64>(0).is_zero());
        assert!(super::make_safe::<usize>(0).is_zero());
    }
}

// -----------------------------------------------------------------------------
// Policy Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod safe_integral_policy_tests {
    use super::Integer;
    use super::SafeIntegral;
    use super::SignedInteger;
    use super::UnsignedInteger;

    fn safe_integral_constructors_checked_policy_for_t<T>()
    where
        T: Integer,
    {
        assert_eq!(SafeIntegral::<T>::new(T::magic_1()).is_unchecked(), false);
        assert_eq!(SafeIntegral::<T>::new(T::magic_1()).is_invalid(), false);
    }

    #[test]
    fn safe_integral_constructors_checked_policy() {
        safe_integral_constructors_checked_policy_for_t::<i8>();
        safe_integral_constructors_checked_policy_for_t::<i16>();
        safe_integral_constructors_checked_policy_for_t::<i32>();
        safe_integral_constructors_checked_policy_for_t::<i64>();
        safe_integral_constructors_checked_policy_for_t::<u8>();
        safe_integral_constructors_checked_policy_for_t::<u16>();
        safe_integral_constructors_checked_policy_for_t::<u32>();
        safe_integral_constructors_checked_policy_for_t::<u64>();
        safe_integral_constructors_checked_policy_for_t::<usize>();
    }

    fn safe_integral_assignment_checked_policy_for_t<T>()
    where
        T: Integer,
    {
        let val1 = SafeIntegral::<T>::magic_1();
        let val2 = val1;
        assert_eq!(val2.is_unchecked(), false);
        assert_eq!(val2.is_invalid(), false);

        let val1 = SafeIntegral::<T>::failure();
        let val2 = val1;
        assert_eq!(val2.is_unchecked(), true);
        assert_eq!(val2.is_invalid(), true);
    }

    #[test]
    fn safe_integral_assignment_checked_policy() {
        safe_integral_assignment_checked_policy_for_t::<i8>();
        safe_integral_assignment_checked_policy_for_t::<i16>();
        safe_integral_assignment_checked_policy_for_t::<i32>();
        safe_integral_assignment_checked_policy_for_t::<i64>();
        safe_integral_assignment_checked_policy_for_t::<u8>();
        safe_integral_assignment_checked_policy_for_t::<u16>();
        safe_integral_assignment_checked_policy_for_t::<u32>();
        safe_integral_assignment_checked_policy_for_t::<u64>();
        safe_integral_assignment_checked_policy_for_t::<usize>();
    }

    fn safe_integral_get_policy_for_t<T>()
    where
        T: Integer + std::panic::RefUnwindSafe,
    {
        let val = SafeIntegral::<T>::magic_1();
        assert_eq!(val.get(), T::magic_1());

        let val = SafeIntegral::<T>::magic_1() + SafeIntegral::<T>::magic_1();
        assert_eq!(val.checked().get(), T::magic_2());

        let val = SafeIntegral::<T>::failure();
        assert_panics!(val.get());

        let val = SafeIntegral::<T>::magic_1() + SafeIntegral::<T>::magic_1();
        assert_panics!(val.get() == T::magic_1());
    }

    #[test]
    fn safe_integral_get_policy() {
        safe_integral_get_policy_for_t::<i8>();
        safe_integral_get_policy_for_t::<i16>();
        safe_integral_get_policy_for_t::<i32>();
        safe_integral_get_policy_for_t::<i64>();
        safe_integral_get_policy_for_t::<u8>();
        safe_integral_get_policy_for_t::<u16>();
        safe_integral_get_policy_for_t::<u32>();
        safe_integral_get_policy_for_t::<u64>();
        safe_integral_get_policy_for_t::<usize>();
    }

    fn safe_integral_is_pos_policy_for_t<T>()
    where
        T: Integer + std::panic::RefUnwindSafe,
    {
        let val = SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_pos(), true);

        let val = SafeIntegral::<T>::magic_1() + SafeIntegral::<T>::magic_1();
        assert_eq!(val.checked().is_pos(), true);

        let val = SafeIntegral::<T>::failure();
        assert_panics!(val.is_pos());

        let val = SafeIntegral::<T>::magic_1() + SafeIntegral::<T>::magic_1();
        assert_panics!(val.is_pos());
    }

    #[test]
    fn safe_integral_is_pos_policy() {
        safe_integral_is_pos_policy_for_t::<i8>();
        safe_integral_is_pos_policy_for_t::<i16>();
        safe_integral_is_pos_policy_for_t::<i32>();
        safe_integral_is_pos_policy_for_t::<i64>();
        safe_integral_is_pos_policy_for_t::<u8>();
        safe_integral_is_pos_policy_for_t::<u16>();
        safe_integral_is_pos_policy_for_t::<u32>();
        safe_integral_is_pos_policy_for_t::<u64>();
        safe_integral_is_pos_policy_for_t::<usize>();
    }

    fn safe_integral_is_zero_policy_for_t<T>()
    where
        T: Integer + std::panic::RefUnwindSafe,
    {
        let val = SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_zero(), false);

        let val = SafeIntegral::<T>::magic_1() + SafeIntegral::<T>::magic_1();
        assert_eq!(val.checked().is_zero(), false);

        let val = SafeIntegral::<T>::failure();
        assert_panics!(val.is_zero());

        let val = SafeIntegral::<T>::magic_1() + SafeIntegral::<T>::magic_1();
        assert_panics!(val.is_zero());
    }

    #[test]
    fn safe_integral_is_zero_policy() {
        safe_integral_is_zero_policy_for_t::<i8>();
        safe_integral_is_zero_policy_for_t::<i16>();
        safe_integral_is_zero_policy_for_t::<i32>();
        safe_integral_is_zero_policy_for_t::<i64>();
        safe_integral_is_zero_policy_for_t::<u8>();
        safe_integral_is_zero_policy_for_t::<u16>();
        safe_integral_is_zero_policy_for_t::<u32>();
        safe_integral_is_zero_policy_for_t::<u64>();
        safe_integral_is_zero_policy_for_t::<usize>();
    }

    fn safe_integral_is_neg_policy_for_t<T>()
    where
        T: SignedInteger + std::panic::RefUnwindSafe,
    {
        let val = SafeIntegral::<T>::magic_neg_1();
        assert_eq!(val.is_neg(), true);

        let val = SafeIntegral::<T>::magic_neg_1() + SafeIntegral::<T>::magic_neg_1();
        assert_eq!(val.checked().is_neg(), true);

        let val = SafeIntegral::<T>::failure();
        assert_panics!(val.is_neg());

        let val = SafeIntegral::<T>::magic_neg_1() + SafeIntegral::<T>::magic_neg_1();
        assert_panics!(val.is_neg());
    }

    #[test]
    fn safe_integral_is_neg_policy() {
        safe_integral_is_neg_policy_for_t::<i8>();
        safe_integral_is_neg_policy_for_t::<i16>();
        safe_integral_is_neg_policy_for_t::<i32>();
        safe_integral_is_neg_policy_for_t::<i64>();
    }

    fn safe_integral_is_poisoned_policy_for_t<T>()
    where
        T: Integer,
    {
        let mut val = SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_poisoned(), false);

        let mut val = SafeIntegral::<T>::failure();
        assert_eq!(val.is_poisoned(), true);

        let mut val = SafeIntegral::<T>::magic_1() + SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        val.is_poisoned();
        assert_eq!(val.is_checked(), true);
    }

    #[test]
    fn safe_integral_is_poisoned_policy() {
        safe_integral_is_poisoned_policy_for_t::<i8>();
        safe_integral_is_poisoned_policy_for_t::<i16>();
        safe_integral_is_poisoned_policy_for_t::<i32>();
        safe_integral_is_poisoned_policy_for_t::<i64>();
        safe_integral_is_poisoned_policy_for_t::<u8>();
        safe_integral_is_poisoned_policy_for_t::<u16>();
        safe_integral_is_poisoned_policy_for_t::<u32>();
        safe_integral_is_poisoned_policy_for_t::<u64>();
        safe_integral_is_poisoned_policy_for_t::<usize>();
    }

    fn safe_integral_checked_policy_for_t<T>()
    where
        T: Integer + std::panic::RefUnwindSafe,
    {
        let val = SafeIntegral::<T>::magic_1();
        assert!(val.checked() == SafeIntegral::<T>::magic_1());

        let val = SafeIntegral::<T>::magic_1() + SafeIntegral::<T>::magic_1();
        assert!(val.checked() == SafeIntegral::<T>::magic_2());

        let val = SafeIntegral::<T>::failure();
        assert_panics!(val.checked());
    }

    #[test]
    fn safe_integral_checked_policy() {
        safe_integral_checked_policy_for_t::<i8>();
        safe_integral_checked_policy_for_t::<i16>();
        safe_integral_checked_policy_for_t::<i32>();
        safe_integral_checked_policy_for_t::<i64>();
        safe_integral_checked_policy_for_t::<u8>();
        safe_integral_checked_policy_for_t::<u16>();
        safe_integral_checked_policy_for_t::<u32>();
        safe_integral_checked_policy_for_t::<u64>();
        safe_integral_checked_policy_for_t::<usize>();
    }

    fn safe_integral_arithmetic_policy_for_t<T>()
    where
        T: Integer,
    {
        let val = SafeIntegral::<T>::magic_1() + SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        let val = SafeIntegral::<T>::magic_1() + T::magic_1();
        assert_eq!(val.is_checked(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val += SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val += T::magic_1();
        assert_eq!(val.is_checked(), false);

        let val = SafeIntegral::<T>::failure() + SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::magic_1() + SafeIntegral::<T>::failure();
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::failure() + T::magic_1();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val += SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val += SafeIntegral::<T>::failure();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val += T::magic_1();
        assert_eq!(val.is_valid(), false);

        let val = SafeIntegral::<T>::magic_1() - SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        let val = SafeIntegral::<T>::magic_1() - T::magic_1();
        assert_eq!(val.is_checked(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val -= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val -= T::magic_1();
        assert_eq!(val.is_checked(), false);

        let val = SafeIntegral::<T>::failure() - SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::magic_1() - SafeIntegral::<T>::failure();
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::failure() - T::magic_1();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val -= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val -= SafeIntegral::<T>::failure();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val -= T::magic_1();
        assert_eq!(val.is_valid(), false);

        let val = SafeIntegral::<T>::magic_1() * SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        let val = SafeIntegral::<T>::magic_1() * T::magic_1();
        assert_eq!(val.is_checked(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val *= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val *= T::magic_1();
        assert_eq!(val.is_checked(), false);

        let val = SafeIntegral::<T>::failure() * SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::magic_1() * SafeIntegral::<T>::failure();
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::failure() * T::magic_1();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val *= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val *= SafeIntegral::<T>::failure();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val *= T::magic_1();
        assert_eq!(val.is_valid(), false);

        let val = SafeIntegral::<T>::magic_1() / SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        let val = SafeIntegral::<T>::magic_1() / T::magic_1();
        assert_eq!(val.is_checked(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val /= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val /= T::magic_1();
        assert_eq!(val.is_checked(), false);

        let val = SafeIntegral::<T>::failure() / SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::magic_1() / SafeIntegral::<T>::failure();
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::failure() / T::magic_1();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val /= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val /= SafeIntegral::<T>::failure();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val /= T::magic_1();
        assert_eq!(val.is_valid(), false);

        let val = SafeIntegral::<T>::magic_1() % SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        let val = SafeIntegral::<T>::magic_1() % T::magic_1();
        assert_eq!(val.is_checked(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val %= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val %= T::magic_1();
        assert_eq!(val.is_checked(), false);

        let val = SafeIntegral::<T>::failure() % SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::magic_1() % SafeIntegral::<T>::failure();
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::failure() % T::magic_1();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val %= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val %= SafeIntegral::<T>::failure();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val %= T::magic_1();
        assert_eq!(val.is_valid(), false);
    }

    #[test]
    fn safe_integral_arithmetic_policy() {
        safe_integral_arithmetic_policy_for_t::<i8>();
        safe_integral_arithmetic_policy_for_t::<i16>();
        safe_integral_arithmetic_policy_for_t::<i32>();
        safe_integral_arithmetic_policy_for_t::<i64>();
        safe_integral_arithmetic_policy_for_t::<u8>();
        safe_integral_arithmetic_policy_for_t::<u16>();
        safe_integral_arithmetic_policy_for_t::<u32>();
        safe_integral_arithmetic_policy_for_t::<u64>();
        safe_integral_arithmetic_policy_for_t::<usize>();
    }

    fn safe_integral_shift_policy_for_t<T>()
    where
        T: UnsignedInteger,
    {
        let val = SafeIntegral::<T>::magic_1() << SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), true);
        let val = SafeIntegral::<T>::magic_1() << T::magic_1();
        assert_eq!(val.is_checked(), true);
        let mut val = SafeIntegral::<T>::magic_1();
        val <<= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), true);
        let mut val = SafeIntegral::<T>::magic_1();
        val <<= T::magic_1();
        assert_eq!(val.is_checked(), true);

        let val = SafeIntegral::<T>::failure() << SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::magic_1() << SafeIntegral::<T>::failure();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::failure() << T::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val <<= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val <<= SafeIntegral::<T>::failure();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val <<= T::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);

        let val = SafeIntegral::<T>::magic_1() >> SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), true);
        let val = SafeIntegral::<T>::magic_1() >> T::magic_1();
        assert_eq!(val.is_checked(), true);
        let mut val = SafeIntegral::<T>::magic_1();
        val >>= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), true);
        let mut val = SafeIntegral::<T>::magic_1();
        val >>= T::magic_1();
        assert_eq!(val.is_checked(), true);

        let val = SafeIntegral::<T>::failure() >> SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::magic_1() >> SafeIntegral::<T>::failure();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::failure() >> T::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val >>= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val >>= SafeIntegral::<T>::failure();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val >>= T::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
    }

    #[test]
    fn safe_integral_shift_policy() {
        safe_integral_shift_policy_for_t::<u8>();
        safe_integral_shift_policy_for_t::<u16>();
        safe_integral_shift_policy_for_t::<u32>();
        safe_integral_shift_policy_for_t::<u64>();
        safe_integral_shift_policy_for_t::<usize>();
    }

    fn safe_integral_binary_policy_for_t<T>()
    where
        T: UnsignedInteger,
    {
        let val = SafeIntegral::<T>::magic_1() & SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), true);
        let val = SafeIntegral::<T>::magic_1() & T::magic_1();
        assert_eq!(val.is_checked(), true);
        let mut val = SafeIntegral::<T>::magic_1();
        val &= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), true);
        let mut val = SafeIntegral::<T>::magic_1();
        val &= T::magic_1();
        assert_eq!(val.is_checked(), true);

        let val = SafeIntegral::<T>::failure() & SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::magic_1() & SafeIntegral::<T>::failure();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::failure() & T::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val &= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val &= SafeIntegral::<T>::failure();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val &= T::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);

        let val = SafeIntegral::<T>::magic_1() | SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), true);
        let val = SafeIntegral::<T>::magic_1() | T::magic_1();
        assert_eq!(val.is_checked(), true);
        let mut val = SafeIntegral::<T>::magic_1();
        val |= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), true);
        let mut val = SafeIntegral::<T>::magic_1();
        val |= T::magic_1();
        assert_eq!(val.is_checked(), true);

        let val = SafeIntegral::<T>::failure() | SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::magic_1() | SafeIntegral::<T>::failure();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::failure() | T::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val |= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val |= SafeIntegral::<T>::failure();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val |= T::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);

        let val = SafeIntegral::<T>::magic_1() ^ SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), true);
        let val = SafeIntegral::<T>::magic_1() ^ T::magic_1();
        assert_eq!(val.is_checked(), true);
        let mut val = SafeIntegral::<T>::magic_1();
        val ^= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), true);
        let mut val = SafeIntegral::<T>::magic_1();
        val ^= T::magic_1();
        assert_eq!(val.is_checked(), true);

        let val = SafeIntegral::<T>::failure() ^ SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::magic_1() ^ SafeIntegral::<T>::failure();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::failure() ^ T::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val ^= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val ^= SafeIntegral::<T>::failure();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val ^= T::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
    }

    #[test]
    fn safe_integral_binary_policy() {
        safe_integral_binary_policy_for_t::<u8>();
        safe_integral_binary_policy_for_t::<u16>();
        safe_integral_binary_policy_for_t::<u32>();
        safe_integral_binary_policy_for_t::<u64>();
        safe_integral_binary_policy_for_t::<usize>();
    }

    fn safe_integral_not_policy_for_t<T>()
    where
        T: UnsignedInteger,
    {
        let val = !SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), true);

        let val = !SafeIntegral::<T>::failure();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
    }

    #[test]
    fn safe_integral_not_policy() {
        safe_integral_not_policy_for_t::<u8>();
        safe_integral_not_policy_for_t::<u16>();
        safe_integral_not_policy_for_t::<u32>();
        safe_integral_not_policy_for_t::<u64>();
        safe_integral_not_policy_for_t::<usize>();
    }

    fn safe_integral_neg_policy_for_t<T>()
    where
        T: SignedInteger,
    {
        let val = -SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), true);

        let val = -SafeIntegral::<T>::failure();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);

        let val = -SafeIntegral::<T>::min_value();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
    }

    #[test]
    fn safe_integral_neg_policy() {
        safe_integral_neg_policy_for_t::<i8>();
        safe_integral_neg_policy_for_t::<i16>();
        safe_integral_neg_policy_for_t::<i32>();
        safe_integral_neg_policy_for_t::<i64>();
    }
}
