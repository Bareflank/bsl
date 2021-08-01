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

/// @brief provides the default ErrcType prototype
pub type ErrcType = crate::BasicErrcType<i32>;

// -----------------------------------------------------------------------------
// Pre-defined Error Codes
// -----------------------------------------------------------------------------

/// @brief Defines the "no error" case
#[allow(non_upper_case_globals)]
pub const errc_success: ErrcType = ErrcType::new(0);
/// @brief Defines the general unchecked error case
#[allow(non_upper_case_globals)]
pub const errc_failure: ErrcType = ErrcType::new(-1);
/// @brief Defines the general precondition error case
#[allow(non_upper_case_globals)]
pub const errc_precondition: ErrcType = ErrcType::new(-2);
/// @brief Defines the general postcondition error case
#[allow(non_upper_case_globals)]
pub const errc_postcondition: ErrcType = ErrcType::new(-3);
/// @brief Defines the general assertion error case
#[allow(non_upper_case_globals)]
pub const errc_assetion: ErrcType = ErrcType::new(-4);

/// @brief Defines an invalid argument error code
#[allow(non_upper_case_globals)]
pub const errc_invalid_argument: ErrcType = ErrcType::new(-10);
/// @brief Defines an out of bounds error code
#[allow(non_upper_case_globals)]
pub const errc_index_out_of_bounds: ErrcType = ErrcType::new(-11);

/// @brief Defines an unsigned wrap error
#[allow(non_upper_case_globals)]
pub const errc_unsigned_wrap: ErrcType = ErrcType::new(-30);
/// @brief Defines a narrow overflow error
#[allow(non_upper_case_globals)]
pub const errc_narrow_overflow: ErrcType = ErrcType::new(-31);
/// @brief Defines a signed overflow error
#[allow(non_upper_case_globals)]
pub const errc_signed_overflow: ErrcType = ErrcType::new(-32);
/// @brief Defines a divide by zero error
#[allow(non_upper_case_globals)]
pub const errc_divide_by_zero: ErrcType = ErrcType::new(-33);
/// @brief Defines an out of bounds error code
#[allow(non_upper_case_globals)]
pub const errc_nullptr_dereference: ErrcType = ErrcType::new(-34);

/// @brief Defines when a resource is busy
#[allow(non_upper_case_globals)]
pub const errc_busy: ErrcType = ErrcType::new(-50);
/// @brief Defines when a resource already_exists
#[allow(non_upper_case_globals)]
pub const errc_already_exists: ErrcType = ErrcType::new(-51);
/// @brief Defines when something is unsupported
#[allow(non_upper_case_globals)]
pub const errc_unsupported: ErrcType = ErrcType::new(-52);

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod test_errc_type {
    use super::*;

    #[test]
    fn errc_type_success() {
        assert!(errc_success.success());
        assert!(!errc_failure.success());
        assert!(!errc_precondition.success());
        assert!(!errc_postcondition.success());
        assert!(!errc_assetion.success());
        assert!(!errc_invalid_argument.success());
        assert!(!errc_index_out_of_bounds.success());
        assert!(!errc_unsigned_wrap.success());
        assert!(!errc_narrow_overflow.success());
        assert!(!errc_signed_overflow.success());
        assert!(!errc_divide_by_zero.success());
        assert!(!errc_nullptr_dereference.success());
        assert!(!errc_busy.success());
        assert!(!errc_already_exists.success());
        assert!(!errc_unsupported.success());
    }

    #[test]
    fn errc_type_failure() {
        assert!(!errc_success.failure());
        assert!(errc_failure.failure());
        assert!(errc_precondition.failure());
        assert!(errc_postcondition.failure());
        assert!(errc_assetion.failure());
        assert!(errc_invalid_argument.failure());
        assert!(errc_index_out_of_bounds.failure());
        assert!(errc_unsigned_wrap.failure());
        assert!(errc_narrow_overflow.failure());
        assert!(errc_signed_overflow.failure());
        assert!(errc_divide_by_zero.failure());
        assert!(errc_nullptr_dereference.failure());
        assert!(errc_busy.failure());
        assert!(errc_already_exists.failure());
        assert!(errc_unsupported.failure());
    }
}
