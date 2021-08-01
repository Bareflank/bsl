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

use crate::IntoBool;

/// <!-- description -->
///   @brief If test is false, a contract violation has occurred. This
///     should be used to assert preconditions that if not meet, would
///     result in undefined behavior. These should not be tested by a
///     unit test, meaning they are contract violations. These asserts
///     are simply there as a sanity check during a debug build.
///
/// <!-- inputs/outputs -->
///   @param test the contract to check
///
#[track_caller]
pub fn expects<T>(test: T)
where
    T: IntoBool,
{
    if !test.into_bool() {
        crate::assert("expects contract violation", crate::here());
    } else {
        crate::touch();
    }
}

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod test_expects {
    use super::*;
    use crate::*;

    #[test]
    fn expects_bool() {
        expects(true);
        assert_panics!(expects(false));
    }

    #[test]
    fn expects_errc_type() {
        expects(errc_success);
        assert_panics!(expects(errc_failure));
    }
}
