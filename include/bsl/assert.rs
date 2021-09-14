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
use crate::SourceLocation;

/// <!-- description -->
///   @brief Outputs a raw error string to stderr if debugging is
///     turned on, along with the location of the assert. If
///     BSL_ASSERT_FAST_FAILS is enabled, the assert will fast fail.
///     In release mode, this function does nothing.
///
/// <!-- inputs/outputs -->
///   @param str a string to output to stderr
///   @param sloc the location of the assert
///
#[cfg(debug_assertions)]
pub fn assert(msg: &str, sloc: SourceLocation) -> ! {
    use crate::ylw;
    use crate::cyn;
    use crate::rst;

    let file = sloc.file();
    let line = sloc.line();
    panic!("ASSERT: {} --> {}{}{}:{}{}{}\n", msg, ylw, file, rst, cyn, line, rst);
}

#[cfg(not(debug_assertions))]
pub fn assert(_msg: &str, _sloc: SourceLocation) {}

// -----------------------------------------------------------------------------
// Helper Macros
// -----------------------------------------------------------------------------

#[cfg(test)]
#[macro_export]
macro_rules! assert_panics {
    ($expression:expr) => {
        assert!(std::panic::catch_unwind(|| $expression).is_err())
    };
}

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod test_assert {
    use super::*;

    #[test]
    fn assert_general() {
        // NOTE:
        // - the following test ensures 100% code coverage and can be removed
        //   when the LLVM coverage bugs have been addressed. For some reason
        //   when this is added, code coverage acts as expected.
        let x = 10;
        assert!(x == 10);

        assert_panics!(assert!(false));
        assert_panics!(assert_panics!(assert!(true)));
        assert_panics!(assert("panic", crate::here()));
    }
}
