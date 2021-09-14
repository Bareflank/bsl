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
use core::fmt;
use core::panic::Location;

#[derive(Debug, Copy, Clone)]
pub struct SourceLocation(&'static Location<'static>);

impl SourceLocation
{
    #[track_caller]
    pub fn caller() -> SourceLocation {
        return SourceLocation {
            0: Location::caller(),
        };
    }

    pub fn file(&self) -> &str {
        self.0.file()
    }

    pub fn line(&self) -> u32 {
        self.0.line()
    }
}


/// <!-- description -->
///   @brief This provides a less verbose version of
///     bsl::SourceLocation::current() to help reduce how large this
///     code must be. They are equivalent, and should not produce any
///     additional overhead in release mode.
///
/// <!-- inputs/outputs -->
///   @param sloc the SourceLocation object corresponding to
///     the location of the call site.
///   @return the SourceLocation object corresponding to
///     the location of the call site.
///
#[track_caller]
pub fn here() -> SourceLocation {
    return SourceLocation::caller();
}

// -----------------------------------------------------------------------------
// Output
// -----------------------------------------------------------------------------

impl fmt::Display for SourceLocation
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use crate::ylw;
        use crate::cyn;
        use crate::rst;

        let file = self.file();
        let line = self.line();
        return write!(f, "  --> {}{}{}:{}{}{}\n", ylw, file, rst, cyn, line, rst);
    }
}

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod test_source_location {
    use super::*;
    use crate::*;

    #[test]
    fn source_location_general() {
        debug!("{}", here());
        debug!("{:?}", here());
        debug!("{}", here().clone());
        debug!("{}", SourceLocation::caller());
        debug!("{}", SourceLocation::caller().file());
        debug!("{}", SourceLocation::caller().line());
    }
}
