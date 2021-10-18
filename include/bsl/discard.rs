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

/// <!-- description -->
///   @brief This function discards a parameter that it is given. This is
///     the same as executing a static cast. The reason this exists is
///     it better documents the intent to discard the result of a function
///     or an intentionally unused parameter. This function also exists
///     because in some cases, we must pass the address of a discard as
///     as a template parameter, which cannot be done with a static cast.
///
/// <!-- inputs/outputs -->
///   @param arg the argument to ignore
///
pub fn discard<T>(_arg: T) {}

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod test_discard {
    use super::*;

    fn foo() -> u32 {
        return 42;
    }

    #[test]
    fn discard_general() {
        let val1 = 42;
        let mut val2 = 42;
        val2 = val2 + 23;

        discard(val1);
        discard(val2);
        discard(foo());
    }
}
