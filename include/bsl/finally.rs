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

/// @struct bsl::finally
///
/// <!-- description -->
///   @brief Executes a provided function on destruction. This class is
///     useful for providing general cleanup code that is common with
///     each step of a process. It should be noted that this should never
///     be used global, and instead is only intended to be used from the
///     scope of a function.
///
/// <!-- template parameters -->
///   @tparam FuncT the type of function to call
///
pub struct Finally<FuncT>
where
    FuncT: FnMut(),
{
    /// @brief stores the function invoke on destruction
    m_func: FuncT,
    /// @brief stores whether or not the function was invoked
    m_invoked: bool,
}

impl<FuncT> Finally<FuncT>
where
    FuncT: FnMut(),
{
    /// <!-- description -->
    ///   @brief Creates a bsl::finally given the function to call
    ///     on destruction.
    ///
    /// <!-- inputs/outputs -->
    ///   @param func the function to call on destruction
    ///
    pub fn new(func: FuncT) -> Self {
        Self {
            m_func: func,
            m_invoked: false,
        }
    }

    /// <!-- description -->
    ///   @brief Set the invoked status to true, preventing the provided
    ///     function from being called on destruction.
    ///
    pub fn ignore(&mut self) {
        self.m_invoked = true;
    }
}

impl<FuncT> Drop for Finally<FuncT>
where
    FuncT: FnMut(),
{
    /// <!-- description -->
    ///   @brief Destroyes a previously created bsl::finally, calling
    ///     the provided function if ignore() was never called
    ///
    fn drop(&mut self) {
        if !self.m_invoked {
            let func = &mut self.m_func;
            func();
        }
    }
}

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod test_finally {
    use core::cell::Cell;

    #[test]
    fn finally_general() {
        let executed = Cell::new(false);
        let func = || {
            executed.set(true);
        };

        executed.set(false);
        {
            let _execute_foo = super::Finally::new(func);
        }
        assert!(executed.get() == true);

        executed.set(false);
        {
            let mut execute_foo = super::Finally::new(func);
            execute_foo.ignore();
        }
        assert!(executed.get() == false);
    }
}
