/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///
/// @file touch.hpp
///

#ifndef TOUCH_HPP
#define TOUCH_HPP

namespace bsl
{
    /// <!-- description -->
    ///   @brief In some cases, we must provide an "line of code", even if
    ///     there really isn't anything to do. This is done to ensure line
    ///     coverage proves that all possible branches are taken. The best
    ///     examples of this is when you have an if statement, that terminates
    ///     without a line of code following.
    ///
    ///     For example:
    ///     @code
    ///     [[nodiscard]] constexpr bsl::errc_type
    ///     foo1(bool const a, bool const b) noexcept
    ///     {
    ///         if (a) {
    ///             if (b) {
    ///                 return bsl::errc_success;
    ///             }
    ///         }
    ///
    ///         return bsl::errc_failure;
    ///     }
    ///
    ///     [[nodiscard]] constexpr bsl::errc_type
    ///     foo2(bool const a, bool const b) noexcept
    ///     {
    ///         if (a) {
    ///             if (b) {
    ///                 return bsl::errc_success;
    ///             }
    ///             else {
    ///                 bsl::touch();
    ///             }
    ///         }
    ///
    ///         return bsl::errc_failure;
    ///     }
    ///     @endcode
    ///
    ///     In foo1, the `if (b)` statement does not have an `else` with it.
    ///     As a result, the code coverage tool has no way of knowing if the
    ///     branch is not taken without relying on the compiler's ability to
    ///     report this sort of behavior which in practice is not reliable.
    ///     Instead, in foo2, we provide an `else`, but we still need a line
    ///     of code for the code coverage tool to detect that the branch was
    ///     not taken. A comment will not work as that will not be included
    ///     in the coverage analysis. Instead, we add the bsl::touch() logic
    ///     which ensures that the line is seen by the coverage tool, and
    ///     therefor the coverage tool will know if all of our branchs are
    ///     taken properly. If you see bsl::touch(), it is likely due to this
    ///     type of situation. Note that we care about the code coverage part
    ///     of this because some critical systems applications required MC/DC
    ///     testing. To overcome the complications with this, we do not allow
    ///     any of the boolean operators, and we also require that this type
    ///     of thing is done. With these rules, all MC/DC testing can be
    ///     verified using simple line coverage (i.e., no need for truth
    ///     tables and complicated testing practices).
    ///
    constexpr void
    touch() noexcept
    {}
}

#endif
