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
/// @file always_false.hpp
///

#ifndef BSL_ALWAYS_FALSE_HPP
#define BSL_ALWAYS_FALSE_HPP

namespace bsl
{
    /// <!-- description -->
    ///   @brief Always returns false. This can be used in a static_assert
    ///     to cause the static_assert to trigger if a function is used.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T used to ensure the call to always_false is only evaluated
    ///     once a template type is instantiated.
    ///   @return Always returns false.
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    always_false() noexcept -> bool
    {
        // The following redundent statement is one of the best ways to
        // ensure "false" is not determined in a static_assert until after
        // the function with the static_assert is used.
        // NOLINTNEXTLINE(misc-redundant-expression)
        return sizeof(T) != sizeof(T);
    }
}

#endif
