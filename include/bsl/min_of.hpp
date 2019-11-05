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
/// @file min_of.hpp
///

#ifndef BSL_MIN_OF_HPP
#define BSL_MIN_OF_HPP

namespace bsl
{
    /// <!-- description -->
    ///   @brief Returns a if a is smaller than b, otherwise returns b. Note
    ///     that this function is called min_of to prevent a name collision
    ///     with numeric_limits<>::min().
    ///   @include example_min_of_overview.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T The type that defines both a and b
    ///   @param a the first parameter to compare
    ///   @param b the second parameter to compare
    ///   @return Returns a if a is smaller than b, otherwise returns b.
    ///
    template<typename T>
    constexpr T const &
    min_of(T const &a, T const &b) noexcept
    {
        return (b < a) ? b : a;
    }
}

#endif
