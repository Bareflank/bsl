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
/// @file fill.hpp
///

#ifndef BSL_FILL_HPP
#define BSL_FILL_HPP

#include "enable_if.hpp"
#include "is_copy_assignable.hpp"
#include "is_nothrow_copy_assignable.hpp"
#include "safe_integral.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief Sets all elements of a view to "value". T must be
    ///     copy assignable.
    ///   @include example_fill_overview.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type that defines the values being filled
    ///   @param vw the view to fill
    ///   @param value the value to set the view's elements to
    ///
    /// <!-- inputs/outputs -->
    ///   @throw throws if the copy assignment of T throws
    ///
    template<typename VIEW, typename T, enable_if_t<is_copy_assignable<T>::value, bool> = true>
    constexpr void
    fill(VIEW &vw, T const &value) noexcept(    // --
        is_nothrow_copy_assignable<T>::value)
    {
        for (safe_uintmax i{}; i < vw.size(); ++i) {
            *vw.at_if(i) = value;
        }
    }

    /// <!-- description -->
    ///   @brief Sets all elements of a view to "value". T must be
    ///     copy assignable.
    ///   @include example_fill_overview.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type that defines the values being filled
    ///   @param first the position to start the loop
    ///   @param last the position to end the loop
    ///   @param value the value to set the view's elements to
    ///
    /// <!-- inputs/outputs -->
    ///   @throw throws if the copy assignment of T throws
    ///
    template<typename ITER, typename T, enable_if_t<is_copy_assignable<T>::value, bool> = true>
    constexpr void
    fill(ITER first, ITER last, T const &value) noexcept(    // --
        is_nothrow_copy_assignable<T>::value)
    {
        for (; first < last; ++first) {
            *first.get_if() = value;
        }
    }
}

#endif
